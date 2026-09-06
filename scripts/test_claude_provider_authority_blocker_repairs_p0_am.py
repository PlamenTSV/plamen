from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
from types import SimpleNamespace

import pytest

import claude_auth_route as A
import claude_child_environment as C
import claude_executable_observation as O
import claude_launch_security as L
import claude_provider_preparation as P
import claude_stored_subscription_source as S
import test_claude_launch_authority_fixtures as T


VERSION = "2.1.220"


def _digest(value: dict[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _stored_evidence() -> A.PromotedStoredSubscriptionSourceEvidence:
    core: dict[str, object] = {
        "schema": A.STORED_SUBSCRIPTION_SOURCE_SCHEMA,
        "store_class": "FILE_BACKED",
        "source_identity": "fixture-private-store",
        "source_size": 64,
        "available": True,
        "observation_authority_sha256": "7" * 64,
        "credential_values_recorded": False,
        "credential_content_hashes_recorded": False,
    }
    return A._promote_stored_subscription_source_evidence(
        {**core, "receipt_sha256": _digest(core)},
        provider_authority_sha256="7" * 64,
    )


def _auth_environment(
    ambient: dict[str, str],
) -> tuple[
    A.ClaudeAuthEnvironmentCapability,
    dict[str, object],
    A.ClaudeAuthSourceCapability,
]:
    observation = A.observe_claude_auth_sources(
        ambient,
        settings={},
        settings_authority_sha256=None,
        stored_subscription_evidence=_stored_evidence(),
    )
    endpoint = A.compile_claude_endpoint_policy(
        desired_route="STORED_SUBSCRIPTION_OAUTH",
        endpoint_mode="OFFICIAL_DEFAULT",
        endpoint_environment={},
    )
    environment, receipt = A.compile_claude_auth_environment(
        ambient,
        desired_route="STORED_SUBSCRIPTION_OAUTH",
        source_observation=observation,
        claude_code_version=VERSION,
        endpoint_policy=endpoint,
    )
    return environment, receipt, observation


def _profile_environment(root: Path, *, private: bool) -> dict[str, str]:
    result = {
        "CLAUDE_CONFIG_DIR": str(root / "claude"),
        "CLAUDE_CODE_TMPDIR": str(root / "tmp"),
        "TMP": str(root / "tmp"),
        "TEMP": str(root / "tmp"),
        "TMPDIR": str(root / "tmp"),
    }
    if private:
        result.update(
            {
                "HOME": str(root / "home"),
                "USERPROFILE": str(root / "home"),
                "APPDATA": str(root / "home" / "appdata"),
                "LOCALAPPDATA": str(root / "home" / "localappdata"),
            }
        )
    return result


def test_offline_helper_bundle_is_not_production_launch_authority(
    tmp_path: Path,
) -> None:
    bundle = T.compile_test_claude_launch_authority(
        cwd=tmp_path,
        launch_model="fixture-model",
        stdout_limit_bytes=64 * 1024,
        session_label="no-provider-authority",
    )
    request = bundle["request"]
    assert set(request) == {
        "schema",
        "policy",
        "executable_observation",
        "request_sha256",
    }
    assert request["schema"] == L.CLAUDE_LAUNCH_SECURITY_REQUEST_SCHEMA
    assert "authority_class" not in request
    assert L.replay_claude_launch_security_request(request) == request

    current_core = {
        key: value for key, value in request.items() if key != "request_sha256"
    }
    legacy_cores = (
        {
            **current_core,
            "schema": T.TEST_ONLY_LAUNCH_SECURITY_REQUEST_SCHEMA,
        },
        {
            **current_core,
            "authority_class": T.TEST_ONLY_NO_PROVIDER_AUTHORITY,
        },
    )
    for legacy_core in legacy_cores:
        legacy = {**legacy_core, "request_sha256": _digest(legacy_core)}
        with pytest.raises(
            L.ClaudeLaunchSecurityError,
            match="test-only request has no provider authority",
        ):
            L.replay_claude_launch_security_request(legacy)

    with pytest.raises(
        P.ClaudeProviderPreparationError,
        match="exact validator-issued Claude provider preparation is required",
    ):
        P.attach_claude_provider_runtime(
            request,
            ambient_environment={},
            source_config_dir=None,
            project_root=tmp_path,
            trusted_cwds=(tmp_path,),
        )


def test_windows_metadata_uses_only_the_winverifytrust_validated_signer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "claude.exe"
    executable.write_bytes(b"MZ" + (b"\0" * 2048))
    monkeypatch.setattr(O.os, "name", "nt")
    monkeypatch.setattr(
        O,
        "_windows_version_strings",
        lambda _path: {
            "product_name": "Claude Code",
            "file_version": f"{VERSION}.0",
        },
    )
    monkeypatch.setattr(
        O,
        "_win_verify_trust_validated_signer",
        lambda _path: {
            "publisher_name": "Unrelated Publisher",
            "signer_subject": "CN=Unrelated Publisher",
        },
    )
    monkeypatch.setattr(
        O,
        "_pe_authenticode_signers",
        lambda _path: [
            {
                "publisher_name": "Unrelated Publisher",
                "signer_subject": "CN=Unrelated Publisher",
            },
            {
                "publisher_name": "Anthropic PBC",
                "signer_subject": "CN=Anthropic PBC",
            },
        ],
    )
    assert O._query_windows_native_metadata(
        executable,
        environment={},
    ) is None

    monkeypatch.setattr(
        O,
        "_win_verify_trust_validated_signer",
        lambda _path: {
            "publisher_name": "Anthropic PBC",
            "signer_subject": "CN=Anthropic PBC",
        },
    )
    metadata = O._query_windows_native_metadata(
        executable,
        environment={},
    )
    assert metadata is not None
    assert metadata["publisher_name"] == "Anthropic PBC"


def _write_npm_wrapper(root: Path) -> tuple[Path, Path]:
    wrapper = root / "claude.cmd"
    runtime = root / "node.exe"
    shutil.copyfile(O.sys.executable, runtime)
    runtime.chmod(0o700)
    package = root / "node_modules" / "@anthropic-ai" / "claude-code"
    package.mkdir(parents=True)
    (package / "package.json").write_text(
        '{"name":"@anthropic-ai/claude-code","version":"2.1.220",'
        '"dependencies":{}}\n',
        encoding="utf-8",
    )
    sibling = root / "node_modules" / "undeclared-loadable"
    sibling.mkdir()
    (sibling / "package.json").write_text(
        '{"name":"undeclared-loadable","version":"1.0.0","main":"index.js"}\n',
        encoding="utf-8",
    )
    (sibling / "index.js").write_text(
        "module.exports = 'before';\n",
        encoding="utf-8",
    )
    (package / "cli.js").write_text(
        "require('undeclared-loadable');\n",
        encoding="utf-8",
    )
    wrapper.write_text(
        '@echo off\r\n'
        '"%~dp0node.exe" '
        '"%~dp0node_modules\\@anthropic-ai\\claude-code\\cli.js" %*\r\n',
        encoding="utf-8",
        newline="",
    )
    return wrapper.resolve(strict=True), sibling / "index.js"


def test_npm_resolution_denominator_binds_undeclared_sibling(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wrapper, sibling = _write_npm_wrapper(tmp_path)
    monkeypatch.setattr(
        O,
        "run_owned_process",
        lambda command, **kwargs: SimpleNamespace(
            args=tuple(command),
            returncode=0,
            stdout=f"{VERSION} (Claude Code)\n",
            stderr="",
            process_tree_terminated=True,
        ),
    )
    observation = O.observe_claude_executable(
        configured_claude_bin=str(wrapper),
        environment={"PATH": str(tmp_path)},
    )
    if observation["launch_authority"] == O.PROOF_GRADE:
        bound_paths = {
            row["path"] for row in observation["implementation_files"]
        }
        assert str(sibling.resolve(strict=True)) in bound_paths
        sibling.write_text("module.exports = 'after';\n", encoding="utf-8")
        with pytest.raises(
            O.ClaudeExecutableObservationError,
            match="changed|drift",
        ):
            O.recheck_claude_executable_before_launch(
                observation,
                launch_executable=str(wrapper),
            )
    else:
        assert observation["implementation_status"] == (
            O.TRANSITIVE_IMPLEMENTATION_UNBOUND
        )


def test_auth_environment_capability_has_one_atomic_consumer(
    tmp_path: Path,
) -> None:
    from concurrent.futures import ThreadPoolExecutor
    import threading

    ambient = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(tmp_path / "ambient-home"),
    }
    auth, receipt, observation = _auth_environment(ambient)
    barrier = threading.Barrier(2)

    def consume() -> str:
        barrier.wait(timeout=10)
        try:
            C.compile_claude_child_environment(
                ambient=ambient,
                auth_environment=auth,
                auth_environment_receipt=receipt,
                source_observation=observation,
                attempt_profile_environment=_profile_environment(
                    tmp_path / "lease",
                    private=False,
                ),
                phase_environment_policies=("base",),
                home_variable_policy="PRESERVE_TOOLCHAIN_HOME",
            )
        except C.ClaudeChildEnvironmentError:
            return "REJECTED"
        return "CONSUMED"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _index: consume(), range(2)))
    assert sorted(outcomes) == ["CONSUMED", "REJECTED"]
    assert dict(auth) == {}


def _write_credentials(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "claudeAiOauth": {
                    "accessToken": "fixture-access",
                    "refreshToken": "fixture-refresh",
                    "expiresAt": 4102444800000,
                    "scopes": ["user:inference"],
                }
            }
        ),
        encoding="utf-8",
    )
    path.chmod(0o600)


def test_stored_materialization_rejects_raw_descriptor_and_authority_digest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        S,
        "_detect_host_platform",
        lambda: S.HOST_WINDOWS_NATIVE,
    )
    monkeypatch.setattr(
        S,
        "_verify_windows_source_security",
        lambda _path: None,
    )
    source = tmp_path / "source" / ".credentials.json"
    _write_credentials(source)
    capability = S.acquire_stored_subscription_materialization(
        source_path=source
    )
    target = tmp_path / "target"
    descriptor = os.open(
        target,
        os.O_RDWR | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    try:
        with pytest.raises(
            (S.ClaudeStoredSubscriptionSourceError, TypeError),
            match="typed|capability|target",
        ):
            capability.consume_into_private_descriptor(
                descriptor,
                expected_source_evidence=capability.source_evidence,
                private_target_authority_sha256="a" * 64,
            )
        assert os.fstat(descriptor).st_size == 0
    finally:
        os.close(descriptor)


def test_private_home_replaces_ambient_xdg_and_receipt_cannot_self_promote(
    tmp_path: Path,
) -> None:
    ambient = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(tmp_path / "ambient-home"),
        "USERPROFILE": str(tmp_path / "ambient-home"),
        "APPDATA": str(tmp_path / "ambient-appdata"),
        "LOCALAPPDATA": str(tmp_path / "ambient-localappdata"),
        "XDG_CONFIG_HOME": str(tmp_path / "ambient-xdg-config"),
        "XDG_CACHE_HOME": str(tmp_path / "ambient-xdg-cache"),
        "XDG_DATA_HOME": str(tmp_path / "ambient-xdg-data"),
    }
    auth, receipt, observation = _auth_environment(ambient)
    binding_core = {
        "schema": "plamen.claude_attempt_profile.v3",
        "run_id": "run-private-home",
        "work_plan_sha256": "1" * 64,
        "attempt_id": "attempt-private-home",
        "home_variable_policy": "PRIVATE_HOME",
    }
    overlay = C._mint_claude_private_home_overlay_authority(
        attempt_profile_environment=_profile_environment(
            tmp_path / "lease",
            private=True,
        ),
        attempt_profile_binding={
            **binding_core,
            "profile_sha256": _digest(binding_core),
        },
    )
    result = C.compile_claude_child_environment(
        ambient=ambient,
        auth_environment=auth,
        auth_environment_receipt=receipt,
        source_observation=observation,
        attempt_profile_environment=_profile_environment(
            tmp_path / "lease",
            private=True,
        ),
        private_home_overlay_authority=overlay,
        phase_environment_policies=("base",),
        home_variable_policy="PRIVATE_HOME",
    )
    for name in ("XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME"):
        assert result.environment[name].startswith(
            str(tmp_path / "lease" / "home")
        )
        assert "ambient-xdg" not in result.environment[name]

    auth2, receipt2, observation2 = _auth_environment(ambient)
    preserved = C.compile_claude_child_environment(
        ambient=ambient,
        auth_environment=auth2,
        auth_environment_receipt=receipt2,
        source_observation=observation2,
        attempt_profile_environment=_profile_environment(
            tmp_path / "preserve",
            private=False,
        ),
        phase_environment_policies=("base",),
        home_variable_policy="PRESERVE_TOOLCHAIN_HOME",
    ).receipt
    forged = dict(preserved)
    forged["home_variable_policy"] = "PRIVATE_HOME"
    forged["configuration_isolation_status"] = "ATTEMPT_PRIVATE_HOME_BOUND"
    forged["proof_grade_configuration_isolation"] = True
    forged["attempt_profile_keys"] = sorted(
        set(forged["attempt_profile_keys"])
        | {"HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA"}
    )
    core = dict(forged)
    core.pop("receipt_sha256")
    forged["receipt_sha256"] = _digest(core)
    with pytest.raises(
        C.ClaudeChildEnvironmentError,
        match="authority|overlay|replay",
    ):
        C.replay_claude_child_environment_receipt(forged)
