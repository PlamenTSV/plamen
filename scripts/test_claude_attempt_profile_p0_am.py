from __future__ import annotations

import hashlib
import inspect
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

import auxiliary_writable_root_lease as A
import claude_attempt_profile as C
import claude_stored_subscription_source as S


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _valid_credential_bytes(label: str) -> bytes:
    return json.dumps(
        {
            "claudeAiOauth": {
                "accessToken": f"access-{label}",
                "refreshToken": f"refresh-{label}",
                "expiresAt": 4_102_444_800_000,
                "scopes": ["user:profile"],
            }
        },
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _simulate_provider_state_update(
    profile: C.ClaudeAttemptProfile,
    *,
    remove_bypass_acceptance: bool = False,
) -> dict[str, object]:
    state = json.loads(profile.state_path.read_text(encoding="utf-8"))
    state["numStartups"] = 2
    for project in state["projects"].values():
        project.pop("hasCompletedProjectOnboarding", None)
        project.pop("projectOnboardingSeenCount", None)
    if profile.binding["auth_route"] == "STORED_SUBSCRIPTION_OAUTH":
        state["oauthAccount"] = {
            "accountUuid": "fixture-account-id",
            "emailAddress": "fixture@example.invalid",
            "organizationUuid": "fixture-organization-id",
            "hasExtraUsageEnabled": False,
            "billingType": "fixture-billing-class",
            "accountCreatedAt": "2025-01-01T00:00:00.000Z",
            "subscriptionCreatedAt": "2025-01-02T00:00:00.000Z",
            "ccOnboardingFlags": {},
            "claudeCodeTrialEndsAt": None,
            "claudeCodeTrialDurationDays": None,
            "seatTier": None,
            "displayName": "Fixture Display",
            "fullName": "Fixture Full Name",
            "profileFetchedAt": 1_753_680_000_000,
        }
    if remove_bypass_acceptance:
        state.pop("bypassPermissionsModeAccepted", None)
    profile.state_path.write_text(
        json.dumps(
            state,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    profile.state_path.chmod(0o600)
    return state


def _empty_private_target(path: Path) -> int:
    return os.open(
        path,
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )


_RUN_ID = "12345678-1234-4abc-8def-1234567890ab"
_STARTUP_EPOCH = "1" * 32
_STARTUP_RECEIPT_SHA256 = "2" * 64
_STARTUP_PERMIT = {
    "schema": "plamen.auxiliary_writable_root_startup_permit_binding.v2",
    "run_id": _RUN_ID,
    "startup_epoch": _STARTUP_EPOCH,
    "current_pointer_sha256": "3" * 64,
    "receipt_relative_path": (
        "_auxiliary_writable_root_startup_receipts/"
        f"startup-{_STARTUP_EPOCH}-{_STARTUP_RECEIPT_SHA256}.json"
    ),
    "receipt_sha256": _STARTUP_RECEIPT_SHA256,
    "allocation_disposition": "ALLOW_NEW_LEASES",
}


@pytest.fixture(autouse=True)
def _isolated_auxiliary_namespace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    namespace = tmp_path / "auxiliary-runtime"
    monkeypatch.setattr(
        A,
        "_default_runtime_namespace",
        lambda: namespace,
    )
    monkeypatch.setattr(
        S,
        "_detect_host_platform",
        lambda: S.HOST_LINUX_NATIVE,
    )
    monkeypatch.setattr(
        S,
        "_validate_posix_source_security",
        lambda _path, _info: None,
    )
    monkeypatch.setattr(
        S,
        "_validate_file_store_shape",
        lambda _raw: None,
    )


def _profile_kwargs(
    *,
    runtime: Path,
    project: Path,
    global_home: Path,
    state: Path,
    attempt_id: str,
    process_scope_identity: str | None = None,
    home_variable_policy: str = "PRIVATE_HOME",
    credential_mode: str = "COPIED_STORED_SUBSCRIPTION",
    auth_route: str = "STORED_SUBSCRIPTION_OAUTH",
) -> dict[str, object]:
    del runtime
    scope_identity = process_scope_identity or f"scope-{attempt_id}"
    attempt_arm_sha256 = _digest(f"attempt-arm:{attempt_id}")
    lease = A.reserve_auxiliary_writable_root(
        attempt_id=attempt_id,
        purpose="claude-attempt-profile",
    ).arm(
        attempt_arm_sha256=attempt_arm_sha256,
        process_scope_identity=scope_identity,
    )
    capability = None
    expected_source_evidence = None
    if credential_mode == "COPIED_STORED_SUBSCRIPTION":
        capability = S.acquire_stored_subscription_materialization(
            source_path=global_home / ".credentials.json"
        )
        expected_source_evidence = capability.source_evidence
    return {
        "leased_parent": lease,
        "project_root": project,
        "trusted_cwds": (project,),
        "stored_subscription_capability": capability,
        "expected_stored_subscription_source_evidence": (
            expected_source_evidence
        ),
        "credential_mode": credential_mode,
        "auth_route": auth_route,
        "run_id": _RUN_ID,
        "startup_permit_binding": dict(_STARTUP_PERMIT),
        "outer_attempt_arm_sha256": attempt_arm_sha256,
        "work_plan_sha256": _digest("shared-work-plan"),
        "attempt_id": attempt_id,
        "process_scope_identity": scope_identity,
        "launch_security_policy_sha256": _digest(
            "shared-launch-security-policy"
        ),
        "executable_observation_sha256": _digest(
            "shared-executable-observation"
        ),
        "auth_environment_receipt_sha256": _digest(
            "shared-auth-environment-receipt"
        ),
        "settings_authority_sha256": _digest(
            "shared-settings-authority"
        ),
        "mcp_authority_sha256": _digest("shared-mcp-authority"),
        "home_variable_policy": home_variable_policy,
        "permission_mode": "bypassPermissions",
    }


def _closure_token(
    monkeypatch: pytest.MonkeyPatch,
    profile: C.ClaudeAttemptProfile,
    *,
    identity: str | None = None,
    closed: bool = True,
    population_zero: bool = True,
    emergency_closed: bool = False,
    attached: bool = True,
) -> C.ClaudeProfileScopeClosureToken:
    class FakeOwnedProcessScope:
        pass

    expected_identity = str(profile.binding["process_scope_identity"])
    FakeOwnedProcessScope.persistent_identity = expected_identity
    FakeOwnedProcessScope.population_zero_proven = population_zero
    FakeOwnedProcessScope.closed = closed
    FakeOwnedProcessScope.emergency_closed = emergency_closed
    FakeOwnedProcessScope.attached = attached
    FakeOwnedProcessScope.terminated = attached
    FakeOwnedProcessScope.process_creation_state = (
        "ATTACHED" if attached else "NOT_ATTEMPTED"
    )
    FakeOwnedProcessScope.process_creation_evidence = {
        "state": FakeOwnedProcessScope.process_creation_state,
        "creation_attempted": attached,
        "process_object_returned": attached,
        "attached": attached,
        "created_process_termination_proven": False,
    }
    FakeOwnedProcessScope.pre_release_process_identity = (
        {"kind": "FIXTURE", "value": "attached"}
        if attached
        else None
    )

    monkeypatch.setattr(
        C,
        "_owned_process_scope_type",
        lambda: FakeOwnedProcessScope,
    )
    monkeypatch.setattr(
        A,
        "_owned_process_scope_type",
        lambda: FakeOwnedProcessScope,
    )
    scope = FakeOwnedProcessScope()
    if not profile._leased_parent.process_scope_bound:
        profile._leased_parent.bind_process_scope(
            scope
        )
    FakeOwnedProcessScope.persistent_identity = identity or expected_identity
    authority = None
    if (
        FakeOwnedProcessScope.persistent_identity == expected_identity
        and closed
        and population_zero
        and attached
        and not emergency_closed
    ):
        _simulate_provider_state_update(profile)
        authority = C.mint_claude_fresh_postprocess_authority(
            profile,
            scope,
        )
    return C.prove_claude_profile_scope_closed(
        profile,
        scope,
        postprocess_authority=authority,
    )


def _materialized_fixture(
    tmp_path: Path,
    *,
    attempt_id: str,
    secret: bytes = b'{"oauthToken":"secret-never-log"}',
) -> tuple[C.ClaudeAttemptProfile, dict[str, object], bytes]:
    global_home = tmp_path / f"global-{attempt_id}"
    global_home.mkdir()
    (global_home / ".credentials.json").write_bytes(secret)
    (global_home / "settings.json").write_text("{}", encoding="utf-8")
    state = tmp_path / f"state-{attempt_id}.json"
    state.write_text("{}", encoding="utf-8")
    project = tmp_path / f"project-{attempt_id}"
    project.mkdir()
    runtime = tmp_path / f"runtime-{attempt_id}"
    runtime.mkdir()
    kwargs = _profile_kwargs(
        runtime=runtime,
        project=project,
        global_home=global_home,
        state=state,
        attempt_id=attempt_id,
    )
    return (
        C.materialize_claude_attempt_profile(**kwargs),
        kwargs,
        secret,
    )


def test_attempt_profile_copies_only_credentials_and_synthesizes_state(
    tmp_path: Path,
) -> None:
    global_home = tmp_path / "global-claude"
    global_home.mkdir()
    secret = b'{"oauthToken":"secret-never-log"}'
    (global_home / ".credentials.json").write_bytes(secret)
    (global_home / "settings.json").write_text(
        '{"enabledPlugins":{"unsafe":true}}',
        encoding="utf-8",
    )
    global_state = tmp_path / "global-state.json"
    global_state.write_text('{"projects":{"private":"large"}}', encoding="utf-8")
    project = tmp_path / "project"
    project.mkdir()
    runtime_parent = tmp_path / "runtime"
    runtime_parent.mkdir()
    before = {
        "credentials": _sha(global_home / ".credentials.json"),
        "settings": _sha(global_home / "settings.json"),
        "state": _sha(global_state),
    }

    profile = C.materialize_claude_attempt_profile(
        **_profile_kwargs(
            runtime=runtime_parent,
            project=project,
            global_home=global_home,
            state=global_state,
            attempt_id="attempt-001",
        )
    )

    assert (profile.config_dir / ".credentials.json").read_bytes() == secret
    assert sorted(path.name for path in profile.config_dir.iterdir()) == [
        ".claude.json",
        ".credentials.json",
        "settings.json",
    ]
    state = json.loads(profile.state_path.read_text(encoding="utf-8"))
    assert state["hasCompletedOnboarding"] is True
    assert state["migrationVersion"] == 13
    assert state["lastOnboardingVersion"] == "2.1.252"
    assert state["lastReleaseNotesSeen"] == "2.1.252"
    assert state["bypassPermissionsModeAccepted"] is True
    expected_project_key = (
        os.path.normpath(str(project.resolve())).replace("\\", "/")
        if os.name == "nt"
        else os.path.normpath(str(project.resolve()))
    )
    assert list(state["projects"]) == [expected_project_key]
    project_state = state["projects"][expected_project_key]
    assert project_state["disabledMcpjsonServers"] == []
    assert "disabledMcpServers" not in project_state
    assert project_state["mcpContextUris"] == []
    assert project_state["projectOnboardingSeenCount"] == 0
    assert "private" not in profile.state_path.read_text(encoding="utf-8")
    settings = json.loads(
        (profile.config_dir / "settings.json").read_text(encoding="utf-8")
    )
    assert settings["enabledPlugins"] == {}
    assert settings["hooks"] == {}
    assert settings["mcpServers"] == {}
    assert settings["permissions"]["defaultMode"] == "bypassPermissions"
    assert profile.environment["CLAUDE_CONFIG_DIR"] == str(profile.config_dir)
    assert profile.environment["TMPDIR"] == str(profile.temp_dir)
    assert {
        "DISABLE_AUTOUPDATER",
        "DISABLE_TELEMETRY",
    }.isdisjoint(profile.environment)
    assert profile.binding["process_scope_identity"] == "scope-attempt-001"
    assert profile.binding["state_provider_version"] == "2.1.252"
    assert profile.binding["directory_security"]["verified_before_secret_write"] is True
    assert before == {
        "credentials": _sha(global_home / ".credentials.json"),
        "settings": _sha(global_home / "settings.json"),
        "state": _sha(global_state),
    }
    assert secret.decode("utf-8") not in json.dumps(profile.binding, sort_keys=True)
    assert "credential_sha256" not in profile.binding
    assert "global_source_fingerprints" not in profile.binding
    assert hashlib.sha256(secret).hexdigest() not in json.dumps(
        profile.binding,
        sort_keys=True,
    )
    credential_copy = profile.binding["credential_copy"]
    assert credential_copy["source_evidence"]["store_class"] == (
        "FILE_BACKED"
    )
    assert credential_copy["source_size"] == len(secret)
    assert credential_copy["exact_copy_verified"] is True
    assert credential_copy["source_path_reopened"] is False
    assert credential_copy["source_bytes_reread"] is False
    assert credential_copy["credential_values_recorded"] is False
    assert credential_copy["credential_content_hashes_recorded"] is False
    assert len(credential_copy["private_target_authority_sha256"]) == 64
    assert len(credential_copy["materialization_id"]) == 32


def test_environment_oauth_profile_is_credential_free_and_replayable(
    tmp_path: Path,
) -> None:
    global_home = tmp_path / "global-oauth"
    global_home.mkdir()
    state = tmp_path / "global-oauth-state.json"
    state.write_text("{}", encoding="utf-8")
    project = tmp_path / "project-oauth"
    project.mkdir()
    runtime = tmp_path / "runtime-oauth"
    runtime.mkdir()
    kwargs = _profile_kwargs(
        runtime=runtime,
        project=project,
        global_home=global_home,
        state=state,
        attempt_id="attempt-oauth-token",
        credential_mode="ENVIRONMENT_OAUTH_TOKEN",
        auth_route="OAUTH_TOKEN",
    )

    profile = C.materialize_claude_attempt_profile(**kwargs)
    binding = profile.binding

    assert sorted(path.name for path in profile.config_dir.iterdir()) == [
        ".claude.json",
        "settings.json",
    ]
    assert not os.path.lexists(profile.config_dir / ".credentials.json")
    assert binding["credential_mode"] == "ENVIRONMENT_OAUTH_TOKEN"
    assert binding["auth_route"] == "OAUTH_TOKEN"
    assert binding["credential_copy"] == "ABSENT"
    assert "credential_target_path_authority_sha256" not in binding
    serialized = json.dumps(binding, sort_keys=True)
    assert ".credentials.json" not in serialized
    assert "CLAUDE_SECURESTORAGE_CONFIG_DIR" not in profile.environment
    assert "CLAUDE_SECURESTORAGE_CONFIG_DIR" not in binding[
        "environment_keys"
    ]
    assert C.replay_claude_attempt_profile_binding(
        profile,
        binding,
    )["valid"] is True
    _simulate_provider_state_update(
        profile,
        remove_bypass_acceptance=True,
    )
    assert C.replay_claude_attempt_profile_postprocess_binding(
        profile,
        binding,
    )["valid"] is True

    receipt = profile.abort_before_process_scope(
        attempt_arm_sha256=str(kwargs["outer_attempt_arm_sha256"]),
        process_scope_identity=str(kwargs["process_scope_identity"]),
        reason_code="OAUTH_PROFILE_FIXTURE_COMPLETE",
    )
    assert receipt["completion_authority"] is False
    assert C.replay_claude_attempt_profile_revocation(
        profile,
        receipt,
    )["valid"] is True


@pytest.mark.parametrize(
    (
        "credential_mode",
        "auth_route",
        "with_stored_capability",
        "error_pattern",
    ),
    [
        (
            "ENVIRONMENT_OAUTH_TOKEN",
            "STORED_SUBSCRIPTION_OAUTH",
            False,
            "contradictory",
        ),
        (
            "COPIED_STORED_SUBSCRIPTION",
            "OAUTH_TOKEN",
            True,
            "contradictory",
        ),
        (
            "ENVIRONMENT_OAUTH_TOKEN",
            "OAUTH_TOKEN",
            True,
            "forbids stored",
        ),
        (
            "COPIED_STORED_SUBSCRIPTION",
            "STORED_SUBSCRIPTION_OAUTH",
            False,
            "capability is invalid",
        ),
    ],
)
def test_credential_mode_route_matrix_fails_closed(
    tmp_path: Path,
    credential_mode: str,
    auth_route: str,
    with_stored_capability: bool,
    error_pattern: str,
) -> None:
    suffix = str(
        abs(
            hash(
                (
                    credential_mode,
                    auth_route,
                    with_stored_capability,
                )
            )
        )
    )
    global_home = tmp_path / f"global-{suffix}"
    global_home.mkdir()
    (global_home / ".credentials.json").write_text(
        '{"oauthToken":"must-be-discarded"}',
        encoding="utf-8",
    )
    state = tmp_path / f"state-{suffix}.json"
    state.write_text("{}", encoding="utf-8")
    project = tmp_path / f"project-{suffix}"
    project.mkdir()
    runtime = tmp_path / f"runtime-{suffix}"
    runtime.mkdir()
    helper_mode = (
        "COPIED_STORED_SUBSCRIPTION"
        if with_stored_capability
        else "ENVIRONMENT_OAUTH_TOKEN"
    )
    helper_route = (
        "STORED_SUBSCRIPTION_OAUTH"
        if with_stored_capability
        else "OAUTH_TOKEN"
    )
    kwargs = _profile_kwargs(
        runtime=runtime,
        project=project,
        global_home=global_home,
        state=state,
        attempt_id=f"attempt-matrix-{suffix}",
        credential_mode=helper_mode,
        auth_route=helper_route,
    )
    capability = kwargs["stored_subscription_capability"]
    lease = kwargs["leased_parent"]
    kwargs["credential_mode"] = credential_mode
    kwargs["auth_route"] = auth_route

    with pytest.raises(
        C.ClaudeAttemptProfileError,
        match=error_pattern,
    ):
        C.materialize_claude_attempt_profile(**kwargs)

    assert isinstance(lease, A.AuxiliaryWritableRootLease)
    assert not lease.root.exists()
    if with_stored_capability:
        assert isinstance(
            capability,
            S.StoredSubscriptionMaterializationCapability,
        )
        descriptor = _empty_private_target(
            tmp_path / f"discard-check-{suffix}"
        )
        try:
            with pytest.raises(
                S.ClaudeStoredSubscriptionSourceError,
                match="no longer available",
            ):
                capability.consume_into_private_descriptor(
                    descriptor,
                    expected_source_evidence=capability.source_evidence,
                )
        finally:
            os.close(descriptor)


def test_attempt_profile_v3_binds_complete_attempt_authority(
    tmp_path: Path,
) -> None:
    profile, kwargs, _secret = _materialized_fixture(
        tmp_path,
        attempt_id="attempt-v3-authority",
    )
    binding = profile.binding
    lease = kwargs["leased_parent"]
    assert isinstance(lease, A.AuxiliaryWritableRootLease)

    assert binding["schema"] == C.ATTEMPT_PROFILE_SCHEMA
    assert binding["run_id"] == _RUN_ID
    assert binding["startup_permit_binding"] == _STARTUP_PERMIT
    assert binding["startup_epoch"] == _STARTUP_EPOCH
    assert binding["startup_permit_sha256"] == _digest(
        json.dumps(
            _STARTUP_PERMIT,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    assert binding["outer_attempt_arm_sha256"] == kwargs[
        "outer_attempt_arm_sha256"
    ]
    assert binding["work_plan_sha256"] == kwargs["work_plan_sha256"]
    assert binding["attempt_id"] == kwargs["attempt_id"]
    assert binding["process_scope_identity"] == kwargs[
        "process_scope_identity"
    ]
    assert binding["auxiliary_lease_binding_sha256"] == lease.binding[
        "binding_sha256"
    ]
    assert binding["launch_security_policy_sha256"] == kwargs[
        "launch_security_policy_sha256"
    ]
    assert binding["executable_observation_sha256"] == kwargs[
        "executable_observation_sha256"
    ]
    assert binding["auth_environment_receipt_sha256"] == kwargs[
        "auth_environment_receipt_sha256"
    ]
    assert binding["settings_authority_sha256"] == kwargs[
        "settings_authority_sha256"
    ]
    assert binding["mcp_authority_sha256"] == kwargs[
        "mcp_authority_sha256"
    ]
    assert len(binding["trusted_cwd_denominator_sha256"]) == 64
    assert binding["private_root"]["lease_root"] == str(
        lease.root.resolve()
    )
    assert binding["private_root"]["profile_root"] == str(
        profile.root.resolve()
    )
    assert len(binding["private_root_identity_sha256"]) == 64
    assert len(binding["directory_security_sha256"]) == 64
    assert binding[
        "credential_target_path_authority_sha256"
    ] == binding["credential_copy"][
        "private_target_authority_sha256"
    ]
    assert C.replay_claude_attempt_profile_binding(
        profile,
        binding,
    )["valid"] is True


@pytest.mark.parametrize(
    "attribute",
    (
        "config_dir",
        "home_dir",
        "state_path",
        "temp_dir",
        "environment",
    ),
)
def test_profile_replay_rejects_public_runtime_attribute_substitution(
    tmp_path: Path,
    attribute: str,
) -> None:
    profile, _kwargs, _secret = _materialized_fixture(
        tmp_path,
        attempt_id=f"attempt-runtime-attribute-{attribute}",
    )
    if attribute == "environment":
        profile.environment = {
            **dict(profile.environment),
            "INJECTED": "1",
        }
    else:
        setattr(
            profile,
            attribute,
            tmp_path / f"substituted-{attribute}",
        )

    with pytest.raises(
        C.ClaudeAttemptProfileError,
        match="path authority|environment authority",
    ):
        C.replay_claude_attempt_profile_binding(
            profile,
            profile.binding,
        )


@pytest.mark.parametrize(
    "field",
    [
        "run_id",
        "startup_permit_sha256",
        "startup_epoch",
        "outer_attempt_arm_sha256",
        "work_plan_sha256",
        "attempt_id",
        "process_scope_identity",
        "auxiliary_lease_binding_sha256",
        "launch_security_policy_sha256",
        "executable_observation_sha256",
        "auth_environment_receipt_sha256",
        "settings_authority_sha256",
        "mcp_authority_sha256",
        "trusted_cwd_denominator_sha256",
        "private_root_identity_sha256",
        "directory_security_sha256",
        "credential_target_path_authority_sha256",
    ],
)
def test_profile_replay_rejects_each_v3_binding_substitution(
    tmp_path: Path,
    field: str,
) -> None:
    profile, _kwargs, _secret = _materialized_fixture(
        tmp_path,
        attempt_id=f"attempt-substitute-{field[:20]}",
    )
    substituted = profile.binding
    substituted[field] = (
        _RUN_ID
        if field != "run_id"
        else "87654321-4321-4cba-8fed-ba0987654321"
    )
    if substituted[field] == profile.binding[field]:
        substituted[field] = "f" * (
            32 if field == "startup_epoch" else 64
        )

    with pytest.raises(
        C.ClaudeAttemptProfileError,
        match="binding",
    ):
        C.replay_claude_attempt_profile_binding(profile, substituted)


def test_profile_replay_rejects_nested_startup_and_private_root_substitution(
    tmp_path: Path,
) -> None:
    profile, _kwargs, _secret = _materialized_fixture(
        tmp_path,
        attempt_id="attempt-nested-substitution",
    )
    startup_substitution = profile.binding
    startup_substitution["startup_permit_binding"]["startup_epoch"] = (
        "f" * 32
    )
    with pytest.raises(C.ClaudeAttemptProfileError, match="binding"):
        C.replay_claude_attempt_profile_binding(
            profile,
            startup_substitution,
        )

    root_substitution = profile.binding
    root_substitution["private_root"]["profile_root"] = str(tmp_path)
    with pytest.raises(C.ClaudeAttemptProfileError, match="binding"):
        C.replay_claude_attempt_profile_binding(
            profile,
            root_substitution,
        )


def test_retry_reuses_policy_but_gets_fresh_attempt_owned_profile(
    tmp_path: Path,
) -> None:
    first, first_kwargs, _secret = _materialized_fixture(
        tmp_path,
        attempt_id="attempt-retry-one",
    )
    second, second_kwargs, _secret = _materialized_fixture(
        tmp_path,
        attempt_id="attempt-retry-two",
    )

    for key in (
        "work_plan_sha256",
        "launch_security_policy_sha256",
        "executable_observation_sha256",
        "auth_environment_receipt_sha256",
        "settings_authority_sha256",
        "mcp_authority_sha256",
    ):
        assert first_kwargs[key] == second_kwargs[key]
        assert first.binding[key] == second.binding[key]
    assert first.root != second.root
    assert first.binding["profile_sha256"] != second.binding["profile_sha256"]
    assert first.binding["attempt_id"] != second.binding["attempt_id"]
    assert (
        first.binding["process_scope_identity"]
        != second.binding["process_scope_identity"]
    )
    assert (
        first.binding["auxiliary_lease_binding_sha256"]
        != second.binding["auxiliary_lease_binding_sha256"]
    )
    assert (
        first.binding["credential_copy"]["materialization_id"]
        != second.binding["credential_copy"]["materialization_id"]
    )


def test_profile_materializer_consumes_capability_exactly_once(
    tmp_path: Path,
) -> None:
    profile, kwargs, _secret = _materialized_fixture(
        tmp_path,
        attempt_id="attempt-one-shot",
    )
    capability = kwargs["stored_subscription_capability"]
    evidence = kwargs[
        "expected_stored_subscription_source_evidence"
    ]
    assert isinstance(
        capability,
        S.StoredSubscriptionMaterializationCapability,
    )

    descriptor = _empty_private_target(tmp_path / "reuse-target")
    try:
        with pytest.raises(
            S.ClaudeStoredSubscriptionSourceError,
            match="no longer available",
        ):
            capability.consume_into_private_descriptor(
                descriptor,
                expected_source_evidence=evidence,
            )
        assert os.fstat(descriptor).st_size == 0
    finally:
        os.close(descriptor)
    assert profile.root.exists()


def test_materializer_rejects_substituted_expected_source_and_rolls_back(
    tmp_path: Path,
) -> None:
    global_home = tmp_path / "global-source"
    global_home.mkdir()
    (global_home / ".credentials.json").write_text(
        '{"token":"expected-source"}',
        encoding="utf-8",
    )
    other_home = tmp_path / "other-source"
    other_home.mkdir()
    (other_home / ".credentials.json").write_text(
        '{"token":"substituted-source-longer"}',
        encoding="utf-8",
    )
    state = tmp_path / ".claude.json"
    state.write_text("{}", encoding="utf-8")
    project = tmp_path / "project"
    project.mkdir()
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    kwargs = _profile_kwargs(
        runtime=runtime,
        project=project,
        global_home=global_home,
        state=state,
        attempt_id="attempt-source-substitution",
    )
    capability = kwargs["stored_subscription_capability"]
    other = S.acquire_stored_subscription_materialization(
        source_path=other_home / ".credentials.json"
    )
    kwargs[
        "expected_stored_subscription_source_evidence"
    ] = other.source_evidence
    lease = kwargs["leased_parent"]
    try:
        with pytest.raises(
            C.ClaudeAttemptProfileError,
            match="materialization failed",
        ):
            C.materialize_claude_attempt_profile(**kwargs)
    finally:
        other.discard()
    assert isinstance(lease, A.AuxiliaryWritableRootLease)
    assert not lease.root.exists()

    descriptor = _empty_private_target(tmp_path / "poison-check")
    try:
        with pytest.raises(
            S.ClaudeStoredSubscriptionSourceError,
            match="no longer available",
        ):
            capability.consume_into_private_descriptor(
                descriptor,
                expected_source_evidence=capability.source_evidence,
            )
    finally:
        os.close(descriptor)


def test_materializer_never_reopens_credential_source_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    global_home = tmp_path / "global"
    global_home.mkdir()
    source = global_home / ".credentials.json"
    source.write_text('{"token":"descriptor-only"}', encoding="utf-8")
    state = tmp_path / ".claude.json"
    state.write_text("{}", encoding="utf-8")
    project = tmp_path / "project"
    project.mkdir()
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    kwargs = _profile_kwargs(
        runtime=runtime,
        project=project,
        global_home=global_home,
        state=state,
        attempt_id="attempt-no-source-reopen",
    )
    original_read_bytes = Path.read_bytes
    expected_source = source.resolve()

    def forbid_source_read(path: Path) -> bytes:
        if path.resolve() == expected_source:
            raise AssertionError("credential source path was reread")
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", forbid_source_read)
    profile = C.materialize_claude_attempt_profile(**kwargs)

    assert profile.binding["credential_copy"][
        "source_path_reopened"
    ] is False
    assert profile.binding["credential_copy"][
        "source_bytes_reread"
    ] is False


def test_profile_binding_replays_after_exact_process_scope_is_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile, _kwargs, _secret = _materialized_fixture(
        tmp_path,
        attempt_id="attempt-bound-replay",
    )

    class FakeOwnedProcessScope:
        persistent_identity = profile.binding["process_scope_identity"]

    monkeypatch.setattr(
        A,
        "_owned_process_scope_type",
        lambda: FakeOwnedProcessScope,
    )
    profile._leased_parent.bind_process_scope(FakeOwnedProcessScope())

    assert C.replay_claude_attempt_profile_binding(
        profile,
        profile.binding,
    )["valid"] is True


def test_postprocess_replay_accepts_in_place_credential_refresh_only(
    tmp_path: Path,
) -> None:
    profile, _kwargs, _secret = _materialized_fixture(
        tmp_path,
        attempt_id="attempt-postprocess-refresh",
        secret=_valid_credential_bytes("before-refresh"),
    )
    credential = profile.config_dir / ".credentials.json"
    unchanged = C.replay_claude_attempt_profile_postprocess_binding(
        profile,
        profile.binding,
    )
    assert unchanged["current_attempt_credential_copy_status"] == (
        "ORIGINAL_PRIVATE_COPY_UNCHANGED"
    )
    before = credential.stat()
    with credential.open("r+b") as handle:
        handle.seek(0)
        handle.write(_valid_credential_bytes("after-longer-refresh"))
        handle.truncate()
        handle.flush()
        os.fsync(handle.fileno())
    after = credential.stat()
    assert (before.st_dev, before.st_ino) == (
        after.st_dev,
        after.st_ino,
    )

    with pytest.raises(
        C.ClaudeAttemptProfileError,
        match="credential copy drifted",
    ):
        C.replay_claude_attempt_profile_binding(
            profile,
            profile.binding,
        )
    _simulate_provider_state_update(profile)
    replay = C.replay_claude_attempt_profile_postprocess_binding(
        profile,
        profile.binding,
    )
    assert replay["valid"] is True
    assert replay["current_attempt_credential_copy_status"] == (
        "UNTRUSTED_PRIVATE_COPY_CHANGED_OR_REPLACED_DISCARD_ONLY"
    )
    assert replay["reason"] == (
        "POSTPROCESS_PROFILE_STRUCTURE_AND_AUTHORITY_REPLAYED"
    )


def test_postprocess_replay_accepts_atomic_credential_refresh(
    tmp_path: Path,
) -> None:
    profile, _kwargs, _secret = _materialized_fixture(
        tmp_path,
        attempt_id="attempt-postprocess-replacement",
        secret=_valid_credential_bytes("before-replacement"),
    )
    credential = profile.config_dir / ".credentials.json"
    before = credential.stat()
    replacement = profile.config_dir / "replacement"
    replacement.write_bytes(
        _valid_credential_bytes("atomic-refresh")
    )
    replacement.chmod(0o600)
    os.replace(replacement, credential)
    after = credential.stat()
    assert (before.st_dev, before.st_ino) != (
        after.st_dev,
        after.st_ino,
    )

    with pytest.raises(
        C.ClaudeAttemptProfileError,
        match="identity|drift",
    ):
        C.replay_claude_attempt_profile_binding(
            profile,
            profile.binding,
        )
    _simulate_provider_state_update(profile)
    replay = C.replay_claude_attempt_profile_postprocess_binding(
        profile,
        profile.binding,
    )
    assert replay["valid"] is True
    assert replay["current_attempt_credential_copy_status"] == (
        "UNTRUSTED_PRIVATE_COPY_CHANGED_OR_REPLACED_DISCARD_ONLY"
    )


def test_postprocess_authority_rechecks_credential_bytes_at_revocation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile, _kwargs, _secret = _materialized_fixture(
        tmp_path,
        attempt_id="attempt-postprocess-freshness",
        secret=_valid_credential_bytes("before-authority-mint"),
    )

    class FakeOwnedProcessScope:
        persistent_identity = profile.binding["process_scope_identity"]
        closed = True
        population_zero_proven = True
        attached = True
        emergency_closed = False
        process_creation_state = "ATTACHED"
        process_creation_evidence = {
            "state": "ATTACHED",
            "creation_attempted": True,
            "process_object_returned": True,
            "attached": True,
            "created_process_termination_proven": False,
        }

    monkeypatch.setattr(
        C,
        "_owned_process_scope_type",
        lambda: FakeOwnedProcessScope,
    )
    monkeypatch.setattr(
        A,
        "_owned_process_scope_type",
        lambda: FakeOwnedProcessScope,
    )
    scope = FakeOwnedProcessScope()
    profile._leased_parent.bind_process_scope(scope)
    _simulate_provider_state_update(profile)
    authority = C.mint_claude_fresh_postprocess_authority(
        profile,
        scope,
    )
    closure = C.prove_claude_profile_scope_closed(
        profile,
        scope,
        postprocess_authority=authority,
    )

    credential = profile.config_dir / ".credentials.json"
    with credential.open("r+b") as handle:
        handle.seek(0)
        handle.write(_valid_credential_bytes("after-authority-mint"))
        handle.truncate()
        handle.flush()
        os.fsync(handle.fileno())

    with pytest.raises(
        C.ClaudeAttemptProfileError,
        match="changed after authority mint",
    ):
        profile.revoke(closure)
    assert profile.root.exists()

    refreshed_authority = C.mint_claude_fresh_postprocess_authority(
        profile,
        scope,
    )
    refreshed_closure = C.prove_claude_profile_scope_closed(
        profile,
        scope,
        postprocess_authority=refreshed_authority,
    )
    receipt = profile.revoke(refreshed_closure)
    assert receipt["cleanup_mode"] == "NORMAL_COMPLETION"
    assert receipt["completion_authority"] is True


def test_postprocess_replay_rejects_unsupported_replacement_schema(
    tmp_path: Path,
) -> None:
    profile, _kwargs, _secret = _materialized_fixture(
        tmp_path,
        attempt_id="attempt-postprocess-invalid-replacement",
        secret=_valid_credential_bytes("before-invalid-replacement"),
    )
    credential = profile.config_dir / ".credentials.json"
    replacement = profile.config_dir / "replacement"
    replacement.write_bytes(b'{"unsupported":"credential-shape"}')
    replacement.chmod(0o600)
    os.replace(replacement, credential)

    with pytest.raises(
        C.ClaudeAttemptProfileError,
        match="schema is unsupported",
    ):
        C.replay_claude_attempt_profile_postprocess_binding(
            profile,
            profile.binding,
        )


def test_postprocess_replay_rejects_credential_symlink(
    tmp_path: Path,
) -> None:
    profile, _kwargs, _secret = _materialized_fixture(
        tmp_path,
        attempt_id="attempt-postprocess-symlink",
        secret=_valid_credential_bytes("before-symlink"),
    )
    credential = profile.config_dir / ".credentials.json"
    outside = tmp_path / "outside-credential"
    outside.write_bytes(b'{"oauthToken":"outside"}')
    credential.unlink()
    try:
        credential.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"file symlinks unavailable: {exc}")

    with pytest.raises(
        C.ClaudeAttemptProfileError,
        match="symlink|reparse|identity|drift",
    ):
        C.replay_claude_attempt_profile_postprocess_binding(
            profile,
            profile.binding,
        )


def test_postprocess_replay_rejects_credential_hardlink_alias(
    tmp_path: Path,
) -> None:
    profile, _kwargs, _secret = _materialized_fixture(
        tmp_path,
        attempt_id="attempt-postprocess-hardlink",
        secret=_valid_credential_bytes("before-hardlink"),
    )
    credential = profile.config_dir / ".credentials.json"
    alias = tmp_path / "credential-alias"
    try:
        os.link(credential, alias)
    except OSError as exc:
        pytest.skip(f"hardlinks unavailable: {exc}")
    try:
        with pytest.raises(
            C.ClaudeAttemptProfileError,
            match="single-link|identity|drift",
        ):
            C.replay_claude_attempt_profile_postprocess_binding(
                profile,
                profile.binding,
            )
    finally:
        alias.unlink()


def test_postprocess_state_accepts_only_version_pinned_benign_deltas(
    tmp_path: Path,
) -> None:
    profile, _kwargs, _secret = _materialized_fixture(
        tmp_path,
        attempt_id="attempt-state-benign-deltas",
        secret=_valid_credential_bytes("state-benign-deltas"),
    )
    state = _simulate_provider_state_update(
        profile,
        remove_bypass_acceptance=True,
    )
    state.update(
        {
            "userID": "a" * 64,
            "machineID": "b" * 64,
            "firstStartTime": profile.binding[
                "attempt_profile_created_at_utc"
            ],
            "claudeCodeFirstTokenDate": "2026-07-28T00:00:00.000Z",
            "changelogLastFetched": 1_753_680_000_000,
            "penguinModeOrgEnabled": False,
            "cachedExtraUsageDisabledReason": "plan-policy",
            "cachedGrowthBookFeatures": {"safeFeature": True},
            "cachedExperimentFeatures": ["safe-experiment"],
            "cachedExperimentData": {"variant": "control"},
            "cachedGrowthBookFeaturesAt": 1_753_680_000_000,
            "clientDataCacheSlots": {},
            "additionalModelOptionsCache": [],
            "additionalModelCostsCache": {},
            "modelAccessCache": [],
            "orgModelDefaultCache": None,
            "autoCompactWindowsCache": None,
            "cachedUsageUtilization": {"fiveHour": 0.25},
            "seenNotifications": {},
            "tipsHistory": {"tip-1": 1},
            "tipLifetimeShownCounts": {"tip-1": 1},
            "pluginUsage": {},
            "pluginUsageLspGraceAppliedIds": [],
            "memoryUsageCount": 0,
            "promptQueueUseCount": 1,
            "btwUseCount": 0,
            "hasSeenTasksHint": True,
            "hasUsedStash": False,
            "hasUsedBackgroundTask": False,
            "queuedCommandUpHintCount": 0,
        }
    )
    project_key = profile.binding["state_project_keys"][0]
    project = state["projects"][project_key]
    project.update(
        {
            "lastCost": 0.25,
            "lastAPIDuration": 100,
            "lastAPIDurationWithoutRetries": 90,
            "lastToolDuration": 10,
            "lastDuration": 110,
            "lastStartTime": 1_753_680_000_000,
            "lastLinesAdded": 4,
            "lastLinesRemoved": 1,
            "lastTotalInputTokens": 1000,
            "lastTotalOutputTokens": 200,
            "lastTotalCacheCreationInputTokens": 30,
            "lastTotalCacheReadInputTokens": 40,
            "lastTotalWebSearchRequests": 0,
            "lastFpsAverage": 60.0,
            "lastFpsLow1Pct": 45.0,
            "lastGracefulShutdown": True,
            "lastVersionBase": "2.1.220",
            "lastModelUsage": {
                "claude-opus-5-20260728": {
                    "inputTokens": 1000,
                    "outputTokens": 200,
                    "cacheReadInputTokens": 40,
                    "cacheCreationInputTokens": 30,
                    "webSearchRequests": 0,
                    "costUSD": 0.25,
                },
            },
            "lastSessionId": "session-redacted-fixture",
            "lastSessionMetrics": {
                "turns": 3,
                "latency_ms": 100.5,
            },
        }
    )
    profile.state_path.write_text(
        json.dumps(
            state,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    profile.state_path.chmod(0o600)

    assert C.replay_claude_attempt_profile_postprocess_binding(
        profile,
        profile.binding,
    )["valid"] is True


def test_postprocess_state_accepts_exact_claude_2_1_252_account_shape_without_export(
    tmp_path: Path,
) -> None:
    profile, _kwargs, _secret = _materialized_fixture(
        tmp_path,
        attempt_id="attempt-state-oauth-account-shape",
        secret=_valid_credential_bytes("state-oauth-account-shape"),
    )
    state = _simulate_provider_state_update(profile)
    account = state["oauthAccount"]
    project_key = profile.binding["state_project_keys"][0]
    project = state["projects"][project_key]

    replay = C.replay_claude_attempt_profile_postprocess_binding(
        profile,
        profile.binding,
    )

    assert replay["valid"] is True
    assert "hasCompletedProjectOnboarding" not in project
    assert "projectOnboardingSeenCount" not in project
    serialized_replay = json.dumps(replay, sort_keys=True)
    for value in account.values():
        if isinstance(value, str):
            assert value not in serialized_replay


def test_postprocess_state_accepts_unchanged_no_persistence_startup_counter(
    tmp_path: Path,
) -> None:
    profile, _kwargs, _secret = _materialized_fixture(
        tmp_path,
        attempt_id="attempt-state-startup-unchanged",
        secret=_valid_credential_bytes("state-startup-unchanged"),
    )
    state = _simulate_provider_state_update(profile)
    state["numStartups"] = 1
    profile.state_path.write_text(
        json.dumps(state, separators=(",", ":")),
        encoding="utf-8",
    )
    profile.state_path.chmod(0o600)

    assert C.replay_claude_attempt_profile_postprocess_binding(
        profile,
        profile.binding,
    )["valid"] is True


@pytest.mark.parametrize(
    "startup_count",
    [0, 3, -1, True, 1.0, "1", None],
)
def test_postprocess_state_rejects_unbound_startup_counter_values(
    tmp_path: Path,
    startup_count: object,
) -> None:
    profile, _kwargs, _secret = _materialized_fixture(
        tmp_path,
        attempt_id=(
            "attempt-state-startup-invalid-"
            f"{type(startup_count).__name__}-{str(startup_count).lower()}"
        ),
        secret=_valid_credential_bytes("state-startup-invalid"),
    )
    state = _simulate_provider_state_update(profile)
    state["numStartups"] = startup_count
    profile.state_path.write_text(
        json.dumps(state, separators=(",", ":")),
        encoding="utf-8",
    )
    profile.state_path.chmod(0o600)

    with pytest.raises(
        C.ClaudeAttemptProfileError,
        match="startup counter",
    ):
        C.replay_claude_attempt_profile_postprocess_binding(
            profile,
            profile.binding,
        )


@pytest.mark.parametrize(
    ("mutation", "error_pattern"),
    [
        ({"accessToken": "fixture-secret"}, "authority-bearing|schema"),
        ({"surprise": True}, "schema"),
        ({"ccOnboardingFlags": {"refreshToken": False}}, "flags"),
        ({"ccOnboardingFlags": {"nested": {}}}, "flags"),
        ({"hasExtraUsageEnabled": 1}, "boolean"),
        ({"profileFetchedAt": "now"}, "numeric"),
        ({"seatTier": []}, "seat tier"),
        ({"accountCreatedAt": "not-a-timestamp"}, "timestamp"),
        ({"emailAddress": None}, "string"),
    ],
)
def test_postprocess_state_rejects_oauth_account_schema_or_type_drift(
    tmp_path: Path,
    mutation: dict[str, object],
    error_pattern: str,
) -> None:
    profile, _kwargs, _secret = _materialized_fixture(
        tmp_path,
        attempt_id=(
            "attempt-state-oauth-drift-"
            + next(iter(mutation)).replace("_", "-")
        ),
        secret=_valid_credential_bytes("state-oauth-drift"),
    )
    state = _simulate_provider_state_update(profile)
    state["oauthAccount"].update(mutation)
    profile.state_path.write_text(
        json.dumps(state, separators=(",", ":")),
        encoding="utf-8",
    )
    profile.state_path.chmod(0o600)

    with pytest.raises(C.ClaudeAttemptProfileError, match=error_pattern):
        C.replay_claude_attempt_profile_postprocess_binding(
            profile,
            profile.binding,
        )


def test_postprocess_state_accepts_portable_oauth_account_variants_or_absence(
    tmp_path: Path,
) -> None:
    profile, _kwargs, _secret = _materialized_fixture(
        tmp_path,
        attempt_id="attempt-state-oauth-portable-variants",
        secret=_valid_credential_bytes("state-oauth-portable-variants"),
    )
    state = _simulate_provider_state_update(profile)
    account = state["oauthAccount"]
    account.update(
        {
            "accountCreatedAt": None,
            "subscriptionCreatedAt": None,
            "claudeCodeTrialEndsAt": "2026-12-31T00:00:00.000Z",
            "claudeCodeTrialDurationDays": 30,
            "seatTier": "fixture-tier",
            "ccOnboardingFlags": {
                "safeFlag": True,
                "rolloutGroup": "fixture-group",
                "cohort": 2,
                "unsetFlag": None,
            },
        }
    )
    profile.state_path.write_text(
        json.dumps(state, separators=(",", ":")),
        encoding="utf-8",
    )
    profile.state_path.chmod(0o600)
    assert C.replay_claude_attempt_profile_postprocess_binding(
        profile,
        profile.binding,
    )["valid"] is True

    state.pop("oauthAccount")
    profile.state_path.write_text(
        json.dumps(state, separators=(",", ":")),
        encoding="utf-8",
    )
    profile.state_path.chmod(0o600)
    assert C.replay_claude_attempt_profile_postprocess_binding(
        profile,
        profile.binding,
    )["valid"] is True


def test_postprocess_state_rejects_account_metadata_on_environment_token_route(
    tmp_path: Path,
) -> None:
    global_home = tmp_path / "global-environment-route"
    global_home.mkdir()
    state_path = tmp_path / "global-environment-route-state.json"
    state_path.write_text("{}", encoding="utf-8")
    project = tmp_path / "project-environment-route"
    project.mkdir()
    runtime = tmp_path / "runtime-environment-route"
    runtime.mkdir()
    profile = C.materialize_claude_attempt_profile(
        **_profile_kwargs(
            runtime=runtime,
            project=project,
            global_home=global_home,
            state=state_path,
            attempt_id="attempt-state-environment-route-account",
            credential_mode="ENVIRONMENT_OAUTH_TOKEN",
            auth_route="OAUTH_TOKEN",
        )
    )
    state = _simulate_provider_state_update(profile)
    state["oauthAccount"] = {
        "accountUuid": "fixture-account-id",
        "emailAddress": "fixture@example.invalid",
        "organizationUuid": "fixture-organization-id",
        "hasExtraUsageEnabled": False,
        "billingType": "fixture-billing-class",
        "accountCreatedAt": "2025-01-01T00:00:00.000Z",
        "subscriptionCreatedAt": "2025-01-02T00:00:00.000Z",
        "ccOnboardingFlags": {},
        "claudeCodeTrialEndsAt": None,
        "claudeCodeTrialDurationDays": None,
        "seatTier": None,
        "displayName": "Fixture Display",
        "fullName": "Fixture Full Name",
        "profileFetchedAt": 1_753_680_000_000,
    }
    profile.state_path.write_text(
        json.dumps(state, separators=(",", ":")),
        encoding="utf-8",
    )
    profile.state_path.chmod(0o600)

    with pytest.raises(C.ClaudeAttemptProfileError, match="auth route"):
        C.replay_claude_attempt_profile_postprocess_binding(
            profile,
            profile.binding,
        )


@pytest.mark.parametrize(
    ("project_mutation", "error_pattern"),
    [
        ({"hasCompletedProjectOnboarding": True}, "canonicalization"),
        ({"projectOnboardingSeenCount": 0}, "canonicalization"),
        (
            {
                "hasCompletedProjectOnboarding": False,
                "projectOnboardingSeenCount": 0,
            },
            "canonicalization",
        ),
        ({"hasTrustDialogAccepted": False}, "security projection"),
    ],
)
def test_postprocess_state_rejects_project_canonicalization_drift(
    tmp_path: Path,
    project_mutation: dict[str, object],
    error_pattern: str,
) -> None:
    profile, _kwargs, _secret = _materialized_fixture(
        tmp_path,
        attempt_id=(
            "attempt-state-project-canonical-"
            + next(iter(project_mutation)).replace("_", "-")
        ),
        secret=_valid_credential_bytes("state-project-canonical"),
    )
    state = _simulate_provider_state_update(profile)
    project_key = profile.binding["state_project_keys"][0]
    state["projects"][project_key].update(project_mutation)
    profile.state_path.write_text(
        json.dumps(state, separators=(",", ":")),
        encoding="utf-8",
    )
    profile.state_path.chmod(0o600)

    with pytest.raises(C.ClaudeAttemptProfileError, match=error_pattern):
        C.replay_claude_attempt_profile_postprocess_binding(
            profile,
            profile.binding,
        )


def test_postprocess_state_accepts_exact_retained_project_onboarding_pair(
    tmp_path: Path,
) -> None:
    profile, _kwargs, _secret = _materialized_fixture(
        tmp_path,
        attempt_id="attempt-state-project-onboarding-retained",
        secret=_valid_credential_bytes("state-project-onboarding-retained"),
    )
    state = _simulate_provider_state_update(profile)
    project_key = profile.binding["state_project_keys"][0]
    state["projects"][project_key].update(
        {
            "hasCompletedProjectOnboarding": True,
            "projectOnboardingSeenCount": 0,
        }
    )
    profile.state_path.write_text(
        json.dumps(state, separators=(",", ":")),
        encoding="utf-8",
    )
    profile.state_path.chmod(0o600)

    assert C.replay_claude_attempt_profile_postprocess_binding(
        profile,
        profile.binding,
    )["valid"] is True


def test_postprocess_state_rejects_other_project_security_field_removal(
    tmp_path: Path,
) -> None:
    profile, _kwargs, _secret = _materialized_fixture(
        tmp_path,
        attempt_id="attempt-state-project-security-removal",
        secret=_valid_credential_bytes("state-project-security-removal"),
    )
    state = _simulate_provider_state_update(profile)
    project_key = profile.binding["state_project_keys"][0]
    state["projects"][project_key].pop("hasTrustDialogAccepted")
    profile.state_path.write_text(
        json.dumps(state, separators=(",", ":")),
        encoding="utf-8",
    )
    profile.state_path.chmod(0o600)

    with pytest.raises(
        C.ClaudeAttemptProfileError,
        match="security projection",
    ):
        C.replay_claude_attempt_profile_postprocess_binding(
            profile,
            profile.binding,
        )


def test_postprocess_state_allows_only_exact_first_token_null(
    tmp_path: Path,
) -> None:
    profile, _kwargs, _secret = _materialized_fixture(
        tmp_path,
        attempt_id="attempt-state-exact-first-token-null",
        secret=_valid_credential_bytes("exact-first-token-null"),
    )
    state = _simulate_provider_state_update(profile)
    state["claudeCodeFirstTokenDate"] = None
    profile.state_path.write_text(
        json.dumps(state, separators=(",", ":")),
        encoding="utf-8",
    )
    profile.state_path.chmod(0o600)
    assert C.replay_claude_attempt_profile_postprocess_binding(
        profile,
        profile.binding,
    )["valid"] is True

    state["firstStartTime"] = None
    profile.state_path.write_text(
        json.dumps(state, separators=(",", ":")),
        encoding="utf-8",
    )
    profile.state_path.chmod(0o600)
    with pytest.raises(
        C.ClaudeAttemptProfileError,
        match="firstStartTime",
    ):
        C.replay_claude_attempt_profile_postprocess_binding(
            profile,
            profile.binding,
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("mcpServers", {}),
        ("oauthAccount", {}),
        ("githubRepoPaths", {"repo": "C:/private"}),
        ("surpriseTelemetry", True),
    ],
)
def test_postprocess_state_rejects_authority_and_unknown_root_fields(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    profile, _kwargs, _secret = _materialized_fixture(
        tmp_path,
        attempt_id=f"attempt-state-root-{field}",
        secret=_valid_credential_bytes(f"state-root-{field}"),
    )
    state = _simulate_provider_state_update(profile)
    state[field] = value
    profile.state_path.write_text(
        json.dumps(state, separators=(",", ":")),
        encoding="utf-8",
    )
    profile.state_path.chmod(0o600)

    with pytest.raises(
        C.ClaudeAttemptProfileError,
        match="authority-bearing|unsupported version|metadata schema",
    ):
        C.replay_claude_attempt_profile_postprocess_binding(
            profile,
            profile.binding,
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("allowedTools", ["Bash"]),
        ("disabledMcpServers", []),
        ("exampleFiles", ["private.sol"]),
        ("lastSessionFirstPrompt", "sensitive history"),
    ],
)
def test_postprocess_state_rejects_project_authority_and_history(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    profile, _kwargs, _secret = _materialized_fixture(
        tmp_path,
        attempt_id=f"attempt-state-project-{field}",
        secret=_valid_credential_bytes(f"state-project-{field}"),
    )
    state = _simulate_provider_state_update(profile)
    project_key = profile.binding["state_project_keys"][0]
    state["projects"][project_key][field] = value
    profile.state_path.write_text(
        json.dumps(state, separators=(",", ":")),
        encoding="utf-8",
    )
    profile.state_path.chmod(0o600)

    with pytest.raises(
        C.ClaudeAttemptProfileError,
        match="project security projection|unsupported field",
    ):
        C.replay_claude_attempt_profile_postprocess_binding(
            profile,
            profile.binding,
        )


def test_postprocess_state_atomic_replacement_is_denied_or_rejected(
    tmp_path: Path,
) -> None:
    profile, _kwargs, _secret = _materialized_fixture(
        tmp_path,
        attempt_id="attempt-state-atomic-replacement",
        secret=_valid_credential_bytes("state-atomic-replacement"),
    )
    _simulate_provider_state_update(profile)
    before = profile.state_path.stat()
    replacement = profile.config_dir / "state-replacement"
    replacement.write_bytes(profile.state_path.read_bytes())
    replacement.chmod(0o600)
    if os.name == "nt":
        with pytest.raises(PermissionError):
            os.replace(replacement, profile.state_path)
        after = profile.state_path.stat()
        assert (before.st_dev, before.st_ino) == (
            after.st_dev,
            after.st_ino,
        )
        assert C.replay_claude_attempt_profile_postprocess_binding(
            profile,
            profile.binding,
        )["valid"] is True
        replacement.unlink()
    else:
        os.replace(replacement, profile.state_path)
        after = profile.state_path.stat()
        assert (before.st_dev, before.st_ino) != (
            after.st_dev,
            after.st_ino,
        )
        with pytest.raises(
            C.ClaudeAttemptProfileError,
            match="identity",
        ):
            C.replay_claude_attempt_profile_postprocess_binding(
                profile,
                profile.binding,
            )
    profile.abort_before_process_scope(
        attempt_arm_sha256=str(
            profile.binding["outer_attempt_arm_sha256"]
        ),
        process_scope_identity=str(
            profile.binding["process_scope_identity"]
        ),
        reason_code="STATE_ATOMIC_REPLACEMENT_FIXTURE_DONE",
    )


@pytest.mark.parametrize("alias_kind", ("symlink", "hardlink"))
def test_postprocess_state_rejects_aliases(
    tmp_path: Path,
    alias_kind: str,
) -> None:
    profile, _kwargs, _secret = _materialized_fixture(
        tmp_path,
        attempt_id=f"attempt-state-{alias_kind}",
        secret=_valid_credential_bytes(f"state-{alias_kind}"),
    )
    _simulate_provider_state_update(profile)
    outside = tmp_path / f"outside-state-{alias_kind}.json"
    outside.write_bytes(profile.state_path.read_bytes())
    outside.chmod(0o600)
    if alias_kind == "symlink":
        if os.name == "nt":
            with pytest.raises(PermissionError):
                profile.state_path.unlink()
            assert C.replay_claude_attempt_profile_postprocess_binding(
                profile,
                profile.binding,
            )["valid"] is True
            profile.abort_before_process_scope(
                attempt_arm_sha256=str(
                    profile.binding["outer_attempt_arm_sha256"]
                ),
                process_scope_identity=str(
                    profile.binding["process_scope_identity"]
                ),
                reason_code="STATE_SYMLINK_FIXTURE_DONE",
            )
            return
        profile.state_path.unlink()
        try:
            profile.state_path.symlink_to(outside)
        except OSError as exc:
            pytest.skip(f"file symlinks unavailable: {exc}")
    else:
        try:
            os.link(profile.state_path, outside)
        except FileExistsError:
            outside.unlink()
            try:
                os.link(profile.state_path, outside)
            except OSError as exc:
                pytest.skip(f"hardlinks unavailable: {exc}")
        except OSError as exc:
            pytest.skip(f"hardlinks unavailable: {exc}")

    with pytest.raises(
        C.ClaudeAttemptProfileError,
        match="symlink|reparse|one link|single-link|identity",
    ):
        C.replay_claude_attempt_profile_postprocess_binding(
            profile,
            profile.binding,
        )
    profile.abort_before_process_scope(
        attempt_arm_sha256=str(
            profile.binding["outer_attempt_arm_sha256"]
        ),
        process_scope_identity=str(
            profile.binding["process_scope_identity"]
        ),
        reason_code=f"STATE_{alias_kind.upper()}_FIXTURE_DONE",
    )


@pytest.mark.parametrize("target", ("settings", "state"))
def test_postprocess_replay_rejects_synthesized_profile_drift(
    tmp_path: Path,
    target: str,
) -> None:
    profile, _kwargs, _secret = _materialized_fixture(
        tmp_path,
        attempt_id=f"attempt-postprocess-{target}",
        secret=_valid_credential_bytes(f"before-{target}-drift"),
    )
    path = (
        profile.config_dir / "settings.json"
        if target == "settings"
        else profile.state_path
    )
    if target == "settings":
        _simulate_provider_state_update(profile)
    path.write_text('{"drifted":true}', encoding="utf-8")

    with pytest.raises(
        C.ClaudeAttemptProfileError,
        match="settings bytes drifted|state .*drifted",
    ):
        C.replay_claude_attempt_profile_postprocess_binding(
            profile,
            profile.binding,
        )


def test_prelaunch_abort_revokes_parent_lease_without_scope_token(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile, kwargs, secret = _materialized_fixture(
        tmp_path,
        attempt_id="attempt-prelaunch-abort",
    )
    lease = kwargs["leased_parent"]
    capability = kwargs["stored_subscription_capability"]
    evidence = kwargs[
        "expected_stored_subscription_source_evidence"
    ]
    assert isinstance(lease, A.AuxiliaryWritableRootLease)
    assert secret in (profile.config_dir / ".credentials.json").read_bytes()
    with pytest.raises(
        C.ClaudeAttemptProfileError,
        match="abort authority",
    ):
        profile.abort_before_process_scope(
            attempt_arm_sha256="f" * 64,
            process_scope_identity=str(kwargs["process_scope_identity"]),
            reason_code="CANCELLED_BEFORE_POPEN",
        )
    assert profile.root.exists()
    assert lease.root.exists()

    original_abort = A.AuxiliaryWritableRootLease.abort_before_process_scope

    def assert_profile_first(
        self: A.AuxiliaryWritableRootLease,
        **authority: object,
    ) -> dict[str, object]:
        assert not profile.root.exists()
        return original_abort(self, **authority)

    monkeypatch.setattr(
        A.AuxiliaryWritableRootLease,
        "abort_before_process_scope",
        assert_profile_first,
    )
    receipt = profile.abort_before_process_scope(
        attempt_arm_sha256=str(kwargs["outer_attempt_arm_sha256"]),
        process_scope_identity=str(kwargs["process_scope_identity"]),
        reason_code="CANCELLED_BEFORE_POPEN",
    )

    assert receipt["cleanup_mode"] == "PRELAUNCH_ABORT"
    assert receipt["completion_authority"] is False
    assert receipt["process_scope_created"] is False
    assert receipt["revoked"] is True
    assert not profile.root.exists()
    assert not lease.root.exists()
    assert C.replay_claude_attempt_profile_revocation(
        profile,
        receipt,
    )["valid"] is True
    assert profile.abort_before_process_scope(
        attempt_arm_sha256=str(kwargs["outer_attempt_arm_sha256"]),
        process_scope_identity=str(kwargs["process_scope_identity"]),
        reason_code="CANCELLED_BEFORE_POPEN",
    ) == receipt


def test_prelaunch_abort_claim_blocks_bind_before_profile_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bind/delete interleaving cannot remove a profile under a live scope."""

    profile, kwargs, _secret = _materialized_fixture(
        tmp_path,
        attempt_id="attempt-prelaunch-claim-race",
    )
    lease = kwargs["leased_parent"]
    assert isinstance(lease, A.AuxiliaryWritableRootLease)

    class FakeOwnedProcessScope:
        persistent_identity = profile.binding[
            "process_scope_identity"
        ]

    monkeypatch.setattr(
        A,
        "_owned_process_scope_type",
        lambda: FakeOwnedProcessScope,
    )
    original_revoke = (
        C.ClaudeAttemptProfile._revoke_owned_profile_root
    )
    bind_attempted = False

    def attempt_bind_when_cleanup_starts(
        self: C.ClaudeAttemptProfile,
        **authority: object,
    ) -> dict[str, object]:
        nonlocal bind_attempted
        bind_attempted = True
        with pytest.raises(
            A.AuxiliaryWritableRootLeaseError,
            match="prelaunch abort.*claimed|abort claim",
        ):
            lease.bind_process_scope(FakeOwnedProcessScope())
        return original_revoke(self, **authority)

    monkeypatch.setattr(
        C.ClaudeAttemptProfile,
        "_revoke_owned_profile_root",
        attempt_bind_when_cleanup_starts,
    )
    receipt = profile.abort_before_process_scope(
        attempt_arm_sha256=str(
            profile.binding["outer_attempt_arm_sha256"]
        ),
        process_scope_identity=str(
            profile.binding["process_scope_identity"]
        ),
        reason_code="CANCELLED_BEFORE_POPEN",
    )

    assert bind_attempted is True
    assert lease.process_scope_bound is False
    assert receipt["cleanup_mode"] == "PRELAUNCH_ABORT"
    assert receipt["completion_authority"] is False
    assert not profile.root.exists()
    assert not lease.root.exists()


def test_bound_prelaunch_scope_cleanup_is_distinct_and_profile_first(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile, kwargs, _secret = _materialized_fixture(
        tmp_path,
        attempt_id="attempt-bound-prelaunch",
    )
    lease = kwargs["leased_parent"]
    assert isinstance(lease, A.AuxiliaryWritableRootLease)

    class FakeOwnedProcessScope:
        persistent_identity = profile.binding[
            "process_scope_identity"
        ]
        attached = False
        terminated = False
        closed = True
        population_zero_proven = True
        emergency_closed = False
        pre_release_process_identity = None
        process_creation_state = "NOT_ATTEMPTED"
        process_creation_evidence = {
            "state": "NOT_ATTEMPTED",
            "creation_attempted": False,
            "process_object_returned": False,
            "attached": False,
            "created_process_termination_proven": False,
        }

    monkeypatch.setattr(
        C,
        "_owned_process_scope_type",
        lambda: FakeOwnedProcessScope,
    )
    monkeypatch.setattr(
        A,
        "_owned_process_scope_type",
        lambda: FakeOwnedProcessScope,
    )
    scope = FakeOwnedProcessScope()
    lease.bind_process_scope(scope)

    token = C.prove_claude_bound_prelaunch_scope_closed(
        profile,
        scope,
    )
    with pytest.raises(
        C.ClaudeAttemptProfileError,
        match="closure token",
    ):
        profile.revoke(token)  # type: ignore[arg-type]
    receipt = profile.revoke_bound_prelaunch_scope(token)

    assert receipt["cleanup_mode"] == "BOUND_PRELAUNCH_ABORT"
    assert receipt["completion_authority"] is False
    assert receipt["process_scope_created"] is True
    assert receipt["process_attached"] is False
    assert receipt["profile_root_absent_after"] is True
    assert not profile.root.exists()
    assert lease.root.exists()
    assert C.replay_claude_attempt_profile_revocation(
        profile,
        receipt,
    )["valid"] is True


def test_normal_completion_authority_rejects_never_attached_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile, _kwargs, _secret = _materialized_fixture(
        tmp_path,
        attempt_id="attempt-normal-never-attached",
    )

    with pytest.raises(
        C.ClaudeAttemptProfileError,
        match="bound-prelaunch",
    ):
        _closure_token(
            monkeypatch,
            profile,
            attached=False,
        )
    assert profile.root.exists()


def test_bound_prelaunch_cleanup_rejects_any_process_attachment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile, kwargs, _secret = _materialized_fixture(
        tmp_path,
        attempt_id="attempt-bound-attached",
    )
    lease = kwargs["leased_parent"]
    assert isinstance(lease, A.AuxiliaryWritableRootLease)

    class FakeOwnedProcessScope:
        persistent_identity = profile.binding[
            "process_scope_identity"
        ]
        attached = True
        terminated = True
        closed = True
        population_zero_proven = True
        emergency_closed = False
        pre_release_process_identity = {
            "kind": "FIXTURE",
            "value": "process-was-attached",
        }
        process_creation_state = "ATTACHED"
        process_creation_evidence = {
            "state": "ATTACHED",
            "creation_attempted": True,
            "process_object_returned": True,
            "attached": True,
            "created_process_termination_proven": False,
        }

    monkeypatch.setattr(
        C,
        "_owned_process_scope_type",
        lambda: FakeOwnedProcessScope,
    )
    monkeypatch.setattr(
        A,
        "_owned_process_scope_type",
        lambda: FakeOwnedProcessScope,
    )
    scope = FakeOwnedProcessScope()
    lease.bind_process_scope(scope)

    with pytest.raises(
        C.ClaudeAttemptProfileError,
        match="attach",
    ):
        C.prove_claude_bound_prelaunch_scope_closed(
            profile,
            scope,
        )
    assert profile.root.exists()
    assert lease.root.exists()


@pytest.mark.parametrize(
    (
        "process_creation_state",
        "creation_attempted",
        "process_object_returned",
        "accepted",
    ),
    [
        (
            "CREATION_FAILED_WITHOUT_PROCESS_OBJECT",
            True,
            False,
            True,
        ),
        ("PROCESS_CREATED", True, True, False),
    ],
)
def test_bound_prelaunch_cleanup_uses_monotonic_process_creation_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    process_creation_state: str,
    creation_attempted: bool,
    process_object_returned: bool,
    accepted: bool,
) -> None:
    profile, kwargs, _secret = _materialized_fixture(
        tmp_path,
        attempt_id=(
            "attempt-create-failed"
            if accepted
            else "attempt-process-created"
        ),
    )
    lease = kwargs["leased_parent"]
    assert isinstance(lease, A.AuxiliaryWritableRootLease)

    class FakeOwnedProcessScope:
        persistent_identity = profile.binding[
            "process_scope_identity"
        ]
        attached = False
        terminated = False
        closed = True
        population_zero_proven = True
        emergency_closed = False
        pre_release_process_identity = None

    FakeOwnedProcessScope.process_creation_state = process_creation_state
    FakeOwnedProcessScope.process_creation_evidence = {
        "state": process_creation_state,
        "creation_attempted": creation_attempted,
        "process_object_returned": process_object_returned,
        "attached": False,
        "created_process_termination_proven": False,
    }
    monkeypatch.setattr(
        C,
        "_owned_process_scope_type",
        lambda: FakeOwnedProcessScope,
    )
    monkeypatch.setattr(
        A,
        "_owned_process_scope_type",
        lambda: FakeOwnedProcessScope,
    )
    scope = FakeOwnedProcessScope()
    lease.bind_process_scope(scope)

    if not accepted:
        with pytest.raises(
            C.ClaudeAttemptProfileError,
            match="no-process creation state",
        ):
            C.prove_claude_bound_prelaunch_scope_closed(
                profile,
                scope,
            )
        assert profile.root.exists()
        return

    token = C.prove_claude_bound_prelaunch_scope_closed(
        profile,
        scope,
    )
    receipt = profile.revoke_bound_prelaunch_scope(token)
    assert receipt["process_creation_state"] == (
        "CREATION_FAILED_WITHOUT_PROCESS_OBJECT"
    )
    assert receipt["completion_authority"] is False
    assert C.replay_claude_attempt_profile_revocation(
        profile,
        receipt,
    )["valid"] is True


def test_process_attach_failure_cleanup_is_distinct_and_noncompletion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile, kwargs, _secret = _materialized_fixture(
        tmp_path,
        attempt_id="attempt-process-attach-failure",
    )
    lease = kwargs["leased_parent"]
    assert isinstance(lease, A.AuxiliaryWritableRootLease)

    class FakeOwnedProcessScope:
        persistent_identity = profile.binding[
            "process_scope_identity"
        ]
        process_creation_state = "PROCESS_CREATED"
        process_creation_evidence = {
            "state": "PROCESS_CREATED",
            "creation_attempted": True,
            "process_object_returned": True,
            "attached": False,
            "created_process_termination_proven": True,
        }
        created_process_termination_proven = True
        attached = False
        terminated = False
        pre_release_process_identity = None
        closed = True
        population_zero_proven = True
        emergency_closed = False

    monkeypatch.setattr(
        C,
        "_owned_process_scope_type",
        lambda: FakeOwnedProcessScope,
    )
    monkeypatch.setattr(
        A,
        "_owned_process_scope_type",
        lambda: FakeOwnedProcessScope,
    )
    scope = FakeOwnedProcessScope()
    lease.bind_process_scope(scope)

    token = C.prove_claude_process_attach_failure_scope_closed(
        profile,
        scope,
    )
    assert isinstance(
        token,
        C.ClaudeProcessAttachFailureScopeClosureToken,
    )
    with pytest.raises(
        C.ClaudeAttemptProfileError,
        match="closure token",
    ):
        profile.revoke(token)  # type: ignore[arg-type]
    receipt = profile.revoke_process_attach_failure_scope(token)
    assert receipt["cleanup_mode"] == (
        "PROCESS_ATTACH_FAILURE_CLEANUP"
    )
    assert receipt["completion_authority"] is False
    assert receipt["process_creation_state"] == "PROCESS_CREATED"
    assert receipt["created_process_termination_proven"] is True
    assert receipt["process_attached"] is False
    assert not profile.root.exists()
    assert lease.root.exists()
    assert C.replay_claude_attempt_profile_revocation(
        profile,
        receipt,
    )["valid"] is True
    mutated = dict(receipt)
    mutated["created_process_termination_proven"] = False
    with pytest.raises(
        C.ClaudeAttemptProfileError,
        match="substituted",
    ):
        C.replay_claude_attempt_profile_revocation(
            profile,
            mutated,
        )


@pytest.mark.parametrize(
    "defect",
    (
        "termination-proof-absent",
        "termination-evidence-mismatch",
        "wrong-creation-state",
    ),
)
def test_process_attach_failure_cleanup_rejects_incomplete_proof(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    defect: str,
) -> None:
    profile, kwargs, _secret = _materialized_fixture(
        tmp_path,
        attempt_id=f"attempt-attach-proof-{defect}",
    )
    lease = kwargs["leased_parent"]
    assert isinstance(lease, A.AuxiliaryWritableRootLease)

    class FakeOwnedProcessScope:
        persistent_identity = profile.binding[
            "process_scope_identity"
        ]
        process_creation_state = (
            "NOT_ATTEMPTED"
            if defect == "wrong-creation-state"
            else "PROCESS_CREATED"
        )
        created_process_termination_proven = (
            defect != "termination-proof-absent"
        )
        attached = False
        terminated = False
        pre_release_process_identity = None
        closed = True
        population_zero_proven = True
        emergency_closed = False

    FakeOwnedProcessScope.process_creation_evidence = {
        "state": FakeOwnedProcessScope.process_creation_state,
        "creation_attempted": True,
        "process_object_returned": True,
        "attached": False,
        "created_process_termination_proven": (
            False
            if defect == "termination-evidence-mismatch"
            else FakeOwnedProcessScope.created_process_termination_proven
        ),
    }
    monkeypatch.setattr(
        C,
        "_owned_process_scope_type",
        lambda: FakeOwnedProcessScope,
    )
    monkeypatch.setattr(
        A,
        "_owned_process_scope_type",
        lambda: FakeOwnedProcessScope,
    )
    scope = FakeOwnedProcessScope()
    lease.bind_process_scope(scope)

    with pytest.raises(
        C.ClaudeAttemptProfileError,
        match="PROCESS_CREATED|termination proof|evidence is malformed",
    ):
        C.prove_claude_process_attach_failure_scope_closed(
            profile,
            scope,
        )
    assert profile.root.exists()


def test_process_attach_failure_cleanup_requires_strict_prelaunch_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile, kwargs, _secret = _materialized_fixture(
        tmp_path,
        attempt_id="attempt-attach-failure-strict-replay",
    )
    lease = kwargs["leased_parent"]
    assert isinstance(lease, A.AuxiliaryWritableRootLease)

    class FakeOwnedProcessScope:
        persistent_identity = profile.binding[
            "process_scope_identity"
        ]
        process_creation_state = "PROCESS_CREATED"
        process_creation_evidence = {
            "state": "PROCESS_CREATED",
            "creation_attempted": True,
            "process_object_returned": True,
            "attached": False,
            "created_process_termination_proven": True,
        }
        created_process_termination_proven = True
        attached = False
        terminated = False
        pre_release_process_identity = None
        closed = True
        population_zero_proven = True
        emergency_closed = False

    monkeypatch.setattr(
        C,
        "_owned_process_scope_type",
        lambda: FakeOwnedProcessScope,
    )
    monkeypatch.setattr(
        A,
        "_owned_process_scope_type",
        lambda: FakeOwnedProcessScope,
    )
    scope = FakeOwnedProcessScope()
    lease.bind_process_scope(scope)
    credential = profile.config_dir / ".credentials.json"
    credential.write_text(
        '{"oauthToken":"unexpected-provider-execution"}',
        encoding="utf-8",
    )

    with pytest.raises(
        C.ClaudeAttemptProfileError,
        match="credential copy drifted",
    ):
        C.prove_claude_process_attach_failure_scope_closed(
            profile,
            scope,
        )
    assert profile.root.exists()


def test_bound_prelaunch_proof_requires_strict_prelaunch_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile, kwargs, _secret = _materialized_fixture(
        tmp_path,
        attempt_id="attempt-bound-strict-replay",
    )
    lease = kwargs["leased_parent"]
    assert isinstance(lease, A.AuxiliaryWritableRootLease)

    class FakeOwnedProcessScope:
        persistent_identity = profile.binding[
            "process_scope_identity"
        ]
        attached = False
        terminated = False
        closed = True
        population_zero_proven = True
        emergency_closed = False
        pre_release_process_identity = None
        process_creation_state = "NOT_ATTEMPTED"
        process_creation_evidence = {
            "state": "NOT_ATTEMPTED",
            "creation_attempted": False,
            "process_object_returned": False,
            "attached": False,
            "created_process_termination_proven": False,
        }

    monkeypatch.setattr(
        C,
        "_owned_process_scope_type",
        lambda: FakeOwnedProcessScope,
    )
    monkeypatch.setattr(
        A,
        "_owned_process_scope_type",
        lambda: FakeOwnedProcessScope,
    )
    scope = FakeOwnedProcessScope()
    lease.bind_process_scope(scope)
    credential = profile.config_dir / ".credentials.json"
    with credential.open("r+b") as handle:
        handle.seek(0)
        handle.write(b'{"oauthToken":"prelaunch-drift"}')
        handle.truncate()

    with pytest.raises(
        C.ClaudeAttemptProfileError,
        match="credential copy drifted",
    ):
        C.prove_claude_bound_prelaunch_scope_closed(
            profile,
            scope,
        )
    assert profile.root.exists()


def test_public_profile_and_revocation_evidence_are_not_secret_oracles(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = _valid_credential_bytes(
        "high-entropy-offline-oracle-fixture"
    )
    secret_digest = hashlib.sha256(secret).hexdigest()
    profile, _kwargs, _secret = _materialized_fixture(
        tmp_path,
        attempt_id="attempt-no-secret-oracle",
        secret=secret,
    )
    binding_json = json.dumps(profile.binding, sort_keys=True)
    assert secret.decode("utf-8") not in binding_json
    assert secret_digest not in binding_json
    assert ".credentials.json" not in binding_json
    assert secret.decode("utf-8") not in repr(profile)
    assert secret_digest not in repr(profile)
    assert ".credentials.json" not in repr(profile)
    private_key = profile._private_credential_integrity_key
    private_tag = profile._private_credential_integrity_tag

    receipt = profile.revoke(_closure_token(monkeypatch, profile))
    receipt_json = json.dumps(receipt, sort_keys=True)
    assert secret.decode("utf-8") not in receipt_json
    assert secret_digest not in receipt_json
    assert ".credentials.json" not in receipt_json
    assert private_key and not any(private_key)
    assert private_tag and not any(private_tag)
    assert profile._private_credential_integrity_key == bytearray()
    assert profile._private_credential_integrity_tag == bytearray()
    assert C.replay_claude_attempt_profile_revocation(
        profile,
        receipt,
    )["valid"] is True


def test_normal_completion_authority_is_invalid_after_state_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile, _kwargs, _secret = _materialized_fixture(
        tmp_path,
        attempt_id="attempt-stale-postprocess-authority",
        secret=_valid_credential_bytes("stale-postprocess-authority"),
    )
    closure = _closure_token(monkeypatch, profile)
    state = json.loads(
        profile.state_path.read_text(encoding="utf-8")
    )
    state["mcpServers"] = {
        "late-substitution": {"command": "must-not-run"}
    }
    profile.state_path.write_text(
        json.dumps(state, separators=(",", ":")),
        encoding="utf-8",
    )
    profile.state_path.chmod(0o600)

    with pytest.raises(
        C.ClaudeAttemptProfileError,
        match="authority-bearing|postprocess",
    ):
        profile.revoke(closure)
    assert profile.root.is_dir()
    assert profile._revocation_receipt is None


def test_home_variable_policy_is_explicit_and_can_preserve_toolchain_home(
    tmp_path: Path,
) -> None:
    global_home = tmp_path / "global-claude"
    global_home.mkdir()
    (global_home / ".credentials.json").write_text(
        '{"oauthToken":"fixture"}',
        encoding="utf-8",
    )
    state = tmp_path / ".claude.json"
    state.write_text("{}", encoding="utf-8")
    project = tmp_path / "project"
    project.mkdir()
    runtime = tmp_path / "runtime"
    runtime.mkdir()

    profile = C.materialize_claude_attempt_profile(
        **_profile_kwargs(
            runtime=runtime,
            project=project,
            global_home=global_home,
            state=state,
            attempt_id="attempt-preserve-home",
            home_variable_policy="PRESERVE_TOOLCHAIN_HOME",
        )
    )

    assert profile.binding["home_variable_policy"] == (
        "PRESERVE_TOOLCHAIN_HOME"
    )
    assert profile.binding["permission_mode"] == "bypassPermissions"
    assert {
        "HOME",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
    }.isdisjoint(profile.environment)
    assert profile.environment["CLAUDE_CONFIG_DIR"] == str(profile.config_dir)


@pytest.mark.parametrize(
    "home_variable_policy",
    ("PRIVATE_HOME", "PRESERVE_TOOLCHAIN_HOME"),
)
def test_synthesized_state_follows_claude_config_dir_for_every_home_policy(
    tmp_path: Path,
    home_variable_policy: str,
) -> None:
    global_home = tmp_path / "global-claude"
    global_home.mkdir()
    (global_home / ".credentials.json").write_text(
        '{"oauthToken":"fixture"}',
        encoding="utf-8",
    )
    state = tmp_path / "legacy-global-state.json"
    state.write_text("{}", encoding="utf-8")
    project = tmp_path / "project"
    project.mkdir()
    runtime = tmp_path / "runtime"
    runtime.mkdir()

    profile = C.materialize_claude_attempt_profile(
        **_profile_kwargs(
            runtime=runtime,
            project=project,
            global_home=global_home,
            state=state,
            attempt_id=f"attempt-state-{home_variable_policy.lower()}",
            home_variable_policy=home_variable_policy,
        )
    )

    assert profile.environment["CLAUDE_CONFIG_DIR"] == str(
        profile.config_dir
    )
    assert profile.state_path == (
        Path(profile.environment["CLAUDE_CONFIG_DIR"])
        / ".claude.json"
    )
    assert profile.state_path.is_file()
    assert not (profile.home_dir / ".claude.json").exists()


def test_profile_refuses_cleanup_without_scope_closure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    global_home = tmp_path / "global"
    global_home.mkdir()
    credentials = global_home / ".credentials.json"
    credentials.write_bytes(
        _valid_credential_bytes("global-original")
    )
    state = tmp_path / ".claude.json"
    state.write_text("{}", encoding="utf-8")
    project = tmp_path / "project"
    project.mkdir()
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    profile = C.materialize_claude_attempt_profile(
        **_profile_kwargs(
            runtime=runtime,
            project=project,
            global_home=global_home,
            state=state,
            attempt_id="attempt-002",
        )
    )

    with pytest.raises(TypeError):
        C.ClaudeProfileScopeClosureToken()  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        profile.revoke(  # type: ignore[call-arg]
            process_scope_closed=True,
            population_zero_proven=True,
        )
    with pytest.raises(C.ClaudeAttemptProfileError, match="closure token"):
        profile.revoke(object())  # type: ignore[arg-type]
    with pytest.raises(C.ClaudeAttemptProfileError, match="closure"):
        _closure_token(monkeypatch, profile, closed=False)
    with pytest.raises(C.ClaudeAttemptProfileError, match="population-zero"):
        _closure_token(monkeypatch, profile, population_zero=False)
    assert profile.root.exists()


def test_emergency_zero_population_authorizes_cleanup_only_not_completion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    global_home = tmp_path / "global"
    global_home.mkdir()
    (global_home / ".credentials.json").write_text(
        '{"token":"cleanup-only"}',
        encoding="utf-8",
    )
    state = tmp_path / ".claude.json"
    state.write_text("{}", encoding="utf-8")
    project = tmp_path / "project"
    project.mkdir()
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    profile = C.materialize_claude_attempt_profile(
        **_profile_kwargs(
            runtime=runtime,
            project=project,
            global_home=global_home,
            state=state,
            attempt_id="attempt-emergency-zero",
        )
    )

    closure = _closure_token(
        monkeypatch,
        profile,
        emergency_closed=True,
        population_zero=True,
    )
    receipt = profile.revoke(closure)

    assert receipt["cleanup_mode"] == (
        "EMERGENCY_ZERO_POPULATION_CLEANUP"
    )
    assert receipt["completion_authority"] is False
    assert receipt["revoked"] is True
    assert not profile.root.exists()


def test_profile_revoke_deletes_secret_without_reopening_global_sources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    global_home = tmp_path / "global"
    global_home.mkdir()
    credentials = global_home / ".credentials.json"
    credentials.write_bytes(
        _valid_credential_bytes("global-original")
    )
    settings = global_home / "settings.json"
    state = tmp_path / ".claude.json"
    state.write_text('{"numStartups":4}', encoding="utf-8")
    project = tmp_path / "project"
    project.mkdir()
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    profile = C.materialize_claude_attempt_profile(
        **_profile_kwargs(
            runtime=runtime,
            project=project,
            global_home=global_home,
            state=state,
            attempt_id="attempt-drift",
        )
    )

    credentials.write_bytes(
        _valid_credential_bytes("global-mutated")
    )
    state.unlink()
    settings.write_text('{"created":"during-attempt"}', encoding="utf-8")
    closure = _closure_token(monkeypatch, profile)
    receipt = profile.revoke(closure)

    assert not profile.root.exists()
    assert receipt["revoked"] is True
    assert receipt["global_source_stable"] is None
    assert receipt["global_source_drift"] == []
    repeat = profile.revoke(closure)
    assert repeat == receipt
    assert C.replay_claude_attempt_profile_revocation(
        profile,
        repeat,
    )["valid"] is True
    serialized = json.dumps(receipt, sort_keys=True)
    assert "original" not in serialized
    assert "mutated" not in serialized
    assert str(credentials) not in serialized
    assert str(state) not in serialized
    assert str(settings) not in serialized


def test_materialization_rolls_back_after_post_credential_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    global_home = tmp_path / "global"
    global_home.mkdir()
    secret = b'{"token":"must-be-revoked"}'
    (global_home / ".credentials.json").write_bytes(secret)
    state = tmp_path / ".claude.json"
    state.write_text("{}", encoding="utf-8")
    project = tmp_path / "project"
    project.mkdir()
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    original_write = C._write_private
    writes = 0

    def fail_after_credentials(path: Path, raw: bytes) -> None:
        nonlocal writes
        writes += 1
        if writes == 2:
            raise C.ClaudeAttemptProfileError("injected settings failure")
        original_write(path, raw)

    monkeypatch.setattr(C, "_write_private", fail_after_credentials)

    kwargs = _profile_kwargs(
        runtime=runtime,
        project=project,
        global_home=global_home,
        state=state,
        attempt_id="attempt-rollback",
    )
    lease = kwargs["leased_parent"]
    capability = kwargs["stored_subscription_capability"]
    evidence = kwargs[
        "expected_stored_subscription_source_evidence"
    ]
    assert isinstance(lease, A.AuxiliaryWritableRootLease)

    with pytest.raises(C.ClaudeAttemptProfileError, match="settings failure"):
        C.materialize_claude_attempt_profile(
            **kwargs,
        )

    assert writes == 2
    assert not lease.root.exists()
    descriptor = _empty_private_target(tmp_path / "rollback-reuse")
    try:
        with pytest.raises(
            S.ClaudeStoredSubscriptionSourceError,
            match="no longer available",
        ):
            capability.consume_into_private_descriptor(
                descriptor,
                expected_source_evidence=evidence,
            )
        assert os.fstat(descriptor).st_size == 0
    finally:
        os.close(descriptor)


def test_materialization_failure_claims_before_partial_profile_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    global_home = tmp_path / "global-claim-before-rollback"
    global_home.mkdir()
    (global_home / ".credentials.json").write_bytes(
        _valid_credential_bytes("claim-before-rollback")
    )
    state = tmp_path / "state-claim-before-rollback.json"
    state.write_text("{}", encoding="utf-8")
    project = tmp_path / "project-claim-before-rollback"
    project.mkdir()
    runtime = tmp_path / "runtime-claim-before-rollback"
    runtime.mkdir()
    kwargs = _profile_kwargs(
        runtime=runtime,
        project=project,
        global_home=global_home,
        state=state,
        attempt_id="attempt-claim-before-rollback",
    )
    lease = kwargs["leased_parent"]
    assert isinstance(lease, A.AuxiliaryWritableRootLease)

    class FakeOwnedProcessScope:
        persistent_identity = kwargs["process_scope_identity"]

    monkeypatch.setattr(
        A,
        "_owned_process_scope_type",
        lambda: FakeOwnedProcessScope,
    )
    original_revoke = (
        C._owned_directory.OwnedDirectoryGuard.revoke_after_zero
    )
    bind_attempted = False

    def assert_claim_precedes_cleanup(
        self: object,
        **authority: object,
    ) -> dict[str, object]:
        nonlocal bind_attempted
        bind_attempted = True
        with pytest.raises(
            A.AuxiliaryWritableRootLeaseError,
            match="prelaunch abort.*claimed|abort claim",
        ):
            lease.bind_process_scope(FakeOwnedProcessScope())
        return original_revoke(self, **authority)

    def fail_settings_write(_path: Path, _raw: bytes) -> None:
        raise RuntimeError("fixture post-credential failure")

    monkeypatch.setattr(
        C._owned_directory.OwnedDirectoryGuard,
        "revoke_after_zero",
        assert_claim_precedes_cleanup,
    )
    monkeypatch.setattr(C, "_write_private", fail_settings_write)

    with pytest.raises(
        RuntimeError,
        match="fixture post-credential failure",
    ):
        C.materialize_claude_attempt_profile(**kwargs)

    assert bind_attempted is True
    assert lease.process_scope_bound is False
    assert not lease.root.exists()


def test_revoke_unlinks_worker_created_aliases_without_following_them(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    global_home = tmp_path / "global"
    global_home.mkdir()
    (global_home / ".credentials.json").write_bytes(
        _valid_credential_bytes("alias-ephemeral")
    )
    state = tmp_path / ".claude.json"
    state.write_text("{}", encoding="utf-8")
    project = tmp_path / "project"
    project.mkdir()
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "must-survive.txt"
    sentinel.write_text("outside-owned-runtime", encoding="utf-8")
    profile = C.materialize_claude_attempt_profile(
        **_profile_kwargs(
            runtime=runtime,
            project=project,
            global_home=global_home,
            state=state,
            attempt_id="attempt-alias",
        )
    )
    alias = profile.temp_dir / "worker-created-alias"
    try:
        alias.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlinks unavailable: {exc}")

    receipt = profile.revoke(_closure_token(monkeypatch, profile))

    assert receipt["revoked"] is True
    assert not profile.root.exists()
    assert sentinel.read_text(encoding="utf-8") == "outside-owned-runtime"


def test_quarantine_cleanup_removes_nested_happy_path(
    tmp_path: Path,
) -> None:
    root = tmp_path / "bound-root"
    nested = root / "one" / "two"
    nested.mkdir(parents=True)
    (root / "root.txt").write_text("root", encoding="utf-8")
    (nested / "nested.txt").write_text("nested", encoding="utf-8")
    expected = C._directory_identity(root)

    C._safe_remove_tree(root, expected_identity=expected)

    assert not os.path.lexists(root)
    assert not any(
        item.name.startswith(".q-")
        for item in tmp_path.iterdir()
    )


def test_quarantine_cleanup_descendant_swap_never_crosses_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "bound-root"
    child = root / "child"
    child.mkdir(parents=True)
    (child / "owned.txt").write_text("owned", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "must-survive.txt"
    victim.write_text("outside", encoding="utf-8")
    real_scandir = C.os.scandir
    injected = False

    def racing_scandir(path: object):
        nonlocal injected
        candidate = Path(path)
        if not injected and candidate.name == "child":
            injected = True
            parked = candidate.parent / "parked-child"
            candidate.rename(parked)
            try:
                os.symlink(
                    outside,
                    candidate,
                    target_is_directory=True,
                )
            except OSError as exc:
                parked.rename(candidate)
                pytest.skip(f"directory symlinks unavailable: {exc}")
        return real_scandir(path)

    monkeypatch.setattr(C.os, "scandir", racing_scandir)
    with pytest.raises(
        C.ClaudeAttemptProfileError,
        match="identity drifted",
    ):
        C._safe_remove_tree(root)

    assert victim.read_text(encoding="utf-8") == "outside"


def test_profile_revoke_removes_secret_runtime_after_proven_closure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    global_home = tmp_path / "global"
    global_home.mkdir()
    (global_home / ".credentials.json").write_bytes(
        _valid_credential_bytes("revoke-ephemeral")
    )
    state = tmp_path / ".claude.json"
    state.write_text("{}", encoding="utf-8")
    project = tmp_path / "project"
    project.mkdir()
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    profile = C.materialize_claude_attempt_profile(
        **_profile_kwargs(
            runtime=runtime,
            project=project,
            global_home=global_home,
            state=state,
            attempt_id="attempt-003",
        )
    )

    receipt = profile.revoke(_closure_token(monkeypatch, profile))

    assert receipt["revoked"] is True
    assert not profile.root.exists()
    assert "ephemeral" not in json.dumps(receipt)


def test_production_materializer_has_no_caller_supplied_runtime_path(
    tmp_path: Path,
) -> None:
    global_home = tmp_path / "global"
    global_home.mkdir()
    (global_home / ".credentials.json").write_bytes(
        _valid_credential_bytes("scope-first-second")
    )
    state = tmp_path / ".claude.json"
    state.write_text("{}", encoding="utf-8")
    project = tmp_path / "project"
    project.mkdir()
    runtime = project / "runtime"
    runtime.mkdir()

    signature = inspect.signature(C.materialize_claude_attempt_profile)
    assert "runtime_parent" not in signature.parameters
    assert "source_config_dir" not in signature.parameters
    assert "source_state_path" not in signature.parameters
    assert "leased_parent" in signature.parameters
    assert "stored_subscription_capability" in signature.parameters
    assert "credential_mode" in signature.parameters
    assert "auth_route" in signature.parameters
    assert (
        "expected_stored_subscription_source_evidence"
        in signature.parameters
    )
    kwargs = _profile_kwargs(
        runtime=runtime,
        project=project,
        global_home=global_home,
        state=state,
        attempt_id="attempt-004",
    )
    kwargs.pop("leased_parent")
    kwargs["runtime_parent"] = runtime
    with pytest.raises(TypeError, match="runtime_parent"):
        C.materialize_claude_attempt_profile(**kwargs)


def test_scope_closure_is_bound_to_exact_profile_and_scope_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    global_home = tmp_path / "global"
    global_home.mkdir()
    (global_home / ".credentials.json").write_bytes(
        _valid_credential_bytes("scope-first-second")
    )
    state = tmp_path / ".claude.json"
    state.write_text("{}", encoding="utf-8")
    project = tmp_path / "project"
    project.mkdir()
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    first = C.materialize_claude_attempt_profile(
        **_profile_kwargs(
            runtime=runtime,
            project=project,
            global_home=global_home,
            state=state,
            attempt_id="attempt-first",
        )
    )
    second = C.materialize_claude_attempt_profile(
        **_profile_kwargs(
            runtime=runtime,
            project=project,
            global_home=global_home,
            state=state,
            attempt_id="attempt-second",
        )
    )

    with pytest.raises(C.ClaudeAttemptProfileError, match="scope identity"):
        _closure_token(monkeypatch, first, identity="scope-wrong")
    first_token = _closure_token(monkeypatch, first)
    with pytest.raises(C.ClaudeAttemptProfileError, match="closure token"):
        second.revoke(first_token)
    caller_binding = first.binding
    caller_binding["process_scope_identity"] = "scope-attacker"
    caller_binding["profile_sha256"] = "0" * 64
    assert first.binding["process_scope_identity"] == "scope-attempt-first"
    assert first.binding["profile_sha256"] != "0" * 64
    assert first.root.exists()
    assert second.root.exists()


def test_directory_security_is_installed_and_verified_before_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    global_home = tmp_path / "global"
    global_home.mkdir()
    (global_home / ".credentials.json").write_text(
        '{"token":"ordering-proof"}',
        encoding="utf-8",
    )
    state = tmp_path / ".claude.json"
    state.write_text("{}", encoding="utf-8")
    project = tmp_path / "project"
    project.mkdir()
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    secured: set[Path] = set()
    original_secure = C._install_and_verify_private_directory_security
    original_write = C._write_private

    def record_secure(path: Path) -> dict[str, object]:
        evidence = original_secure(path)
        secured.add(path.resolve())
        return evidence

    def assert_secure_before_write(path: Path, raw: bytes) -> None:
        assert path.parent.resolve() in secured
        assert any(
            root in path.resolve().parents
            for root in secured
        )
        original_write(path, raw)

    monkeypatch.setattr(
        C,
        "_install_and_verify_private_directory_security",
        record_secure,
    )
    monkeypatch.setattr(C, "_write_private", assert_secure_before_write)

    profile = C.materialize_claude_attempt_profile(
        **_profile_kwargs(
            runtime=runtime,
            project=project,
            global_home=global_home,
            state=state,
            attempt_id="attempt-ordering",
        )
    )
    assert profile.binding["directory_security"]["verified_before_secret_write"]


def test_directory_security_failure_is_precredential_and_rolls_back(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    global_home = tmp_path / "global"
    global_home.mkdir()
    (global_home / ".credentials.json").write_text(
        '{"token":"never-materialized"}',
        encoding="utf-8",
    )
    state = tmp_path / ".claude.json"
    state.write_text("{}", encoding="utf-8")
    project = tmp_path / "project"
    project.mkdir()
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    original_secure = C._install_and_verify_private_directory_security
    writes: list[Path] = []

    def reject_config(path: Path) -> dict[str, object]:
        if path.name == "claude-config":
            raise C.ClaudeAttemptProfileError(
                "injected private DACL verification failure"
            )
        return original_secure(path)

    def record_write(path: Path, _raw: bytes) -> None:
        writes.append(path)

    monkeypatch.setattr(
        C,
        "_install_and_verify_private_directory_security",
        reject_config,
    )
    monkeypatch.setattr(C, "_write_private", record_write)

    kwargs = _profile_kwargs(
        runtime=runtime,
        project=project,
        global_home=global_home,
        state=state,
        attempt_id="attempt-dacl-fail",
    )
    lease = kwargs["leased_parent"]
    capability = kwargs["stored_subscription_capability"]
    evidence = kwargs[
        "expected_stored_subscription_source_evidence"
    ]
    assert isinstance(lease, A.AuxiliaryWritableRootLease)
    with pytest.raises(C.ClaudeAttemptProfileError, match="DACL"):
        C.materialize_claude_attempt_profile(
            **kwargs,
        )
    assert writes == []
    assert not lease.root.exists()
    descriptor = _empty_private_target(tmp_path / "discard-check")
    try:
        with pytest.raises(
            S.ClaudeStoredSubscriptionSourceError,
            match="no longer available",
        ):
            capability.consume_into_private_descriptor(
                descriptor,
                expected_source_evidence=evidence,
            )
    finally:
        os.close(descriptor)


def test_root_directory_security_failure_leaves_no_profile_or_secret(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    global_home = tmp_path / "global"
    global_home.mkdir()
    (global_home / ".credentials.json").write_text(
        '{"token":"never-materialized"}',
        encoding="utf-8",
    )
    state = tmp_path / ".claude.json"
    state.write_text("{}", encoding="utf-8")
    project = tmp_path / "project"
    project.mkdir()
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    writes: list[Path] = []

    def reject_root(_path: Path) -> dict[str, object]:
        raise C.ClaudeAttemptProfileError(
            "injected root DACL installation failure"
        )

    monkeypatch.setattr(
        C,
        "_install_and_verify_private_directory_security",
        reject_root,
    )
    monkeypatch.setattr(
        C,
        "_write_private",
        lambda path, _raw: writes.append(path),
    )

    kwargs = _profile_kwargs(
        runtime=runtime,
        project=project,
        global_home=global_home,
        state=state,
        attempt_id="attempt-root-dacl-fail",
    )
    lease = kwargs["leased_parent"]
    assert isinstance(lease, A.AuxiliaryWritableRootLease)
    with pytest.raises(C.ClaudeAttemptProfileError, match="root DACL"):
        C.materialize_claude_attempt_profile(
            **kwargs,
        )
    assert writes == []
    assert not lease.root.exists()


def test_directory_guard_binds_before_first_secret_materialization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    global_home = tmp_path / "global"
    global_home.mkdir()
    (global_home / ".credentials.json").write_bytes(
        _valid_credential_bytes("guard-order")
    )
    state = tmp_path / ".claude.json"
    state.write_text("{}", encoding="utf-8")
    project = tmp_path / "project"
    project.mkdir()
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    events: list[str] = []
    original_bind = C._owned_directory.bind_owned_directory
    original_open = C._open_empty_private_regular_file

    def bind_first(*args: object, **kwargs: object):
        assert events == []
        guard = original_bind(*args, **kwargs)
        events.append("GUARD_BOUND")
        return guard

    def first_secret(path: Path) -> int:
        assert events == ["GUARD_BOUND"]
        events.append("SECRET_TARGET_OPENED")
        return original_open(path)

    monkeypatch.setattr(
        C._owned_directory,
        "bind_owned_directory",
        bind_first,
    )
    monkeypatch.setattr(
        C,
        "_open_empty_private_regular_file",
        first_secret,
    )
    profile = C.materialize_claude_attempt_profile(
        **_profile_kwargs(
            runtime=runtime,
            project=project,
            global_home=global_home,
            state=state,
            attempt_id="attempt-guard-before-secret",
        )
    )

    assert events == ["GUARD_BOUND", "SECRET_TARGET_OPENED"]
    assert profile.binding["directory_guard"][
        "subject_binding_sha256"
    ] == profile.binding[
        "directory_guard_subject_binding_sha256"
    ]
    receipt = profile.revoke(
        _closure_token(monkeypatch, profile)
    )
    assert receipt["directory_guard_terminal_ledger_head_sha256"]


def test_materialization_failure_guard_ledger_is_terminal_before_outer_abort(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    global_home = tmp_path / "global"
    global_home.mkdir()
    (global_home / ".credentials.json").write_bytes(
        _valid_credential_bytes("guard-rollback")
    )
    state = tmp_path / ".claude.json"
    state.write_text("{}", encoding="utf-8")
    project = tmp_path / "project"
    project.mkdir()
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    observed: list[C._owned_directory.OwnedDirectoryGuard] = []
    original_bind = C._owned_directory.bind_owned_directory

    def capture_guard(*args: object, **kwargs: object):
        guard = original_bind(*args, **kwargs)
        observed.append(guard)
        return guard

    monkeypatch.setattr(
        C._owned_directory,
        "bind_owned_directory",
        capture_guard,
    )
    monkeypatch.setattr(
        C,
        "_write_private",
        lambda _path, _raw: (_ for _ in ()).throw(
            C.ClaudeAttemptProfileError(
                "injected post-secret materialization failure"
            )
        ),
    )
    kwargs = _profile_kwargs(
        runtime=runtime,
        project=project,
        global_home=global_home,
        state=state,
        attempt_id="attempt-guard-rollback",
    )
    lease = kwargs["leased_parent"]

    with pytest.raises(
        C.ClaudeAttemptProfileError,
        match="injected post-secret materialization failure",
    ):
        C.materialize_claude_attempt_profile(**kwargs)

    assert len(observed) == 1
    replay = (
        C._owned_directory.replay_owned_directory_cleanup_ledger(
            observed[0].ledger_path,
            expected_subject_binding_sha256=observed[0].binding[
                "subject_binding_sha256"
            ],
        )
    )
    assert replay["terminal"] is True
    assert replay["records"][-1]["completion_authority"] is False
    assert not os.path.lexists(lease.root)


@pytest.mark.skipif(os.name != "nt", reason="Windows DACL replay fixture")
def test_windows_profile_directories_have_mechanically_replayed_private_dacl(
    tmp_path: Path,
) -> None:
    global_home = tmp_path / "global"
    global_home.mkdir()
    (global_home / ".credentials.json").write_text("{}", encoding="utf-8")
    state = tmp_path / ".claude.json"
    state.write_text("{}", encoding="utf-8")
    project = tmp_path / "project"
    project.mkdir()
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    profile = C.materialize_claude_attempt_profile(
        **_profile_kwargs(
            runtime=runtime,
            project=project,
            global_home=global_home,
            state=state,
            attempt_id="attempt-windows-dacl",
        )
    )

    for path in (profile.root, profile.config_dir, profile.home_dir):
        evidence = C._verify_windows_private_directory_dacl(path)
        assert evidence["dacl_protected"] is True
        assert evidence["ace_count"] == 1
        assert evidence["principal"] == "CURRENT_PROCESS_TOKEN_USER"


@pytest.mark.skipif(
    os.name != "nt",
    reason="Windows exact-file provider state authority fixture",
)
def test_windows_provider_mutable_state_authority_is_exact_and_replayed(
    tmp_path: Path,
) -> None:
    profile, _kwargs, _secret = _materialized_fixture(
        tmp_path,
        attempt_id="attempt-windows-state-authority",
        secret=_valid_credential_bytes("windows-state-authority"),
    )

    authority = profile.binding["provider_mutable_state_security"]
    assert authority["schema"] == (
        "plamen.claude_provider_mutable_state_security.v1"
    )
    assert authority["platform"] == "WINDOWS_LOW_INTEGRITY_EXACT_FILE"
    assert authority["mutable_relative_paths"] == [".claude.json"]
    assert authority["read_policy"] == "READ_IS_PROVIDER_INPUT_AUTHORITY"
    assert authority["existing_file_truncate_write"] is True
    assert authority["create_entries"] is False
    assert authority["delete_entries"] is False
    assert authority["rename_entries"] is False
    assert authority["directory_mutation"] is False
    assert authority["credential_write"] is False
    assert authority["settings_write"] is False
    assert authority["lifecycle_ledger_write"] is False
    assert authority["retained_no_delete_handle"] is True
    assert authority["handle_noninheritable"] is True
    assert authority["completion_authority"] is False
    assert authority["mandatory_label"] == {
        "ace_count": 1,
        "ace_flags": 0,
        "ace_type": "SYSTEM_MANDATORY_LABEL",
        "inheritance": "NONE",
        "integrity_sid": "S-1-16-4096",
        "policy": "NO_WRITE_UP",
        "policy_mask": 1,
    }
    replay = C.replay_claude_attempt_profile_binding(
        profile,
        profile.binding,
    )
    assert replay["valid"] is True

    receipt = profile.abort_before_process_scope(
        attempt_arm_sha256=str(
            profile.binding["outer_attempt_arm_sha256"]
        ),
        process_scope_identity=str(
            profile.binding["process_scope_identity"]
        ),
        reason_code="WINDOWS_STATE_AUTHORITY_FIXTURE_DONE",
    )
    assert receipt["revoked"] is True


@pytest.mark.skipif(
    os.name != "nt",
    reason="Windows Low-Integrity child-token state contract fixture",
)
def test_windows_low_integrity_child_can_mutate_only_existing_state_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from owned_process_scope import OwnedProcessScope
    import windows_low_integrity_lease as W

    low_integrity_lease = tmp_path / "low-integrity-lease"
    monkeypatch.setenv(W.LEASE_TEST_OVERRIDE_ENV, "1")
    monkeypatch.setenv(
        W.LEASE_DIRECTORY_ENV,
        str(low_integrity_lease),
    )
    profile, _kwargs, _secret = _materialized_fixture(
        tmp_path,
        attempt_id="attempt-windows-low-state-contract",
        secret=_valid_credential_bytes("windows-low-state-contract"),
    )
    result_root = tmp_path / "low-child-result"
    result_root.mkdir()
    result_path = result_root / "result.json"
    credential_path = profile.config_dir / ".credentials.json"
    settings_path = profile.config_dir / "settings.json"
    forbidden_sibling = profile.config_dir / "forbidden-sibling"
    forbidden_directory = profile.config_dir / "forbidden-directory"
    renamed_state = profile.config_dir / "renamed-state.json"
    forbidden_parent = profile.root.parent / "forbidden-parent-sibling"
    lifecycle_ledger = profile._directory_guard.ledger_path

    child_source = "\n".join(
        [
            "import json, os",
            "from pathlib import Path",
            f"state_path = Path({str(profile.state_path)!r})",
            f"credential_path = Path({str(credential_path)!r})",
            f"settings_path = Path({str(settings_path)!r})",
            f"forbidden_sibling = Path({str(forbidden_sibling)!r})",
            f"forbidden_directory = Path({str(forbidden_directory)!r})",
            f"renamed_state = Path({str(renamed_state)!r})",
            f"forbidden_parent = Path({str(forbidden_parent)!r})",
            f"lifecycle_ledger = Path({str(lifecycle_ledger)!r})",
            f"result_path = Path({str(result_path)!r})",
            "result = {}",
            "result['credential_read'] = bool("
            "credential_path.read_bytes())",
            "result['settings_read'] = bool(settings_path.read_bytes())",
            "state = json.loads(state_path.read_text(encoding='utf-8'))",
            "state['numStartups'] = 2",
            "with state_path.open('r+', encoding='utf-8') as handle:",
            "    handle.seek(0)",
            "    handle.write(json.dumps(state, sort_keys=True, "
            "separators=(',', ':')))",
            "    handle.truncate()",
            "result['state_truncate_write'] = True",
            "def denied(name, operation):",
            "    try:",
            "        operation()",
            "    except (OSError, PermissionError):",
            "        result[name] = True",
            "    else:",
            "        result[name] = False",
            "denied('credential_write_denied', lambda: "
            "credential_path.open('ab').write(b'x'))",
            "denied('settings_write_denied', lambda: "
            "settings_path.open('ab').write(b'x'))",
            "denied('sibling_create_denied', lambda: "
            "forbidden_sibling.write_bytes(b'x'))",
            "denied('directory_create_denied', "
            "lambda: forbidden_directory.mkdir())",
            "denied('state_rename_denied', lambda: "
            "os.replace(state_path, renamed_state))",
            "denied('state_delete_denied', lambda: state_path.unlink())",
            "denied('parent_sibling_create_denied', lambda: "
            "forbidden_parent.write_bytes(b'x'))",
            "denied('lifecycle_ledger_write_denied', lambda: "
            "lifecycle_ledger.open('ab').write(b'x'))",
            "result_path.write_text(json.dumps(result, sort_keys=True), "
            "encoding='utf-8')",
        ]
    )
    scope = OwnedProcessScope(
        writable_roots=(result_root,),
        persistent_identity=str(
            profile.binding["process_scope_identity"]
        ),
    )
    profile._leased_parent.bind_process_scope(scope)
    process = scope.create_process(
        scope.wrap_argv(
            (sys.executable, "-I", "-S", "-c", child_source)
        ),
        popen_factory=None,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        close_fds=False,
        **scope.popen_kwargs(),
    )
    try:
        scope.attach(process)
        stdout, stderr = process.communicate(timeout=20)
        assert process.returncode == 0, (
            stdout.decode("utf-8", errors="replace"),
            stderr.decode("utf-8", errors="replace"),
        )
        scope.terminate()
        scope.close()
    finally:
        if not scope.closed:
            try:
                scope.terminate()
            except Exception:
                pass
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            try:
                scope.close()
            except Exception:
                pass

    result = json.loads(result_path.read_text(encoding="utf-8"))
    assert result == {
        "credential_read": True,
        "credential_write_denied": True,
        "directory_create_denied": True,
        "lifecycle_ledger_write_denied": True,
        "parent_sibling_create_denied": True,
        "settings_read": True,
        "settings_write_denied": True,
        "sibling_create_denied": True,
        "state_delete_denied": True,
        "state_rename_denied": True,
        "state_truncate_write": True,
    }
    assert profile.state_path.exists()
    assert not forbidden_sibling.exists()
    assert not forbidden_directory.exists()
    assert not renamed_state.exists()
    assert not forbidden_parent.exists()

    postprocess = C.mint_claude_fresh_postprocess_authority(
        profile,
        scope,
    )
    closure = C.prove_claude_profile_scope_closed(
        profile,
        scope,
        postprocess_authority=postprocess,
    )
    profile_receipt = profile.revoke(closure)
    assert profile_receipt["revoked"] is True
    auxiliary_closure = A.prove_owned_process_scope_closed(
        profile._leased_parent,
        scope,
    )
    auxiliary_receipt = profile._leased_parent.revoke(
        auxiliary_closure
    )
    assert auxiliary_receipt["revoked"] is True


@pytest.mark.skipif(os.name != "nt", reason="Windows DACL replay fixture")
def test_windows_default_inherited_directory_dacl_is_not_accepted_as_private(
    tmp_path: Path,
) -> None:
    inherited = tmp_path / "inherits-parent-dacl"
    inherited.mkdir()
    with pytest.raises(
        C.ClaudeAttemptProfileError,
        match="not protected|unexpected principals",
    ):
        C._verify_windows_private_directory_dacl(inherited)


def _normal_failure_profile_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    attempt_id: str,
    closed: bool = True,
    population_zero: bool = True,
    emergency: bool = False,
    attached: bool = True,
) -> tuple[C.ClaudeAttemptProfile, object]:
    root = tmp_path / f"profile-{attempt_id}"
    config = root / "config"
    home = root / "home"
    temp = root / "tmp"
    for path in (config, home, temp):
        path.mkdir(parents=True, exist_ok=True)
    state = config / ".claude.json"
    state.write_text("{}", encoding="utf-8")

    scope_identity = f"scope-{attempt_id}"

    class FakeOwnedProcessScope:
        pass

    FakeOwnedProcessScope.persistent_identity = scope_identity
    FakeOwnedProcessScope.process_creation_state = (
        "ATTACHED" if attached else "NOT_ATTEMPTED"
    )
    FakeOwnedProcessScope.process_creation_evidence = {
        "state": FakeOwnedProcessScope.process_creation_state,
        "creation_attempted": attached,
        "process_object_returned": attached,
        "attached": attached,
        "created_process_termination_proven": False,
    }
    FakeOwnedProcessScope.closed = closed
    FakeOwnedProcessScope.population_zero_proven = population_zero
    FakeOwnedProcessScope.emergency_closed = emergency
    FakeOwnedProcessScope.attached = attached

    class FakeBoundLease:
        process_scope_bound = True

    monkeypatch.setattr(
        C,
        "_owned_process_scope_type",
        lambda: FakeOwnedProcessScope,
    )
    binding = {
        "profile_sha256": _digest(f"profile:{attempt_id}"),
        "attempt_id": attempt_id,
        "process_scope_identity": scope_identity,
        "auxiliary_lease_binding_sha256": _digest(
            f"lease:{attempt_id}"
        ),
        "private_root": {
            "profile_root_identity": C._directory_identity(root),
        },
    }
    guard_subject_sha256 = _digest(f"guard:{attempt_id}")
    directory_guard = C._owned_directory.bind_owned_directory(
        root,
        subject_binding_sha256=guard_subject_sha256,
        ledger_directory=tmp_path / "profile-lifecycle-v1",
    )
    binding["directory_guard_subject_binding_sha256"] = (
        guard_subject_sha256
    )
    binding["directory_guard"] = directory_guard.binding
    provider_mutable_state_authority = (
        C._ClaudeProviderMutableStateAuthority.acquire(state)
    )
    binding["provider_mutable_state_security"] = (
        provider_mutable_state_authority.binding
    )
    profile = C.ClaudeAttemptProfile(
        root=root,
        config_dir=config,
        home_dir=home,
        state_path=state,
        temp_dir=temp,
        environment={},
        _binding=binding,
        _leased_parent=FakeBoundLease(),
        _directory_guard=directory_guard,
        _provider_mutable_state_authority=(
            provider_mutable_state_authority
        ),
        _private_credential_file_identity={},
        _private_credential_integrity_key=bytearray(b"k" * 32),
        _private_credential_integrity_tag=bytearray(b"t" * 32),
    )
    return profile, FakeOwnedProcessScope()


def test_normal_scope_failure_authority_is_opaque_one_shot_and_noncompletion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile, scope = _normal_failure_profile_fixture(
        tmp_path,
        monkeypatch,
        attempt_id="failure-opaque",
    )
    failure_sha256 = _digest("primary-provider-nonzero-exit")

    token = C.prove_claude_normal_scope_failure_closed(
        profile,
        scope,
        primary_failure_evidence_sha256=failure_sha256,
    )

    assert type(token) is C.ClaudeNormalScopeFailureClosureToken
    assert failure_sha256 not in repr(token)
    with pytest.raises(TypeError, match="opaque"):
        C.ClaudeNormalScopeFailureClosureToken(
            _capability=object(),
            profile_sha256="a" * 64,
            scope_identity="forged",
            evidence_sha256="b" * 64,
            primary_failure_evidence_sha256="c" * 64,
            generation=1,
            nonce=object(),
        )

    receipt = profile.revoke_normal_scope_failure(token)
    assert receipt["cleanup_mode"] == "NORMAL_SCOPE_FAILURE_CLEANUP"
    assert receipt["primary_failure_evidence_sha256"] == failure_sha256
    assert receipt["completion_authority"] is False
    assert receipt["completion_capable"] is False
    assert receipt["emergency_zero_population"] is False
    assert not profile.root.exists()
    assert C.replay_claude_attempt_profile_revocation(
        profile,
        receipt,
    )["completion_authority"] is False

    with pytest.raises(
        C.ClaudeAttemptProfileError,
        match="consumed|already revoked|one-shot",
    ):
        profile.revoke_normal_scope_failure(token)


@pytest.mark.parametrize(
    ("closed", "population_zero", "emergency", "attached"),
    (
        (False, False, False, True),
        (True, False, False, True),
        (True, True, True, True),
        (True, True, False, False),
    ),
)
def test_normal_scope_failure_authority_requires_attached_ordinary_exact_zero(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    closed: bool,
    population_zero: bool,
    emergency: bool,
    attached: bool,
) -> None:
    profile, scope = _normal_failure_profile_fixture(
        tmp_path,
        monkeypatch,
        attempt_id=(
            f"failure-shape-{int(closed)}-{int(population_zero)}-"
            f"{int(emergency)}-{int(attached)}"
        ),
        closed=closed,
        population_zero=population_zero,
        emergency=emergency,
        attached=attached,
    )
    with pytest.raises(
        C.ClaudeAttemptProfileError,
        match="failure cleanup|ordinary|zero|ATTACHED",
    ):
        C.prove_claude_normal_scope_failure_closed(
            profile,
            scope,
            primary_failure_evidence_sha256="a" * 64,
        )
    assert profile.root.exists()


@pytest.mark.parametrize(
    "failure_sha256",
    ("", "A" * 64, "0" * 63, None, True),
)
def test_normal_scope_failure_authority_rejects_ambiguous_failure_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_sha256: object,
) -> None:
    profile, scope = _normal_failure_profile_fixture(
        tmp_path,
        monkeypatch,
        attempt_id=f"failure-evidence-{type(failure_sha256).__name__}",
    )
    with pytest.raises(
        C.ClaudeAttemptProfileError,
        match="primary failure evidence",
    ):
        C.prove_claude_normal_scope_failure_closed(
            profile,
            scope,
            primary_failure_evidence_sha256=failure_sha256,
        )
    assert profile.root.exists()


def test_normal_scope_failure_authority_rejects_stale_or_cross_profile_token(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first, first_scope = _normal_failure_profile_fixture(
        tmp_path,
        monkeypatch,
        attempt_id="failure-first",
    )
    # Both scopes intentionally share the same trusted fixture type. The
    # profile and persistent identities still differ and remain authoritative.
    trusted_type = C._owned_process_scope_type()
    second_parent = tmp_path / "second-parent"
    second_parent.mkdir()
    second, _second_scope = _normal_failure_profile_fixture(
        second_parent,
        monkeypatch,
        attempt_id="failure-second",
    )
    monkeypatch.setattr(C, "_owned_process_scope_type", lambda: trusted_type)
    token = C.prove_claude_normal_scope_failure_closed(
        first,
        first_scope,
        primary_failure_evidence_sha256="b" * 64,
    )
    with pytest.raises(C.ClaudeAttemptProfileError, match="invalid"):
        second.revoke_normal_scope_failure(token)

    replacement = C.prove_claude_normal_scope_failure_closed(
        first,
        first_scope,
        primary_failure_evidence_sha256="c" * 64,
    )
    with pytest.raises(
        C.ClaudeAttemptProfileError,
        match="stale|one-shot|invalid",
    ):
        first.revoke_normal_scope_failure(token)
    assert first.revoke_normal_scope_failure(replacement)[
        "completion_capable"
    ] is False
