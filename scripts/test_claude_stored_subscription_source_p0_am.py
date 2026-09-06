from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import pickle
import subprocess
import time

import pytest

import claude_auth_route as A
import claude_stored_subscription_source as S


def _credential_document(secret: str = "credential-value-never-record") -> bytes:
    return json.dumps(
        {
            "claudeAiOauth": {
                "accessToken": secret,
                "refreshToken": f"{secret}-refresh",
                "expiresAt": 4_102_444_800_000,
                "scopes": ["user:inference", "user:profile"],
            }
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _write_credentials(
    path: Path,
    secret: str = "credential-value-never-record",
) -> bytes:
    raw = _credential_document(secret)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    try:
        path.chmod(0o600)
    except OSError:
        pass
    _install_windows_private_acl(path)
    return raw


def _run_icacls(*arguments: str) -> None:
    completed = subprocess.run(
        ["icacls", *arguments],
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
        raise AssertionError(
            f"icacls fixture setup failed with {completed.returncode}"
        )


def _install_windows_private_acl(path: Path) -> None:
    if os.name != "nt":
        return
    sid = S._current_windows_user_sid_string()
    _run_icacls(
        str(path.parent),
        "/inheritance:r",
        "/grant:r",
        f"*{sid}:(OI)(CI)(F)",
    )
    _run_icacls(
        str(path),
        "/inheritance:r",
        "/grant:r",
        f"*{sid}:(F)",
    )


def _receipt_digest(core: dict[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(
            core,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _force_host(monkeypatch: pytest.MonkeyPatch, host: str) -> None:
    monkeypatch.setattr(S, "_detect_host_platform", lambda: host)
    if host in {S.HOST_LINUX_NATIVE, S.HOST_WSL_NATIVE} and os.name == "nt":
        monkeypatch.setattr(
            S,
            "_validate_posix_source_security",
            lambda _path, _info: None,
        )


def test_windows_native_file_store_emits_exact_redacted_replayable_schema(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_host(monkeypatch, S.HOST_WINDOWS_NATIVE)
    source = tmp_path / ".claude" / ".credentials.json"
    secret = "windows-subscription-secret-unique"
    raw = _write_credentials(source, secret)

    evidence = S.observe_stored_subscription_source(source_path=source)

    assert set(evidence) == {
        "schema",
        "store_class",
        "source_identity",
        "source_size",
        "available",
        "observation_authority_sha256",
        "credential_values_recorded",
        "credential_content_hashes_recorded",
        "receipt_sha256",
    }
    assert evidence["schema"] == A.STORED_SUBSCRIPTION_SOURCE_SCHEMA
    assert evidence["store_class"] == "FILE_BACKED"
    assert evidence["available"] is True
    assert evidence["source_size"] == len(raw)
    assert evidence["credential_values_recorded"] is False
    assert evidence["credential_content_hashes_recorded"] is False
    assert A.replay_stored_subscription_source_evidence(evidence) == evidence
    assert S.replay_stored_subscription_source_observation(evidence) == evidence
    with pytest.raises(A.ClaudeAuthRouteError, match="promoted neutral"):
        A.observe_claude_auth_sources(
            {},
            settings={},
            settings_authority_sha256=None,
            stored_subscription_evidence=evidence,
        )
    capability = S.acquire_stored_subscription_materialization(
        source_path=source,
    )
    source_observation = A.observe_claude_auth_sources(
        {},
        settings={},
        settings_authority_sha256=None,
        stored_subscription_evidence=capability.source_evidence,
    )
    route = A.classify_claude_auth_route(
        {},
        source_observation=source_observation,
    )
    assert route["selected_route"] == "STORED_SUBSCRIPTION_OAUTH"
    capability.discard()

    serialized = json.dumps(evidence, sort_keys=True)
    assert secret not in serialized
    assert hashlib.sha256(secret.encode("utf-8")).hexdigest() not in serialized
    assert hashlib.sha256(raw).hexdigest() not in serialized
    assert str(source) not in serialized
    assert "S-1-" not in serialized


def test_live_observation_authority_is_one_shot_and_not_recreated_by_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_host(monkeypatch, S.HOST_WINDOWS_NATIVE)
    source = tmp_path / ".claude" / ".credentials.json"
    _write_credentials(source)

    authority = S.observe_stored_subscription_source_authority(
        source_path=source
    )
    durable = S.replay_stored_subscription_source_observation(authority)
    assert type(authority) is A.PromotedStoredSubscriptionSourceEvidence
    assert type(durable) is dict

    observed = A.observe_claude_auth_sources(
        {},
        settings={},
        settings_authority_sha256=None,
        stored_subscription_evidence=authority,
    )
    assert A.classify_claude_auth_route(
        {},
        source_observation=observed,
    )["selected_route"] == "STORED_SUBSCRIPTION_OAUTH"
    with pytest.raises(A.ClaudeAuthRouteError, match="consumed|stale"):
        A.observe_claude_auth_sources(
            {},
            settings={},
            settings_authority_sha256=None,
            stored_subscription_evidence=authority,
        )
    with pytest.raises(A.ClaudeAuthRouteError, match="promoted neutral"):
        A.observe_claude_auth_sources(
            {},
            settings={},
            settings_authority_sha256=None,
            stored_subscription_evidence=durable,
        )


def test_linux_file_profile_uses_same_exact_redacted_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_host(monkeypatch, S.HOST_LINUX_NATIVE)
    source = tmp_path / ".claude" / ".credentials.json"
    _write_credentials(source)

    evidence = S.observe_stored_subscription_source(source_path=source)

    assert evidence["store_class"] == "FILE_BACKED"
    assert evidence["available"] is True
    assert evidence["source_identity"].startswith("file-linux-")
    assert S.reconcile_stored_subscription_source_observation(
        evidence,
        source_path=source,
    ) == evidence


def test_missing_file_is_honestly_unavailable_and_replays(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_host(monkeypatch, S.HOST_WINDOWS_NATIVE)
    source = tmp_path / ".claude" / ".credentials.json"

    evidence = S.observe_stored_subscription_source(source_path=source)

    assert evidence["store_class"] == "FILE_BACKED"
    assert evidence["available"] is False
    assert evidence["source_size"] == 0
    assert "missing" in evidence["source_identity"]
    assert A.replay_stored_subscription_source_evidence(evidence) == evidence


def test_unconfigured_file_source_is_honestly_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_host(monkeypatch, S.HOST_LINUX_NATIVE)

    evidence = S.observe_stored_subscription_source(source_path=None)

    assert evidence["store_class"] == "FILE_BACKED"
    assert evidence["available"] is False
    assert evidence["source_identity"] == "file-linux-path-unconfigured"


def test_macos_keychain_is_explicitly_unimplemented_and_never_fake_available(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_host(monkeypatch, S.HOST_MACOS)
    evidence = S.observe_stored_subscription_source(source_path=None)
    assert evidence["store_class"] == "OS_KEYCHAIN"
    assert evidence["source_identity"] == "macos-keychain-unimplemented"
    assert evidence["available"] is False
    assert evidence["source_size"] == 0
    assert A.replay_stored_subscription_source_evidence(evidence) == evidence

    fake_file = tmp_path / ".credentials.json"
    _write_credentials(fake_file)
    with pytest.raises(
        S.ClaudeStoredSubscriptionSourceError,
        match="keychain.*unimplemented",
    ):
        S.observe_stored_subscription_source(source_path=fake_file)


def test_unsupported_host_fails_closed_without_inventing_store_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_host(monkeypatch, S.HOST_UNSUPPORTED)
    with pytest.raises(
        S.ClaudeStoredSubscriptionSourceError,
        match="unsupported host",
    ):
        S.observe_stored_subscription_source(source_path=None)


def test_wrong_file_name_and_noncanonical_path_are_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_host(monkeypatch, S.HOST_WINDOWS_NATIVE)
    wrong = tmp_path / ".claude" / "credentials.json"
    _write_credentials(wrong)
    with pytest.raises(
        S.ClaudeStoredSubscriptionSourceError,
        match=r"\.credentials\.json",
    ):
        S.observe_stored_subscription_source(source_path=wrong)

    canonical = tmp_path / ".claude" / ".credentials.json"
    _write_credentials(canonical)
    aliased = str(canonical.parent / "." / canonical.name)
    if os.path.normpath(aliased) != aliased:
        with pytest.raises(
            S.ClaudeStoredSubscriptionSourceError,
            match="canonical path spelling",
        ):
            S.observe_stored_subscription_source(source_path=aliased)


def test_symlink_or_reparse_alias_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_host(monkeypatch, S.HOST_WINDOWS_NATIVE)
    target = tmp_path / "real" / ".credentials.json"
    _write_credentials(target)
    link_parent = tmp_path / ".claude"
    link_parent.mkdir()
    link = link_parent / ".credentials.json"
    try:
        link.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"host cannot create a file symlink: {exc}")

    with pytest.raises(
        S.ClaudeStoredSubscriptionSourceError,
        match="symlink/reparse",
    ):
        S.observe_stored_subscription_source(source_path=link)


def test_hardlink_alias_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_host(monkeypatch, S.HOST_WINDOWS_NATIVE)
    source = tmp_path / ".claude" / ".credentials.json"
    _write_credentials(source)
    alias = tmp_path / "hardlink-copy"
    try:
        os.link(source, alias)
    except OSError as exc:
        pytest.skip(f"host cannot create a hardlink: {exc}")

    with pytest.raises(
        S.ClaudeStoredSubscriptionSourceError,
        match="hardlink",
    ):
        S.observe_stored_subscription_source(source_path=source)


@pytest.mark.skipif(os.name != "nt", reason="Windows DACL fixture")
def test_windows_file_dacl_with_untrusted_reader_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_host(monkeypatch, S.HOST_WINDOWS_NATIVE)
    source = tmp_path / ".claude" / ".credentials.json"
    _write_credentials(source)
    _run_icacls(str(source), "/grant", "*S-1-1-0:(R)")

    with pytest.raises(
        S.ClaudeStoredSubscriptionSourceError,
        match="DACL.*untrusted principal",
    ) as raised:
        S.observe_stored_subscription_source(source_path=source)
    assert "S-1-" not in str(raised.value)


@pytest.mark.skipif(os.name != "nt", reason="Windows DACL fixture")
def test_windows_parent_dacl_with_untrusted_writer_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_host(monkeypatch, S.HOST_WINDOWS_NATIVE)
    source = tmp_path / ".claude" / ".credentials.json"
    _write_credentials(source)
    _run_icacls(
        str(source.parent),
        "/grant",
        "*S-1-1-0:(OI)(CI)(M)",
    )

    with pytest.raises(
        S.ClaudeStoredSubscriptionSourceError,
        match="ancestor DACL.*untrusted principal",
    ) as raised:
        S.observe_stored_subscription_source(source_path=source)
    assert "S-1-" not in str(raised.value)


def test_windows_dacl_observation_failure_cannot_claim_availability(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_host(monkeypatch, S.HOST_WINDOWS_NATIVE)
    source = tmp_path / ".claude" / ".credentials.json"
    _write_credentials(source)

    def unavailable(_path: Path) -> None:
        raise S.ClaudeStoredSubscriptionSourceError(
            "Windows DACL authority unavailable"
        )

    monkeypatch.setattr(S, "_verify_windows_source_security", unavailable)
    with pytest.raises(
        S.ClaudeStoredSubscriptionSourceError,
        match="DACL authority unavailable",
    ):
        S.observe_stored_subscription_source(source_path=source)


@pytest.mark.skipif(os.name != "nt", reason="Windows DACL fixture")
def test_windows_source_owner_must_equal_current_token_user(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_host(monkeypatch, S.HOST_WINDOWS_NATIVE)
    source = tmp_path / ".claude" / ".credentials.json"
    _write_credentials(source)
    monkeypatch.setattr(
        S,
        "_current_windows_user_sid_string",
        lambda: "S-1-5-21-1-2-3-999999",
    )

    with pytest.raises(
        S.ClaudeStoredSubscriptionSourceError,
        match="owner is not the current Windows token user",
    ):
        S.observe_stored_subscription_source(source_path=source)


def test_windows_dacl_mutation_between_replays_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / ".credentials.json"
    calls = 0

    def changing_snapshot(
        _path: Path,
        *,
        label: str,
    ) -> tuple[str, tuple[tuple[int, int, int, str], ...]]:
        nonlocal calls
        calls += 1
        return (
            "S-1-5-21-current",
            ((0, 0, calls, label),),
        )

    monkeypatch.setattr(
        S,
        "_windows_private_acl_snapshot",
        changing_snapshot,
    )
    with pytest.raises(
        S.ClaudeStoredSubscriptionSourceError,
        match="DACL changed during observation",
    ):
        S._verify_windows_source_security(source)


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"not-json",
        b"{}",
        b'{"claudeAiOauth":{}}',
        b'{"claudeAiOauth":{"accessToken":"x","refreshToken":"y"}}',
        (
            b'{"claudeAiOauth":{"accessToken":"x","accessToken":"y",'
            b'"refreshToken":"z","expiresAt":1}}'
        ),
    ],
)
def test_unsupported_or_ambiguous_file_store_shape_fails_closed_without_echo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    raw: bytes,
) -> None:
    _force_host(monkeypatch, S.HOST_WINDOWS_NATIVE)
    source = tmp_path / ".claude" / ".credentials.json"
    source.parent.mkdir(parents=True)
    source.write_bytes(raw)
    _install_windows_private_acl(source)

    with pytest.raises(
        S.ClaudeStoredSubscriptionSourceError,
        match="unsupported credential-store format",
    ) as raised:
        S.observe_stored_subscription_source(source_path=source)
    decoded = raw.decode("utf-8", errors="ignore")
    if decoded:
        assert decoded not in str(raised.value)


@pytest.mark.parametrize(
    "oauth_patch",
    [
        {"accessToken": ""},
        {"refreshToken": ""},
        {"accessToken": None},
        {"refreshToken": None},
        {"expiresAt": None},
        {"expiresAt": 0},
        {"scopes": [""]},
    ],
)
def test_empty_or_incomplete_oauth_slots_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    oauth_patch: dict[str, object],
) -> None:
    _force_host(monkeypatch, S.HOST_WINDOWS_NATIVE)
    document = json.loads(_credential_document().decode("utf-8"))
    document["claudeAiOauth"].update(oauth_patch)
    source = tmp_path / ".claude" / ".credentials.json"
    source.parent.mkdir(parents=True)
    source.write_text(
        json.dumps(document, separators=(",", ":")),
        encoding="utf-8",
    )
    _install_windows_private_acl(source)

    with pytest.raises(
        S.ClaudeStoredSubscriptionSourceError,
        match="unsupported credential-store format",
    ):
        S.observe_stored_subscription_source(source_path=source)


def test_expired_access_slot_with_refresh_token_remains_refresh_capable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Access-token expiry is not refresh-token expiry or route absence."""

    _force_host(monkeypatch, S.HOST_WINDOWS_NATIVE)
    document = json.loads(_credential_document().decode("utf-8"))
    document["claudeAiOauth"]["expiresAt"] = int(time.time() * 1000) - 1
    source = tmp_path / ".claude" / ".credentials.json"
    source.parent.mkdir(parents=True)
    source.write_text(
        json.dumps(document, separators=(",", ":")),
        encoding="utf-8",
    )
    _install_windows_private_acl(source)

    evidence = S.observe_stored_subscription_source(source_path=source)
    assert evidence["available"] is True
    assert evidence["credential_values_recorded"] is False


def test_source_mutation_invalidates_reconciliation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_host(monkeypatch, S.HOST_WINDOWS_NATIVE)
    source = tmp_path / ".claude" / ".credentials.json"
    _write_credentials(source, "before-secret")
    evidence = S.observe_stored_subscription_source(source_path=source)

    _write_credentials(source, "after-secret-with-a-different-size")

    with pytest.raises(
        S.ClaudeStoredSubscriptionSourceError,
        match="source observation drifted",
    ):
        S.reconcile_stored_subscription_source_observation(
            evidence,
            source_path=source,
        )


def test_in_observation_same_size_mutation_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_host(monkeypatch, S.HOST_WINDOWS_NATIVE)
    source = tmp_path / ".claude" / ".credentials.json"
    first = _credential_document("credential-value-a")
    second = _credential_document("credential-value-b")
    assert len(first) == len(second)
    source.parent.mkdir(parents=True)
    source.write_bytes(first)
    _install_windows_private_acl(source)

    original_read = S._read_descriptor_bounded
    credential_reads = 0

    def racing_read(
        descriptor: int,
        *,
        ceiling: int,
        label: str,
    ) -> bytes:
        nonlocal credential_reads
        raw = original_read(
            descriptor,
            ceiling=ceiling,
            label=label,
        )
        if label == "stored subscription credential source":
            credential_reads += 1
            if credential_reads == 1:
                source.write_bytes(second)
        return raw

    monkeypatch.setattr(S, "_read_descriptor_bounded", racing_read)
    with pytest.raises(
        S.ClaudeStoredSubscriptionSourceError,
        match="changed or drifted",
    ):
        S.observe_stored_subscription_source(source_path=source)


def test_observation_authority_and_receipt_mutation_fail_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_host(monkeypatch, S.HOST_WINDOWS_NATIVE)
    source = tmp_path / ".claude" / ".credentials.json"
    _write_credentials(source)
    evidence = S.observe_stored_subscription_source(source_path=source)

    mutated = dict(evidence)
    mutated["observation_authority_sha256"] = "0" * 64
    core = dict(mutated)
    core.pop("receipt_sha256")
    mutated["receipt_sha256"] = _receipt_digest(core)
    assert A.replay_stored_subscription_source_evidence(mutated) == mutated
    with pytest.raises(
        S.ClaudeStoredSubscriptionSourceError,
        match="implementation authority",
    ):
        S.replay_stored_subscription_source_observation(mutated)

    malformed = dict(evidence)
    malformed["available"] = False
    with pytest.raises(A.ClaudeAuthRouteError):
        A.replay_stored_subscription_source_evidence(malformed)


def test_wsl_native_root_policy_accepts_native_linux_and_rejects_drvfs() -> None:
    native_mountinfo = (
        "36 25 0:32 / / rw,relatime - ext4 /dev/sdc rw\n"
        "48 36 0:49 / /mnt/c rw - 9p drvfs rw\n"
    )
    assert S.wsl_path_has_native_linux_semantics(
        "/home/a/.claude/.credentials.json",
        mountinfo_text=native_mountinfo,
    )
    assert not S.wsl_path_has_native_linux_semantics(
        "/mnt/c/Users/a/.claude/.credentials.json",
        mountinfo_text=native_mountinfo,
    )
    assert not S.wsl_path_has_native_linux_semantics(
        r"C:\Users\a\.claude\.credentials.json",
        mountinfo_text=native_mountinfo,
    )


def test_wsl_observer_refuses_non_native_root_before_file_observation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_host(monkeypatch, S.HOST_WSL_NATIVE)
    monkeypatch.setattr(
        S,
        "_read_linux_mountinfo",
        lambda: (
            "36 25 0:32 / / rw,relatime - ext4 /dev/sdc rw\n"
            "48 36 0:49 / /mnt/c rw - 9p drvfs rw\n"
        ),
    )
    with pytest.raises(
        S.ClaudeStoredSubscriptionSourceError,
        match="native Linux root",
    ):
        S._require_wsl_native_root("/mnt/c/Users/a/.claude/.credentials.json")


def test_posix_private_mode_predicate_rejects_group_or_other_access() -> None:
    assert S._posix_mode_is_private(0o100600)
    assert not S._posix_mode_is_private(0o100640)
    assert not S._posix_mode_is_private(0o100604)


def _empty_private_target(path: Path) -> int:
    descriptor = os.open(
        path,
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    _install_windows_private_acl(path)
    return descriptor


def _private_target_capability(
    descriptor: int,
    path: Path,
    *,
    label: str,
) -> S.PrivateCredentialTargetCapability:
    authority_digest = hashlib.sha256(label.encode("utf-8")).hexdigest()
    parent = path.parent.stat()
    authority = {
        "schema": S.PRIVATE_CREDENTIAL_TARGET_AUTHORITY_SCHEMA,
        "run_id": f"run-{label}",
        "startup_permit_sha256": authority_digest,
        "outer_attempt_arm_sha256": authority_digest,
        "execution_generation_sha256": authority_digest,
        "work_plan_sha256": authority_digest,
        "attempt_id": f"attempt-{label}",
        "process_scope_identity": f"scope-{label}",
        "auxiliary_lease_binding_sha256": authority_digest,
        "launch_security_policy_sha256": authority_digest,
        "executable_observation_sha256": authority_digest,
        "auth_environment_receipt_sha256": authority_digest,
        "settings_authority_sha256": authority_digest,
        "mcp_authority_sha256": authority_digest,
        "target_role": "CLAUDE_STORED_SUBSCRIPTION_CREDENTIAL",
        "credential_parent_identity": {
            "device": int(parent.st_dev),
            "inode": int(parent.st_ino),
        },
    }
    return S.authorize_private_credential_target(
        descriptor,
        destination_path=path,
        target_authority=authority,
    )


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission semantics required")
@pytest.mark.parametrize("mode", (0o640, 0o604))
def test_private_target_authority_rejects_group_or_other_access(
    tmp_path: Path,
    mode: int,
) -> None:
    target = tmp_path / f"target-{mode:o}"
    descriptor = _empty_private_target(target)
    try:
        target.chmod(mode)
        with pytest.raises(
            S.ClaudeStoredSubscriptionSourceError,
            match="owner-private|permissions|private",
        ):
            _private_target_capability(
                descriptor,
                target,
                label=f"mode-{mode:o}",
            )
        assert os.fstat(descriptor).st_size == 0
    finally:
        os.close(descriptor)


@pytest.mark.skipif(os.name != "nt", reason="Windows DACL semantics required")
def test_private_target_authority_rejects_everyone_read_access(
    tmp_path: Path,
) -> None:
    target = tmp_path / "everyone-readable-target"
    descriptor = _empty_private_target(target)
    try:
        _run_icacls(str(target), "/grant", "*S-1-1-0:(R)")
        with pytest.raises(
            S.ClaudeStoredSubscriptionSourceError,
            match="unapproved trustee|access|ACL",
        ):
            _private_target_capability(
                descriptor,
                target,
                label="everyone-read",
            )
        assert os.fstat(descriptor).st_size == 0
    finally:
        os.close(descriptor)


def test_private_target_capability_rejects_authority_a_with_descriptor_b(
    tmp_path: Path,
) -> None:
    private_root = tmp_path / ".claude"
    _write_credentials(private_root / ".credentials.json")
    first_path = private_root / "private-a"
    second_path = private_root / "private-b"
    first = _empty_private_target(first_path)
    second = _empty_private_target(second_path)
    try:
        authority_a = _private_target_capability(
            first,
            first_path,
            label="authority-a",
        )
        object.__setattr__(
            authority_a,
            "_PrivateCredentialTargetCapability__descriptor",
            second,
        )
        with pytest.raises(
            S.ClaudeStoredSubscriptionSourceError,
            match="identity|rebound|empty private regular file",
        ):
            authority_a._consume()
        assert os.fstat(first).st_size == 0
        assert os.fstat(second).st_size == 0
    finally:
        os.close(first)
        os.close(second)


def test_materialization_capability_consumes_exact_observed_bytes_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_host(monkeypatch, S.HOST_WINDOWS_NATIVE)
    source = tmp_path / ".claude" / ".credentials.json"
    secret = "one-shot-exact-source-secret"
    raw = _write_credentials(source, secret)
    capability = S.acquire_stored_subscription_materialization(
        source_path=source
    )
    evidence = capability.source_evidence
    assert A.replay_stored_subscription_source_evidence(evidence) == evidence

    target = source.parent / "private-attempt-credentials"
    descriptor = _empty_private_target(target)
    try:
        receipt = capability.consume_into_private_descriptor(
            _private_target_capability(
                descriptor,
                target,
                label="exact-copy",
            ),
            expected_source_evidence=evidence,
        )
        os.lseek(descriptor, 0, os.SEEK_SET)
        assert os.read(descriptor, len(raw) + 1) == raw
    finally:
        os.close(descriptor)

    assert (
        S.replay_stored_subscription_materialization_receipt(receipt)
        == receipt
    )
    serialized = json.dumps(receipt, sort_keys=True)
    assert secret not in serialized
    assert hashlib.sha256(raw).hexdigest() not in serialized
    assert str(source) not in serialized
    assert "S-1-" not in serialized

    second = _empty_private_target(tmp_path / "second-target")
    try:
        with pytest.raises(
            S.ClaudeStoredSubscriptionSourceError,
            match="no longer available",
        ):
            capability.consume_into_private_descriptor(
                second,
                expected_source_evidence=evidence,
            )
        assert os.fstat(second).st_size == 0
    finally:
        os.close(second)


def test_capability_is_opaque_noncopyable_and_nonserializable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_host(monkeypatch, S.HOST_WINDOWS_NATIVE)
    source = tmp_path / ".claude" / ".credentials.json"
    secret = "opaque-capability-secret"
    _write_credentials(source, secret)
    capability = S.acquire_stored_subscription_materialization(
        source_path=source
    )
    try:
        assert secret not in repr(capability)
        with pytest.raises(TypeError):
            vars(capability)
        with pytest.raises(TypeError):
            copy.copy(capability)
        with pytest.raises(TypeError):
            copy.deepcopy(capability)
        with pytest.raises(TypeError):
            pickle.dumps(capability)
        with pytest.raises(TypeError):
            json.dumps(capability)
    finally:
        capability.discard()


def test_capability_never_reopens_or_rereads_source_during_consumption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_host(monkeypatch, S.HOST_WINDOWS_NATIVE)
    source = tmp_path / ".claude" / ".credentials.json"
    raw = _write_credentials(source)
    capability = S.acquire_stored_subscription_materialization(
        source_path=source
    )
    evidence = capability.source_evidence
    target = source.parent / "private-target"
    descriptor = _empty_private_target(target)
    target_capability = _private_target_capability(
        descriptor,
        target,
        label="no-reopen",
    )

    monkeypatch.setattr(
        S,
        "_read_descriptor_bounded",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("source was reread")
        ),
    )
    original_open = os.open

    def no_reopen(*_args: object, **_kwargs: object) -> int:
        raise AssertionError("source was reopened")

    monkeypatch.setattr(S.os, "open", no_reopen)
    try:
        receipt = capability.consume_into_private_descriptor(
            target_capability,
            expected_source_evidence=evidence,
        )
        os.lseek(descriptor, 0, os.SEEK_SET)
        assert os.read(descriptor, len(raw) + 1) == raw
        assert receipt["source_path_reopened"] is False
        assert receipt["source_bytes_reread"] is False
    finally:
        monkeypatch.setattr(S.os, "open", original_open)
        os.close(descriptor)


def test_source_change_after_acquisition_fails_closed_and_poison_consumption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_host(monkeypatch, S.HOST_WINDOWS_NATIVE)
    source = tmp_path / ".claude" / ".credentials.json"
    _write_credentials(source, "source-before-change")
    capability = S.acquire_stored_subscription_materialization(
        source_path=source
    )
    evidence = capability.source_evidence
    _write_credentials(source, "source-after-change-with-new-size")

    first_path = source.parent / "first-target"
    first = _empty_private_target(first_path)
    try:
        with pytest.raises(
            S.ClaudeStoredSubscriptionSourceError,
            match="source changed",
        ):
            capability.consume_into_private_descriptor(
                _private_target_capability(
                    first,
                    first_path,
                    label="source-change",
                ),
                expected_source_evidence=evidence,
            )
        assert os.fstat(first).st_size == 0
    finally:
        os.close(first)

    second = _empty_private_target(tmp_path / "second-target")
    try:
        with pytest.raises(
            S.ClaudeStoredSubscriptionSourceError,
            match="no longer available",
        ):
            capability.consume_into_private_descriptor(
                second,
                expected_source_evidence=evidence,
            )
    finally:
        os.close(second)


def test_tampered_expected_evidence_fails_before_destination_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_host(monkeypatch, S.HOST_WINDOWS_NATIVE)
    source = tmp_path / ".claude" / ".credentials.json"
    _write_credentials(source)
    capability = S.acquire_stored_subscription_materialization(
        source_path=source
    )
    evidence = capability.source_evidence
    tampered = dict(evidence)
    tampered["source_size"] += 1
    core = dict(tampered)
    core.pop("receipt_sha256")
    tampered["receipt_sha256"] = _receipt_digest(core)
    assert A.replay_stored_subscription_source_evidence(tampered) == tampered

    target = source.parent / "target"
    descriptor = _empty_private_target(target)
    try:
        with pytest.raises(
            S.ClaudeStoredSubscriptionSourceError,
            match="evidence drifted",
        ):
            capability.consume_into_private_descriptor(
                descriptor,
                expected_source_evidence=tampered,
            )
        assert os.fstat(descriptor).st_size == 0
    finally:
        os.close(descriptor)


def test_private_buffer_tamper_is_detected_without_secret_disclosure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_host(monkeypatch, S.HOST_WINDOWS_NATIVE)
    source = tmp_path / ".claude" / ".credentials.json"
    secret = "private-buffer-tamper-secret"
    _write_credentials(source, secret)
    capability = S.acquire_stored_subscription_materialization(
        source_path=source
    )
    evidence = capability.source_evidence
    private_buffer = getattr(
        capability,
        "_StoredSubscriptionMaterializationCapability__buffer",
    )
    private_buffer[0] ^= 1

    target = source.parent / "target"
    descriptor = _empty_private_target(target)
    try:
        with pytest.raises(
            S.ClaudeStoredSubscriptionSourceError,
            match="capability was tampered",
        ) as raised:
            capability.consume_into_private_descriptor(
                _private_target_capability(
                    descriptor,
                    target,
                    label="buffer-tamper",
                ),
                expected_source_evidence=evidence,
            )
        assert secret not in str(raised.value)
        assert os.fstat(descriptor).st_size == 0
    finally:
        os.close(descriptor)


def test_materialization_receipt_tamper_fails_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_host(monkeypatch, S.HOST_WINDOWS_NATIVE)
    source = tmp_path / ".claude" / ".credentials.json"
    _write_credentials(source)
    capability = S.acquire_stored_subscription_materialization(
        source_path=source
    )
    target = source.parent / "target"
    descriptor = _empty_private_target(target)
    try:
        receipt = capability.consume_into_private_descriptor(
            _private_target_capability(
                descriptor,
                target,
                label="receipt",
            ),
            expected_source_evidence=capability.source_evidence,
        )
    finally:
        os.close(descriptor)

    tampered = dict(receipt)
    tampered["source_bytes_reread"] = True
    core = dict(tampered)
    core.pop("receipt_sha256")
    tampered["receipt_sha256"] = _receipt_digest(core)
    with pytest.raises(
        S.ClaudeStoredSubscriptionSourceError,
        match="does not replay",
    ):
        S.replay_stored_subscription_materialization_receipt(tampered)


def test_nonempty_destination_or_discarded_capability_cannot_materialize(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_host(monkeypatch, S.HOST_WINDOWS_NATIVE)
    source = tmp_path / ".claude" / ".credentials.json"
    _write_credentials(source)
    capability = S.acquire_stored_subscription_materialization(
        source_path=source
    )
    evidence = capability.source_evidence
    target = tmp_path / "target"
    target.write_bytes(b"occupied")
    descriptor = os.open(
        target,
        os.O_RDWR | getattr(os, "O_BINARY", 0),
    )
    try:
        with pytest.raises(
            S.ClaudeStoredSubscriptionSourceError,
            match="empty private regular file",
        ):
            _private_target_capability(
                descriptor,
                target,
                label="nonempty",
            )
        assert target.read_bytes() == b"occupied"
    finally:
        os.close(descriptor)
        capability.discard()

    fresh = S.acquire_stored_subscription_materialization(
        source_path=source
    )
    fresh.discard()
    empty = _empty_private_target(tmp_path / "empty-target")
    try:
        with pytest.raises(
            S.ClaudeStoredSubscriptionSourceError,
            match="no longer available",
        ):
            fresh.consume_into_private_descriptor(
                empty,
                expected_source_evidence=fresh.source_evidence,
            )
    finally:
        os.close(empty)
