from __future__ import annotations

import dataclasses
import json
import os
import pickle
from pathlib import Path
import subprocess
import sys

import pytest

import claude_auth_route as A
import claude_provider_preparation as P
import claude_runtime_materialization as M
import claude_stored_subscription_source as S
import test_claude_provider_preparation as F
import test_claude_provider_authority_blocker_repairs_p0_am as BF
import test_claude_runtime_materialization_p0_am as MF
import test_claude_stored_subscription_source_p0_am as SF


def _eligible_package(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    settings_mode: str = "SAFE_MODE",
) -> tuple[P.ClaudeProviderPreparation, dict[str, object]]:
    values = F._inputs(
        tmp_path,
        settings_mode=settings_mode,
        mcp_servers=(
            ("unified-vuln-db",)
            if settings_mode == "BOUND_SETTINGS"
            else ()
        ),
    )
    F._install_observers(
        monkeypatch,
        Path(str(values["configured_claude_bin"])),
    )
    package = P.prepare_claude_provider(**F._public_inputs(values))
    assert package.eligible
    return package, values


def _claim(
    package: P.ClaudeProviderPreparation,
    attachment: P.BoundClaudeProviderRuntime,
) -> P.ClaimedClaudeProviderRuntime:
    return P.claim_bound_claude_provider_runtime(
        attachment,
        provider_preparation=package,
        expected_preparation_sha256=package.preparation_sha256,
        expected_runtime_host_policy_sha256=package.record[
            "runtime_host_policy"
        ]["policy_sha256"],
        expected_attachment_sha256=attachment.attachment_sha256,
    )


def test_preparation_cannot_be_forged_by_replace_raw_constructor_or_subclass(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    package, values = _eligible_package(monkeypatch, tmp_path)
    forged_record = package.record
    forged_record["command_template"] = [
        "python",
        "-c",
        P.PROMPT_PLACEHOLDER,
    ]
    forged_record["preparation_sha256"] = F._digest(
        {
            key: value
            for key, value in forged_record.items()
            if key != "preparation_sha256"
        }
    )
    forged_bytes = F._canonical(forged_record) + b"\n"

    with pytest.raises(TypeError):
        dataclasses.replace(package, _record_bytes=forged_bytes)
    with pytest.raises((TypeError, P.ClaudeProviderPreparationError)):
        P.ClaudeProviderPreparation(
            _record_bytes=forged_bytes,
            _promotion_token=P._PROMOTION_TOKEN,
        )

    class Spoof(P.ClaudeProviderPreparation):
        @property
        def record(self) -> dict[str, object]:
            return forged_record

        @property
        def preparation_sha256(self) -> str:
            return "f" * 64

        @property
        def eligible(self) -> bool:
            return True

        def validate_for_backend(self, _backend: str) -> None:
            return None

    spoof = object.__new__(Spoof)
    with pytest.raises(P.ClaudeProviderPreparationError):
        P.attach_claude_provider_runtime(
            spoof,
            ambient_environment=values["ambient_environment"],
            source_config_dir=values["source_config_dir"],
            project_root=values["project_root"],
            trusted_cwds=values["trusted_cwds"],
        )


def test_preparation_slot_substitution_is_replayed_before_command_or_attach(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    package, values = _eligible_package(monkeypatch, tmp_path)
    original = package.to_bytes()
    record = json.loads(original)
    record["command_template"] = [
        "python",
        "-c",
        P.PROMPT_PLACEHOLDER,
    ]
    record["preparation_sha256"] = F._digest(
        {
            key: value
            for key, value in record.items()
            if key != "preparation_sha256"
        }
    )
    forged = F._canonical(record) + b"\n"
    private_name = next(
        name
        for name in (
            "_record_bytes",
            "_ClaudeProviderPreparation__record_bytes",
        )
        if hasattr(package, name)
    )
    object.__setattr__(package, private_name, forged)
    with pytest.raises(P.ClaudeProviderPreparationError):
        package.command_for_bound_stdin()
    with pytest.raises(P.ClaudeProviderPreparationError):
        P.attach_claude_provider_runtime(
            package,
            ambient_environment=values["ambient_environment"],
            source_config_dir=values["source_config_dir"],
            project_root=values["project_root"],
            trusted_cwds=values["trusted_cwds"],
        )


def test_bound_and_claimed_runtime_bind_all_payloads_and_external_one_shot(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    package, values = _eligible_package(
        monkeypatch,
        tmp_path,
        settings_mode="BOUND_SETTINGS",
    )
    attachment = F._attach(package, values)
    original_settings = bytes(values["_bound_settings_bytes"])
    object.__setattr__(
        attachment,
        "_BoundClaudeProviderRuntime__bound_settings",
        bytearray(b'{"changed":true}\n'),
    )
    with pytest.raises(P.ClaudeProviderPreparationError, match="drift"):
        _claim(package, attachment)

    attachment = F._attach(package, values)
    saved_host = object.__getattribute__(
        attachment,
        "_BoundClaudeProviderRuntime__host_inputs",
    )
    saved_settings = object.__getattribute__(
        attachment,
        "_BoundClaudeProviderRuntime__bound_settings",
    )
    saved_mcp = object.__getattribute__(
        attachment,
        "_BoundClaudeProviderRuntime__mcp_config",
    )
    claimed = _claim(package, attachment)
    assert claimed.bound_settings_bytes == original_settings
    with pytest.raises(TypeError):
        dataclasses.replace(
            claimed,
            bound_settings_bytes=b'{"forged":true}\n',
        )
    with pytest.raises(TypeError):
        pickle.dumps(claimed)

    object.__setattr__(
        attachment,
        "_BoundClaudeProviderRuntime__host_inputs",
        saved_host,
    )
    object.__setattr__(
        attachment,
        "_BoundClaudeProviderRuntime__bound_settings",
        saved_settings,
    )
    object.__setattr__(
        attachment,
        "_BoundClaudeProviderRuntime__mcp_config",
        saved_mcp,
    )
    with pytest.raises(P.ClaudeProviderPreparationError, match="claimed"):
        _claim(package, attachment)


def test_claimed_runtime_slot_replacement_does_not_change_authorized_payload(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    package, values = _eligible_package(
        monkeypatch,
        tmp_path,
        settings_mode="BOUND_SETTINGS",
    )
    claimed = _claim(package, F._attach(package, values))
    private_name = next(
        name
        for name in (
            "_ClaimedClaudeProviderRuntime__bound_settings_bytes",
            "bound_settings_bytes",
        )
        if hasattr(claimed, name)
    )
    object.__setattr__(
        claimed,
        private_name,
        b'{"forged":true}\n',
    )
    with pytest.raises(P.ClaudeProviderPreparationError, match="drift"):
        _ = claimed.bound_settings_bytes


def test_source_project_and_trusted_cwd_denominator_swaps_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    trusted_a = tmp_path / "trusted-a"
    trusted_b = tmp_path / "trusted-b"
    trusted_a.mkdir()
    trusted_b.mkdir()
    values = F._inputs(tmp_path / "case")
    values["trusted_cwds"] = (values["project_root"], trusted_a)
    F._install_observers(
        monkeypatch,
        Path(str(values["configured_claude_bin"])),
    )
    package = P.prepare_claude_provider(**F._public_inputs(values))
    assert package.eligible

    alternate_source = tmp_path / "alternate-source"
    alternate_source.mkdir()
    with pytest.raises(P.ClaudeProviderPreparationError, match="source"):
        P.attach_claude_provider_runtime(
            package,
            ambient_environment=values["ambient_environment"],
            source_config_dir=alternate_source,
            project_root=values["project_root"],
            trusted_cwds=values["trusted_cwds"],
        )
    with pytest.raises(P.ClaudeProviderPreparationError, match="project"):
        P.attach_claude_provider_runtime(
            package,
            ambient_environment=values["ambient_environment"],
            source_config_dir=values["source_config_dir"],
            project_root=Path(values["project_root"]).parent,
            trusted_cwds=values["trusted_cwds"],
        )
    with pytest.raises(P.ClaudeProviderPreparationError, match="trusted"):
        P.attach_claude_provider_runtime(
            package,
            ambient_environment=values["ambient_environment"],
            source_config_dir=values["source_config_dir"],
            project_root=values["project_root"],
            trusted_cwds=(values["project_root"], trusted_b),
        )


def test_promoted_source_evidence_consumption_is_external_to_mutable_slots(
) -> None:
    evidence = F._stored_evidence()
    promoted = A._promote_stored_subscription_source_evidence(
        evidence,
        provider_authority_sha256=(
            evidence["observation_authority_sha256"]
        ),
    )
    saved = {
        "_PromotedStoredSubscriptionSourceEvidence__key": bytearray(
            object.__getattribute__(
                promoted,
                "_PromotedStoredSubscriptionSourceEvidence__key",
            )
        ),
        "_PromotedStoredSubscriptionSourceEvidence__tag": bytearray(
            object.__getattribute__(
                promoted,
                "_PromotedStoredSubscriptionSourceEvidence__tag",
            )
        ),
        "_PromotedStoredSubscriptionSourceEvidence__provider_authority_sha256": (
            object.__getattribute__(
                promoted,
                "_PromotedStoredSubscriptionSourceEvidence"
                "__provider_authority_sha256",
            )
        ),
    }
    assert promoted._consume_for_auth_observation()
    for name, value in saved.items():
        object.__setattr__(promoted, name, value)
    object.__setattr__(
        promoted,
        "_PromotedStoredSubscriptionSourceEvidence__active",
        True,
    )
    with pytest.raises(A.ClaudeAuthRouteError, match="stale|consumed"):
        promoted._consume_for_auth_observation()


def test_runtime_host_inputs_cannot_be_reset_and_reclaimed(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    source = tmp_path / "source"
    project.mkdir()
    source.mkdir()
    host = M.compile_claude_runtime_host_inputs(
        auth_route="STORED_SUBSCRIPTION_OAUTH",
        ambient_environment={"PATH": "fixture"},
        source_config_dir=source,
        project_root=project,
        trusted_cwds=(project,),
    )
    names = (
        "__ambient_environment",
        "__auth_route",
        "__identity",
        "__project_root",
        "__source_config_dir",
        "__trusted_cwds",
    )
    saved = {
        name: object.__getattribute__(
            host,
            f"_ClaudeRuntimeHostInputs{name}",
        )
        for name in names
    }
    key = bytearray(
        object.__getattribute__(
            host,
            "_ClaudeRuntimeHostInputs__integrity_key",
        )
    )
    tag = bytes(
        object.__getattribute__(
            host,
            "_ClaudeRuntimeHostInputs__integrity_tag",
        )
    )
    assert host._claim()["project_root"] == project.resolve(strict=True)
    for name, value in saved.items():
        object.__setattr__(
            host,
            f"_ClaudeRuntimeHostInputs{name}",
            value,
        )
    object.__setattr__(
        host,
        "_ClaudeRuntimeHostInputs__integrity_key",
        key,
    )
    object.__setattr__(
        host,
        "_ClaudeRuntimeHostInputs__integrity_tag",
        tag,
    )
    object.__setattr__(
        host,
        "_ClaudeRuntimeHostInputs__claimed",
        False,
    )
    with pytest.raises(
        M.ClaudeRuntimeMaterializationError,
        match="already claimed",
    ):
        host._claim()


def test_private_target_and_stored_materialization_one_shots_are_external(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    SF._force_host(monkeypatch, S.HOST_WINDOWS_NATIVE)
    source = tmp_path / ".claude" / ".credentials.json"
    SF._write_credentials(source)

    target = source.parent / "private-target"
    descriptor = SF._empty_private_target(target)
    try:
        capability = SF._private_target_capability(
            descriptor,
            target,
            label="external-one-shot",
        )
        key = bytearray(
            object.__getattribute__(
                capability,
                "_PrivateCredentialTargetCapability__integrity_key",
            )
        )
        tag = bytearray(
            object.__getattribute__(
                capability,
                "_PrivateCredentialTargetCapability__integrity_tag",
            )
        )
        assert capability._consume()[0] == descriptor
        object.__setattr__(
            capability,
            "_PrivateCredentialTargetCapability__integrity_key",
            key,
        )
        object.__setattr__(
            capability,
            "_PrivateCredentialTargetCapability__integrity_tag",
            tag,
        )
        object.__setattr__(
            capability,
            "_PrivateCredentialTargetCapability__active",
            True,
        )
        with pytest.raises(
            S.ClaudeStoredSubscriptionSourceError,
            match="stale|consumed",
        ):
            capability._consume()
    finally:
        os.close(descriptor)

    materialization = S.acquire_stored_subscription_materialization(
        source_path=source
    )
    materialization.discard()
    object.__setattr__(
        materialization,
        "_StoredSubscriptionMaterializationCapability__state",
        "READY",
    )
    with pytest.raises(
        S.ClaudeStoredSubscriptionSourceError,
        match="no longer available",
    ):
        materialization.discard()


def test_raw_bound_and_claimed_structures_cannot_mint_authority(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    host = M.compile_claude_runtime_host_inputs(
        auth_route="OAUTH_TOKEN",
        ambient_environment={"CLAUDE_CODE_OAUTH_TOKEN": "private"},
        source_config_dir=None,
        project_root=project,
        trusted_cwds=(project,),
    )
    with pytest.raises(TypeError):
        P.BoundClaudeProviderRuntime(
            _token=P._ATTACHMENT_TOKEN,
            preparation_sha256="1" * 64,
            runtime_host_policy_sha256="2" * 64,
            attachment_id="3" * 32,
            host_inputs=host,
            bound_settings=None,
            mcp_config=None,
        )
    with pytest.raises(TypeError):
        P.ClaimedClaudeProviderRuntime(
            host_inputs=host,
            bound_settings_bytes=None,
            selected_mcp_config_bytes=None,
            attachment_sha256="4" * 64,
            _promotion_token=P._PROMOTION_TOKEN,
        )


def test_deleted_or_replaced_stored_source_fails_attachment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    values = F._inputs(tmp_path)
    source_path = Path(values["stored_subscription_source_path"])
    SF._write_credentials(source_path)
    executable = Path(str(values["configured_claude_bin"]))
    F._install_observers(monkeypatch, executable)
    monkeypatch.setattr(
        P,
        "observe_stored_subscription_source_authority",
        S.observe_stored_subscription_source_authority,
    )
    monkeypatch.setattr(
        P,
        "replay_stored_subscription_source_observation",
        S.replay_stored_subscription_source_observation,
    )
    package = P.prepare_claude_provider(**F._public_inputs(values))
    assert package.eligible

    source_path.unlink()
    with pytest.raises(P.ClaudeProviderPreparationError, match="stale|source"):
        F._attach(package, values)


def test_preparation_bytes_cross_process_only_through_full_replay(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    values = F._inputs(tmp_path)
    SF._write_credentials(Path(values["stored_subscription_source_path"]))
    F._install_observers(
        monkeypatch,
        Path(str(values["configured_claude_bin"])),
    )
    monkeypatch.setattr(
        P,
        "observe_stored_subscription_source_authority",
        S.observe_stored_subscription_source_authority,
    )
    monkeypatch.setattr(
        P,
        "replay_stored_subscription_source_observation",
        S.replay_stored_subscription_source_observation,
    )
    package = P.prepare_claude_provider(**F._public_inputs(values))
    assert package.eligible
    payload = tmp_path / "provider-preparation.json"
    payload.write_bytes(package.to_bytes())
    record = package.record
    script = (
        "from pathlib import Path\n"
        "import claude_provider_preparation as P\n"
        f"raw=Path({str(payload)!r}).read_bytes()\n"
        "package=P.replay_claude_provider_preparation("
        "raw,expected_backend='claude',"
        f"expected_startup_authority_sha256={record['startup_authority_sha256']!r},"
        f"expected_source_snapshot_sha256={record['source_snapshot_sha256']!r})\n"
        "assert package.command_for_bound_stdin()[1:3]==('-p','--model')\n"
        "print('FULL_REPLAY_OK')\n"
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(Path(P.__file__).resolve(strict=True).parent),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "FULL_REPLAY_OK"
    with pytest.raises(TypeError):
        pickle.dumps(package)


def test_nested_mutable_copies_cannot_rebind_issued_authority(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    package, _values = _eligible_package(monkeypatch, tmp_path)
    copied = package.record
    copied["semantic_intent"]["launch_model"] = "forged-model"
    copied["command_template"][0] = "forged-executable"
    assert package.record["semantic_intent"]["launch_model"] == F.MODEL
    assert package.record["command_template"][0] != "forged-executable"
    assert package.command_for_bound_stdin()[1:3] == (
        "-p",
        "--model",
    )


def test_auth_source_and_environment_raw_mint_and_slot_reset_fail_closed(
    tmp_path: Path,
) -> None:
    ambient = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(tmp_path / "home"),
    }
    promoted = BF._stored_evidence()
    source = A.observe_claude_auth_sources(
        ambient,
        settings={},
        settings_authority_sha256=None,
        stored_subscription_evidence=promoted,
    )
    source_receipt = dict(source)
    source_key = bytearray(
        object.__getattribute__(
            source,
            "_ClaudeAuthSourceCapability__key",
        )
    )
    source_tag = bytearray(
        object.__getattribute__(
            source,
            "_ClaudeAuthSourceCapability__tag",
        )
    )
    source._consume_environment(ambient)
    object.__setattr__(
        source,
        "_ClaudeAuthSourceCapability__key",
        source_key,
    )
    object.__setattr__(
        source,
        "_ClaudeAuthSourceCapability__tag",
        source_tag,
    )
    object.__setattr__(
        source,
        "_ClaudeAuthSourceCapability__active",
        True,
    )
    with pytest.raises(A.ClaudeAuthRouteError, match="stale|consumed"):
        source._consume_environment(ambient)
    with pytest.raises(TypeError):
        A.ClaudeAuthSourceCapability(
            source_receipt,
            environment=ambient,
            _token=A._PROMOTION_TOKEN,
        )

    environment, receipt, _observation = BF._auth_environment(ambient)
    environment_values = dict(environment)
    environment_key = bytearray(
        object.__getattribute__(
            environment,
            "_ClaudeAuthEnvironmentCapability__key",
        )
    )
    environment_tag = bytearray(
        object.__getattribute__(
            environment,
            "_ClaudeAuthEnvironmentCapability__tag",
        )
    )
    environment._consume_verified_environment(
        receipt_sha256=receipt["receipt_sha256"],
    )
    dict.update(environment, environment_values)
    object.__setattr__(
        environment,
        "_ClaudeAuthEnvironmentCapability__key",
        environment_key,
    )
    object.__setattr__(
        environment,
        "_ClaudeAuthEnvironmentCapability__tag",
        environment_tag,
    )
    object.__setattr__(
        environment,
        "_ClaudeAuthEnvironmentCapability__active",
        True,
    )
    with pytest.raises(A.ClaudeAuthRouteError, match="stale|rebound"):
        environment._consume_verified_environment(
            receipt_sha256=receipt["receipt_sha256"],
        )
    with pytest.raises(TypeError):
        A.ClaudeAuthEnvironmentCapability(
            environment_values,
            receipt_sha256=receipt["receipt_sha256"],
            _token=A._PROMOTION_TOKEN,
        )


def test_runtime_request_raw_mint_and_slot_reset_fail_closed(
    tmp_path: Path,
) -> None:
    request = MF._request(
        MF._kwargs(
            tmp_path=tmp_path,
            attempt_id="provider-sealing-request",
        )
    )
    private_names = (
        "__values",
        "__launch_security_request",
        "__auth_route",
        "__ambient_environment",
        "__base_argv",
        "__scratchpad",
        "__startup_permit_binding",
        "__project_root",
        "__trusted_cwds",
        "__source_config_dir",
        "__auxiliary_reservation",
        "__identity",
    )
    saved = {
        name: object.__getattribute__(
            request,
            f"_ClaudeRuntimeMaterializationRequest{name}",
        )
        for name in private_names
    }
    key = bytearray(
        object.__getattribute__(
            request,
            "_ClaudeRuntimeMaterializationRequest__integrity_key",
        )
    )
    tag = bytes(
        object.__getattribute__(
            request,
            "_ClaudeRuntimeMaterializationRequest__integrity_tag",
        )
    )
    with pytest.raises(TypeError):
        M.ClaudeRuntimeMaterializationRequest(
            _capability=M._REQUEST_CAPABILITY,
            values=saved["__values"],
            launch_security_request=saved["__launch_security_request"],
            auth_route=saved["__auth_route"],
            ambient_environment=saved["__ambient_environment"],
            base_argv=saved["__base_argv"],
            scratchpad=saved["__scratchpad"],
            startup_permit_binding=saved["__startup_permit_binding"],
            project_root=saved["__project_root"],
            trusted_cwds=saved["__trusted_cwds"],
            source_config_dir=saved["__source_config_dir"],
            auxiliary_reservation=saved["__auxiliary_reservation"],
            integrity_key=bytearray(key),
            integrity_tag=tag,
            identity=saved["__identity"],
        )
    assert request._claim()["attempt_id"] == "provider-sealing-request"
    for name, value in saved.items():
        object.__setattr__(
            request,
            f"_ClaudeRuntimeMaterializationRequest{name}",
            value,
        )
    object.__setattr__(
        request,
        "_ClaudeRuntimeMaterializationRequest__integrity_key",
        key,
    )
    object.__setattr__(
        request,
        "_ClaudeRuntimeMaterializationRequest__integrity_tag",
        tag,
    )
    object.__setattr__(
        request,
        "_ClaudeRuntimeMaterializationRequest__claimed",
        False,
    )
    with pytest.raises(
        M.ClaudeRuntimeMaterializationError,
        match="already claimed",
    ):
        request._claim()


@pytest.mark.skipif(
    not hasattr(os, "fork"),
    reason="fork inheritance is POSIX-only",
)
def test_one_shot_runtime_authority_cannot_be_inherited_across_fork(
    tmp_path: Path,
) -> None:
    project = tmp_path / "fork-project"
    project.mkdir()
    host = M.compile_claude_runtime_host_inputs(
        auth_route="OAUTH_TOKEN",
        ambient_environment={"CLAUDE_CODE_OAUTH_TOKEN": "private"},
        source_config_dir=None,
        project_root=project,
        trusted_cwds=(project,),
    )
    child = os.fork()
    if child == 0:
        try:
            host._claim()
        except M.ClaudeRuntimeMaterializationError:
            os._exit(0)
        os._exit(17)
    _pid, status = os.waitpid(child, 0)
    assert os.waitstatus_to_exitcode(status) == 0
    assert host._claim()["project_root"] == project.resolve(strict=True)
