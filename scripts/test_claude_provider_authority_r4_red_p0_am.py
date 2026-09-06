from __future__ import annotations

import hashlib
import os
from pathlib import Path
import weakref

import pytest

import claude_provider_preparation as P
import claude_runtime_materialization as M
import auxiliary_writable_root_lease as AUX
import test_claude_provider_preparation as PF
import test_claude_runtime_materialization_p0_am as MF
from test_support_startup_permit import (
    FIXTURE_RUN_ID,
    durable_startup_permit,
)


def _eligible_oauth_package(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> tuple[P.ClaudeProviderPreparation, dict[str, object]]:
    values = PF._inputs(tmp_path, route="OAUTH_TOKEN")
    PF._install_observers(
        monkeypatch,
        Path(str(values["configured_claude_bin"])),
    )
    package = P.prepare_claude_provider(**PF._public_inputs(values))
    assert package.eligible
    assert package.record["settings_policy"]["mode"] == "SAFE_MODE"
    return package, values


def _raw_bound_with_legitimate_parent_hashes(
    package: P.ClaudeProviderPreparation,
    values: dict[str, object],
) -> P.BoundClaudeProviderRuntime:
    host = M.compile_claude_runtime_host_inputs(
        auth_route="OAUTH_TOKEN",
        ambient_environment=values["ambient_environment"],
        source_config_dir=None,
        project_root=values["project_root"],
        trusted_cwds=values["trusted_cwds"],
        runtime_local_authority_sha256=None,
    )
    preparation_sha256 = package.preparation_sha256
    host_policy_sha256 = package.record["runtime_host_policy"][
        "policy_sha256"
    ]
    attachment_id = "3" * 32
    issuance_id = "r4-direct-bound-pending-insert"
    settings = b'{"forged_under_safe_mode":true}\n'
    mcp = b'{"mcpServers":{"forged":{}}}\n'
    pending = {
        "preparation_sha256": preparation_sha256,
        "runtime_host_policy_sha256": host_policy_sha256,
        "attachment_id": attachment_id,
        "host_inputs": host,
        "bound_settings": settings,
        "mcp_config": mcp,
    }
    P._BOUND_PENDING[issuance_id] = pending
    return P.BoundClaudeProviderRuntime(
        _token=P._ATTACHMENT_TOKEN,
        _issuance_id=issuance_id,
        preparation_sha256=preparation_sha256,
        runtime_host_policy_sha256=host_policy_sha256,
        attachment_id=attachment_id,
        host_inputs=host,
        bound_settings=settings,
        mcp_config=mcp,
    )


def _request_kwargs_for_claimed_host(
    *,
    tmp_path: Path,
    claimed: P.ClaimedClaudeProviderRuntime,
    ambient: dict[str, str],
) -> dict[str, object]:
    kwargs = MF._kwargs(
        tmp_path=tmp_path,
        attempt_id="r4-forged-provider-runtime",
        route="OAUTH_TOKEN",
        ambient=ambient,
    )
    kwargs.pop("host_inputs")
    kwargs["provider_runtime"] = claimed
    return kwargs


def test_direct_pending_insert_cannot_cross_public_claim_sink(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    package, values = _eligible_oauth_package(monkeypatch, tmp_path)
    bound = _raw_bound_with_legitimate_parent_hashes(package, values)
    with pytest.raises(
        P.ClaudeProviderPreparationError,
        match="parent|settings|authority|issued",
    ):
        P.claim_bound_claude_provider_runtime(
            bound,
            provider_preparation=package,
            expected_preparation_sha256=package.preparation_sha256,
            expected_runtime_host_policy_sha256=package.record[
                "runtime_host_policy"
            ]["policy_sha256"],
            expected_attachment_sha256=bound.attachment_sha256,
        )


def test_arbitrary_private_mint_cannot_cross_runtime_request_sink(
    tmp_path: Path,
) -> None:
    ambient = MF._ambient()
    ambient["CLAUDE_CODE_OAUTH_TOKEN"] = "private-fixture-token"
    project = tmp_path / "project"
    project.mkdir()
    host = M.compile_claude_runtime_host_inputs(
        auth_route="OAUTH_TOKEN",
        ambient_environment=ambient,
        source_config_dir=None,
        project_root=project,
        trusted_cwds=(project,),
    )
    claimed = P._mint_claimed_claude_provider_runtime(
        host_inputs=host,
        bound_settings_bytes=b'{"forged":true}\n',
        selected_mcp_config_bytes=b'{"mcpServers":{"forged":{}}}\n',
        attachment_sha256="4" * 64,
    )
    kwargs = _request_kwargs_for_claimed_host(
        tmp_path=tmp_path,
        claimed=claimed,
        ambient=ambient,
    )
    with pytest.raises(
        (P.ClaudeProviderPreparationError,
         M.ClaudeRuntimeMaterializationError),
        match="parent|provider|authority|runtime-local",
    ):
        M.compile_claude_runtime_materialization_request(**kwargs)


def test_claimed_host_cannot_downgrade_into_raw_request_lane(
    tmp_path: Path,
) -> None:
    ambient = MF._ambient()
    ambient["CLAUDE_CODE_OAUTH_TOKEN"] = "private-fixture-token"
    project = tmp_path / "project"
    project.mkdir()
    host = M.compile_claude_runtime_host_inputs(
        auth_route="OAUTH_TOKEN",
        ambient_environment=ambient,
        source_config_dir=None,
        project_root=project,
        trusted_cwds=(project,),
    )
    claimed = P._mint_claimed_claude_provider_runtime(
        host_inputs=host,
        bound_settings_bytes=None,
        selected_mcp_config_bytes=None,
        attachment_sha256="6" * 64,
    )
    kwargs = MF._kwargs(
        tmp_path=tmp_path,
        attempt_id="r4-raw-host-downgrade",
        route="OAUTH_TOKEN",
        ambient=ambient,
    )
    kwargs["host_inputs"] = claimed.host_inputs
    with pytest.raises(
        M.ClaudeRuntimeMaterializationError,
        match="provider runtime is required|provider parent",
    ):
        M.compile_claude_runtime_materialization_request(**kwargs)


def test_object_new_and_issued_insert_cannot_cross_runtime_request_sink(
    tmp_path: Path,
) -> None:
    ambient = MF._ambient()
    ambient["CLAUDE_CODE_OAUTH_TOKEN"] = "private-fixture-token"
    project = tmp_path / "project"
    project.mkdir()
    host = M.compile_claude_runtime_host_inputs(
        auth_route="OAUTH_TOKEN",
        ambient_environment=ambient,
        source_config_dir=None,
        project_root=project,
        trusted_cwds=(project,),
    )
    forged = object.__new__(P.ClaimedClaudeProviderRuntime)
    object.__setattr__(
        forged,
        "_ClaimedClaudeProviderRuntime__host_inputs",
        host,
    )
    object.__setattr__(
        forged,
        "_ClaimedClaudeProviderRuntime__bound_settings_bytes",
        b'{"forged":true}\n',
    )
    object.__setattr__(
        forged,
        "_ClaimedClaudeProviderRuntime__selected_mcp_config_bytes",
        None,
    )
    object.__setattr__(
        forged,
        "_ClaimedClaudeProviderRuntime__attachment_sha256",
        "5" * 64,
    )
    state = {
        "host_inputs": host,
        "host_inputs_sha256": host.host_inputs_sha256,
        "bound_settings_sha256": hashlib.sha256(
            b'{"forged":true}\n'
        ).hexdigest(),
        "selected_mcp_config_sha256": None,
        "attachment_sha256": "5" * 64,
        "issuer_pid": os.getpid(),
    }
    P._CLAIMED_ISSUED[id(forged)] = (weakref.ref(forged), state)
    kwargs = _request_kwargs_for_claimed_host(
        tmp_path=tmp_path,
        claimed=forged,
        ambient=ambient,
    )
    with pytest.raises(
        (P.ClaudeProviderPreparationError,
         M.ClaudeRuntimeMaterializationError),
        match="parent|provider|authority|runtime-local",
    ):
        M.compile_claude_runtime_materialization_request(**kwargs)


def test_consumed_host_global_state_reset_cannot_reclaim(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    host = M.compile_claude_runtime_host_inputs(
        auth_route="OAUTH_TOKEN",
        ambient_environment={
            "CLAUDE_CODE_OAUTH_TOKEN": "private-fixture-token"
        },
        source_config_dir=None,
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
    host._claim()
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
    M._HOST_INPUT_ISSUED[id(host)][1]["consumed"] = False
    with pytest.raises(
        M.ClaudeRuntimeMaterializationError,
        match="already claimed",
    ):
        host._claim()


def test_exact_provider_parent_reaches_request_and_materialization_sinks(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    package_values = PF._inputs(tmp_path, route="OAUTH_TOKEN")
    original_intent = package_values["semantic_intent"]
    package_values["semantic_intent"] = (
        P.compile_claude_provider_semantic_intent(
            run_id=FIXTURE_RUN_ID,
            phase=original_intent["phase"],
            backend=original_intent["backend"],
            launch_model=original_intent["launch_model"],
            accepted_models=original_intent["accepted_models"],
            cwd=original_intent["cwd"],
            session_id=original_intent["session_id"],
            max_line_bytes=original_intent["max_line_bytes"],
            max_stream_bytes=original_intent["max_stream_bytes"],
            desired_auth_route=original_intent[
                "desired_auth_route"
            ],
            home_variable_policy=original_intent[
                "home_variable_policy"
            ],
            phase_environment_policies=original_intent[
                "phase_environment_policies"
            ],
            functional_controls=original_intent[
                "functional_controls"
            ],
            required_capabilities=original_intent[
                "required_capabilities"
            ],
            forbidden_capabilities=original_intent[
                "forbidden_capabilities"
            ],
            accepted_output_styles=original_intent[
                "accepted_output_styles"
            ],
        )
    )
    scratchpad = Path(package_values["startup_scratchpad"])
    startup = durable_startup_permit(
        scratchpad,
        run_id=FIXTURE_RUN_ID,
    )
    package_values["startup_authority_binding"] = startup
    PF._install_observers(
        monkeypatch,
        Path(str(package_values["configured_claude_bin"])),
    )
    package = P.prepare_claude_provider(
        **PF._public_inputs(package_values)
    )
    command = package.command_for_bound_stdin()
    end = command.index("--no-session-persistence") + 1
    monkeypatch.setattr(
        AUX,
        "_default_runtime_namespace",
        lambda: tmp_path / "runtime-authority",
    )
    def claimed_runtime() -> P.ClaimedClaudeProviderRuntime:
        bound = PF._attach(package, package_values)
        return P.claim_bound_claude_provider_runtime(
            bound,
            provider_preparation=package,
            expected_preparation_sha256=package.preparation_sha256,
            expected_runtime_host_policy_sha256=package.record[
                "runtime_host_policy"
            ]["policy_sha256"],
            expected_attachment_sha256=bound.attachment_sha256,
        )

    def runtime_request(
        claimed: P.ClaimedClaudeProviderRuntime,
        *,
        suffix: str,
    ) -> M.ClaudeRuntimeMaterializationRequest:
        return M.compile_claude_runtime_materialization_request(
            launch_security_request=package.record[
                "launch_security_request"
            ],
            provider_runtime=claimed,
            base_argv=command[:end],
            scratchpad=scratchpad,
            startup_permit_binding=startup,
            run_id=FIXTURE_RUN_ID,
            outer_attempt_arm_sha256=PF._digest(
                {"outer-attempt-arm": suffix}
            ),
            work_plan_sha256=PF._digest({"work-plan": "r4-legitimate"}),
            attempt_id=f"r4-legitimate-provider-{suffix}",
            process_scope_identity=(
                f"scope-r4-legitimate-provider-{suffix}"
            ),
        )

    one_shot = claimed_runtime()
    assert P.consume_claimed_claude_provider_runtime(one_shot)[
        "provider_preparation"
    ].preparation_sha256 == package.preparation_sha256
    with pytest.raises(
        P.ClaudeProviderPreparationError,
        match="already consumed",
    ):
        P.consume_claimed_claude_provider_runtime(one_shot)

    discarded = runtime_request(claimed_runtime(), suffix="discarded")
    discard_receipt = discarded.discard()
    assert discard_receipt["discarded"] is True
    assert discarded.discard() == discard_receipt

    tampered = runtime_request(claimed_runtime(), suffix="tampered")
    object.__setattr__(
        tampered,
        "_ClaudeRuntimeMaterializationRequest__provider_runtime_parent",
        None,
    )
    with pytest.raises(
        M.ClaudeRuntimeMaterializationError,
        match=(
            "provider.parent|authority drifted|"
            "exact claimed provider runtime is required"
        ),
    ):
        M.materialize_claude_runtime(tampered)
    with pytest.raises(
        M.ClaudeRuntimeMaterializationError,
        match="provider.parent|authority drifted",
    ):
        tampered.discard()

    request = runtime_request(claimed_runtime(), suffix="accepted")
    result = M.materialize_claude_runtime(request)
    assert result.receipt["completion_capable"] is True
    assert result.receipt["selected_auth_route"] == "OAUTH_TOKEN"
    assert result.final_argv == command
    cleanup = result.abort_before_process_scope(
        "R4_LEGITIMATE_PROVIDER_ABORT"
    )
    assert cleanup["completion_authority"] is False
