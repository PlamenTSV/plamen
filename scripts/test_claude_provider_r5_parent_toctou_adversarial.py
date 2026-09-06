from __future__ import annotations

from pathlib import Path

import pytest

import auxiliary_writable_root_lease as AUX
import claude_provider_preparation as P
import claude_runtime_materialization as M
import test_claude_provider_preparation as PF
from test_support_startup_permit import (
    FIXTURE_RUN_ID,
    durable_startup_permit,
)


def _legitimate_request(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> M.ClaudeRuntimeMaterializationRequest:
    values = PF._inputs(tmp_path, route="OAUTH_TOKEN")
    intent = values["semantic_intent"]
    values["semantic_intent"] = P.compile_claude_provider_semantic_intent(
        run_id=FIXTURE_RUN_ID,
        phase=intent["phase"],
        backend=intent["backend"],
        launch_model=intent["launch_model"],
        accepted_models=intent["accepted_models"],
        cwd=intent["cwd"],
        session_id=intent["session_id"],
        max_line_bytes=intent["max_line_bytes"],
        max_stream_bytes=intent["max_stream_bytes"],
        desired_auth_route=intent["desired_auth_route"],
        home_variable_policy=intent["home_variable_policy"],
        phase_environment_policies=intent["phase_environment_policies"],
        functional_controls=intent["functional_controls"],
        required_capabilities=intent["required_capabilities"],
        forbidden_capabilities=intent["forbidden_capabilities"],
        accepted_output_styles=intent["accepted_output_styles"],
    )
    scratchpad = Path(values["startup_scratchpad"])
    startup = durable_startup_permit(
        scratchpad,
        run_id=FIXTURE_RUN_ID,
    )
    values["startup_authority_binding"] = startup
    PF._install_observers(
        monkeypatch,
        Path(str(values["configured_claude_bin"])),
    )
    package = P.prepare_claude_provider(**PF._public_inputs(values))
    command = package.command_for_bound_stdin()
    base_end = command.index("--no-session-persistence") + 1
    monkeypatch.setattr(
        AUX,
        "_default_runtime_namespace",
        lambda: tmp_path / "runtime-authority",
    )
    bound = PF._attach(package, values)
    claimed = P.claim_bound_claude_provider_runtime(
        bound,
        provider_preparation=package,
        expected_preparation_sha256=package.preparation_sha256,
        expected_runtime_host_policy_sha256=package.record[
            "runtime_host_policy"
        ]["policy_sha256"],
        expected_attachment_sha256=bound.attachment_sha256,
    )
    return M.compile_claude_runtime_materialization_request(
        launch_security_request=package.record[
            "launch_security_request"
        ],
        provider_runtime=claimed,
        base_argv=command[:base_end],
        scratchpad=scratchpad,
        startup_permit_binding=startup,
        run_id=FIXTURE_RUN_ID,
        outer_attempt_arm_sha256=PF._digest(
            {"outer-attempt-arm": "r5-parent-toctou"}
        ),
        work_plan_sha256=PF._digest(
            {"work-plan": "r5-parent-toctou"}
        ),
        attempt_id="r5-parent-toctou",
        process_scope_identity="scope-r5-parent-toctou",
    )


def test_public_sink_replays_the_same_parent_it_prechecked(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    request = _legitimate_request(monkeypatch, tmp_path)
    slot = (
        "_ClaudeRuntimeMaterializationRequest"
        "__provider_runtime_parent"
    )
    legitimate_parent = getattr(request, slot)
    expected_preparation = legitimate_parent[0].preparation_sha256
    expected_attachment = legitimate_parent[4]

    class ClearParentOnSecondIdentityRead:
        def __init__(self) -> None:
            self.reads = 0

        @property
        def preparation_sha256(self) -> str:
            self.reads += 1
            if self.reads == 2:
                object.__setattr__(request, slot, None)
            return expected_preparation

    probe = ClearParentOnSecondIdentityRead()
    object.__setattr__(
        request,
        slot,
        (
            probe,
            legitimate_parent[1],
            legitimate_parent[2],
            legitimate_parent[3],
            expected_attachment,
        ),
    )

    materialized = None
    try:
        materialized = M.materialize_claude_runtime(request)
    except M.ClaudeRuntimeMaterializationError:
        return
    finally:
        if materialized is not None:
            materialized.abort_before_process_scope(
                "R5_PARENT_TOCTOU_RED_CLEANUP"
            )
    pytest.fail(
        "public sink accepted a parent cleared between identity consume "
        "and canonical replay"
    )
