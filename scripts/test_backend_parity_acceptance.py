"""Exact Codex/Claude native-backend parity and routing acceptance."""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path

import pytest

import claude_stored_subscription_source as claude_credentials
import codex_stored_auth_source as codex_credentials
import posix_backend_execution as execution
import posix_backend_launch_policy as policy
from semantic_work_plan import BackendArmExecutionIdentity
import worker_execution_receipts as wer


RECEIPT = "a" * 64


def test_exact_backend_parity_matrix_has_no_mcp_or_daybreak_dependency() -> None:
    matrix = policy.backend_parity_acceptance_matrix()

    assert matrix["schema"] == policy.BACKEND_PARITY_ACCEPTANCE_SCHEMA
    assert set(matrix["backends"]) == {"claude", "codex"}
    assert matrix["common"] == {
        "backend_network": "VERIFIED_PROXY_ONLY",
        "credential_custody": (
            "NATIVE_PROCESS_DOMAIN_SPLIT_NO_DESCENDANT_READ_V1"
        ),
        "credential_descriptor_inherited": False,
        "credential_secret_in_outer_environment": False,
        "daybreak_model_required": False,
        "fallback": "EXPLICIT_AUTHORIZATION_AND_NEW_GENERATION_ONLY",
        "mcp_required": False,
        "model_availability": (
            "EXACT_CAPABILITY_RECEIPT_REQUIRED_BEFORE_SELECTION"
        ),
        "model_owned_children": False,
        "resume": {
            "backend_or_model_change": "NEW_EXECUTION_GENERATION",
            "mode": "EXACT_CHECKPOINT_REPLAY_NEW_NATIVE_ATTEMPT",
            "provider_conversation_resume": False,
            "same_backend_model_tools_required": True,
        },
        "retry_dispositions": {
            "AUTHENTICATION": "HARD_STOP",
            "CONTEXT_LIMIT": "NEW_PLAN_GENERATION_REQUIRED",
            "MALFORMED_STREAM": "HARD_STOP",
            "MODEL_UNAVAILABLE": "EXPLICIT_MODEL_GENERATION_REQUIRED",
            "OUTPUT_OVERFLOW": "HARD_STOP",
            "POLICY_REFUSAL": "NEW_PROMPT_GENERATION_REQUIRED",
            "RATE_OR_USAGE_LIMIT": "PAUSE_EXACT_ROUTE",
            "TRANSIENT_CAPACITY": (
                "RETRY_EXACT_ROUTE_OR_EXPLICIT_MODEL_GENERATION"
            ),
            "TRANSIENT_TRANSPORT": "RETRY_EXACT_ROUTE",
        },
        "stream_replay": {
            "digest_bound": True,
            "overflow_is_terminal": True,
            "requires_eof": True,
            "stderr_limit_bytes": 2 * 1024 * 1024,
            "stdout_limit_bytes": 8 * 1024 * 1024,
        },
        "tool_network": "DENY",
    }
    for backend in matrix["backends"].values():
        assert backend["tool_execution"] == "LOCAL_GUEST_NATIVE_TOOLS"
    serialized_routes = json.dumps(matrix["model_routes"], sort_keys=True).lower()
    assert "daybreak" not in serialized_routes
    assert policy.required_claude_mcp_bytes() == b'{"mcpServers":{}}'


def test_route_matrix_preserves_sol_default_and_capability_equivalents() -> None:
    routes = policy.backend_parity_acceptance_matrix()["model_routes"]
    assert routes == {
        "claude": {
            "R1_ECONOMY_STRUCTURED": ["claude-sonnet-5"],
            "R2_STANDARD_REASONING": ["claude-sonnet-5"],
            "R3_FRONTIER_REASONING": [
                "claude-opus-5",
                "claude-sonnet-5",
            ],
        },
        "codex": {
            "R1_ECONOMY_STRUCTURED": ["gpt-5.6-luna"],
            "R2_STANDARD_REASONING": [
                "gpt-5.6-terra",
                "gpt-5.6-luna",
            ],
            "R3_FRONTIER_REASONING": [
                "gpt-5.6-sol",
                "gpt-5.6-terra",
                "gpt-5.6-luna",
            ],
        },
    }


def test_model_resolution_never_silently_substitutes_or_uses_unverified_id() -> None:
    selected = policy.resolve_backend_model_route(
        backend="codex",
        model_capability_tier="R3_FRONTIER_REASONING",
        verified_available_models=["gpt-5.6-sol", "gpt-5.6-terra"],
        capability_receipt_sha256=RECEIPT,
    )
    assert selected["selected_model"] == "gpt-5.6-sol"
    assert selected["fallback_used"] is False
    assert selected["authority_class"] == "STRUCTURAL_SELECTION_ONLY"
    assert policy.replay_backend_model_route(selected) == selected

    with pytest.raises(policy.PosixBackendLaunchPolicyError, match="MODEL_UNAVAILABLE"):
        policy.resolve_backend_model_route(
            backend="codex",
            model_capability_tier="R3_FRONTIER_REASONING",
            verified_available_models=["gpt-5.6-terra", "gpt-5.6-luna"],
            capability_receipt_sha256=RECEIPT,
        )

    fallback = policy.resolve_backend_model_route(
        backend="codex",
        model_capability_tier="R3_FRONTIER_REASONING",
        verified_available_models=["gpt-5.6-terra", "gpt-5.6-luna"],
        capability_receipt_sha256=RECEIPT,
        allow_model_fallback=True,
    )
    assert fallback["selected_model"] == "gpt-5.6-terra"
    assert fallback["fallback_authorized"] is True
    assert fallback["fallback_used"] is True

    for field, replacement in (
        ("selected_model", "gpt-5.6-luna"),
        ("fallback_authorized", False),
        ("capability_receipt_sha256", "b" * 64),
        ("route_sha256", "b" * 64),
    ):
        tampered = {**fallback, field: replacement}
        with pytest.raises(
            policy.PosixBackendLaunchPolicyError,
            match="MODEL_ROUTE_REPLAY",
        ):
            policy.replay_backend_model_route(tampered)

    for unverified in ("gpt-daybreak-blue-latest", "account-default"):
        with pytest.raises(
            policy.PosixBackendLaunchPolicyError,
            match="MODEL_ROUTE|MODEL_UNAVAILABLE",
        ):
            policy.resolve_backend_model_route(
                backend="codex",
                model_capability_tier="R3_FRONTIER_REASONING",
                verified_available_models=[unverified],
                capability_receipt_sha256=RECEIPT,
                requested_model=unverified,
                allow_model_fallback=True,
            )


def test_claude_equivalent_requires_receipt_availability_and_explicit_fallback() -> None:
    with pytest.raises(policy.PosixBackendLaunchPolicyError, match="MODEL_FALLBACK"):
        policy.resolve_backend_model_route(
            backend="claude",
            model_capability_tier="R3_FRONTIER_REASONING",
            verified_available_models=["claude-sonnet-5"],
            capability_receipt_sha256=RECEIPT,
            requested_model="claude-sonnet-5",
        )
    selected = policy.resolve_backend_model_route(
        backend="claude",
        model_capability_tier="R3_FRONTIER_REASONING",
        verified_available_models=["claude-sonnet-5"],
        capability_receipt_sha256=RECEIPT,
        requested_model="claude-sonnet-5",
        allow_model_fallback=True,
    )
    assert selected["selected_model"] == "claude-sonnet-5"


def test_stream_limits_are_one_exact_cross_backend_denominator() -> None:
    assert policy.STDOUT_LIMIT_BYTES == wer.DEFAULT_STDOUT_LIMIT_BYTES
    assert policy.STDERR_LIMIT_BYTES == wer.DEFAULT_STDERR_LIMIT_BYTES
    assert execution.BACKEND_STDOUT_LIMIT_BYTES == policy.STDOUT_LIMIT_BYTES
    assert execution.BACKEND_STDERR_LIMIT_BYTES == policy.STDERR_LIMIT_BYTES
    assert policy.STDOUT_LIMIT_BYTES <= execution.NATIVE_STREAM_OBSERVED_LIMIT_BYTES
    assert policy.STDERR_LIMIT_BYTES <= execution.NATIVE_STREAM_OBSERVED_LIMIT_BYTES


def test_credential_sources_fit_one_private_noninherited_fd_denominator() -> None:
    assert codex_credentials.MAX_CODEX_AUTH_BYTES == policy.MAX_CREDENTIAL_BYTES
    assert (
        claude_credentials.MAX_CREDENTIAL_FILE_BYTES
        == policy.MAX_CREDENTIAL_BYTES
    )
    matrix = policy.backend_parity_acceptance_matrix()
    assert matrix["backends"]["claude"]["credential_delivery"] == (
        policy.CLAUDE_CREDENTIAL_DELIVERY
    )
    assert matrix["backends"]["claude"]["credential_materialization_path"] == (
        policy.CLAUDE_CREDENTIAL_MATERIALIZATION_PATH
    )
    assert "ENV" not in policy.CLAUDE_CREDENTIAL_DELIVERY


def test_resume_identity_rejects_backend_or_model_substitution() -> None:
    original = BackendArmExecutionIdentity(
        semantic_work_unit_key="1" * 64,
        semantic_digest="2" * 64,
        backend_arm_id="arm-a",
        backend="codex",
        execution_generation=1,
        exact_model_id="gpt-5.6-sol",
        model_capability_tier="R3_FRONTIER_REASONING",
        capability_receipt_digest=RECEIPT,
    )
    assert replace(original).is_exact_resume_of(original)
    assert not replace(original, exact_model_id="gpt-5.6-terra").is_exact_resume_of(
        original
    )
    assert not replace(
        original,
        backend="claude",
        exact_model_id="claude-opus-5",
    ).is_exact_resume_of(original)


def test_driver_has_no_account_default_or_rejection_derived_model_route() -> None:
    source = (Path(__file__).parent / "plamen_driver.py").read_text(
        encoding="utf-8",
    )
    assert source.count("_build_codex_cmd_no_model(") == 1
    assert 'config["_codex_skip_model"] = True' not in source
    assert 'config["_codex_model_fallback"] =' not in source
    assert 'config["_codex_phase_model_fallbacks"]' not in source
    assert "Account-default retry is forbidden" in source
    assert (
        'order = ("gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna")'
        in source
    )
