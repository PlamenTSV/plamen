from __future__ import annotations

from copy import deepcopy
from typing import Any, Callable, Mapping

import pytest

from review_fixtures.program_facts_r2_1_b0_red_support import (
    body_digest,
    require_accepts,
    require_callable,
)


ENVIRONMENT_AUTHORITY_MODULE = "program_facts_evm_environment_authority"
LOCAL_PERMIT_VALIDATOR = "validate_local_activation_permit_v1"

H0 = "0" * 64
H1 = "1" * 64
H2 = "2" * 64
H3 = "3" * 64
H4 = "4" * 64
H5 = "5" * 64
H6 = "6" * 64
H7 = "7" * 64
H8 = "8" * 64
H9 = "9" * 64

WINDOWS_CAPABILITIES = (
    "PINNED_HELPER_RUNTIME_TOOL_EXECUTION_IDENTITY",
    "IMMUTABLE_READONLY_VHDX_READ_ROOT",
    "BOUNDED_WRITABLE_VHDX_ROOT",
    "SECRET_FREE_CLOSED_CHILD_ENVIRONMENT",
    "EXPLICIT_INHERITED_HANDLE_ALLOWLIST",
    "NO_NETWORK_ADAPTER",
    "NON_BREAKAWAY_GUEST_JOB_PROCESS_TREE_OWNERSHIP",
    "HCS_COMPUTE_SYSTEM_PROCESS_TREE_OWNERSHIP",
    "JOB_HCS_RESOURCE_ENFORCEMENT_AND_READBACK",
    "FIXED_VHDX_BYTE_AND_FILE_RECORD_BOUND",
    "TERMINAL_DESCENDANT_ZERO_EVIDENCE",
    "FLUSH_DETACH_CLEANUP_EVIDENCE",
)

LOCAL_SCOPE = {
    "authority_scope": (
        "LOCAL_WINDOWS_CLAUDE_EVM_AUDIT_TESTING_CANDIDATE"
    ),
    "pipeline_scope": "SMART_CONTRACT",
    "ecosystem_scope": "EVM",
    "backend_scope": "CLAUDE",
    "audit_mode_scope": "THOROUGH",
    "program_facts_mode_scope": "ACTIVE_EMIT_ONLY",
    "host_os": "WINDOWS",
    "host_architecture": "AMD64",
    "consumer_activation": False,
    "terminal_negative_authority": False,
}

SCOPE_REVIEW = {
    "path": (
        "review_fixtures/"
        "program_facts_local_windows_graph_active_scope_amendment_"
        "independent_review_r2_20260730.md"
    ),
    "size": 5814,
    "sha256": (
        "1bf333e19e5b088401f080e625a052a1db0163c2146f421a034ee11a2f5d8dc0"
    ),
}


def _positive_local_permit_carrier() -> dict[str, Any]:
    observed_capabilities = [
        {
            "capability_id": capability,
            "state": "ENFORCED",
            "configured": True,
            "observed": True,
            "evidence_scope": {
                "run_id": "fixture-run",
                "run_generation": 7,
                "host_os": "WINDOWS",
                "host_architecture": "AMD64",
            },
        }
        for capability in WINDOWS_CAPABILITIES
    ]
    permit: dict[str, Any] = {
        "schema_version": "plamen.program_facts_evm_activation_permit.v1",
        "permit_class": "PRODUCTION_RELEASE_POLICY",
        "run_id": "fixture-run",
        "run_generation": 7,
        "scope": deepcopy(LOCAL_SCOPE),
        "scope_review": deepcopy(SCOPE_REVIEW),
        "execution_authority_digest": H0,
        "composition_authority_digest": H1,
        "methodology_package_digest": H2,
        "provider_environment_digest": H3,
        "provider_package_digest": H4,
        "native_host_receipt_digest": H5,
        "code_manifest_digest": H6,
        "schema_manifest_digest": H7,
        "issuer_policy_digest": H8,
        "platform_capability": {
            "boundary_profile": (
                "WINDOWS_HYPERV_HCS_PROVIDER_BOUNDARY_V1"
            ),
            "provided_capabilities": list(WINDOWS_CAPABILITIES),
            "required_capabilities": list(WINDOWS_CAPABILITIES),
            "observed_capabilities": observed_capabilities,
        },
        "authority_ceiling": {
            "provider_execution": False,
            "consumer_activation": False,
            "terminal_negative_authority": False,
            "public_generation_selection": False,
        },
        "permit_digest": H0,
    }
    permit["permit_digest"] = body_digest(permit, "permit_digest")
    document: dict[str, Any] = {
        "schema_version": (
            "plamen.program_facts_local_activation_permit_carrier.v1"
        ),
        "request": {
            "run_id": "fixture-run",
            "run_generation": 7,
            "scope": deepcopy(LOCAL_SCOPE),
            "requested_mode": "ACTIVE_EMIT_ONLY",
        },
        "permit": permit,
        "observed_authority": {
            "execution_authority_digest": H0,
            "composition_authority_digest": H1,
            "methodology_package_digest": H2,
            "provider_environment_digest": H3,
            "provider_package_digest": H4,
            "native_host_receipt_digest": H5,
            "code_manifest_digest": H6,
            "schema_manifest_digest": H7,
            "issuer_policy_digest": H8,
        },
        "decision": {
            "state": "VALIDATED_B0_NO_EXECUTION_AUTHORITY",
            "permit_validated": True,
            "launched_process_count": 0,
        },
    }
    _assert_local_positive(document)
    return document


def _assert_local_positive(document: Mapping[str, Any]) -> None:
    request = document["request"]
    permit = document["permit"]
    assert request["run_id"] == permit["run_id"]
    assert request["run_generation"] == permit["run_generation"]
    assert request["scope"] == permit["scope"] == LOCAL_SCOPE
    assert permit["scope_review"] == SCOPE_REVIEW
    platform = permit["platform_capability"]
    assert platform["boundary_profile"] == (
        "WINDOWS_HYPERV_HCS_PROVIDER_BOUNDARY_V1"
    )
    assert platform["provided_capabilities"] == list(WINDOWS_CAPABILITIES)
    assert platform["required_capabilities"] == list(WINDOWS_CAPABILITIES)
    assert [
        row["capability_id"] for row in platform["observed_capabilities"]
    ] == list(WINDOWS_CAPABILITIES)
    assert all(
        row["state"] == "ENFORCED"
        and row["configured"] is True
        and row["observed"] is True
        and row["evidence_scope"]
        == {
            "run_id": "fixture-run",
            "run_generation": 7,
            "host_os": "WINDOWS",
            "host_architecture": "AMD64",
        }
        for row in platform["observed_capabilities"]
    )
    for field, observed in document["observed_authority"].items():
        assert permit[field] == observed
    assert permit["authority_ceiling"] == {
        "provider_execution": False,
        "consumer_activation": False,
        "terminal_negative_authority": False,
        "public_generation_selection": False,
    }
    assert permit["permit_digest"] == body_digest(permit, "permit_digest")
    assert document["decision"] == {
        "state": "VALIDATED_B0_NO_EXECUTION_AUTHORITY",
        "permit_validated": True,
        "launched_process_count": 0,
    }


def _validator(law: str) -> Callable[..., Any]:
    return require_callable(
        ENVIRONMENT_AUTHORITY_MODULE,
        LOCAL_PERMIT_VALIDATOR,
        law,
    )


def _accept_positive(
    validator: Callable[..., Any],
    law: str,
    document: Mapping[str, Any],
) -> Any:
    _assert_local_positive(document)
    return require_accepts(validator, law, document)


def _require_targeted_rejection(
    validator: Callable[..., Any],
    law: str,
    reason_code: str,
    document: Mapping[str, Any],
) -> None:
    try:
        result = validator(document)
    except Exception as exc:
        assert reason_code in str(exc), (
            f"R21_B0_RED[{law}]: wrong rejection cause: "
            f"{exc.__class__.__name__}: {exc}; expected {reason_code}"
        )
        return
    assert isinstance(result, Mapping), (
        f"R21_B0_RED[{law}]: rejection must carry {reason_code}"
    )
    assert result.get("accepted") is False
    assert result.get("reason_code") == reason_code


def _resign_permit(document: dict[str, Any]) -> None:
    permit = document["permit"]
    if isinstance(permit, dict):
        permit["permit_digest"] = body_digest(permit, "permit_digest")


def _require_denied_no_launch(
    validator: Callable[..., Any],
    law: str,
    document: Mapping[str, Any],
) -> None:
    try:
        result = validator(document)
    except Exception as exc:
        pytest.fail(
            f"R21_B0_RED[{law}]: valid missing-permit denial was "
            f"rejected: {exc.__class__.__name__}: {exc}",
            pytrace=False,
        )
    assert isinstance(result, Mapping), (
        f"R21_B0_RED[{law}]: denial must return a classified mapping"
    )
    assert result.get("accepted", True) is not False
    assert result.get("state") == "DENIED_MISSING_PERMIT"
    assert result.get("permit_validated") is False
    assert result.get("launched_process_count") == 0


def test_a13_active_requested_without_permit_launches_nothing() -> None:
    law = "A13/active-request-without-permit-is-no-launch"
    positive = _positive_local_permit_carrier()
    validator = _validator(law)
    _accept_positive(validator, law, positive)

    denied = deepcopy(positive)
    denied["permit"] = None
    denied["decision"] = {
        "state": "DENIED_MISSING_PERMIT",
        "permit_validated": False,
        "launched_process_count": 0,
    }
    _require_denied_no_launch(validator, law, denied)
    assert denied["decision"]["launched_process_count"] == 0


def test_a13_forged_or_test_only_permit_rejected_by_production_entry() -> None:
    law = "A13/production-entry-rejects-forged-and-test-only-permits"
    positive = _positive_local_permit_carrier()
    validator = _validator(law)
    _accept_positive(validator, law, positive)

    for permit_class in (
        "FORGED_SHAPE_ONLY",
        "TEST_ONLY_NONAUTHORITATIVE",
    ):
        mutation = deepcopy(positive)
        mutation["permit"]["permit_class"] = permit_class
        _resign_permit(mutation)
        _require_targeted_rejection(
            validator,
            law,
            "PF_A13_NONPRODUCTION_PERMIT_CLASS",
            mutation,
        )


def test_a13_permit_for_other_os_or_architecture_rejected() -> None:
    law = "A13/permit-host-row-is-exact"
    positive = _positive_local_permit_carrier()
    validator = _validator(law)
    _accept_positive(validator, law, positive)

    for field, replacement in (
        ("host_os", "LINUX"),
        ("host_architecture", "ARM64"),
    ):
        mutation = deepcopy(positive)
        mutation["permit"]["scope"][field] = replacement
        _resign_permit(mutation)
        _require_targeted_rejection(
            validator,
            law,
            "PF_A13_HOST_SCOPE_MISMATCH",
            mutation,
        )


def test_a13_code_schema_package_or_authority_drift_invalidates_permit() -> None:
    law = "A13/all-permit-authority-bindings-replay"
    positive = _positive_local_permit_carrier()
    validator = _validator(law)
    _accept_positive(validator, law, positive)

    for field in (
        "code_manifest_digest",
        "schema_manifest_digest",
        "provider_package_digest",
        "execution_authority_digest",
        "composition_authority_digest",
    ):
        mutation = deepcopy(positive)
        mutation["permit"][field] = H9
        _resign_permit(mutation)
        _require_targeted_rejection(
            validator,
            law,
            "PF_A13_PERMIT_AUTHORITY_DRIFT",
            mutation,
        )


def test_a13_accepted_permit_cannot_activate_any_consumer() -> None:
    law = "A13/permit-has-zero-consumer-authority"
    positive = _positive_local_permit_carrier()
    validator = _validator(law)
    _accept_positive(validator, law, positive)

    mutation = deepcopy(positive)
    mutation["permit"]["scope"]["consumer_activation"] = True
    mutation["permit"]["authority_ceiling"]["consumer_activation"] = True
    _resign_permit(mutation)
    _require_targeted_rejection(
        validator,
        law,
        "PF_A13_CONSUMER_ACTIVATION_FORBIDDEN",
        mutation,
    )


def test_a13_local_windows_scope_tuple_and_scope_review_binding_are_exact() -> None:
    law = "A13/local-windows-scope-and-review-binding-exact"
    positive = _positive_local_permit_carrier()
    validator = _validator(law)
    _accept_positive(validator, law, positive)

    for field, value in (
        ("backend_scope", "CODEX"),
        ("ecosystem_scope", "SOLANA"),
        ("audit_mode_scope", "CORE"),
        ("program_facts_mode_scope", "SHADOW_RAW"),
    ):
        mutation = deepcopy(positive)
        mutation["permit"]["scope"][field] = value
        _resign_permit(mutation)
        _require_targeted_rejection(
            validator,
            law,
            "PF_A13_LOCAL_SCOPE_TUPLE_DIVERGENCE",
            mutation,
        )

    review_mutation = deepcopy(positive)
    review_mutation["permit"]["scope_review"]["sha256"] = H9
    _resign_permit(review_mutation)
    _require_targeted_rejection(
        validator,
        law,
        "PF_A13_SCOPE_REVIEW_BINDING_DIVERGENCE",
        review_mutation,
    )


def test_a13_local_windows_permit_requires_all_twelve_observed_enforced_capabilities() -> None:
    law = "A13/windows-permit-requires-twelve-enforced-observations"
    positive = _positive_local_permit_carrier()
    validator = _validator(law)
    _accept_positive(validator, law, positive)

    missing = deepcopy(positive)
    missing["permit"]["platform_capability"]["observed_capabilities"].pop()
    _resign_permit(missing)
    _require_targeted_rejection(
        validator,
        law,
        "PF_A13_WINDOWS_CAPABILITY_DENOMINATOR_INCOMPLETE",
        missing,
    )

    configured_only = deepcopy(positive)
    configured_only["permit"]["platform_capability"][
        "observed_capabilities"
    ][0]["state"] = "CONFIGURED"
    configured_only["permit"]["platform_capability"][
        "observed_capabilities"
    ][0]["observed"] = False
    _resign_permit(configured_only)
    _require_targeted_rejection(
        validator,
        law,
        "PF_A13_WINDOWS_CAPABILITY_NOT_ENFORCED",
        configured_only,
    )


@pytest.mark.parametrize(
    "authority_attack",
    ("synthesize", "upgrade", "borrow"),
    ids=("synthesize", "upgrade", "borrow"),
)
def test_a13_local_windows_permit_cannot_synthesize_upgrade_or_borrow_capability(
    authority_attack: str,
) -> None:
    law = f"A13/windows-capability-authority-{authority_attack}"
    positive = _positive_local_permit_carrier()
    validator = _validator(law)
    _accept_positive(validator, law, positive)

    mutation = deepcopy(positive)
    platform = mutation["permit"]["platform_capability"]
    if authority_attack == "synthesize":
        platform["required_capabilities"].append(
            "SYNTHESIZED_UNOBSERVED_CAPABILITY"
        )
    elif authority_attack == "upgrade":
        platform["observed_capabilities"][0]["state"] = "OBSERVED"
        platform["observed_capabilities"][0]["configured"] = True
        platform["observed_capabilities"][0]["observed"] = True
    else:
        platform["observed_capabilities"][0]["evidence_scope"][
            "run_id"
        ] = "other-run"
    _resign_permit(mutation)
    _require_targeted_rejection(
        validator,
        law,
        {
            "synthesize": "PF_A13_CAPABILITY_SYNTHESIS_FORBIDDEN",
            "upgrade": "PF_A13_CAPABILITY_UPGRADE_FORBIDDEN",
            "borrow": "PF_A13_CAPABILITY_BORROW_FORBIDDEN",
        }[authority_attack],
        mutation,
    )
