from __future__ import annotations

from copy import deepcopy

from review_fixtures.program_facts_r2_1_b0_red_support import (
    LINUX_PROVIDED_CAPABILITIES,
    assert_schema_accepts,
    assert_schema_rejects,
    linux_environment_document,
    linux_permit_document,
    permit_validation_kwargs,
    require_accepts,
    require_callable,
    require_rejects,
)


def test_a8_linux_receipt_names_exact_provided_and_not_provided_capabilities() -> None:
    law = "R2.1-1/exact-linux-capability-roster"
    document = linux_environment_document()
    assert_schema_accepts("provider_environment", document)
    validator = require_callable(
        "program_facts_evm_environment_authority",
        "validate_provider_environment_v1",
        law,
    )
    require_accepts(validator, law, document)


def test_a8_linux_profile_never_claims_same_uid_host_confidentiality() -> None:
    law = "R2.1-1/no-same-uid-confidentiality-claim"
    validator = require_callable(
        "program_facts_evm_environment_authority",
        "validate_provider_environment_v1",
        law,
    )
    positive = linux_environment_document()
    require_accepts(validator, law, positive)
    document = deepcopy(positive)
    document["linux_boundary"]["same_uid_host_confidentiality_claim"] = True
    assert_schema_rejects("provider_environment", document)
    require_rejects(validator, law, document)


def test_a13_permit_cannot_upgrade_same_uid_confidentiality_limitation() -> None:
    law = "R2.1-1/permit-cannot-upgrade-linux-limitation"
    validator = require_callable(
        "program_facts_evm_environment_authority",
        "validate_activation_permit_v1",
        law,
    )
    environment = linux_environment_document()
    positive = linux_permit_document()
    require_accepts(
        validator,
        law,
        positive,
        **permit_validation_kwargs(
            positive,
            provider_environment=environment,
        ),
    )
    permit = deepcopy(positive)
    permit["platform_capability"]["same_uid_host_confidentiality_claim"] = True
    assert_schema_rejects("activation_permit", permit)
    require_rejects(
        validator,
        law,
        permit,
        **permit_validation_kwargs(
            positive,
            provider_environment=environment,
        ),
    )


def test_a13_policy_requiring_unprovided_linux_confidentiality_denies_row() -> None:
    law = "R2.1-1/policy-requiring-unprovided-capability-denies"
    permit = linux_permit_document()
    environment = linux_environment_document()
    assert_schema_accepts("activation_permit", permit)
    assert_schema_accepts("provider_environment", environment)
    matcher = require_callable(
        "program_facts_evm_environment_authority",
        "match_activation_permit_v1",
        law,
    )
    require_accepts(
        matcher,
        law,
        permit,
        **permit_validation_kwargs(
            permit,
            provider_environment=environment,
        ),
        policy_required_capabilities=[
            "SECRET_FREE_CLOSED_CHILD_ENVIRONMENT",
            "NO_NETWORK_NAMESPACE_ACCESS",
        ],
    )
    require_rejects(
        matcher,
        law,
        permit,
        **permit_validation_kwargs(
            permit,
            provider_environment=environment,
        ),
        policy_required_capabilities=["SAME_UID_HOST_CONFIDENTIALITY"],
    )


def test_a15_linux_child_environment_remains_secret_free_despite_limitation() -> None:
    law = "R2.1-1/linux-child-environment-stays-secret-free"
    builder = require_callable(
        "program_facts_evm_environment_authority",
        "build_program_facts_child_environment_v1",
        law,
    )
    child = require_accepts(
        builder,
        law,
        provider_environment=linux_environment_document(),
        ambient_environment={
            "PATH": "host-path",
            "AWS_SECRET_ACCESS_KEY": "seeded-secret",
            "HTTPS_PROXY": "http://secret-proxy",
            "SSH_AUTH_SOCK": "secret-agent",
            "PLAMEN_ALLOWED_TOOL_PATH": "provider-only-path",
        },
    )
    assert isinstance(child, dict)
    serialized = repr(sorted(child.items()))
    assert "seeded-secret" not in serialized
    assert "secret-proxy" not in serialized
    assert "secret-agent" not in serialized
    assert "AWS_SECRET_ACCESS_KEY" not in child
    assert "HTTPS_PROXY" not in child
    assert "SSH_AUTH_SOCK" not in child


def test_a8_existing_file_environment_handle_network_resource_and_process_zero_denials_remain_required() -> None:
    law = "R2.1-1/limitation-does-not-waive-containment"
    environment = linux_environment_document()
    assert_schema_accepts("provider_environment", environment)
    validator = require_callable(
        "program_facts_evm_environment_authority",
        "validate_linux_native_containment_v1",
        law,
    )
    require_accepts(
        validator,
        law,
        environment,
        observed_capabilities={
            capability: True for capability in LINUX_PROVIDED_CAPABILITIES
        },
    )
    for missing_capability in LINUX_PROVIDED_CAPABILITIES[1:]:
        observations = {
            capability: capability != missing_capability
            for capability in LINUX_PROVIDED_CAPABILITIES
        }
        require_rejects(
            validator,
            law,
            environment,
            observed_capabilities=observations,
        )
