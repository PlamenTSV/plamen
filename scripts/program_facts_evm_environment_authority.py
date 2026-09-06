"""Pure environment/permit authority for the R2.1 Linux boundary.

This module validates control documents only.  It does not inspect the host,
launch a process, install a provider, or claim that a Linux host provides
same-UID hostile-process confidentiality.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
from types import MappingProxyType
from typing import Any

from program_facts_v2_contracts import (
    ProgramFactsTypeError,
    canonical_json_bytes,
    normalized_document,
    require_sha256,
)
LINUX_BOUNDARY_PROFILE = "LINUX_PROVIDER_BOUNDARY_V1"
LINUX_PROVIDED_CAPABILITIES = (
    "PINNED_HELPER_RUNTIME_TOOL_EXECUTION_IDENTITY",
    "IMMUTABLE_ENUMERATED_FILESYSTEM_READ_ROOTS",
    "BOUNDED_ENUMERATED_WRITABLE_ROOTS",
    "SECRET_FREE_CLOSED_CHILD_ENVIRONMENT",
    "CLOSED_INHERITED_FILE_DESCRIPTOR_SET",
    "NO_NETWORK_NAMESPACE_ACCESS",
    "CGROUP_PROCESS_TREE_AND_RESOURCE_OWNERSHIP",
    "TERMINAL_CGROUP_POPULATION_ZERO_EVIDENCE",
)
LINUX_LIMITATIONS = (
    "SAME_UID_HOST_CONFIDENTIALITY_NOT_PROVIDED",
    "GENERAL_HOSTILE_HOST_ISOLATION_NOT_PROVIDED",
)
UNPROVIDED_LINUX_CAPABILITIES = frozenset(
    {
        "SAME_UID_HOST_CONFIDENTIALITY",
        "GENERAL_HOSTILE_HOST_ISOLATION",
        "SAME_UID_PROCESS_MEMORY_OR_SIGNAL_ISOLATION",
    }
)
_ENV_SCHEMA = "program_facts_evm_provider_environment.v1.schema.json"
_PERMIT_SCHEMA = "program_facts_evm_activation_permit.v1.schema.json"
_SAFE_CHILD_ENVIRONMENT = MappingProxyType(
    {
        "PATH": "/program-facts/provider/bin",
        "HOME": "/program-facts/empty-home",
        "TMPDIR": "/program-facts/work/tmp",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
)
_ALLOWED_CHILD_KEYS = frozenset(_SAFE_CHILD_ENVIRONMENT)
_SECRET_MARKERS = (
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "PRIVATE_KEY",
    "API_KEY",
    "ACCESS_KEY",
    "CREDENTIAL",
    "AUTH_SOCK",
    "PROXY",
)
_REVIEW_ROLES = ("B", "C", "NATIVE_HOST", "PACKAGE")


def _validate_linux_boundary(boundary: Mapping[str, Any]) -> None:
    if boundary.get("boundary_profile") != LINUX_BOUNDARY_PROFILE:
        raise ProgramFactsTypeError("unexpected Linux boundary profile")
    if tuple(boundary.get("provided_capabilities", ())) != LINUX_PROVIDED_CAPABILITIES:
        raise ProgramFactsTypeError("Linux provided-capability roster is not exact")
    if tuple(boundary.get("limitations", ())) != LINUX_LIMITATIONS:
        raise ProgramFactsTypeError("Linux limitation roster is not exact")
    if boundary.get("same_uid_host_confidentiality_claim") is not False:
        raise ProgramFactsTypeError(
            "same-UID hostile-process confidentiality is not provided"
        )


def validate_provider_environment_v1(
    document: Mapping[str, Any],
) -> dict[str, Any]:
    normalized = normalized_document(
        document,
        schema_name=_ENV_SCHEMA,
        label="provider environment",
    )
    if normalized["platform"] == "LINUX":
        boundary = normalized.get("linux_boundary")
        if not isinstance(boundary, Mapping):
            raise ProgramFactsTypeError("Linux environment requires a boundary receipt")
        _validate_linux_boundary(boundary)
    elif normalized.get("linux_boundary") is not None:
        raise ProgramFactsTypeError(
            "non-Linux environment cannot claim the Linux boundary"
        )
    return normalized


def validate_activation_permit_v1(
    document: Mapping[str, Any],
    *,
    expected_run_id: str,
    expected_run_generation: int,
    expected_execution_authority_digest: str,
    expected_composition_authority_digest: str,
    expected_methodology_package_digest: str,
    expected_provider_environment_digest: str,
    expected_provider_package_digest: str,
    expected_native_host_receipt_digest: str,
    expected_independent_review_receipts: Mapping[str, str],
    expected_issuer_policy_digest: str,
    expected_issuer_id: str,
    expected_release_id: str,
    expected_activation_decision_digest: str,
    provider_environment: Mapping[str, Any],
) -> dict[str, Any]:
    permit = normalized_document(
        document,
        schema_name=_PERMIT_SCHEMA,
        label="activation permit",
    )
    permit_body = dict(permit)
    claimed_permit_digest = permit_body.pop("permit_digest")
    derived_permit_digest = hashlib.sha256(
        canonical_json_bytes(permit_body)
    ).hexdigest()
    if claimed_permit_digest != derived_permit_digest:
        raise ProgramFactsTypeError("activation permit self-digest diverges")

    scalar_expectations = {
        "run_id": (expected_run_id, "permit run_id diverges"),
        "run_generation": (
            expected_run_generation,
            "permit run_generation diverges",
        ),
        "execution_authority_digest": (
            expected_execution_authority_digest,
            "permit execution authority diverges",
        ),
        "composition_authority_digest": (
            expected_composition_authority_digest,
            "permit composition authority diverges",
        ),
        "methodology_package_digest": (
            expected_methodology_package_digest,
            "permit methodology package diverges",
        ),
        "provider_environment_digest": (
            expected_provider_environment_digest,
            "permit provider environment diverges",
        ),
        "provider_package_digest": (
            expected_provider_package_digest,
            "permit provider package diverges",
        ),
        "native_host_receipt_digest": (
            expected_native_host_receipt_digest,
            "permit native host receipt diverges",
        ),
        "issuer_policy_digest": (
            expected_issuer_policy_digest,
            "permit issuer policy diverges",
        ),
        "issuer_id": (expected_issuer_id, "permit issuer_id diverges"),
        "release_id": (expected_release_id, "permit release_id diverges"),
        "activation_decision_digest": (
            expected_activation_decision_digest,
            "permit activation decision diverges",
        ),
    }
    for key, (expected, message) in scalar_expectations.items():
        if permit[key] != expected:
            raise ProgramFactsTypeError(message)
    for key in (
        "execution_authority_digest",
        "composition_authority_digest",
        "methodology_package_digest",
        "provider_environment_digest",
        "provider_package_digest",
        "native_host_receipt_digest",
        "issuer_policy_digest",
        "activation_decision_digest",
    ):
        require_sha256(scalar_expectations[key][0], label=f"expected {key}")
    if (
        not isinstance(expected_run_generation, int)
        or isinstance(expected_run_generation, bool)
        or expected_run_generation < 0
    ):
        raise ProgramFactsTypeError("expected run generation is invalid")
    if not isinstance(expected_independent_review_receipts, Mapping):
        raise ProgramFactsTypeError("expected independent reviews must be a mapping")
    expected_reviews = dict(expected_independent_review_receipts)
    if tuple(sorted(expected_reviews)) != tuple(sorted(_REVIEW_ROLES)):
        raise ProgramFactsTypeError(
            "expected independent-review role denominator is not exact"
        )
    for role in _REVIEW_ROLES:
        require_sha256(expected_reviews[role], label=f"expected {role} review")
    observed_reviews = {
        row["role"]: row["sha256"] for row in permit["independent_review_receipts"]
    }
    if observed_reviews != expected_reviews:
        raise ProgramFactsTypeError(
            "permit independent review receipts diverge"
        )

    capability = permit["platform_capability"]
    if capability["os"] == "LINUX":
        _validate_linux_boundary(capability)
        required = tuple(capability["required_capabilities"])
        if len(required) != len(set(required)):
            raise ProgramFactsTypeError("required capabilities contain duplicates")
        if any(item not in LINUX_PROVIDED_CAPABILITIES for item in required):
            raise ProgramFactsTypeError(
                "permit requires a capability not provided by the Linux profile"
            )
    environment = validate_provider_environment_v1(provider_environment)
    if environment["environment_digest"] != expected_provider_environment_digest:
        raise ProgramFactsTypeError(
            "provider environment digest differs from expected authority"
        )
    if capability["os"] != environment["platform"]:
        raise ProgramFactsTypeError("permit and environment platforms differ")
    if (
        capability["sandbox_environment_receipt_digest"]
        != environment["sandbox_receipt_digest"]
    ):
        raise ProgramFactsTypeError(
            "permit does not bind the environment sandbox receipt"
        )
    if capability["os"] == "LINUX":
        boundary = environment["linux_boundary"]
        for key in (
            "boundary_profile",
            "provided_capabilities",
            "limitations",
            "same_uid_host_confidentiality_claim",
        ):
            if capability[key] != boundary[key]:
                raise ProgramFactsTypeError(
                    f"permit Linux boundary field {key!r} diverges"
                )
    return permit


def match_activation_permit_v1(
    document: Mapping[str, Any],
    *,
    provider_environment: Mapping[str, Any],
    expected_run_id: str,
    expected_run_generation: int,
    expected_execution_authority_digest: str,
    expected_composition_authority_digest: str,
    expected_methodology_package_digest: str,
    expected_provider_environment_digest: str,
    expected_provider_package_digest: str,
    expected_native_host_receipt_digest: str,
    expected_independent_review_receipts: Mapping[str, str],
    expected_issuer_policy_digest: str,
    expected_issuer_id: str,
    expected_release_id: str,
    expected_activation_decision_digest: str,
    policy_required_capabilities: Sequence[str] = (),
) -> dict[str, Any]:
    permit = validate_activation_permit_v1(
        document,
        provider_environment=provider_environment,
        expected_run_id=expected_run_id,
        expected_run_generation=expected_run_generation,
        expected_execution_authority_digest=expected_execution_authority_digest,
        expected_composition_authority_digest=expected_composition_authority_digest,
        expected_methodology_package_digest=expected_methodology_package_digest,
        expected_provider_environment_digest=expected_provider_environment_digest,
        expected_provider_package_digest=expected_provider_package_digest,
        expected_native_host_receipt_digest=expected_native_host_receipt_digest,
        expected_independent_review_receipts=expected_independent_review_receipts,
        expected_issuer_policy_digest=expected_issuer_policy_digest,
        expected_issuer_id=expected_issuer_id,
        expected_release_id=expected_release_id,
        expected_activation_decision_digest=expected_activation_decision_digest,
    )
    capability = permit["platform_capability"]
    requested = tuple(policy_required_capabilities)
    if not all(isinstance(item, str) and item for item in requested):
        raise ProgramFactsTypeError("policy capabilities must be nonempty strings")
    if len(requested) != len(set(requested)):
        raise ProgramFactsTypeError("policy capabilities contain duplicates")
    if any(item in UNPROVIDED_LINUX_CAPABILITIES for item in requested):
        raise ProgramFactsTypeError(
            "policy requires a capability explicitly not provided"
        )
    provided = frozenset(capability["provided_capabilities"])
    if not set(requested).issubset(provided):
        raise ProgramFactsTypeError(
            "policy requires a capability absent from the observed environment"
        )
    if not set(capability["required_capabilities"]).issubset(provided):
        raise ProgramFactsTypeError("permit required capabilities exceed provision")
    return permit


def build_program_facts_child_environment_v1(
    *,
    provider_environment: Mapping[str, Any],
    ambient_environment: Mapping[str, Any] | None = None,
    approved_environment: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Return a closed, secret-free child map without ambient inheritance.

    ``ambient_environment`` is accepted only so the caller can explicitly show
    that ambient state was considered and discarded.  It is never copied.
    Host-local values may be supplied only through the separately approved,
    exact ``approved_environment`` mapping.
    """

    validate_provider_environment_v1(provider_environment)
    if ambient_environment is not None and not isinstance(
        ambient_environment, Mapping
    ):
        raise ProgramFactsTypeError("ambient environment must be a mapping")
    result = dict(_SAFE_CHILD_ENVIRONMENT)
    if approved_environment is not None:
        if not isinstance(approved_environment, Mapping):
            raise ProgramFactsTypeError("approved environment must be a mapping")
        if not set(approved_environment).issubset(_ALLOWED_CHILD_KEYS):
            raise ProgramFactsTypeError("approved environment contains unknown keys")
        for key, value in approved_environment.items():
            if not isinstance(value, str) or "\x00" in value:
                raise ProgramFactsTypeError("approved environment values are invalid")
            if any(marker in key.upper() for marker in _SECRET_MARKERS):
                raise ProgramFactsTypeError("secret-bearing environment key denied")
            result[key] = value
    for key in result:
        if any(marker in key.upper() for marker in _SECRET_MARKERS):
            raise ProgramFactsTypeError("secret-bearing child environment key denied")
    return result


def validate_linux_native_containment_v1(
    provider_environment: Mapping[str, Any],
    *,
    observed_capabilities: Mapping[str, Any],
) -> dict[str, Any]:
    environment = validate_provider_environment_v1(provider_environment)
    if environment["platform"] != "LINUX":
        raise ProgramFactsTypeError("Linux containment requires a Linux environment")
    if not isinstance(observed_capabilities, Mapping):
        raise ProgramFactsTypeError("observed capabilities must be a mapping")
    if frozenset(observed_capabilities) != frozenset(LINUX_PROVIDED_CAPABILITIES):
        raise ProgramFactsTypeError(
            "observed Linux containment denominator is incomplete or extra"
        )
    if any(observed_capabilities[item] is not True for item in LINUX_PROVIDED_CAPABILITIES):
        raise ProgramFactsTypeError("a mandatory Linux containment capability failed")
    return {
        "accepted": True,
        "boundary_profile": LINUX_BOUNDARY_PROFILE,
        "provided_capabilities": list(LINUX_PROVIDED_CAPABILITIES),
        "limitations": list(LINUX_LIMITATIONS),
        "same_uid_host_confidentiality_claim": False,
    }


__all__ = [
    "LINUX_BOUNDARY_PROFILE",
    "LINUX_LIMITATIONS",
    "LINUX_PROVIDED_CAPABILITIES",
    "build_program_facts_child_environment_v1",
    "match_activation_permit_v1",
    "validate_activation_permit_v1",
    "validate_linux_native_containment_v1",
    "validate_provider_environment_v1",
]
