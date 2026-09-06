"""B0 RED fixtures for Program Facts sandbox read-boundary authority."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from typing import Any, Callable, Mapping

from jsonschema import Draft202012Validator
import pytest

from review_fixtures.program_facts_r2_1_b0_red_support import (
    require_accepts,
    require_callable,
)


ROOT = Path(__file__).resolve().parents[1]
PROVIDER_ENVIRONMENT_SCHEMA = (
    ROOT
    / "rules"
    / "schemas"
    / "program_facts_evm_provider_environment.v1.schema.json"
)
ENVIRONMENT_MODULE = "program_facts_evm_environment_authority"
WINDOWS_SANDBOX_MODULE = "windows_hyperv_provider_sandbox"
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


def _sandbox_document() -> dict[str, Any]:
    document = {
        "schema": "plamen.program_facts_sandbox_read_boundary.v1",
        "read_roots": [
            "semantic://approved-os-runtime/",
            "semantic://build-input/",
            "semantic://provider-runtime/",
        ],
        "execute_allowlist": [
            {
                "semantic_path": "semantic://provider-runtime/python.exe",
                "sha256": "1" * 64,
            },
            {
                "semantic_path": "semantic://toolchain/solc.exe",
                "sha256": "2" * 64,
            },
        ],
        "inherited_handle_allowlist": ["STDIN", "STDOUT", "STDERR"],
        "child_environment_secret_free": True,
        "descendant_environment_secret_free": True,
        "network_interfaces": [],
        "network_routes": [],
        "link_policy": "NO_LINK_REPARSE_OR_ALIAS_ESCAPE",
        "allowed_runtime_imports": [
            "semantic://provider-runtime/site-packages/slither/__init__.py"
        ],
        "denied_secret_observations": {
            "seeded-secret": "DENIED",
            "credential-handle": "DENIED",
        },
        "canonical_streams": ["bounded stdout", "bounded stderr"],
        "canonical_diagnostics": ["READ_BOUNDARY_DENIED"],
        "canonical_cas_strings": ["schema-valid raw carrier"],
    }
    _assert_sandbox_positive(document)
    return document


def _assert_sandbox_positive(document: Mapping[str, Any]) -> None:
    assert document["read_roots"] == sorted(document["read_roots"])
    assert len(document["read_roots"]) == len(set(document["read_roots"]))
    assert document["child_environment_secret_free"] is True
    assert document["descendant_environment_secret_free"] is True
    assert document["network_interfaces"] == []
    assert document["network_routes"] == []
    assert document["link_policy"] == "NO_LINK_REPARSE_OR_ALIAS_ESCAPE"
    assert document["allowed_runtime_imports"]
    assert all(
        state == "DENIED"
        for state in document["denied_secret_observations"].values()
    )
    serialized = repr(
        (
            document["canonical_streams"],
            document["canonical_diagnostics"],
            document["canonical_cas_strings"],
        )
    )
    assert "seeded-secret" not in serialized
    assert "credential-handle" not in serialized


def _read_validator(law: str) -> Callable[..., Any]:
    return require_callable(
        ENVIRONMENT_MODULE,
        "validate_sandbox_read_boundary_v1",
        law,
    )


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


def _accept_sandbox_positive(
    validator: Callable[..., Any],
    law: str,
    document: Mapping[str, Any],
) -> None:
    _assert_sandbox_positive(document)
    require_accepts(validator, law, document)


def _windows_environment_document() -> dict[str, Any]:
    return {
        "schema_version": (
            "plamen.program_facts_evm_provider_environment.v1"
        ),
        "environment_digest": "1" * 64,
        "sandbox_receipt_digest": "2" * 64,
        "platform": "WINDOWS",
        "linux_boundary": None,
        "windows_boundary": {
            "boundary_profile": (
                "WINDOWS_HYPERV_HCS_PROVIDER_BOUNDARY_V1"
            ),
            "provided_capabilities": list(WINDOWS_CAPABILITIES),
        },
    }


def _load_environment_schema() -> Mapping[str, Any]:
    assert PROVIDER_ENVIRONMENT_SCHEMA.is_file()
    schema = json.loads(
        PROVIDER_ENVIRONMENT_SCHEMA.read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    return schema


def _require_windows_schema_positive(
    law: str,
    document: Mapping[str, Any],
) -> Draft202012Validator:
    validator = Draft202012Validator(_load_environment_schema())
    errors = list(validator.iter_errors(document))
    if errors:
        pytest.fail(
            f"R21_B0_RED[{law}]: "
            "PF_A8_WINDOWS_SCHEMA_PROFILE_ABSENT: "
            f"{errors[0].message}",
            pytrace=False,
        )
    boundary = document["windows_boundary"]
    assert boundary["boundary_profile"] == (
        "WINDOWS_HYPERV_HCS_PROVIDER_BOUNDARY_V1"
    )
    assert tuple(boundary["provided_capabilities"]) == WINDOWS_CAPABILITIES
    return validator


def _require_schema_rejects(
    law: str,
    validator: Draft202012Validator,
    document: Mapping[str, Any],
) -> None:
    errors = list(validator.iter_errors(document))
    assert errors, (
        f"R21_B0_RED[{law}]: "
        "PF_A8_WINDOWS_SCHEMA_MUTATION_ACCEPTED"
    )


def _windows_evidence_document(law: str) -> dict[str, Any]:
    document: dict[str, Any] = {
        "provider_environment": _windows_environment_document(),
        "capability_states": {
            capability: {
                "configured": True,
                "observed": True,
                "enforced": True,
            }
            for capability in WINDOWS_CAPABILITIES
        },
        "host_filesystem_shares": [],
        "network_adapters": [],
        "guest_job_breakaway_allowed": False,
        "inherited_handles": ["STDIN", "STDOUT", "STDERR"],
        "inherited_handle_allowlist": ["STDIN", "STDOUT", "STDERR"],
        "borrowed_capabilities": [],
        "permit_upgraded_capabilities": [],
        "linux_shaped_evidence": False,
        "generic_windows_tag_only": False,
    }
    _assert_windows_evidence_positive(document, law)
    return document


def _assert_windows_evidence_positive(
    document: Mapping[str, Any],
    law: str,
) -> None:
    _require_windows_schema_positive(
        law,
        document["provider_environment"],
    )
    assert tuple(document["capability_states"]) == WINDOWS_CAPABILITIES
    assert all(
        state
        == {"configured": True, "observed": True, "enforced": True}
        for state in document["capability_states"].values()
    )
    assert document["host_filesystem_shares"] == []
    assert document["network_adapters"] == []
    assert document["guest_job_breakaway_allowed"] is False
    assert document["inherited_handles"] == document[
        "inherited_handle_allowlist"
    ]
    assert document["borrowed_capabilities"] == []
    assert document["permit_upgraded_capabilities"] == []
    assert document["linux_shaped_evidence"] is False
    assert document["generic_windows_tag_only"] is False


def _windows_validator(law: str) -> Callable[..., Any]:
    return require_callable(
        WINDOWS_SANDBOX_MODULE,
        "validate_windows_provider_boundary_v1",
        law,
    )


def _accept_windows_positive(
    validator: Callable[..., Any],
    law: str,
    document: Mapping[str, Any],
) -> None:
    _assert_windows_evidence_positive(document, law)
    require_accepts(validator, law, document)


def test_a8_child_cannot_read_seeded_secret_outside_allowlist() -> None:
    law = "A8/child-read-root-is-closed"
    positive = _sandbox_document()
    validator = _read_validator(law)
    _accept_sandbox_positive(validator, law, positive)
    mutation = deepcopy(positive)
    mutation["denied_secret_observations"]["seeded-secret"] = "READABLE"
    _require_targeted_rejection(
        validator,
        law,
        "PF_A8_READ_OUTSIDE_ALLOWLIST",
        mutation,
    )


def test_a8_child_and_grandchild_cannot_exfiltrate_handle_or_environment_secret() -> None:
    law = "A8/descendant-handle-and-environment-closure"
    positive = _sandbox_document()
    validator = _read_validator(law)
    _accept_sandbox_positive(validator, law, positive)
    mutation = deepcopy(positive)
    mutation["descendant_environment_secret_free"] = False
    _require_targeted_rejection(
        validator,
        law,
        "PF_A8_DESCENDANT_SECRET_OR_HANDLE_EXFILTRATION",
        mutation,
    )


def test_a8_child_and_grandchild_have_no_network_interface_or_route() -> None:
    law = "A8/no-network-interface-or-route"
    positive = _sandbox_document()
    validator = _read_validator(law)
    _accept_sandbox_positive(validator, law, positive)
    mutation = deepcopy(positive)
    mutation["network_routes"] = ["0.0.0.0/0"]
    _require_targeted_rejection(
        validator,
        law,
        "PF_A8_NETWORK_INTERFACE_OR_ROUTE_PRESENT",
        mutation,
    )


def test_a8_unpinned_executable_is_denied() -> None:
    law = "A8/execute-closure-is-pinned"
    positive = _sandbox_document()
    validator = _read_validator(law)
    _accept_sandbox_positive(validator, law, positive)
    mutation = deepcopy(positive)
    mutation["execute_allowlist"].append(
        {
            "semantic_path": "host://Windows/System32/cmd.exe",
            "sha256": None,
        }
    )
    _require_targeted_rejection(
        validator,
        law,
        "PF_A8_UNPINNED_EXECUTABLE",
        mutation,
    )


def test_a8_symlink_or_reparse_cannot_reach_readable_host_secret() -> None:
    law = "A8/no-link-reparse-read-escape"
    positive = _sandbox_document()
    validator = _read_validator(law)
    _accept_sandbox_positive(validator, law, positive)
    mutation = deepcopy(positive)
    mutation["link_policy"] = "FOLLOW_HOST_REPARSE_TARGET"
    _require_targeted_rejection(
        validator,
        law,
        "PF_A8_LINK_OR_REPARSE_ESCAPE",
        mutation,
    )


def test_a8_allowed_runtime_imports_work_inside_closed_boundary() -> None:
    law = "A8/closed-boundary-retains-approved-runtime"
    positive = _sandbox_document()
    validator = _read_validator(law)
    _accept_sandbox_positive(validator, law, positive)
    mutation = deepcopy(positive)
    mutation["allowed_runtime_imports"] = []
    _require_targeted_rejection(
        validator,
        law,
        "PF_A8_APPROVED_RUNTIME_IMPORT_UNAVAILABLE",
        mutation,
    )


def test_a8_denied_secret_never_appears_in_streams_diagnostics_or_cas() -> None:
    law = "A8/denied-secret-absent-from-canonical-artifacts"
    positive = _sandbox_document()
    validator = _read_validator(law)
    _accept_sandbox_positive(validator, law, positive)
    mutation = deepcopy(positive)
    mutation["canonical_diagnostics"].append(
        "denied path contained seeded-secret"
    )
    _require_targeted_rejection(
        validator,
        law,
        "PF_A8_DENIED_SECRET_DISCLOSURE",
        mutation,
    )


def test_a8_windows_hyperv_hcs_schema_accepts_exact_twelve_capabilities() -> None:
    law = "A8/windows-exact-twelve-capability-profile"
    environment = _windows_environment_document()
    _require_windows_schema_positive(law, environment)
    evidence = _windows_evidence_document(law)
    validator = _windows_validator(law)
    _accept_windows_positive(validator, law, evidence)


@pytest.mark.parametrize(
    "missing_capability",
    [
        pytest.param(capability, id=capability)
        for capability in WINDOWS_CAPABILITIES
    ],
)
def test_a8_windows_hyperv_hcs_missing_each_required_capability_rejected(
    missing_capability: str,
) -> None:
    law = "A8/windows-schema-rejects-each-missing-capability"
    positive = _windows_environment_document()
    validator = _require_windows_schema_positive(law, positive)
    mutation = deepcopy(positive)
    mutation["windows_boundary"]["provided_capabilities"].remove(
        missing_capability
    )
    _require_schema_rejects(law, validator, mutation)


@pytest.mark.parametrize(
    "mutation_class",
    (
        pytest.param("extra", id="extra"),
        pytest.param("duplicate", id="duplicate"),
        pytest.param("reordered", id="reordered"),
        pytest.param("unknown", id="unknown"),
    ),
)
def test_a8_windows_hyperv_hcs_extra_duplicate_reordered_or_unknown_capability_rejected(
    mutation_class: str,
) -> None:
    law = "A8/windows-schema-rejects-capability-roster-drift"
    positive = _windows_environment_document()
    validator = _require_windows_schema_positive(law, positive)
    mutation = deepcopy(positive)
    capabilities = mutation["windows_boundary"]["provided_capabilities"]
    if mutation_class == "extra":
        capabilities.append("BORROWED_UNREVIEWED_CAPABILITY")
    elif mutation_class == "duplicate":
        capabilities.append(capabilities[-1])
    elif mutation_class == "reordered":
        capabilities[0], capabilities[1] = capabilities[1], capabilities[0]
    else:
        capabilities[-1] = "UNKNOWN_CAPABILITY"
    _require_schema_rejects(law, validator, mutation)


@pytest.mark.parametrize(
    "mutation_class",
    (
        pytest.param("linux-shaped", id="linux-shaped"),
        pytest.param("generic", id="generic"),
        pytest.param("configured-only", id="configured-only"),
        pytest.param("permit-upgraded", id="permit-upgraded"),
    ),
)
def test_a8_windows_hyperv_hcs_linux_shaped_generic_configured_only_or_permit_upgraded_claim_rejected(
    mutation_class: str,
) -> None:
    law = "A8/windows-native-evidence-cannot-be-substituted"
    positive = _windows_evidence_document(law)
    validator = _windows_validator(law)
    _accept_windows_positive(validator, law, positive)
    mutation = deepcopy(positive)
    if mutation_class == "linux-shaped":
        mutation["linux_shaped_evidence"] = True
    elif mutation_class == "generic":
        mutation["generic_windows_tag_only"] = True
    elif mutation_class == "configured-only":
        mutation["capability_states"][
            "HCS_COMPUTE_SYSTEM_PROCESS_TREE_OWNERSHIP"
        ]["observed"] = False
    else:
        mutation["permit_upgraded_capabilities"] = [
            "NO_NETWORK_ADAPTER"
        ]
    _require_targeted_rejection(
        validator,
        law,
        "PF_A8_WINDOWS_BOUNDARY_CLAIM_INVALID",
        mutation,
    )


@pytest.mark.parametrize(
    "mutation_class",
    (
        pytest.param("host-share", id="host-share"),
        pytest.param("network-adapter", id="network-adapter"),
        pytest.param("breakaway", id="breakaway"),
        pytest.param(
            "missing-handle-allowlist",
            id="missing-handle-allowlist",
        ),
    ),
)
def test_a8_windows_hyperv_hcs_host_share_network_adapter_breakaway_or_missing_handle_allowlist_rejected(
    mutation_class: str,
) -> None:
    law = "A8/windows-closed-host-and-handle-boundary"
    positive = _windows_evidence_document(law)
    validator = _windows_validator(law)
    _accept_windows_positive(validator, law, positive)
    mutation = deepcopy(positive)
    if mutation_class == "host-share":
        mutation["host_filesystem_shares"] = ["C:/Users"]
    elif mutation_class == "network-adapter":
        mutation["network_adapters"] = ["default-switch"]
    elif mutation_class == "breakaway":
        mutation["guest_job_breakaway_allowed"] = True
    else:
        mutation["inherited_handle_allowlist"] = ["STDIN", "STDOUT"]
    _require_targeted_rejection(
        validator,
        law,
        "PF_A8_WINDOWS_CONTAINMENT_EVIDENCE_MISSING",
        mutation,
    )
