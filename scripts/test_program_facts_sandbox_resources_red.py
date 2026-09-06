"""B0 RED fixtures for Program Facts sandbox resource authority."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Callable, Mapping

import pytest

from review_fixtures.program_facts_r2_1_b0_red_support import (
    require_accepts,
    require_callable,
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


def _resource_document() -> dict[str, Any]:
    document: dict[str, Any] = {
        "schema": "plamen.program_facts_sandbox_resource_authority.v1",
        "limits": {
            "descendant_memory_bytes": 512 * 1024 * 1024,
            "active_process_count": 8,
            "workspace_allocated_bytes": 128 * 1024 * 1024,
            "workspace_logical_bytes": 128 * 1024 * 1024,
            "workspace_file_count": 4096,
            "wall_time_ms": 120_000,
        },
        "enforcement": {
            "descendant_memory": "ENFORCED",
            "active_process_count": "ENFORCED",
            "workspace_allocated_bytes": "ENFORCED",
            "workspace_logical_bytes": "ENFORCED",
            "workspace_file_count": "ENFORCED",
            "wall_time": "ENFORCED",
        },
        "observed": {
            "peak_descendant_memory_bytes": 128 * 1024 * 1024,
            "peak_active_process_count": 2,
            "peak_workspace_allocated_bytes": 4096,
            "peak_workspace_logical_bytes": 4096,
            "peak_workspace_file_count": 3,
            "timeout_observed": False,
        },
        "open_handle_count_after_cleanup": 0,
        "process_population_after_cleanup": 0,
        "terminal_precedence": [
            "MEMORY_LIMIT",
            "PROCESS_LIMIT",
            "WORKSPACE_QUOTA",
            "TIMEOUT",
            "CANCELLED",
        ],
        "concurrent_terminal_events": [],
        "selected_terminal_event": "OK",
    }
    _assert_resource_positive(document)
    return document


def _assert_resource_positive(document: Mapping[str, Any]) -> None:
    limits = document["limits"]
    observed = document["observed"]
    assert observed["peak_descendant_memory_bytes"] <= limits[
        "descendant_memory_bytes"
    ]
    assert observed["peak_active_process_count"] <= limits[
        "active_process_count"
    ]
    assert observed["peak_workspace_allocated_bytes"] <= limits[
        "workspace_allocated_bytes"
    ]
    assert observed["peak_workspace_logical_bytes"] <= limits[
        "workspace_logical_bytes"
    ]
    assert observed["peak_workspace_file_count"] <= limits[
        "workspace_file_count"
    ]
    assert all(
        state == "ENFORCED"
        for state in document["enforcement"].values()
    )
    assert document["open_handle_count_after_cleanup"] == 0
    assert document["process_population_after_cleanup"] == 0
    assert len(document["terminal_precedence"]) == len(
        set(document["terminal_precedence"])
    )


def _resource_validator(law: str) -> Callable[..., Any]:
    return require_callable(
        ENVIRONMENT_MODULE,
        "validate_sandbox_resource_authority_v1",
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


def _accept_resource_positive(
    validator: Callable[..., Any],
    law: str,
    document: Mapping[str, Any],
) -> None:
    _assert_resource_positive(document)
    require_accepts(validator, law, document)


def _windows_resource_document() -> dict[str, Any]:
    document: dict[str, Any] = {
        "boundary_profile": "WINDOWS_HYPERV_HCS_PROVIDER_BOUNDARY_V1",
        "capability_states": {
            capability: {
                "configured": True,
                "observed": True,
                "enforced": True,
            }
            for capability in WINDOWS_CAPABILITIES
        },
        "readback": {
            "job_memory_and_process_limits": True,
            "hcs_compute_system_limits": True,
            "vhdx_capacity_and_file_record_bound": True,
        },
        "quota_evidence": {
            "fixed_vhdx_capacity": True,
            "fixed_ntfs_file_record_bound": True,
            "sparse_logical_and_allocated_bounds": True,
        },
        "terminal_evidence": {
            "active_process_zero": True,
            "descendant_count_zero": True,
        },
        "cleanup_evidence": {
            "output_flushed": True,
            "vhdx_flushed": True,
            "vhdx_detached": True,
            "hcs_terminated": True,
        },
    }
    _assert_windows_resource_positive(document)
    return document


def _assert_windows_resource_positive(
    document: Mapping[str, Any],
) -> None:
    assert document["boundary_profile"] == (
        "WINDOWS_HYPERV_HCS_PROVIDER_BOUNDARY_V1"
    )
    assert tuple(document["capability_states"]) == WINDOWS_CAPABILITIES
    assert all(
        state
        == {"configured": True, "observed": True, "enforced": True}
        for state in document["capability_states"].values()
    )
    for group in ("readback", "quota_evidence", "terminal_evidence"):
        assert all(document[group].values())
    assert all(document["cleanup_evidence"].values())


def _windows_resource_validator(law: str) -> Callable[..., Any]:
    return require_callable(
        WINDOWS_SANDBOX_MODULE,
        "validate_windows_resource_authority_v1",
        law,
    )


def _accept_windows_resource_positive(
    validator: Callable[..., Any],
    law: str,
    document: Mapping[str, Any],
) -> None:
    _assert_windows_resource_positive(document)
    require_accepts(validator, law, document)


def test_a9_child_and_descendant_memory_exhaustion_is_contained() -> None:
    law = "A9/descendant-aggregate-memory-enforcement"
    positive = _resource_document()
    validator = _resource_validator(law)
    _accept_resource_positive(validator, law, positive)
    mutation = deepcopy(positive)
    mutation["observed"]["peak_descendant_memory_bytes"] = (
        mutation["limits"]["descendant_memory_bytes"] + 1
    )
    mutation["selected_terminal_event"] = "OK"
    _require_targeted_rejection(
        validator,
        law,
        "PF_A9_MEMORY_EXHAUSTION_UNCONTAINED",
        mutation,
    )


def test_a9_process_fanout_hits_enforced_limit() -> None:
    law = "A9/descendant-process-fanout-enforcement"
    positive = _resource_document()
    validator = _resource_validator(law)
    _accept_resource_positive(validator, law, positive)
    mutation = deepcopy(positive)
    mutation["observed"]["peak_active_process_count"] = (
        mutation["limits"]["active_process_count"] + 1
    )
    mutation["selected_terminal_event"] = "OK"
    _require_targeted_rejection(
        validator,
        law,
        "PF_A9_PROCESS_LIMIT_NOT_ENFORCED",
        mutation,
    )


def test_a9_many_file_and_sparse_file_quota_is_enforced() -> None:
    law = "A9/workspace-byte-file-and-sparse-quota"
    positive = _resource_document()
    validator = _resource_validator(law)
    _accept_resource_positive(validator, law, positive)
    mutation = deepcopy(positive)
    mutation["observed"]["peak_workspace_logical_bytes"] = (
        mutation["limits"]["workspace_logical_bytes"] + 1
    )
    mutation["selected_terminal_event"] = "OK"
    _require_targeted_rejection(
        validator,
        law,
        "PF_A9_WORKSPACE_QUOTA_NOT_ENFORCED",
        mutation,
    )


def test_a9_open_handles_close_and_process_population_reaches_zero() -> None:
    law = "A9/terminal-handle-and-process-zero"
    positive = _resource_document()
    validator = _resource_validator(law)
    _accept_resource_positive(validator, law, positive)
    mutation = deepcopy(positive)
    mutation["open_handle_count_after_cleanup"] = 1
    _require_targeted_rejection(
        validator,
        law,
        "PF_A9_TERMINAL_QUIESCENCE_NOT_PROVEN",
        mutation,
    )


def test_a9_timeout_racing_resource_exhaustion_has_stable_precedence() -> None:
    law = "A9/concurrent-terminal-event-stable-precedence"
    positive = _resource_document()
    validator = _resource_validator(law)
    _accept_resource_positive(validator, law, positive)
    mutation = deepcopy(positive)
    mutation["concurrent_terminal_events"] = ["TIMEOUT", "MEMORY_LIMIT"]
    mutation["selected_terminal_event"] = "TIMEOUT"
    _require_targeted_rejection(
        validator,
        law,
        "PF_A9_TERMINAL_PRECEDENCE_DIVERGED",
        mutation,
    )


def test_a9_configured_observed_and_enforced_capability_mismatch_rejected() -> None:
    law = "A9/configured-observed-enforced-are-distinct"
    positive = _resource_document()
    validator = _resource_validator(law)
    _accept_resource_positive(validator, law, positive)
    mutation = deepcopy(positive)
    mutation["enforcement"]["descendant_memory"] = "CONFIGURED_ONLY"
    _require_targeted_rejection(
        validator,
        law,
        "PF_A9_CAPABILITY_STATE_MISMATCH",
        mutation,
    )


def test_a9_windows_job_hcs_vhdx_capabilities_require_enforced_observed_readback() -> None:
    law = "A9/windows-job-hcs-vhdx-enforced-observed-readback"
    positive = _windows_resource_document()
    validator = _windows_resource_validator(law)
    _accept_windows_resource_positive(validator, law, positive)
    mutation = deepcopy(positive)
    mutation["capability_states"][
        "JOB_HCS_RESOURCE_ENFORCEMENT_AND_READBACK"
    ]["enforced"] = False
    _require_targeted_rejection(
        validator,
        law,
        "PF_A9_WINDOWS_RESOURCE_READBACK_UNPROVEN",
        mutation,
    )


@pytest.mark.parametrize(
    "mutation_class",
    (
        pytest.param("configured-only", id="configured-only"),
        pytest.param(
            "missing-job-readback",
            id="missing-job-readback",
        ),
        pytest.param(
            "missing-hcs-readback",
            id="missing-hcs-readback",
        ),
        pytest.param(
            "missing-vhdx-readback",
            id="missing-vhdx-readback",
        ),
    ),
)
def test_a9_windows_configured_only_or_missing_job_hcs_vhdx_readback_rejected(
    mutation_class: str,
) -> None:
    law = "A9/windows-resource-state-and-readback-totality"
    positive = _windows_resource_document()
    validator = _windows_resource_validator(law)
    _accept_windows_resource_positive(validator, law, positive)
    mutation = deepcopy(positive)
    if mutation_class == "configured-only":
        mutation["capability_states"][
            "JOB_HCS_RESOURCE_ENFORCEMENT_AND_READBACK"
        ]["observed"] = False
    elif mutation_class == "missing-job-readback":
        mutation["readback"]["job_memory_and_process_limits"] = False
    elif mutation_class == "missing-hcs-readback":
        mutation["readback"]["hcs_compute_system_limits"] = False
    else:
        mutation["readback"][
            "vhdx_capacity_and_file_record_bound"
        ] = False
    _require_targeted_rejection(
        validator,
        law,
        "PF_A9_WINDOWS_RESOURCE_READBACK_UNPROVEN",
        mutation,
    )


@pytest.mark.parametrize(
    "mutation_class",
    (
        pytest.param("missing-quota", id="missing-quota"),
        pytest.param(
            "missing-terminal-zero",
            id="missing-terminal-zero",
        ),
        pytest.param(
            "missing-flush-detach",
            id="missing-flush-detach",
        ),
    ),
)
def test_a9_windows_missing_quota_terminal_zero_or_flush_detach_evidence_rejected(
    mutation_class: str,
) -> None:
    law = "A9/windows-quota-terminal-zero-cleanup-totality"
    positive = _windows_resource_document()
    validator = _windows_resource_validator(law)
    _accept_windows_resource_positive(validator, law, positive)
    mutation = deepcopy(positive)
    if mutation_class == "missing-quota":
        mutation["quota_evidence"]["fixed_ntfs_file_record_bound"] = False
    elif mutation_class == "missing-terminal-zero":
        mutation["terminal_evidence"]["descendant_count_zero"] = False
    else:
        mutation["cleanup_evidence"]["vhdx_detached"] = False
    _require_targeted_rejection(
        validator,
        law,
        "PF_A9_WINDOWS_TERMINAL_EVIDENCE_INCOMPLETE",
        mutation,
    )
