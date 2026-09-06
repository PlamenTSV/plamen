"""B0 RED fixtures for Program Facts portability and durability truth."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Callable, Mapping

import pytest

from review_fixtures.program_facts_r2_1_b0_red_support import (
    require_accepts,
    require_callable,
)


PORTABILITY_MODULE = "program_facts_portability_authority"
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


def _portability_document() -> dict[str, Any]:
    document: dict[str, Any] = {
        "schema": "plamen.program_facts_portability_durability.v1",
        "semantic_tree": [
            {
                "semantic_root_id": "audit-source",
                "portable_path": "contracts/Main.sol",
                "size": 128,
                "sha256": "1" * 64,
            },
            {
                "semantic_root_id": "provider-runtime",
                "portable_path": "python/python.exe",
                "size": 256,
                "sha256": "2" * 64,
            },
        ],
        "root_mappings": [
            {
                "host_id": "host-a",
                "mapping": {
                    "audit-source": "C:/audit/project",
                    "provider-runtime": "C:/provider/runtime",
                },
                "semantic_tree_digest": "3" * 64,
            },
            {
                "host_id": "host-b",
                "mapping": {
                    "audit-source": "D:/different/root/project",
                    "provider-runtime": "D:/different/root/runtime",
                },
                "semantic_tree_digest": "3" * 64,
            },
        ],
        "path_classifications": [
            {
                "input": "C:\\audit\\project\\contracts\\Main.sol",
                "class": "WINDOWS_DRIVE_ABSOLUTE",
            },
            {
                "input": "\\\\server\\share\\contracts\\Main.sol",
                "class": "WINDOWS_UNC_ABSOLUTE",
            },
            {
                "input": "//server/share/contracts/Main.sol",
                "class": "WINDOWS_UNC_ABSOLUTE",
            },
            {
                "input": (
                    "\\\\?\\C:\\audit\\project\\contracts\\"
                    + ("deep\\" * 40)
                    + "Main.sol"
                ),
                "class": "WINDOWS_LONG_PATH",
            },
            {
                "input": "/mnt/c/audit/project/contracts/Main.sol",
                "class": "WSL_LINUX_PATH",
            },
        ],
        "casefold_collision_policy": "REJECT",
        "durability": {
            "process_crash_atomic": True,
            "power_loss_durable": False,
            "directory_flush_supported": False,
            "file_flush_completed": True,
            "atomic_same_volume_rename_completed": True,
            "parent_directory_flush_completed": False,
        },
        "reuse": {
            "source_host_id": "host-a",
            "target_host_id": "host-a",
            "physical_path_equal": True,
            "semantic_mapping_receipt_equal": True,
            "reuse_authorized": True,
        },
    }
    _assert_portability_positive(document)
    return document


def _assert_portability_positive(document: Mapping[str, Any]) -> None:
    tree = document["semantic_tree"]
    identities = [
        (row["semantic_root_id"], row["portable_path"]) for row in tree
    ]
    assert identities == sorted(identities)
    assert len(identities) == len(set(identities))
    mappings = document["root_mappings"]
    assert mappings[0]["mapping"] != mappings[1]["mapping"]
    assert mappings[0]["semantic_tree_digest"] == mappings[1][
        "semantic_tree_digest"
    ]
    classifications = {
        row["input"]: row["class"]
        for row in document["path_classifications"]
    }
    assert "WSL_LINUX_PATH" in classifications.values()
    durability = document["durability"]
    assert durability["process_crash_atomic"] is True
    assert durability["power_loss_durable"] is False
    assert durability["directory_flush_supported"] is False
    reuse = document["reuse"]
    assert reuse["source_host_id"] == reuse["target_host_id"]
    assert reuse["semantic_mapping_receipt_equal"] is True


def _validator(law: str) -> Callable[..., Any]:
    return require_callable(
        PORTABILITY_MODULE,
        "validate_program_facts_portability_durability_v1",
        law,
    )


def _accept_positive(
    validator: Callable[..., Any],
    law: str,
    document: Mapping[str, Any],
) -> None:
    _assert_portability_positive(document)
    require_accepts(validator, law, document)


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


def _windows_profile_document() -> dict[str, Any]:
    document = {
        "boundary_profile": "WINDOWS_HYPERV_HCS_PROVIDER_BOUNDARY_V1",
        "host_classification": "WINDOWS_NATIVE_AMD64",
        "provided_capabilities": list(WINDOWS_CAPABILITIES),
        "hyperv_isolation": True,
        "hcs_compute_system": True,
        "mic_only": False,
        "appcontainer_only": False,
        "wsl": False,
    }
    _assert_windows_profile_positive(document)
    return document


def _assert_windows_profile_positive(
    document: Mapping[str, Any],
) -> None:
    assert document["boundary_profile"] == (
        "WINDOWS_HYPERV_HCS_PROVIDER_BOUNDARY_V1"
    )
    assert document["host_classification"] == "WINDOWS_NATIVE_AMD64"
    assert tuple(document["provided_capabilities"]) == WINDOWS_CAPABILITIES
    assert document["hyperv_isolation"] is True
    assert document["hcs_compute_system"] is True
    assert document["mic_only"] is False
    assert document["appcontainer_only"] is False
    assert document["wsl"] is False


def test_a18_same_semantic_tree_at_different_absolute_roots_is_portable() -> None:
    law = "A18/semantic-tree-is-independent-of-absolute-root"
    positive = _portability_document()
    validator = _validator(law)
    _accept_positive(validator, law, positive)


def test_a18_drive_unc_slash_case_long_path_and_wsl_classification_are_exact() -> None:
    law = "A18/path-platform-classification-is-exact"
    positive = _portability_document()
    validator = _validator(law)
    _accept_positive(validator, law, positive)
    mutation = deepcopy(positive)
    wsl_row = next(
        row
        for row in mutation["path_classifications"]
        if row["class"] == "WSL_LINUX_PATH"
    )
    wsl_row["class"] = "WINDOWS_DRIVE_ABSOLUTE"
    _require_targeted_rejection(
        validator,
        law,
        "PF_A18_PATH_CLASSIFICATION_DIVERGED",
        mutation,
    )


def test_a18_unsupported_directory_flush_cannot_claim_power_loss_durability() -> None:
    law = "A18/power-loss-claim-requires-directory-durability"
    positive = _portability_document()
    validator = _validator(law)
    _accept_positive(validator, law, positive)
    mutation = deepcopy(positive)
    mutation["durability"]["power_loss_durable"] = True
    _require_targeted_rejection(
        validator,
        law,
        "PF_A18_POWER_LOSS_DURABILITY_UNSUPPORTED",
        mutation,
    )


def test_a18_process_crash_and_power_loss_states_are_distinct() -> None:
    law = "A18/process-crash-and-power-loss-classes-are-distinct"
    positive = _portability_document()
    validator = _validator(law)
    _accept_positive(validator, law, positive)
    mutation = deepcopy(positive)
    mutation["durability"]["power_loss_durable"] = mutation[
        "durability"
    ]["process_crash_atomic"]
    _require_targeted_rejection(
        validator,
        law,
        "PF_A18_DURABILITY_CLASSES_CONFLATED",
        mutation,
    )


def test_a18_physical_path_equality_cannot_authorize_cross_host_reuse() -> None:
    law = "A18/physical-path-is-not-cross-host-reuse-authority"
    positive = _portability_document()
    validator = _validator(law)
    _accept_positive(validator, law, positive)
    mutation = deepcopy(positive)
    mutation["reuse"]["target_host_id"] = "host-b"
    mutation["reuse"]["semantic_mapping_receipt_equal"] = False
    mutation["reuse"]["reuse_authorized"] = True
    _require_targeted_rejection(
        validator,
        law,
        "PF_A18_CROSS_HOST_REUSE_UNAUTHORIZED",
        mutation,
    )


@pytest.mark.parametrize(
    "mutation_class",
    (
        pytest.param("wsl", id="wsl"),
        pytest.param("mic-only", id="mic-only"),
        pytest.param(
            "appcontainer-only",
            id="appcontainer-only",
        ),
    ),
)
def test_a18_wsl_mic_or_appcontainer_cannot_satisfy_native_hyperv_hcs_profile(
    mutation_class: str,
) -> None:
    law = "A18/windows-profile-cannot-use-weaker-host-class"
    positive = _windows_profile_document()
    validator = _validator(law)
    _assert_windows_profile_positive(positive)
    require_accepts(validator, law, positive)
    mutation = deepcopy(positive)
    if mutation_class == "wsl":
        mutation["host_classification"] = "WSL_LINUX"
        mutation["wsl"] = True
    elif mutation_class == "mic-only":
        mutation["hyperv_isolation"] = False
        mutation["hcs_compute_system"] = False
        mutation["mic_only"] = True
    else:
        mutation["hyperv_isolation"] = False
        mutation["hcs_compute_system"] = False
        mutation["appcontainer_only"] = True
    _require_targeted_rejection(
        validator,
        law,
        "PF_A18_WEAKER_WINDOWS_PROFILE_SUBSTITUTED",
        mutation,
    )
