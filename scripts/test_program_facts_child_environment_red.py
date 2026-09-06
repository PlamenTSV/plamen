"""B0 RED fixtures for the exact Program Facts child environment."""

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
FORBIDDEN_AMBIENT_NAMES = (
    "AWS_SECRET_ACCESS_KEY",
    "GITHUB_TOKEN",
    "HOME",
    "HTTPS_PROXY",
    "PATH",
    "SSH_AUTH_SOCK",
    "USERPROFILE",
)


def _child_environment_document(
    platform: str = "WINDOWS",
) -> dict[str, Any]:
    if platform == "WINDOWS":
        armed = {
            "LANG": "C.UTF-8",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "SYSTEMROOT": "semantic://approved-os-runtime/windows",
            "TEMP": "semantic://writable/temp",
            "TMP": "semantic://writable/temp",
            "TZ": "UTC",
        }
    else:
        armed = {
            "HOME": "semantic://writable/home",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "TMPDIR": "semantic://writable/temp",
            "TZ": "UTC",
        }
    document: dict[str, Any] = {
        "schema": "plamen.program_facts_child_environment.v1",
        "platform": platform,
        "armed_environment": armed,
        "observed_child_environment": deepcopy(armed),
        "required_variables": sorted(armed),
        "forbidden_ambient_names": list(FORBIDDEN_AMBIENT_NAMES),
        "root_mapping_receipt": {
            "semantic_root_id": "provider-runtime",
            "physical_root_identity_digest": "1" * 64,
            "mapping_receipt_digest": "2" * 64,
        },
        "arm_root_mapping_receipt_digest": "2" * 64,
        "completion_root_mapping_receipt_digest": "2" * 64,
        "canonical_artifacts": [
            "environment_digest=" + ("3" * 64),
            "root_mapping_digest=" + ("2" * 64),
        ],
        "canonical_diagnostics": ["CHILD_ENVIRONMENT_VALIDATED"],
    }
    _assert_child_environment_positive(document)
    return document


def _assert_child_environment_positive(
    document: Mapping[str, Any],
) -> None:
    armed = document["armed_environment"]
    observed = document["observed_child_environment"]
    assert armed == observed
    assert document["required_variables"] == sorted(armed)
    if document["platform"] == "WINDOWS":
        assert "SYSTEMROOT" in armed
        assert "TMP" in armed and "TEMP" in armed
        assert "HOME" not in armed and "USERPROFILE" not in armed
    else:
        assert "HOME" in armed and "TMPDIR" in armed
        assert "SYSTEMROOT" not in armed
    for forbidden in document["forbidden_ambient_names"]:
        if document["platform"] == "POSIX" and forbidden == "HOME":
            continue
        assert forbidden not in armed
    receipt = document["root_mapping_receipt"]
    assert receipt["mapping_receipt_digest"] == document[
        "arm_root_mapping_receipt_digest"
    ]
    assert receipt["mapping_receipt_digest"] == document[
        "completion_root_mapping_receipt_digest"
    ]
    serialized = repr(
        (
            document["canonical_artifacts"],
            document["canonical_diagnostics"],
        )
    )
    assert "seeded-secret" not in serialized
    assert "secret-handle" not in serialized


def _validator(law: str) -> Callable[..., Any]:
    return require_callable(
        ENVIRONMENT_MODULE,
        "validate_program_facts_child_environment_authority_v1",
        law,
    )


def _accept_positive(
    validator: Callable[..., Any],
    law: str,
    document: Mapping[str, Any],
) -> None:
    _assert_child_environment_positive(document)
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


def _require_windows_schema_positive(
    law: str,
    document: Mapping[str, Any],
) -> None:
    assert PROVIDER_ENVIRONMENT_SCHEMA.is_file()
    schema = json.loads(
        PROVIDER_ENVIRONMENT_SCHEMA.read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    errors = list(Draft202012Validator(schema).iter_errors(document))
    if errors:
        pytest.fail(
            f"R21_B0_RED[{law}]: "
            "PF_A15_WINDOWS_SCHEMA_PROFILE_ABSENT: "
            f"{errors[0].message}",
            pytrace=False,
        )
    assert tuple(
        document["windows_boundary"]["provided_capabilities"]
    ) == WINDOWS_CAPABILITIES


def _windows_child_document(law: str) -> dict[str, Any]:
    provider = _windows_environment_document()
    _require_windows_schema_positive(law, provider)
    document = {
        "provider_environment": provider,
        "child_environment": _child_environment_document("WINDOWS"),
        "linux_fields": {},
        "ambient_secret_state": {},
        "ambient_handle_state": [],
    }
    _assert_windows_child_positive(document, law)
    return document


def _assert_windows_child_positive(
    document: Mapping[str, Any],
    law: str,
) -> None:
    _require_windows_schema_positive(law, document["provider_environment"])
    _assert_child_environment_positive(document["child_environment"])
    assert document["linux_fields"] == {}
    assert document["ambient_secret_state"] == {}
    assert document["ambient_handle_state"] == []


def test_a15_inherited_path_home_proxy_and_token_are_absent() -> None:
    law = "A15/no-ambient-path-home-proxy-or-token"
    positive = _child_environment_document()
    validator = _validator(law)
    _accept_positive(validator, law, positive)
    mutation = deepcopy(positive)
    mutation["observed_child_environment"]["HTTPS_PROXY"] = (
        "http://host-proxy"
    )
    _require_targeted_rejection(
        validator,
        law,
        "PF_A15_AMBIENT_ENVIRONMENT_INHERITED",
        mutation,
    )


def test_a15_locale_timezone_and_profile_drift_rejected() -> None:
    law = "A15/locale-timezone-profile-are-exact"
    positive = _child_environment_document()
    validator = _validator(law)
    _accept_positive(validator, law, positive)
    mutation = deepcopy(positive)
    mutation["observed_child_environment"]["TZ"] = "Europe/Bucharest"
    _require_targeted_rejection(
        validator,
        law,
        "PF_A15_LOCALE_TIMEZONE_OR_PROFILE_DRIFT",
        mutation,
    )


def test_a15_physical_root_change_requires_new_mapping_receipt() -> None:
    law = "A15/physical-root-is-bound-by-mapping-receipt"
    positive = _child_environment_document()
    validator = _validator(law)
    _accept_positive(validator, law, positive)
    mutation = deepcopy(positive)
    mutation["root_mapping_receipt"][
        "physical_root_identity_digest"
    ] = "f" * 64
    _require_targeted_rejection(
        validator,
        law,
        "PF_A15_ROOT_MAPPING_RECEIPT_STALE",
        mutation,
    )


def test_a15_missing_required_windows_or_posix_runtime_variable_rejected() -> None:
    law = "A15/platform-required-variable-totality"
    validator = _validator(law)
    for platform in ("WINDOWS", "POSIX"):
        positive = _child_environment_document(platform)
        _accept_positive(validator, law, positive)
        mutation = deepcopy(positive)
        required = mutation["required_variables"][0]
        mutation["observed_child_environment"].pop(required)
        _require_targeted_rejection(
            validator,
            law,
            "PF_A15_REQUIRED_RUNTIME_VARIABLE_MISSING",
            mutation,
        )


def test_a15_observed_child_environment_must_equal_armed_map() -> None:
    law = "A15/observed-environment-equals-armed-map"
    positive = _child_environment_document()
    validator = _validator(law)
    _accept_positive(validator, law, positive)
    mutation = deepcopy(positive)
    mutation["observed_child_environment"]["UNARMED"] = "1"
    _require_targeted_rejection(
        validator,
        law,
        "PF_A15_OBSERVED_ENVIRONMENT_DIVERGED",
        mutation,
    )


def test_a15_secrets_never_enter_canonical_or_diagnostic_artifacts() -> None:
    law = "A15/secrets-absent-from-canonical-artifacts"
    positive = _child_environment_document()
    validator = _validator(law)
    _accept_positive(validator, law, positive)
    mutation = deepcopy(positive)
    mutation["canonical_diagnostics"].append(
        "rejected token seeded-secret"
    )
    _require_targeted_rejection(
        validator,
        law,
        "PF_A15_SECRET_DISCLOSED_IN_ARTIFACT",
        mutation,
    )


@pytest.mark.parametrize(
    "mutation_class",
    (
        pytest.param("linux-fields", id="linux-fields"),
        pytest.param("ambient-secret", id="ambient-secret"),
        pytest.param("ambient-handle", id="ambient-handle"),
    ),
)
def test_a15_windows_branch_excludes_linux_fields_and_ambient_secret_or_handle_state(
    mutation_class: str,
) -> None:
    law = "A15/windows-branch-has-no-linux-or-ambient-state"
    positive = _windows_child_document(law)
    validator = _validator(law)
    _assert_windows_child_positive(positive, law)
    require_accepts(validator, law, positive)
    mutation = deepcopy(positive)
    if mutation_class == "linux-fields":
        mutation["linux_fields"] = {
            "cgroup_path": "/sys/fs/cgroup/fixture"
        }
    elif mutation_class == "ambient-secret":
        mutation["ambient_secret_state"] = {
            "GITHUB_TOKEN": "seeded-secret"
        }
    else:
        mutation["ambient_handle_state"] = ["secret-handle"]
    _require_targeted_rejection(
        validator,
        law,
        "PF_A15_WINDOWS_AMBIENT_OR_LINUX_STATE_PRESENT",
        mutation,
    )
