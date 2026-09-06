from __future__ import annotations

from copy import deepcopy
from typing import Any, Callable, Mapping

from review_fixtures.program_facts_r2_1_b0_red_support import (
    body_digest,
    require_accepts,
    require_callable,
)


CANDIDATE_MODULE = "program_facts_evm_candidate_detector"
BUILD_AUTHORITY_MODULE = "program_facts_evm_build_authority"


def _candidate(
    candidate_id: str,
    kind: str,
    portable_path: str,
    semantic_key: str,
    *,
    dynamic_environment: bool = False,
) -> dict[str, Any]:
    return {
        "candidate_id": candidate_id,
        "kind": kind,
        "portable_path": portable_path,
        "semantic_key": semantic_key,
        "dynamic_environment": dynamic_environment,
    }


def _positive_scope() -> dict[str, Any]:
    candidates = [
        _candidate(
            "hardhat-override",
            "HARDHAT_COMPILER_OVERRIDE",
            "apps/bridge/hardhat.config.js#override:contracts/Legacy.sol",
            "hardhat:bridge:override:legacy",
        ),
        _candidate(
            "nested-package",
            "NESTED_BUILD_ROOT",
            "packages/token/foundry.toml",
            "foundry:packages/token:default",
        ),
        _candidate(
            "root-package",
            "BUILD_ROOT",
            "foundry.toml",
            "foundry:root:default",
        ),
        _candidate(
            "root-profile-ci",
            "FOUNDRY_PROFILE",
            "foundry.toml#profile.ci",
            "foundry:root:ci",
        ),
        _candidate(
            "generated-bindings",
            "CONFIG_SELECTED_GENERATED_ROOT",
            "generated/bindings",
            "generated:bindings",
        ),
        _candidate(
            "dynamic-network-branch",
            "ENVIRONMENT_DEPENDENT_CONFIG_BRANCH",
            "hardhat.config.js#network",
            "hardhat:dynamic-network",
            dynamic_environment=True,
        ),
        _candidate(
            "secondary-package",
            "NESTED_BUILD_ROOT",
            "packages/vault/foundry.toml",
            "foundry:packages/vault:default",
        ),
    ]
    candidates.sort(key=lambda row: row["candidate_id"])
    dispositions = [
        {
            "candidate_id": "dynamic-network-branch",
            "state": "UNRESOLVED",
            "reason": "ENVIRONMENT_BRANCH_NOT_BOUND",
            "debt_id": "debt-dynamic-network",
        },
        {
            "candidate_id": "generated-bindings",
            "state": "SELECTED",
            "reason": "CONFIG_DECLARED_GENERATED_INPUT",
        },
        {
            "candidate_id": "hardhat-override",
            "state": "SELECTED",
            "reason": "DETECTED_OVERRIDE",
        },
        {
            "candidate_id": "nested-package",
            "state": "UNRESOLVED",
            "reason": "USER_LIST_OMITTED_DETECTED_CANDIDATE",
            "debt_id": "debt-user-omitted-nested",
        },
        {
            "candidate_id": "root-package",
            "state": "SELECTED",
            "reason": "USER_SELECTED",
        },
        {
            "candidate_id": "root-profile-ci",
            "state": "SELECTED",
            "reason": "DETECTED_PROFILE",
        },
        {
            "candidate_id": "secondary-package",
            "state": "EXCLUDED",
            "reason": "REVIEWED_POLICY_EXCLUSION",
            "debt_id": "debt-reviewed-exclusion",
        },
    ]
    capability_registry = [
        "evm-callgraph-v1",
        "evm-dataflow-v1",
        "evm-storage-layout-v1",
    ]
    capability_dispositions = [
        {
            "capability_id": "evm-callgraph-v1",
            "state": "SELECTED",
            "reason": "REVIEWED_DEFAULT",
        },
        {
            "capability_id": "evm-dataflow-v1",
            "state": "SELECTED",
            "reason": "REVIEWED_DEFAULT",
        },
        {
            "capability_id": "evm-storage-layout-v1",
            "state": "UNRESOLVED",
            "reason": "TOOL_SUPPORT_UNAVAILABLE",
            "debt_id": "debt-capability-storage",
        },
    ]
    debts = [
        {
            "debt_id": "debt-capability-storage",
            "scope_kind": "CAPABILITY",
            "scope_id": "evm-storage-layout-v1",
        },
        {
            "debt_id": "debt-dynamic-network",
            "scope_kind": "CANDIDATE",
            "scope_id": "dynamic-network-branch",
        },
        {
            "debt_id": "debt-reviewed-exclusion",
            "scope_kind": "CANDIDATE",
            "scope_id": "secondary-package",
        },
        {
            "debt_id": "debt-user-omitted-nested",
            "scope_kind": "CANDIDATE",
            "scope_id": "nested-package",
        },
    ]
    document: dict[str, Any] = {
        "schema": "plamen.program_facts_evm_selected_scope.v1",
        "scope_claim": "EXACT_SELECTED_SCOPE_NOT_PROJECT_COMPLETE",
        "snapshot_declarations": {
            "build_roots": [
                "foundry.toml",
                "packages/token/foundry.toml",
                "packages/vault/foundry.toml",
            ],
            "foundry_profiles": ["root-profile-ci"],
            "hardhat_overrides": ["hardhat-override"],
            "generated_paths": ["generated/bindings"],
            "environment_dependent_branches": ["dynamic-network-branch"],
        },
        "detected_candidates": candidates,
        "candidate_dispositions": dispositions,
        "user_selected_candidate_ids": ["root-package"],
        "registry_capability_ids": capability_registry,
        "capability_dispositions": capability_dispositions,
        "unresolved_debts": debts,
    }
    document["selected_scope_body_sha256"] = body_digest(
        document, "selected_scope_body_sha256"
    )
    _assert_local_positive(document)
    return document


def _assert_local_positive(document: Mapping[str, Any]) -> None:
    candidates = document["detected_candidates"]
    candidate_ids = [row["candidate_id"] for row in candidates]
    disposition_ids = [
        row["candidate_id"] for row in document["candidate_dispositions"]
    ]
    assert candidate_ids == sorted(candidate_ids)
    assert len(candidate_ids) == len(set(candidate_ids))
    assert disposition_ids == sorted(disposition_ids)
    assert candidate_ids == disposition_ids
    capabilities = document["registry_capability_ids"]
    capability_dispositions = [
        row["capability_id"]
        for row in document["capability_dispositions"]
    ]
    assert capabilities == sorted(capabilities)
    assert capability_dispositions == capabilities
    debt_ids = {
        row["debt_id"] for row in document["unresolved_debts"]
    }
    for row in document["candidate_dispositions"]:
        if row["state"] in {"EXCLUDED", "UNRESOLVED"}:
            assert row["debt_id"] in debt_ids
    for row in document["capability_dispositions"]:
        if row["state"] in {"EXCLUDED", "UNRESOLVED"}:
            assert row["debt_id"] in debt_ids
    generated = set(document["snapshot_declarations"]["generated_paths"])
    detected_paths = {
        row["portable_path"] for row in document["detected_candidates"]
    }
    assert generated <= detected_paths
    dynamic_ids = set(
        document["snapshot_declarations"][
            "environment_dependent_branches"
        ]
    )
    disposition_by_id = {
        row["candidate_id"]: row
        for row in document["candidate_dispositions"]
    }
    assert all(
        disposition_by_id[candidate_id]["state"] == "UNRESOLVED"
        for candidate_id in dynamic_ids
    )
    assert document["scope_claim"] == (
        "EXACT_SELECTED_SCOPE_NOT_PROJECT_COMPLETE"
    )
    assert document["selected_scope_body_sha256"] == body_digest(
        document, "selected_scope_body_sha256"
    )


def _resign(document: dict[str, Any]) -> None:
    document["detected_candidates"].sort(
        key=lambda row: row["candidate_id"]
    )
    document["candidate_dispositions"].sort(
        key=lambda row: row["candidate_id"]
    )
    document["capability_dispositions"].sort(
        key=lambda row: row["capability_id"]
    )
    document["unresolved_debts"].sort(key=lambda row: row["debt_id"])
    document["selected_scope_body_sha256"] = body_digest(
        document, "selected_scope_body_sha256"
    )


def _scope_validator(law: str) -> Callable[..., Any]:
    return require_callable(
        BUILD_AUTHORITY_MODULE,
        "validate_selected_scope_authority_v1",
        law,
    )


def _candidate_validator(law: str) -> Callable[..., Any]:
    return require_callable(
        CANDIDATE_MODULE,
        "validate_candidate_universe_v1",
        law,
    )


def _accept_positive(
    validator: Callable[..., Any],
    law: str,
    document: Mapping[str, Any],
) -> None:
    _assert_local_positive(document)
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


def test_a5_nested_monorepo_roots_are_all_disposed() -> None:
    law = "A5/nested-monorepo-disposition-totality"
    positive = _positive_scope()
    validator = _scope_validator(law)
    _accept_positive(validator, law, positive)

    mutation = deepcopy(positive)
    mutation["candidate_dispositions"] = [
        row
        for row in mutation["candidate_dispositions"]
        if row["candidate_id"] != "secondary-package"
    ]
    _resign(mutation)
    _require_targeted_rejection(
        validator,
        law,
        "PF_A5_CANDIDATE_DISPOSITION_NOT_TOTAL",
        mutation,
    )


def test_a5_foundry_profiles_and_hardhat_override_branches_are_disposed() -> None:
    law = "A5/profile-and-override-disposition-totality"
    positive = _positive_scope()
    validator = _scope_validator(law)
    _accept_positive(validator, law, positive)

    for candidate_id in ("root-profile-ci", "hardhat-override"):
        mutation = deepcopy(positive)
        mutation["candidate_dispositions"] = [
            row
            for row in mutation["candidate_dispositions"]
            if row["candidate_id"] != candidate_id
        ]
        _resign(mutation)
        _require_targeted_rejection(
            validator,
            law,
            "PF_A5_PROFILE_OR_OVERRIDE_NOT_DISPOSED",
            mutation,
        )


def test_a5_config_selected_generated_paths_enter_candidate_universe() -> None:
    law = "A5/config-generated-path-detection-totality"
    positive = _positive_scope()
    validator = _candidate_validator(law)
    _accept_positive(validator, law, positive)

    mutation = deepcopy(positive)
    mutation["detected_candidates"] = [
        row
        for row in mutation["detected_candidates"]
        if row["candidate_id"] != "generated-bindings"
    ]
    mutation["candidate_dispositions"] = [
        row
        for row in mutation["candidate_dispositions"]
        if row["candidate_id"] != "generated-bindings"
    ]
    _resign(mutation)
    _require_targeted_rejection(
        validator,
        law,
        "PF_A5_CONFIG_GENERATED_PATH_OMITTED",
        mutation,
    )


def test_a5_environment_dependent_config_branch_remains_unresolved() -> None:
    law = "A5/dynamic-config-is-not-silent-selection"
    positive = _positive_scope()
    validator = _scope_validator(law)
    _accept_positive(validator, law, positive)

    mutation = deepcopy(positive)
    row = next(
        row
        for row in mutation["candidate_dispositions"]
        if row["candidate_id"] == "dynamic-network-branch"
    )
    row["state"] = "SELECTED"
    row["reason"] = "IMPLICIT_HOST_ENVIRONMENT"
    row.pop("debt_id")
    _resign(mutation)
    _require_targeted_rejection(
        validator,
        law,
        "PF_A5_DYNAMIC_CONFIG_BRANCH_NOT_UNRESOLVED",
        mutation,
    )


def test_a5_semantic_duplicate_variants_with_different_host_paths_collide() -> None:
    law = "A5/semantic-variant-identity-not-host-path"
    positive = _positive_scope()
    validator = _candidate_validator(law)
    _accept_positive(validator, law, positive)

    mutation = deepcopy(positive)
    left = next(
        row
        for row in mutation["detected_candidates"]
        if row["candidate_id"] == "nested-package"
    )
    right = next(
        row
        for row in mutation["detected_candidates"]
        if row["candidate_id"] == "secondary-package"
    )
    assert left["portable_path"] != right["portable_path"]
    right["semantic_key"] = left["semantic_key"]
    _resign(mutation)
    _require_targeted_rejection(
        validator,
        law,
        "PF_A5_SEMANTIC_VARIANT_COLLISION",
        mutation,
    )


def test_a5_registry_capability_cannot_be_silently_omitted() -> None:
    law = "A5/registry-capability-disposition-totality"
    positive = _positive_scope()
    validator = _scope_validator(law)
    _accept_positive(validator, law, positive)

    mutation = deepcopy(positive)
    mutation["capability_dispositions"] = [
        row
        for row in mutation["capability_dispositions"]
        if row["capability_id"] != "evm-storage-layout-v1"
    ]
    _resign(mutation)
    _require_targeted_rejection(
        validator,
        law,
        "PF_A5_CAPABILITY_DISPOSITION_NOT_TOTAL",
        mutation,
    )


def test_a5_user_list_omitting_detected_candidate_retains_debt() -> None:
    law = "A5/user-omission-retains-visible-debt"
    positive = _positive_scope()
    validator = _scope_validator(law)
    _accept_positive(validator, law, positive)

    mutation = deepcopy(positive)
    mutation["unresolved_debts"] = [
        row
        for row in mutation["unresolved_debts"]
        if row["debt_id"] != "debt-user-omitted-nested"
    ]
    _resign(mutation)
    _require_targeted_rejection(
        validator,
        law,
        "PF_A5_USER_OMISSION_DEBT_MISSING",
        mutation,
    )
