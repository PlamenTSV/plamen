from __future__ import annotations

from copy import deepcopy
import hashlib
from typing import Any, Callable, Mapping

from review_fixtures.program_facts_r2_1_b0_red_support import (
    canonical_bytes,
    require_accepts,
    require_callable,
)


EXECUTION_AUTHORITY_MODULE = "program_facts_execution_authority"
ROSTER_VALIDATOR = "validate_program_facts_change_roster_v1"

SCHEMA_CANDIDATES = (
    "rules/schemas/program_facts_content_pack_manifest.v1.schema.json",
    "rules/schemas/program_facts_evm_build_input_snapshot.v1.schema.json",
    "rules/schemas/program_facts_evm_candidate_universe.v1.schema.json",
    "rules/schemas/program_facts_evm_selected_scope.v1.schema.json",
    "rules/schemas/program_facts_capability_selection.v1.schema.json",
    "rules/schemas/program_facts_evm_build_plan.v1.schema.json",
    "rules/schemas/program_facts_evm_build_attempt.v1.schema.json",
    "rules/schemas/program_facts_evm_provider_request.v1.schema.json",
    "rules/schemas/program_facts_evm_slither_raw.v2.schema.json",
    "rules/schemas/program_facts_evm_tool_manifest.v2.schema.json",
    "rules/schemas/program_facts_evm_execution_set.v1.schema.json",
    "rules/schemas/program_facts_execution_authority.v1.schema.json",
    "rules/schemas/program_facts_composition_authority.v1.schema.json",
    "rules/schemas/program_facts_evm_activation_decision.v1.schema.json",
    "rules/schemas/program_facts_runtime_diagnostic.v2.schema.json",
    "rules/schemas/program_facts_generation_transition.v1.schema.json",
    "rules/schemas/mechanical_program_facts.v2.schema.json",
    "rules/schemas/mechanical_program_facts_receipt.v2.schema.json",
    "rules/schemas/mechanical_program_facts_debt.v2.schema.json",
    "rules/schemas/program_facts_evm_provider_environment.v1.schema.json",
    "rules/schemas/program_facts_evm_activation_permit.v1.schema.json",
)

W_FIXTURES = (
    "scripts/test_worker_transaction_exact_bytes_v3_red.py",
    "scripts/test_program_facts_sandbox_read_boundary_red.py",
    "scripts/test_program_facts_sandbox_resources_red.py",
    "scripts/test_program_facts_execution_lineage_red.py",
    "scripts/test_program_facts_child_environment_red.py",
    "scripts/test_program_facts_portability_durability_red.py",
)

B_FIXTURES = (
    "scripts/test_program_facts_build_input_snapshot_red.py",
    "scripts/test_program_facts_build_partition_red.py",
    "scripts/test_program_facts_selected_scope_red.py",
    "scripts/test_program_facts_provider_environment_lifecycle_red.py",
)

P_FIXTURES = (
    "scripts/test_program_facts_public_v2_representation_red.py",
    "scripts/test_program_facts_generation_reuse_red.py",
    "scripts/test_program_facts_authority_layering_red.py",
    "scripts/test_program_facts_activation_permit_red.py",
    "scripts/test_program_facts_change_roster_red.py",
)

CANDIDATE_PATHS = tuple(
    sorted((*SCHEMA_CANDIDATES, *W_FIXTURES, *B_FIXTURES, *P_FIXTURES))
)

SHARED_CORE_OWNERS = {
    "scripts/artifact_ledger.py": "composition-publication-owner",
    "scripts/phase_io_contracts.py": "serialized-phaseio-owner",
    "scripts/plamen_driver.py": "c4-driver-owner",
    "scripts/worker_transaction.py": "serialized-wtx-owner",
}


def _owner_for(path: str) -> str:
    if path in SCHEMA_CANDIDATES:
        return "lane-s"
    if path in W_FIXTURES:
        return "lane-w"
    if path in B_FIXTURES:
        return "lane-b"
    if path in P_FIXTURES:
        return "lane-p"
    raise AssertionError(f"unclassified candidate path: {path}")


def _candidate_hash_set(rows: list[dict[str, Any]]) -> str:
    pairs = [
        {"path": row["path"], "candidate_sha256": row["candidate_sha256"]}
        for row in rows
    ]
    return hashlib.sha256(canonical_bytes(pairs)).hexdigest()


def _positive_change_roster() -> dict[str, Any]:
    candidates = [
        {
            "path": path,
            "owner": _owner_for(path),
            "semantic_class": (
                "SCHEMA" if path.startswith("rules/schemas/") else "FIXTURE"
            ),
            "candidate_sha256": hashlib.sha256(
                f"candidate:{path}".encode("ascii")
            ).hexdigest(),
        }
        for path in CANDIDATE_PATHS
    ]
    candidate_hash_set = _candidate_hash_set(candidates)
    document: dict[str, Any] = {
        "schema_version": "plamen.program_facts_change_roster.v1",
        "candidate_manifest": {
            "paths": list(CANDIDATE_PATHS),
            "rows": candidates,
            "candidate_hash_set_sha256": candidate_hash_set,
        },
        "normative_owned_paths": list(CANDIDATE_PATHS),
        "shared_core_ownership": [
            {"path": path, "serial_owner": owner}
            for path, owner in sorted(SHARED_CORE_OWNERS.items())
        ],
        "runtime_asset_roster": [
            {
                "path": "rules/schemas/mechanical_program_facts.v2.schema.json",
                "owner": "lane-s",
            },
            {
                "path": (
                    "rules/schemas/"
                    "mechanical_program_facts_receipt.v2.schema.json"
                ),
                "owner": "lane-s",
            },
            {
                "path": (
                    "rules/schemas/"
                    "mechanical_program_facts_debt.v2.schema.json"
                ),
                "owner": "lane-s",
            },
        ],
        "active_foreign_leases": [],
        "review": {
            "reviewer_id": "independent-fixture-reviewer",
            "reviewer_candidate_edit_count": 0,
            "candidate_hash_set_before": candidate_hash_set,
            "candidate_hash_set_after": candidate_hash_set,
        },
        "authority_ceiling": {
            "provider_execution": False,
            "consumer_activation": False,
            "terminal_negative_authority": False,
            "public_generation_selection": False,
        },
    }
    _assert_local_positive(document)
    return document


def _assert_local_positive(document: Mapping[str, Any]) -> None:
    manifest = document["candidate_manifest"]
    assert manifest["paths"] == list(CANDIDATE_PATHS)
    assert manifest["paths"] == sorted(manifest["paths"])
    assert len(manifest["paths"]) == 36
    assert len(manifest["paths"]) == len(set(manifest["paths"]))
    assert manifest["paths"] == document["normative_owned_paths"]
    rows = manifest["rows"]
    assert [row["path"] for row in rows] == manifest["paths"]
    assert all(row["owner"] == _owner_for(row["path"]) for row in rows)
    assert manifest["candidate_hash_set_sha256"] == _candidate_hash_set(rows)
    shared = document["shared_core_ownership"]
    assert len(shared) == len(SHARED_CORE_OWNERS)
    assert len({row["path"] for row in shared}) == len(shared)
    assert all(row["serial_owner"] for row in shared)
    runtime_assets = document["runtime_asset_roster"]
    assert all(row["owner"] for row in runtime_assets)
    assert all(
        row["path"] in manifest["paths"] for row in runtime_assets
    )
    assert document["active_foreign_leases"] == []
    review = document["review"]
    assert review["reviewer_candidate_edit_count"] == 0
    assert (
        review["candidate_hash_set_before"]
        == review["candidate_hash_set_after"]
        == manifest["candidate_hash_set_sha256"]
    )
    assert document["authority_ceiling"] == {
        "provider_execution": False,
        "consumer_activation": False,
        "terminal_negative_authority": False,
        "public_generation_selection": False,
    }


def _validator(law: str) -> Callable[..., Any]:
    return require_callable(
        EXECUTION_AUTHORITY_MODULE,
        ROSTER_VALIDATOR,
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


def test_a17_candidate_manifest_contains_every_normative_owned_path() -> None:
    law = "A17/candidate-manifest-is-exact-normative-path-union"
    positive = _positive_change_roster()
    validator = _validator(law)
    _accept_positive(validator, law, positive)

    mutation = deepcopy(positive)
    missing_path = P_FIXTURES[-1]
    mutation["candidate_manifest"]["paths"].remove(missing_path)
    mutation["candidate_manifest"]["rows"] = [
        row
        for row in mutation["candidate_manifest"]["rows"]
        if row["path"] != missing_path
    ]
    mutation["candidate_manifest"][
        "candidate_hash_set_sha256"
    ] = _candidate_hash_set(mutation["candidate_manifest"]["rows"])
    _require_targeted_rejection(
        validator,
        law,
        "PF_A17_NORMATIVE_CANDIDATE_PATH_MISSING",
        mutation,
    )


def test_a17_shared_core_file_has_one_serial_owner() -> None:
    law = "A17/shared-core-has-one-whole-file-owner"
    positive = _positive_change_roster()
    validator = _validator(law)
    _accept_positive(validator, law, positive)

    mutation = deepcopy(positive)
    mutation["shared_core_ownership"].append(
        {
            "path": "scripts/phase_io_contracts.py",
            "serial_owner": "competing-owner",
        }
    )
    _require_targeted_rejection(
        validator,
        law,
        "PF_A17_SHARED_CORE_OWNER_NOT_SINGULAR",
        mutation,
    )


def test_a17_unassigned_runtime_asset_or_schema_blocks_cut() -> None:
    law = "A17/runtime-assets-and-schemas-require-assigned-owner"
    positive = _positive_change_roster()
    validator = _validator(law)
    _accept_positive(validator, law, positive)

    mutation = deepcopy(positive)
    mutation["runtime_asset_roster"][0]["owner"] = ""
    _require_targeted_rejection(
        validator,
        law,
        "PF_A17_UNASSIGNED_RUNTIME_ASSET_OR_SCHEMA",
        mutation,
    )


def test_a17_active_foreign_owner_blocks_shared_file_cut() -> None:
    law = "A17/foreign-lease-overlap-blocks-shared-cut"
    positive = _positive_change_roster()
    validator = _validator(law)
    _accept_positive(validator, law, positive)

    mutation = deepcopy(positive)
    mutation["active_foreign_leases"] = [
        {
            "owner": "foreign-owner",
            "state": "ACTIVE",
            "write_paths": ["scripts/artifact_ledger.py"],
        }
    ]
    _require_targeted_rejection(
        validator,
        law,
        "PF_A17_ACTIVE_FOREIGN_OWNER_CONFLICT",
        mutation,
    )


def test_a17_reviewer_did_not_edit_candidate_hash_set() -> None:
    law = "A17/reviewer-is-nonauthor-of-candidate-bytes"
    positive = _positive_change_roster()
    validator = _validator(law)
    _accept_positive(validator, law, positive)

    mutation = deepcopy(positive)
    mutation["review"]["reviewer_candidate_edit_count"] = 1
    mutation["review"]["candidate_hash_set_after"] = "f" * 64
    _require_targeted_rejection(
        validator,
        law,
        "PF_A17_REVIEWER_MUTATED_CANDIDATE_HASH_SET",
        mutation,
    )
