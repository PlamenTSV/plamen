from __future__ import annotations

from copy import deepcopy
from typing import Any, Callable, Mapping

from review_fixtures.program_facts_r2_1_b0_red_support import (
    body_digest,
    require_accepts,
    require_callable,
)


BUILD_AUTHORITY_MODULE = "program_facts_evm_build_authority"


def _positive_attempt() -> dict[str, Any]:
    document: dict[str, Any] = {
        "schema": "plamen.program_facts_evm_build_attempt.v1",
        "status": "COMPLETED_WITH_PARTIAL_COVERAGE",
        "selected_variant_id": "foundry-default",
        "source_sets": {
            "eligible": ["src/A.sol", "src/B.sol", "src/C.sol", "src/D.sol"],
            "attempted": ["src/A.sol", "src/B.sol"],
            "compiled": ["src/A.sol"],
            "compile_failed": ["src/B.sol"],
            "policy_excluded": ["src/C.sol"],
            "blocked_unattempted": ["src/D.sol"],
        },
        "capability_coverage": [
            {
                "capability_id": "evm-callgraph-v1",
                "provider_eligible_source_file_ids": ["src/A.sol"],
                "capability_covered_source_file_ids": ["src/A.sol"],
                "status": "FULL",
                "exact_empty_proof": "NOT_APPLICABLE",
            },
            {
                "capability_id": "evm-dataflow-v1",
                "provider_eligible_source_file_ids": [
                    "src/A.sol",
                    "src/B.sol",
                ],
                "capability_covered_source_file_ids": ["src/A.sol"],
                "status": "PARTIAL",
                "exact_empty_proof": "NOT_APPLICABLE",
            },
        ],
    }
    document["attempt_body_sha256"] = body_digest(
        document, "attempt_body_sha256"
    )
    _assert_local_positive(document)
    return document


def _sets(document: Mapping[str, Any]) -> dict[str, set[str]]:
    return {
        name: set(values)
        for name, values in document["source_sets"].items()
    }


def _assert_local_positive(document: Mapping[str, Any]) -> None:
    source_sets = document["source_sets"]
    for values in source_sets.values():
        assert values == sorted(values)
        assert len(values) == len(set(values))
    sets = _sets(document)
    assert sets["compiled"] <= sets["attempted"]
    assert sets["compile_failed"] <= sets["attempted"]
    assert sets["attempted"] == (
        sets["compiled"] | sets["compile_failed"]
    )
    assert not (sets["compiled"] & sets["compile_failed"])
    terminal = (
        sets["attempted"]
        | sets["policy_excluded"]
        | sets["blocked_unattempted"]
    )
    assert terminal == sets["eligible"]
    assert not (sets["attempted"] & sets["policy_excluded"])
    assert not (sets["attempted"] & sets["blocked_unattempted"])
    assert not (
        sets["policy_excluded"] & sets["blocked_unattempted"]
    )
    for row in document["capability_coverage"]:
        eligible = set(row["provider_eligible_source_file_ids"])
        covered = set(row["capability_covered_source_file_ids"])
        assert covered <= eligible
        if row["status"] == "FULL":
            assert covered == eligible
    assert document["attempt_body_sha256"] == body_digest(
        document, "attempt_body_sha256"
    )


def _resign(document: dict[str, Any]) -> None:
    for values in document["source_sets"].values():
        values.sort()
    document["attempt_body_sha256"] = body_digest(
        document, "attempt_body_sha256"
    )


def _validator(law: str) -> Callable[..., Any]:
    return require_callable(
        BUILD_AUTHORITY_MODULE,
        "validate_build_attempt_authority_v1",
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


def test_a4_attempted_and_policy_excluded_overlap_rejected() -> None:
    law = "A4/attempted-policy-excluded-disjointness"
    positive = _positive_attempt()
    validator = _validator(law)
    _accept_positive(validator, law, positive)

    mutation = deepcopy(positive)
    mutation["source_sets"]["policy_excluded"].append("src/A.sol")
    _resign(mutation)
    _require_targeted_rejection(
        validator,
        law,
        "PF_A4_ATTEMPTED_POLICY_EXCLUDED_OVERLAP",
        mutation,
    )


def test_a4_attempted_without_compiled_or_compile_failed_rejected() -> None:
    law = "A4/attempted-total-outcome-partition"
    positive = _positive_attempt()
    validator = _validator(law)
    _accept_positive(validator, law, positive)

    mutation = deepcopy(positive)
    mutation["source_sets"]["eligible"].append("src/E.sol")
    mutation["source_sets"]["attempted"].append("src/E.sol")
    _resign(mutation)
    _require_targeted_rejection(
        validator,
        law,
        "PF_A4_ATTEMPTED_WITHOUT_COMPILE_OUTCOME",
        mutation,
    )


def test_a4_compile_failed_without_attempted_rejected() -> None:
    law = "A4/compile-failed-subset-attempted"
    positive = _positive_attempt()
    validator = _validator(law)
    _accept_positive(validator, law, positive)

    mutation = deepcopy(positive)
    mutation["source_sets"]["compile_failed"].append("foreign/X.sol")
    _resign(mutation)
    _require_targeted_rejection(
        validator,
        law,
        "PF_A4_COMPILE_FAILED_NOT_ATTEMPTED",
        mutation,
    )


def test_a4_compiled_without_attempted_rejected() -> None:
    law = "A4/compiled-subset-attempted"
    positive = _positive_attempt()
    validator = _validator(law)
    _accept_positive(validator, law, positive)

    mutation = deepcopy(positive)
    mutation["source_sets"]["compiled"].append("foreign/Y.sol")
    _resign(mutation)
    _require_targeted_rejection(
        validator,
        law,
        "PF_A4_COMPILED_NOT_ATTEMPTED",
        mutation,
    )


def test_a4_eligible_missing_from_terminal_partition_rejected() -> None:
    law = "A4/eligible-total-terminal-partition"
    positive = _positive_attempt()
    validator = _validator(law)
    _accept_positive(validator, law, positive)

    mutation = deepcopy(positive)
    mutation["source_sets"]["eligible"].append("src/E.sol")
    _resign(mutation)
    _require_targeted_rejection(
        validator,
        law,
        "PF_A4_ELIGIBLE_TERMINAL_PARTITION_INCOMPLETE",
        mutation,
    )


def test_a4_compiled_without_capability_coverage_cannot_be_full() -> None:
    law = "A4/full-means-exact-capability-coverage"
    positive = _positive_attempt()
    validator = _validator(law)
    _accept_positive(validator, law, positive)

    mutation = deepcopy(positive)
    full_row = next(
        row
        for row in mutation["capability_coverage"]
        if row["status"] == "FULL"
    )
    full_row["capability_covered_source_file_ids"] = []
    _resign(mutation)
    _require_targeted_rejection(
        validator,
        law,
        "PF_A4_FULL_WITHOUT_EXACT_CAPABILITY_COVERAGE",
        mutation,
    )
