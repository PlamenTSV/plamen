from __future__ import annotations

from copy import deepcopy
from typing import Any, Callable, Mapping

from review_fixtures.program_facts_r2_1_b0_red_support import (
    body_digest,
    require_accepts,
    require_callable,
)


EXECUTION_AUTHORITY_MODULE = "program_facts_execution_authority"
LAYERING_VALIDATOR = "validate_program_facts_authority_layering_v1"

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
HA = "a" * 64
HB = "b" * 64


def _positive_authority_graph() -> dict[str, Any]:
    execution: dict[str, Any] = {
        "schema_version": "plamen.program_facts_execution_authority.v1",
        "authority_state": "FROZEN_CANDIDATE_EXECUTION_SEMANTICS",
        "components": {
            "build_input": H0,
            "helper": H1,
            "parser": H2,
            "tool_manifest": H3,
            "worker_transaction": H4,
        },
        "execution_authority_digest": H0,
    }
    execution["execution_authority_digest"] = body_digest(
        execution,
        "execution_authority_digest",
    )
    composition: dict[str, Any] = {
        "schema_version": "plamen.program_facts_composition_authority.v1",
        "authority_state": "FROZEN_CANDIDATE_COMPOSITION_SEMANTICS",
        "execution_authority_digest": execution[
            "execution_authority_digest"
        ],
        "components": {
            "composer": H5,
            "public_validators": H6,
            "publication": H7,
            "loader": H8,
        },
        "composition_authority_digest": H0,
    }
    composition["composition_authority_digest"] = body_digest(
        composition,
        "composition_authority_digest",
    )
    methodology: dict[str, Any] = {
        "schema_version": "plamen.program_facts_methodology_package.v2",
        "execution_authority_digest": execution[
            "execution_authority_digest"
        ],
        "composition_authority_digest": composition[
            "composition_authority_digest"
        ],
        "component_policy_digest": H9,
        "methodology_package_digest": H0,
    }
    methodology["methodology_package_digest"] = body_digest(
        methodology,
        "methodology_package_digest",
    )
    document: dict[str, Any] = {
        "schema_version": "plamen.program_facts_authority_layering.v1",
        "execution_authority": execution,
        "composition_authority": composition,
        "methodology_package": methodology,
        "independent_reviews": [
            {
                "role": "B",
                "candidate_digest": execution[
                    "execution_authority_digest"
                ],
                "review_sha256": HA,
            },
            {
                "role": "C",
                "candidate_digest": composition[
                    "composition_authority_digest"
                ],
                "review_sha256": HB,
            },
        ],
        "activation_permit": {
            "execution_authority_digest": execution[
                "execution_authority_digest"
            ],
            "composition_authority_digest": composition[
                "composition_authority_digest"
            ],
            "methodology_package_digest": methodology[
                "methodology_package_digest"
            ],
            "independent_review_sha256s": [HA, HB],
            "permit_digest": H0,
        },
        "build_plan_capture": {
            "origin": "FINAL_RECAPTURE_AFTER_EXECUTION_AUTHORITY_FREEZE",
            "execution_authority_digest": execution[
                "execution_authority_digest"
            ],
            "b1_provisional_plan_digest": H1,
            "final_build_plan_digest": H2,
        },
        "runtime_closure": {
            "state": "FINAL_RUNTIME_QUIESCENT",
            "required_components": [
                "execution-authority",
                "composition-authority",
                "methodology-package",
                "activation-permit",
                "program-facts-bake-v2",
            ],
            "captured_components": [
                "execution-authority",
                "composition-authority",
                "methodology-package",
                "activation-permit",
                "program-facts-bake-v2",
            ],
        },
        "c_bundle_execution": {
            "execution_authority_digest": execution[
                "execution_authority_digest"
            ],
            "composition_authority_digest": composition[
                "composition_authority_digest"
            ],
            "accepted_execution_review_sha256": HA,
        },
    }
    permit = document["activation_permit"]
    permit["permit_digest"] = body_digest(permit, "permit_digest")
    _assert_local_positive(document)
    return document


def _assert_local_positive(document: Mapping[str, Any]) -> None:
    execution = document["execution_authority"]
    composition = document["composition_authority"]
    methodology = document["methodology_package"]
    permit = document["activation_permit"]
    assert execution["execution_authority_digest"] == body_digest(
        execution,
        "execution_authority_digest",
    )
    assert composition["composition_authority_digest"] == body_digest(
        composition,
        "composition_authority_digest",
    )
    assert composition["execution_authority_digest"] == execution[
        "execution_authority_digest"
    ]
    assert methodology["execution_authority_digest"] == execution[
        "execution_authority_digest"
    ]
    assert methodology["composition_authority_digest"] == composition[
        "composition_authority_digest"
    ]
    assert methodology["methodology_package_digest"] == body_digest(
        methodology,
        "methodology_package_digest",
    )
    assert permit["execution_authority_digest"] == execution[
        "execution_authority_digest"
    ]
    assert permit["composition_authority_digest"] == composition[
        "composition_authority_digest"
    ]
    assert permit["methodology_package_digest"] == methodology[
        "methodology_package_digest"
    ]
    assert permit["permit_digest"] == body_digest(permit, "permit_digest")
    capture = document["build_plan_capture"]
    assert capture["origin"] == (
        "FINAL_RECAPTURE_AFTER_EXECUTION_AUTHORITY_FREEZE"
    )
    assert (
        capture["b1_provisional_plan_digest"]
        != capture["final_build_plan_digest"]
    )
    closure = document["runtime_closure"]
    assert closure["required_components"] == closure["captured_components"]
    assert len(closure["required_components"]) == len(
        set(closure["required_components"])
    )


def _validator(law: str) -> Callable[..., Any]:
    return require_callable(
        EXECUTION_AUTHORITY_MODULE,
        LAYERING_VALIDATOR,
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


def _resign_execution(document: dict[str, Any]) -> None:
    execution = document["execution_authority"]
    execution["execution_authority_digest"] = body_digest(
        execution,
        "execution_authority_digest",
    )


def _resign_composition(document: dict[str, Any]) -> None:
    composition = document["composition_authority"]
    composition["composition_authority_digest"] = body_digest(
        composition,
        "composition_authority_digest",
    )


def _resign_permit(document: dict[str, Any]) -> None:
    permit = document["activation_permit"]
    permit["permit_digest"] = body_digest(permit, "permit_digest")


def _rebind_all_authorities(document: dict[str, Any]) -> None:
    _resign_execution(document)
    execution_digest = document["execution_authority"][
        "execution_authority_digest"
    ]
    document["composition_authority"][
        "execution_authority_digest"
    ] = execution_digest
    _resign_composition(document)
    composition_digest = document["composition_authority"][
        "composition_authority_digest"
    ]
    methodology = document["methodology_package"]
    methodology["execution_authority_digest"] = execution_digest
    methodology["composition_authority_digest"] = composition_digest
    methodology["methodology_package_digest"] = body_digest(
        methodology,
        "methodology_package_digest",
    )
    document["independent_reviews"][0][
        "candidate_digest"
    ] = execution_digest
    document["independent_reviews"][1][
        "candidate_digest"
    ] = composition_digest
    permit = document["activation_permit"]
    permit["execution_authority_digest"] = execution_digest
    permit["composition_authority_digest"] = composition_digest
    permit["methodology_package_digest"] = methodology[
        "methodology_package_digest"
    ]
    _resign_permit(document)
    document["build_plan_capture"][
        "execution_authority_digest"
    ] = execution_digest
    bundle = document["c_bundle_execution"]
    bundle["execution_authority_digest"] = execution_digest
    bundle["composition_authority_digest"] = composition_digest


def test_a7_helper_parser_and_composer_change_invalidate_only_correct_layer() -> None:
    law = "A7/component-change-invalidates-owned-authority-layer"
    positive = _positive_authority_graph()
    validator = _validator(law)
    _accept_positive(validator, law, positive)

    execution_mutation = deepcopy(positive)
    execution_mutation["execution_authority"]["components"]["helper"] = H9
    _resign_execution(execution_mutation)
    _require_targeted_rejection(
        validator,
        law,
        "PF_A7_EXECUTION_CHANGE_REQUIRES_DOWNSTREAM_RECAPTURE",
        execution_mutation,
    )

    composition_mutation = deepcopy(positive)
    composition_mutation["composition_authority"]["components"][
        "composer"
    ] = H9
    _resign_composition(composition_mutation)
    _require_targeted_rejection(
        validator,
        law,
        "PF_A7_COMPOSITION_CHANGE_REQUIRES_COMPOSITION_RECAPTURE",
        composition_mutation,
    )


def test_a7_activation_permit_change_does_not_reinterpret_raw_output() -> None:
    law = "A7/permit-is-launch-authority-not-raw-semantics"
    positive = _positive_authority_graph()
    validator = _validator(law)
    _accept_positive(validator, law, positive)

    mutation = deepcopy(positive)
    execution_before = deepcopy(mutation["execution_authority"])
    mutation["activation_permit"]["release_revision"] = 2
    _resign_permit(mutation)
    assert mutation["execution_authority"] == execution_before
    result = require_accepts(validator, law, mutation)
    if isinstance(result, Mapping):
        assert result.get(
            "execution_authority_digest",
            execution_before["execution_authority_digest"],
        ) == execution_before["execution_authority_digest"]


def test_a7_provisional_manifest_cannot_authorize_production() -> None:
    law = "A7/provisional-authority-never-launches-production"
    positive = _positive_authority_graph()
    validator = _validator(law)
    _accept_positive(validator, law, positive)

    mutation = deepcopy(positive)
    mutation["execution_authority"][
        "authority_state"
    ] = "PROVISIONAL_REVIEW_ONLY"
    _rebind_all_authorities(mutation)
    _require_targeted_rejection(
        validator,
        law,
        "PF_A7_PROVISIONAL_AUTHORITY_CANNOT_AUTHORIZE_PRODUCTION",
        mutation,
    )


def test_a7_b1_provisional_plan_cannot_be_adopted_after_execution_freeze() -> None:
    law = "A7/final-build-plan-must-be-recaptured"
    positive = _positive_authority_graph()
    validator = _validator(law)
    _accept_positive(validator, law, positive)

    mutation = deepcopy(positive)
    capture = mutation["build_plan_capture"]
    capture["origin"] = "ADOPTED_B1_PROVISIONAL"
    capture["final_build_plan_digest"] = capture[
        "b1_provisional_plan_digest"
    ]
    _require_targeted_rejection(
        validator,
        law,
        "PF_A7_B1_PROVISIONAL_PLAN_ADOPTION_FORBIDDEN",
        mutation,
    )


def test_a7_final_capture_rejects_missing_future_component() -> None:
    law = "A7/final-runtime-closure-is-path-complete"
    positive = _positive_authority_graph()
    validator = _validator(law)
    _accept_positive(validator, law, positive)

    mutation = deepcopy(positive)
    mutation["runtime_closure"]["captured_components"].remove(
        "program-facts-bake-v2"
    )
    _require_targeted_rejection(
        validator,
        law,
        "PF_A7_FINAL_RUNTIME_COMPONENT_MISSING",
        mutation,
    )


def test_a7_every_c_bundle_execution_binds_accepted_execution_authority() -> None:
    law = "A7/c-bundle-binds-accepted-b-authority"
    positive = _positive_authority_graph()
    validator = _validator(law)
    _accept_positive(validator, law, positive)

    mutation = deepcopy(positive)
    mutation["c_bundle_execution"]["execution_authority_digest"] = H9
    _require_targeted_rejection(
        validator,
        law,
        "PF_A7_C_BUNDLE_EXECUTION_AUTHORITY_DIVERGENCE",
        mutation,
    )


def test_a7_methodology_review_and_permit_order_has_no_digest_cycle() -> None:
    law = "A7/authority-review-permit-digest-graph-is-acyclic"
    positive = _positive_authority_graph()
    validator = _validator(law)
    _accept_positive(validator, law, positive)

    mutation = deepcopy(positive)
    mutation["execution_authority"]["permit_digest"] = mutation[
        "activation_permit"
    ]["permit_digest"]
    _resign_execution(mutation)
    _require_targeted_rejection(
        validator,
        law,
        "PF_A7_AUTHORITY_DIGEST_CYCLE",
        mutation,
    )
