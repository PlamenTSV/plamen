from __future__ import annotations

from copy import deepcopy
import hashlib
from typing import Any, Callable, Mapping

from review_fixtures.program_facts_r2_1_b0_red_support import (
    body_digest,
    canonical_bytes,
    require_accepts,
    require_callable,
)


PUBLIC_TYPES_MODULE = "program_facts_types"
PUBLIC_VALIDATOR = "validate_program_facts_v2_representation_v1"

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

AUTHORITY_FIELDS = (
    "execution_authority_digest",
    "composition_authority_digest",
    "methodology_package_digest",
    "activation_decision_digest",
    "activation_permit_digest",
    "build_input_snapshot_digest",
    "candidate_universe_digest",
    "selected_scope_digest",
    "capability_selection_digest",
    "build_plan_digest",
    "execution_set_digest",
)


def _authority_bindings() -> dict[str, str]:
    return dict(
        zip(
            AUTHORITY_FIELDS,
            (H0, H1, H2, H3, H4, H5, H6, H7, H8, H9, HA),
            strict=True,
        )
    )


def _positive_public_bundle() -> dict[str, Any]:
    authority = _authority_bindings()
    receipt: dict[str, Any] = {
        "schema_version": "plamen.mechanical_program_facts_receipt.v2",
        "run_id": "fixture-run",
        "run_generation": 7,
        "status": "DEGRADED",
        "authority_bindings": deepcopy(authority),
        "provider_executions": [
            {
                "provider_id": "evm-structural-provider-v1",
                "build_variant_id": "foundry-default",
                "capability_id": "evm-callgraph-v1",
                "request_digest": HB,
                "request_size": 128,
                "environment_digest": H5,
                "raw_cas": {
                    "namespace": "program-facts-raw-v2",
                    "digest": H6,
                    "size": 256,
                },
                "execution_set_row_digest": HA,
            }
        ],
        "internal_cells": [
            {
                "capability_id": "evm-callgraph-v1",
                "build_variant_id": "foundry-default",
                "internal_state": "PARTIAL",
                "public_status": "PARTIAL",
            }
        ],
        "public_projection_policy_digest": H7,
        "receipt_body_sha256": H0,
    }
    receipt["receipt_body_sha256"] = body_digest(
        receipt,
        "receipt_body_sha256",
    )
    receipt_bytes = canonical_bytes(receipt) + b"\n"
    document: dict[str, Any] = {
        "schema_version": "plamen.program_facts_public_v2_bundle.v1",
        "payload": {
            "schema_version": "plamen.mechanical_program_facts.v2",
            "status": "DEGRADED",
            "authority_bindings": deepcopy(authority),
            "analysis_scope": {
                "claim": "EXACT_SELECTED_SCOPE_NOT_PROJECT_COMPLETE",
                "selected_candidate_ids": ["foundry-default"],
                "unresolved_debt_ids": ["debt-partial-callgraph"],
            },
            "coverage": [
                {
                    "capability_id": "evm-callgraph-v1",
                    "build_variant_id": "foundry-default",
                    "status": "PARTIAL",
                    "unresolved_debt_ids": ["debt-partial-callgraph"],
                }
            ],
        },
        "receipt": receipt,
        "debt": {
            "schema_version": "plamen.mechanical_program_facts_debt.v2",
            "status": "DEGRADED",
            "authority_bindings": deepcopy(authority),
            "rows": [
                {
                    "debt_id": "debt-partial-callgraph",
                    "reason_code": "CAPABILITY_PARTIAL",
                    "terminal_negative_authority": False,
                }
            ],
        },
        "expected_provider_lineage": deepcopy(
            receipt["provider_executions"]
        ),
        "legacy_projection": {
            "source_snapshot_digest": H8,
            "provider_id": "evm-structural-provider-v1",
            "status": "PARTIAL",
        },
        "ledger_binding": {
            "receipt_full_file_size": len(receipt_bytes),
            "receipt_full_file_sha256": hashlib.sha256(
                receipt_bytes
            ).hexdigest(),
        },
    }
    _assert_local_positive(document)
    return document


def _assert_local_positive(document: Mapping[str, Any]) -> None:
    payload = document["payload"]
    receipt = document["receipt"]
    debt = document["debt"]
    assert payload["authority_bindings"] == receipt["authority_bindings"]
    assert receipt["authority_bindings"] == debt["authority_bindings"]
    assert set(receipt["authority_bindings"]) == set(AUTHORITY_FIELDS)
    assert receipt["receipt_body_sha256"] == body_digest(
        receipt,
        "receipt_body_sha256",
    )
    receipt_bytes = canonical_bytes(receipt) + b"\n"
    assert document["ledger_binding"] == {
        "receipt_full_file_size": len(receipt_bytes),
        "receipt_full_file_sha256": hashlib.sha256(
            receipt_bytes
        ).hexdigest(),
    }
    assert receipt["internal_cells"] == [
        {
            "capability_id": "evm-callgraph-v1",
            "build_variant_id": "foundry-default",
            "internal_state": "PARTIAL",
            "public_status": "PARTIAL",
        }
    ]
    assert payload["coverage"][0]["status"] == "PARTIAL"
    assert payload["status"] == receipt["status"] == debt["status"]
    assert document["expected_provider_lineage"] == receipt[
        "provider_executions"
    ]
    assert all(
        row["terminal_negative_authority"] is False
        for row in debt["rows"]
    )


def _validator(law: str) -> Callable[..., Any]:
    return require_callable(PUBLIC_TYPES_MODULE, PUBLIC_VALIDATOR, law)


def _resign_receipt_and_ledger(document: dict[str, Any]) -> None:
    receipt = document["receipt"]
    receipt["receipt_body_sha256"] = body_digest(
        receipt,
        "receipt_body_sha256",
    )
    receipt_bytes = canonical_bytes(receipt) + b"\n"
    document["ledger_binding"] = {
        "receipt_full_file_size": len(receipt_bytes),
        "receipt_full_file_sha256": hashlib.sha256(
            receipt_bytes
        ).hexdigest(),
    }


def _validation_kwargs(
    document: Mapping[str, Any],
    *,
    current_authority: Mapping[str, str] | None = None,
    historical_replay: bool = False,
) -> dict[str, Any]:
    return {
        "captured_authority": deepcopy(
            document["receipt"]["authority_bindings"]
        ),
        "current_authority": deepcopy(
            current_authority
            or document["receipt"]["authority_bindings"]
        ),
        "historical_replay": historical_replay,
    }


def _accept_positive(
    validator: Callable[..., Any],
    law: str,
    document: Mapping[str, Any],
    **overrides: Any,
) -> Any:
    _assert_local_positive(document)
    kwargs = _validation_kwargs(document, **overrides)
    return require_accepts(validator, law, document, **kwargs)


def _require_targeted_rejection(
    validator: Callable[..., Any],
    law: str,
    reason_code: str,
    document: Mapping[str, Any],
) -> None:
    try:
        result = validator(document, **_validation_kwargs(document))
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


def test_a1_execution_set_digest_substitution_rejected_with_legacy_fields_equal() -> None:
    law = "A1/execution-set-direct-public-binding"
    positive = _positive_public_bundle()
    validator = _validator(law)
    _accept_positive(validator, law, positive)

    mutation = deepcopy(positive)
    legacy_before = deepcopy(mutation["legacy_projection"])
    mutation["receipt"]["authority_bindings"]["execution_set_digest"] = HB
    _resign_receipt_and_ledger(mutation)
    assert mutation["legacy_projection"] == legacy_before
    _require_targeted_rejection(
        validator,
        law,
        "PF_A1_EXECUTION_SET_BINDING_DIVERGENCE",
        mutation,
    )


def test_a1_request_environment_and_raw_cas_substitution_rejected() -> None:
    law = "A1/provider-lineage-direct-public-binding"
    positive = _positive_public_bundle()
    validator = _validator(law)
    _accept_positive(validator, law, positive)

    for field, replacement in (
        ("request_digest", H0),
        ("environment_digest", H1),
        ("raw_cas.digest", H2),
    ):
        mutation = deepcopy(positive)
        execution = mutation["receipt"]["provider_executions"][0]
        if field == "raw_cas.digest":
            execution["raw_cas"]["digest"] = replacement
        else:
            execution[field] = replacement
        _resign_receipt_and_ledger(mutation)
        _require_targeted_rejection(
            validator,
            law,
            "PF_A1_PROVIDER_LINEAGE_SUBSTITUTION",
            mutation,
        )


def test_a1_activation_permit_substitution_rejected_by_all_v2_sidecars() -> None:
    law = "A1/permit-binding-present-in-all-sidecars"
    positive = _positive_public_bundle()
    validator = _validator(law)
    _accept_positive(validator, law, positive)

    for sidecar in ("payload", "receipt", "debt"):
        mutation = deepcopy(positive)
        mutation[sidecar]["authority_bindings"][
            "activation_permit_digest"
        ] = HB
        if sidecar == "receipt":
            _resign_receipt_and_ledger(mutation)
        _require_targeted_rejection(
            validator,
            law,
            "PF_A1_PERMIT_BINDING_DIVERGENCE",
            mutation,
        )


def test_a1_every_internal_cell_and_root_status_has_explicit_public_mapping() -> None:
    law = "A1/total-cell-and-root-status-projection"
    positive = _positive_public_bundle()
    validator = _validator(law)
    _accept_positive(validator, law, positive)

    mutation = deepcopy(positive)
    mutation["payload"]["coverage"] = []
    _require_targeted_rejection(
        validator,
        law,
        "PF_A1_PUBLIC_STATUS_MAPPING_INCOMPLETE",
        mutation,
    )


def test_a1_historical_receipt_replays_captured_not_current_authority() -> None:
    law = "A1/historical-replay-uses-captured-authority"
    positive = _positive_public_bundle()
    validator = _validator(law)
    _accept_positive(validator, law, positive)

    current = _authority_bindings()
    current["execution_authority_digest"] = HB
    current["composition_authority_digest"] = H0
    result = _accept_positive(
        validator,
        law,
        positive,
        current_authority=current,
        historical_replay=True,
    )
    if isinstance(result, Mapping) and "authority_source" in result:
        assert result["authority_source"] == "CAPTURED_HISTORICAL"


def test_a1_no_generic_digest_field_has_undocumented_preimage() -> None:
    law = "A1/no-undocumented-generic-digest-preimage"
    positive = _positive_public_bundle()
    validator = _validator(law)
    _accept_positive(validator, law, positive)

    mutation = deepcopy(positive)
    mutation["receipt"]["implementation_digest"] = HB
    _resign_receipt_and_ledger(mutation)
    _require_targeted_rejection(
        validator,
        law,
        "PF_A1_UNDOCUMENTED_DIGEST_PREIMAGE",
        mutation,
    )


def test_a1_receipt_body_digest_and_ledger_full_file_digest_are_nonrecursive() -> None:
    law = "A1/nonrecursive-body-and-full-file-digests"
    positive = _positive_public_bundle()
    validator = _validator(law)
    _accept_positive(validator, law, positive)

    mutation = deepcopy(positive)
    mutation["receipt"]["receipt_body_sha256"] = mutation["ledger_binding"][
        "receipt_full_file_sha256"
    ]
    _require_targeted_rejection(
        validator,
        law,
        "PF_A1_RECEIPT_DIGEST_GRAPH_RECURSIVE_OR_DIVERGENT",
        mutation,
    )
