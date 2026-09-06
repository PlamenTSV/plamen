from __future__ import annotations

from copy import deepcopy
import hashlib
from typing import Any, Callable, Mapping

from review_fixtures.program_facts_r2_1_b0_red_support import (
    require_accepts,
    require_callable,
)


EXECUTION_AUTHORITY_MODULE = "program_facts_execution_authority"
REUSE_VALIDATOR = "validate_program_facts_generation_reuse_v1"

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


def _positive_generation_replay() -> dict[str, Any]:
    receipt_bytes = (
        b'{"schema_version":"plamen.mechanical_program_facts_receipt.v2",'
        b'"status":"WRITTEN"}\n'
    )
    document: dict[str, Any] = {
        "schema_version": "plamen.program_facts_generation_reuse.v1",
        "current": {
            "run_id": "fixture-run",
            "run_generation": 7,
            "mode": "ACTIVE_EMIT_ONLY",
            "work_unit_id": "program_facts_bake_v2",
            "raw_evidence_digest": H0,
            "parser_digest": H1,
            "helper_digest": H2,
            "tool_digest": H3,
            "config_digest": H4,
            "phaseio_input_set_digest": H5,
            "execution_authority_digest": H6,
            "generation_id": "pf-generation-fixture",
        },
        "candidate": {
            "run_id": "fixture-run",
            "run_generation": 7,
            "mode": "ACTIVE_EMIT_ONLY",
            "work_unit_id": "program_facts_bake_v2",
            "raw_evidence_digest": H0,
            "parser_digest": H1,
            "helper_digest": H2,
            "tool_digest": H3,
            "config_digest": H4,
            "phaseio_input_set_digest": H5,
            "execution_authority_digest": H6,
            "generation_id": "pf-generation-fixture",
            "receipt": {
                "status": "WRITTEN",
                "size": len(receipt_bytes),
                "sha256": hashlib.sha256(receipt_bytes).hexdigest(),
            },
        },
        "decision": {
            "requested": "REUSE_IF_EXACT",
            "adoption_path": "ABSENT_BY_DESIGN",
            "fresh_execution_required": False,
            "rewrite_receipt": False,
        },
        "receipt_bytes": receipt_bytes,
    }
    _assert_local_positive(document)
    return document


def _assert_local_positive(document: Mapping[str, Any]) -> None:
    current = document["current"]
    candidate = document["candidate"]
    compared = (
        "run_id",
        "run_generation",
        "mode",
        "work_unit_id",
        "raw_evidence_digest",
        "parser_digest",
        "helper_digest",
        "tool_digest",
        "config_digest",
        "phaseio_input_set_digest",
        "execution_authority_digest",
        "generation_id",
    )
    assert all(current[field] == candidate[field] for field in compared)
    receipt_bytes = document["receipt_bytes"]
    assert candidate["receipt"]["status"] == "WRITTEN"
    assert candidate["receipt"]["size"] == len(receipt_bytes)
    assert candidate["receipt"]["sha256"] == hashlib.sha256(
        receipt_bytes
    ).hexdigest()
    assert document["decision"] == {
        "requested": "REUSE_IF_EXACT",
        "adoption_path": "ABSENT_BY_DESIGN",
        "fresh_execution_required": False,
        "rewrite_receipt": False,
    }
    assert set(current).issubset(candidate)


def _validator(law: str) -> Callable[..., Any]:
    return require_callable(
        EXECUTION_AUTHORITY_MODULE,
        REUSE_VALIDATOR,
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


def test_a6_same_raw_changed_parser_helper_tool_config_or_mode_never_reused() -> None:
    law = "A6/raw-equality-never-overrides-semantic-drift"
    positive = _positive_generation_replay()
    validator = _validator(law)
    _accept_positive(validator, law, positive)

    for field, replacement in (
        ("parser_digest", H7),
        ("helper_digest", H7),
        ("tool_digest", H7),
        ("config_digest", H7),
        ("mode", "SHADOW_RAW"),
    ):
        mutation = deepcopy(positive)
        mutation["candidate"][field] = replacement
        assert (
            mutation["candidate"]["raw_evidence_digest"]
            == positive["candidate"]["raw_evidence_digest"]
        )
        _require_targeted_rejection(
            validator,
            law,
            "PF_A6_EXECUTION_REUSE_IDENTITY_DRIFT",
            mutation,
        )


def test_a6_changed_run_or_generation_requires_fresh_execution() -> None:
    law = "A6/cross-run-and-generation-reuse-forbidden"
    positive = _positive_generation_replay()
    validator = _validator(law)
    _accept_positive(validator, law, positive)

    for field, replacement in (
        ("run_id", "other-run"),
        ("run_generation", 8),
    ):
        mutation = deepcopy(positive)
        mutation["candidate"][field] = replacement
        mutation["decision"]["fresh_execution_required"] = False
        _require_targeted_rejection(
            validator,
            law,
            "PF_A6_FRESH_EXECUTION_REQUIRED",
            mutation,
        )


def test_a6_old_execution_without_adoption_path_is_rejected() -> None:
    law = "A6/no-latent-cross-generation-adoption"
    positive = _positive_generation_replay()
    validator = _validator(law)
    _accept_positive(validator, law, positive)

    mutation = deepcopy(positive)
    mutation["candidate"]["run_generation"] = 6
    mutation["decision"]["adoption_path"] = "ABSENT_BY_DESIGN"
    _require_targeted_rejection(
        validator,
        law,
        "PF_A6_EXECUTION_ADOPTION_FORBIDDEN",
        mutation,
    )


def test_a6_committed_phaseio_input_drift_same_work_unit_rejected() -> None:
    law = "A6/committed-phaseio-input-drift-blocks-reuse"
    positive = _positive_generation_replay()
    validator = _validator(law)
    _accept_positive(validator, law, positive)

    mutation = deepcopy(positive)
    mutation["candidate"]["phaseio_input_set_digest"] = H8
    _require_targeted_rejection(
        validator,
        law,
        "PF_A6_COMMITTED_PHASEIO_INPUT_DRIFT",
        mutation,
    )


def test_a6_same_generation_replay_does_not_rewrite_written_receipt() -> None:
    law = "A6/same-generation-idempotence-preserves-receipt-bytes"
    positive = _positive_generation_replay()
    validator = _validator(law)
    before = bytes(positive["receipt_bytes"])
    result = _accept_positive(validator, law, positive)
    assert positive["receipt_bytes"] == before
    assert positive["decision"]["rewrite_receipt"] is False
    if isinstance(result, Mapping):
        assert result.get("rewrite_receipt", False) is False
        returned = result.get("receipt_bytes", before)
        assert returned == before
