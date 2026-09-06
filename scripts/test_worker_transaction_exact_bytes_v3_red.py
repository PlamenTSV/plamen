"""B0 RED fixtures for the WorkerTransaction v3 exact-byte contract.

The fixtures are deliberately synthetic and offline.  Production modules are
resolved only inside test functions so an absent future API is recorded as a
law-specific RED rather than an import or collection failure.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
from typing import Any, Callable, Mapping

from review_fixtures.program_facts_r2_1_b0_red_support import (
    require_accepts,
    require_callable,
)


WORKER_TRANSACTION_MODULE = "worker_transaction"
RESERVED_TOKENS = (
    "__PLAMEN_ATTEMPT_ID__",
    "__PLAMEN_ATTEMPT_RELATIVE_PATH__",
    "__PLAMEN_ATTEMPT_OUTPUT_RELATIVE_PATH__",
    "__PLAMEN_ATTEMPT_OUTPUT_DIRECTORY__",
)


def _request_bytes() -> bytes:
    return (
        b'{"__PLAMEN_ATTEMPT_ID__":"__PLAMEN_ATTEMPT_RELATIVE_PATH__",'
        b'"path":"root/__PLAMEN_ATTEMPT_OUTPUT_RELATIVE_PATH__/'
        b'__PLAMEN_ATTEMPT_OUTPUT_DIRECTORY__",'
        b'"literal":"__PLAMEN_ATTEMPT_ID__"}'
    )


def _exact_input_document(payload: bytes | None = None) -> dict[str, Any]:
    source = _request_bytes() if payload is None else payload
    digest = hashlib.sha256(source).hexdigest()
    document: dict[str, Any] = {
        "schema": "plamen.worker_work_plan.v3",
        "input_name": "prompt",
        "delivery_mode": "EXACT_BYTES_NO_TEMPLATE_EXPANSION",
        "adapter_stdin_input_name": "prompt",
        "source_bytes": source,
        "source_size": len(source),
        "source_sha256": digest,
        "armed_view_bytes": source,
        "armed_view_size": len(source),
        "armed_view_sha256": digest,
        "delivered_stdin_bytes": source,
        "delivered_stdin_size": len(source),
        "delivered_stdin_sha256": digest,
        "program_facts_request_encoding": "CANONICAL_UTF8_JSON",
        "template_expansion_applied": False,
    }
    _assert_exact_positive(document)
    return document


def _assert_exact_positive(document: Mapping[str, Any]) -> None:
    source = document["source_bytes"]
    assert isinstance(source, bytes)
    assert document["delivery_mode"] == (
        "EXACT_BYTES_NO_TEMPLATE_EXPANSION"
    )
    assert document["input_name"] == document["adapter_stdin_input_name"]
    assert document["template_expansion_applied"] is False
    for prefix in ("source", "armed_view", "delivered_stdin"):
        value = document[f"{prefix}_bytes"]
        assert value == source
        assert document[f"{prefix}_size"] == len(value)
        assert document[f"{prefix}_sha256"] == hashlib.sha256(
            value
        ).hexdigest()
    assert all(token.encode("ascii") in source for token in RESERVED_TOKENS)


def _validator(law: str) -> Callable[..., Any]:
    return require_callable(
        WORKER_TRANSACTION_MODULE,
        "validate_program_facts_exact_input_v3",
        law,
    )


def _accept_positive(
    validator: Callable[..., Any],
    law: str,
    document: Mapping[str, Any],
) -> None:
    _assert_exact_positive(document)
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


def test_a2_exact_request_preserves_each_current_reserved_token() -> None:
    law = "A2/exact-request-preserves-current-reserved-token-denominator"
    positive = _exact_input_document()
    validator = _validator(law)
    _accept_positive(validator, law, positive)

    for token in RESERVED_TOKENS:
        mutation = deepcopy(positive)
        token_bytes = token.encode("ascii")
        mutation["armed_view_bytes"] = mutation[
            "armed_view_bytes"
        ].replace(token_bytes, b"expanded-value", 1)
        mutation["armed_view_size"] = len(mutation["armed_view_bytes"])
        mutation["armed_view_sha256"] = hashlib.sha256(
            mutation["armed_view_bytes"]
        ).hexdigest()
        _require_targeted_rejection(
            validator,
            law,
            "PF_A2_EXACT_INPUT_RESERVED_TOKEN_CHANGED",
            mutation,
        )


def test_a2_reserved_token_in_json_key_value_and_path_is_unchanged() -> None:
    law = "A2/reserved-token-position-does-not-enable-expansion"
    positive = _exact_input_document()
    validator = _validator(law)
    _accept_positive(validator, law, positive)

    mutation = deepcopy(positive)
    mutation["template_expansion_applied"] = True
    mutation["delivered_stdin_bytes"] = (
        mutation["delivered_stdin_bytes"]
        .replace(b"__PLAMEN_ATTEMPT_ID__", b"attempt-expanded")
        .replace(
            b"__PLAMEN_ATTEMPT_RELATIVE_PATH__",
            b"phase/unit/attempt-expanded",
        )
    )
    mutation["delivered_stdin_size"] = len(
        mutation["delivered_stdin_bytes"]
    )
    mutation["delivered_stdin_sha256"] = hashlib.sha256(
        mutation["delivered_stdin_bytes"]
    ).hexdigest()
    _require_targeted_rejection(
        validator,
        law,
        "PF_A2_EXACT_INPUT_TEMPLATE_EXPANSION_FORBIDDEN",
        mutation,
    )


def test_a2_source_view_and_delivered_stdin_hash_mismatch_rejected() -> None:
    law = "A2/source-view-stdin-exact-byte-equality"
    positive = _exact_input_document()
    validator = _validator(law)
    _accept_positive(validator, law, positive)

    mutation = deepcopy(positive)
    mutation["delivered_stdin_sha256"] = "f" * 64
    _require_targeted_rejection(
        validator,
        law,
        "PF_A2_SOURCE_VIEW_STDIN_DIGEST_DIVERGED",
        mutation,
    )


def test_a2_program_facts_invalid_utf8_rejected_before_workplan() -> None:
    law = "A2/program-facts-utf8-precedes-workplan-compilation"
    positive = _exact_input_document()
    validator = _validator(law)
    _accept_positive(validator, law, positive)

    invalid = deepcopy(positive)
    invalid_bytes = positive["source_bytes"][:-1] + b',"\xff":true}'
    invalid["source_bytes"] = invalid_bytes
    invalid["source_size"] = len(invalid_bytes)
    invalid["source_sha256"] = hashlib.sha256(invalid_bytes).hexdigest()
    invalid["armed_view_bytes"] = invalid_bytes
    invalid["armed_view_size"] = len(invalid_bytes)
    invalid["armed_view_sha256"] = hashlib.sha256(invalid_bytes).hexdigest()
    invalid["delivered_stdin_bytes"] = invalid_bytes
    invalid["delivered_stdin_size"] = len(invalid_bytes)
    invalid["delivered_stdin_sha256"] = hashlib.sha256(
        invalid_bytes
    ).hexdigest()
    invalid["workplan_compiled"] = False
    _require_targeted_rejection(
        validator,
        law,
        "PF_A2_INVALID_UTF8_BEFORE_WORKPLAN",
        invalid,
    )


def test_a2_v1_v2_callers_have_byte_and_behavior_parity_without_exact_mode() -> None:
    law = "A2/legacy-v1-v2-nonexact-byte-and-behavior-parity"
    comparator = require_callable(
        WORKER_TRANSACTION_MODULE,
        "compare_v1_v2_nonexact_input_behavior",
        law,
    )
    positive = {
        "input_bytes": (
            b"write to __PLAMEN_ATTEMPT_OUTPUT_DIRECTORY__ exactly"
        ),
        "scratchpad_semantic_id": "scratchpad-fixture",
        "write_scope": {
            "attempt_id": "attempt-" + ("1" * 24),
            "attempt_relative_path": (
                "recon/unit/attempts/attempt-" + ("1" * 24)
            ),
            "output_relative_path": (
                "recon/unit/attempts/attempt-" + ("1" * 24) + "/output"
            ),
        },
        "v1_delivery_mode": "TEMPLATE_UTF8",
        "v2_delivery_mode": "TEMPLATE_UTF8",
        "v1_behavior": "LEGACY_TEMPLATE_UTF8",
        "v2_behavior": "LEGACY_TEMPLATE_UTF8",
    }
    assert positive["v1_delivery_mode"] == positive["v2_delivery_mode"]
    assert positive["v1_behavior"] == positive["v2_behavior"]
    require_accepts(comparator, law, positive)

    mutation = deepcopy(positive)
    mutation["v2_behavior"] = "EXACT_BYTES_NO_TEMPLATE_EXPANSION"
    _require_targeted_rejection(
        comparator,
        law,
        "PF_A2_LEGACY_NONEXACT_PARITY_DIVERGED",
        mutation,
    )
