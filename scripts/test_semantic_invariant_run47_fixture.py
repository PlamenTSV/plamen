"""DODO run47 invariants Pass 1: the real rejected trace must now seal and validate.

The worker (Read/Write/Edit/Glob/Grep, no shell) wrote an honest note inside the
sentinels that it cannot compute SHA-256, then the JSON with
`"payload_digest": "UNMEASURABLE_NO_HASH_TOOL"`.  The strict parser failed at
char 0 and a 43KB analysis fell back.  Under the driver-sealed contract the
object is extracted tolerantly and every cryptographic field is stamped by the
driver, so only CONTENT problems (unknown state IDs, bad loci, placeholders)
can fail the trace.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import semantic_invariant_authority as A  # noqa: E402

_NOTE = (
    "NOTE ON THIS BLOCK: this worker has no code-execution/hashing tool available "
    "and therefore cannot compute a genuine SHA-256 digest.\n"
)
_TRACE = (
    "# Semantic invariants\n\nprose...\n\n"
    + A.TRACE_BEGIN + "\n" + _NOTE + "\n"
    + '{\n  "schema_version": "' + A.APPLICATION_TRACE_SCHEMA + '",\n'
    + '  "run_binding_digest": "copied-from-worklist",\n'
    + '  "authority_digest": "copied-from-worklist",\n'
    + '  "worklist_digest": "copied-from-worklist",\n'
    + '  "producer_operator_digest": "UNMEASURABLE_NO_HASH_TOOL",\n'
    + '  "rows": [\n'
    + '    {"state_id": "STATE-0123456789ABCDEF", "disposition": "DELIVERED", '
    + '"evidence_loci": ["contracts/GatewayTransferNative.sol:L36"], '
    + '"write_site_status": "COMPLETE", "semantic_status": "SEMANTICS_UNKNOWN", '
    + '"result": "slippage: write-once, no setter anywhere in source."}\n'
    + '  ],\n  "payload_digest": "UNMEASURABLE_NO_HASH_TOOL"\n}\n'
    + A.TRACE_END + "\n\n<!-- PLAMEN_STATUS: COMPLETE -->\n"
)
_WORKLIST = {
    "run_binding": {"binding_digest": "a" * 64},
    "authority_digest": "b" * 64,
    "worklist_digest": "c" * 64,
    "states": [{"state_id": "STATE-0123456789ABCDEF"}],
}


def test_prose_before_the_object_is_not_the_payload() -> None:
    payload = A.parse_semantic_invariant_application_trace(_TRACE)
    assert payload["schema_version"] == A.APPLICATION_TRACE_SCHEMA
    assert payload["rows"][0]["state_id"] == "STATE-0123456789ABCDEF"


def test_model_written_digests_are_driver_sealed_not_fatal() -> None:
    payload = A.parse_semantic_invariant_application_trace(_TRACE)
    rows, invalid, issues, fatal = A._validate_application_payload(payload, _WORKLIST)
    assert not fatal, issues
    assert issues == []
    assert set(rows) == {"STATE-0123456789ABCDEF"} and invalid == set()
    # sealed in place: every cryptographic field is now driver authority
    assert payload["run_binding_digest"] == "a" * 64
    assert payload["producer_operator_digest"] == A.semantic_invariant_producer_operator_digest()
    assert payload["payload_digest"] == A.payload_digest(payload)


def test_content_problems_still_fail() -> None:
    payload = A.parse_semantic_invariant_application_trace(_TRACE)
    payload["rows"][0]["state_id"] = "STATE-FFFFFFFFFFFFFFFF"
    _rows, _invalid, issues, fatal = A._validate_application_payload(payload, _WORKLIST)
    assert fatal
    assert any("unknown state ID" in issue for issue in issues)


def test_two_objects_or_no_object_is_rejected() -> None:
    import pytest
    with pytest.raises(ValueError):
        A.parse_semantic_invariant_application_trace(A.TRACE_BEGIN + "\nno json here\n" + A.TRACE_END)
