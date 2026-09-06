"""RED specifications for version-aware absence invalidation.

The semantic invalidation planner must treat an observed missing preimage as
one exact generation.  It must not become wildcard authority and must not
alias an ACTIVE zero-byte generation.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest

from artifact_ledger import (
    ArtifactLedgerError,
    arm_semantic_mutation,
    finalize_semantic_mutation,
    semantic_dependency_invalidation_plan,
)


RUN_ID = "run-missing-generation"
ROOT_ID = "scratchpad:root.json"


def _binding(*, status: str, payload: bytes = b"") -> dict[str, Any]:
    return {
        "identity": ROOT_ID,
        "input_class": "BOUNDED_LOOKUP",
        "status": status,
        "size": len(payload) if status == "ACTIVE" else 0,
        "sha256": (
            hashlib.sha256(payload).hexdigest()
            if status == "ACTIVE"
            else ""
        ),
        "producer_work_unit_key": "",
        "producer_contract_digest": "",
    }


def _output(identity: str, payload: bytes) -> dict[str, Any]:
    return {
        "identity": identity,
        "status": "ACTIVE",
        "size": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "writer": "DRIVER",
        "write_mode": "REPLACE",
    }


def _unit(
    key: str,
    *,
    binding: dict[str, Any],
    output_identity: str,
) -> dict[str, Any]:
    return {
        "run_id": RUN_ID,
        "input_bindings": {ROOT_ID: binding},
        "artifacts": {
            output_identity: _output(
                output_identity,
                (key + "\n").encode("utf-8"),
            )
        },
    }


def _ledger() -> dict[str, Any]:
    active_payload = b"prior-active-generation\n"
    return {
        "work_units": {
            "consumer/missing": _unit(
                "consumer/missing",
                binding=_binding(status="MISSING"),
                output_identity="scratchpad:missing-child.json",
            ),
            "consumer/active": _unit(
                "consumer/active",
                binding=_binding(
                    status="ACTIVE",
                    payload=active_payload,
                ),
                output_identity="scratchpad:active-child.json",
            ),
            "consumer/active-empty": _unit(
                "consumer/active-empty",
                binding=_binding(status="ACTIVE", payload=b""),
                output_identity="scratchpad:active-empty-child.json",
            ),
        }
    }


def test_missing_preimage_is_exact_generation_not_wildcard_or_empty_file() -> None:
    plan = semantic_dependency_invalidation_plan(
        _ledger(),
        [ROOT_ID],
        run_id=RUN_ID,
        changed_input_states={
            ROOT_ID: {
                "status": "MISSING",
                "size": 0,
                "sha256": "",
            }
        },
    )

    assert plan["changed_input_states"] == {
        ROOT_ID: {
            "status": "MISSING",
            "size": 0,
            "sha256": "",
        }
    }
    assert plan["invalidated_work_unit_keys"] == ["consumer/missing"]
    assert plan["invalidated_artifact_identities"] == [
        "scratchpad:missing-child.json"
    ]
    assert plan["work_unit_triggers"] == [{
        "work_unit_key": "consumer/missing",
        "trigger_identities": [ROOT_ID],
    }]


def test_missing_to_active_semantic_mutation_finalizes_without_wildcard_debt(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    event = arm_semantic_mutation(
        scratchpad,
        tmp_path,
        artifact_identity=ROOT_ID,
        mutation_kind="FIXTURE_MISSING_TO_ACTIVE",
        run_id=RUN_ID,
    )
    assert event["before"] == {
        "status": "MISSING",
        "size": 0,
        "sha256": "",
    }

    payload = b'{"generation":"active"}\n'
    (scratchpad / "root.json").write_bytes(payload)
    finalized = finalize_semantic_mutation(
        scratchpad,
        tmp_path,
        str(event["event_id"]),
        run_id=RUN_ID,
    )

    assert finalized["status"] == "INVALIDATION_APPLIED"
    assert finalized["invalidated_work_unit_keys"] == []
    assert finalized["after"] == {
        "status": "ACTIVE",
        "size": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }
    assert finalized["plan_digest"]


@pytest.mark.parametrize(
    "malformed",
    (
        {"status": "MISSING", "size": 1, "sha256": ""},
        {
            "status": "MISSING",
            "size": 0,
            "sha256": hashlib.sha256(b"").hexdigest(),
        },
        {"status": "ACTIVE", "size": 0, "sha256": ""},
    ),
)
def test_missing_and_active_generation_encodings_are_canonical(
    malformed: dict[str, Any],
) -> None:
    with pytest.raises(
        ArtifactLedgerError,
        match="invalidation preimage state is malformed",
    ):
        semantic_dependency_invalidation_plan(
            _ledger(),
            [ROOT_ID],
            run_id=RUN_ID,
            changed_input_states={ROOT_ID: malformed},
        )
