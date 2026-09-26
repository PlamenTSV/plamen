"""Typed admission of semantically complete output after provider failure.

A provider process can finish an exact artifact and then return a non-zero
transport status (for example, a capacity error emitted while the CLI is
closing the turn).  The transport status remains evidence and is never
rewritten to zero.  This module only recognizes the narrower case where the
same frozen staged-output validator accepted the complete output denominator
and the compatibility runtime published those exact bytes transactionally.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping, Sequence


RECOVERY_SCHEMA = "plamen.provider_nonzero_semantic_completion.v1"
RECOVERY_STATUS = "SEMANTIC_GATE_ACCEPTED"


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def build_provider_nonzero_semantic_completion(
    *,
    provider_returncode: int,
    validator_binding: Mapping[str, Any],
    completed_output_evidence: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Bind one non-zero provider exit to the exact accepted output vector."""

    if (
        type(provider_returncode) is not int
        or provider_returncode == 0
        or not isinstance(validator_binding, Mapping)
        or not isinstance(validator_binding.get("binding_sha256"), str)
        or not completed_output_evidence
    ):
        raise ValueError("provider semantic completion inputs are malformed")
    evidence = [dict(row) for row in completed_output_evidence]
    return {
        "schema": RECOVERY_SCHEMA,
        "status": RECOVERY_STATUS,
        "provider_returncode": provider_returncode,
        "validator_binding_sha256": validator_binding["binding_sha256"],
        "completed_output_evidence_sha256": _digest({"outputs": evidence}),
    }


def provider_transport_completion_is_admitted(receipt: Mapping[str, Any]) -> bool:
    """Return whether a completed receipt has honest transport authority.

    A normal zero exit needs no recovery companion.  A non-zero exit is
    admitted only for Codex, only outside the research-event profile, and only
    when its typed recovery companion binds the frozen validator and the exact
    published output evidence.  Timeout, stream overflow, semantic rejection,
    and absent gates remain failures.
    """

    if not isinstance(receipt, Mapping):
        return False
    returncode = receipt.get("returncode")
    recovery = receipt.get("provider_nonzero_semantic_completion")
    if returncode == 0:
        return recovery is None
    if type(returncode) is not int or returncode == 0:
        return False
    binding = receipt.get("staged_output_validator_binding")
    evidence = receipt.get("completed_output_evidence")
    if (
        receipt.get("backend") != "codex"
        or receipt.get("provider_event_profile") is not None
        or receipt.get("status") != "COMPLETED"
        or receipt.get("failure_code") is not None
        or receipt.get("compatibility_return_value") != 0
        or receipt.get("timed_out") is not False
        or receipt.get("overflowed_stream") is not None
        or receipt.get("staged_output_rejection_reasons") != []
        or not isinstance(binding, Mapping)
        or not isinstance(binding.get("binding_sha256"), str)
        or not isinstance(evidence, list)
        or not evidence
        or not isinstance(recovery, Mapping)
        or set(recovery) != {
            "schema",
            "status",
            "provider_returncode",
            "validator_binding_sha256",
            "completed_output_evidence_sha256",
        }
        or recovery.get("schema") != RECOVERY_SCHEMA
        or recovery.get("status") != RECOVERY_STATUS
        or recovery.get("provider_returncode") != returncode
        or recovery.get("validator_binding_sha256")
        != binding.get("binding_sha256")
    ):
        return False
    try:
        expected = _digest({"outputs": evidence})
    except (TypeError, UnicodeError, ValueError):
        return False
    return recovery.get("completed_output_evidence_sha256") == expected


__all__ = [
    "RECOVERY_SCHEMA",
    "RECOVERY_STATUS",
    "build_provider_nonzero_semantic_completion",
    "provider_transport_completion_is_admitted",
]
