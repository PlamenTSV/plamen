"""Central conservative policy for terminal negative security decisions.

Citation-shaped prose and model agreement are supporting evidence, not proof
that a candidate is safe.  Under the pipeline's current proof-grade invariant,
terminal exclusion requires a replayable provider authority.  The provider
kinds are reserved here so candidate-negative, application-skeptic, inventory,
and lifecycle consumers can converge on one policy without prompt bloat.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Callable, Mapping

from negative_closure_evidence_authority import (
    AUTHORITY_SCHEMA,
    SUPPORTING_NONTERMINAL_BASES,
    TERMINAL_AUTHORITY_KINDS,
    canonical_json_bytes,
)

_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)

# Live authority is loader-owned and replayed from the central provider-bundle
# denominator.  The legacy v1 mapping/callback seam remains in the signature
# during migration only so stale callers fail closed with an explicit reason.
NEGATIVE_CLOSURE_LIVE_MODE = "LIVE_REPLAYED_PROVIDER_AUTHORITY"


def supporting_negative_resolution(
    *,
    requested_effect: str,
    evidence_basis: str,
) -> dict[str, Any]:
    """Return the one recall-safe result for an unbacked negative proposal.

    This is a small subject-neutral policy projection used by the NC-2
    consumers. It deliberately does not accept a validator callback, trust
    registry, or provider bytes: live authority is loader-owned by the central
    broker. Without an exact central decision, all evidence labels remain
    supporting-only and require independent re-verification.
    """

    effect = str(requested_effect or "").strip().upper() or "UNSPECIFIED"
    basis = str(evidence_basis or "").strip().upper() or "UNSPECIFIED"
    reason = (
        "SUPPORTING_EVIDENCE_ONLY"
        if basis in SUPPORTING_NONTERMINAL_BASES
        else "NO_TYPED_NEGATIVE_CLOSURE_AUTHORITY"
    )
    return {
        "policy_mode": NEGATIVE_CLOSURE_LIVE_MODE,
        "requested_effect": effect,
        "evidence_basis": basis,
        "resolution": "REOPEN_MANDATORY_VERIFICATION",
        "terminal_negative_authorized": False,
        "retention_target": "BODY",
        "mandatory_reverification": True,
        "reason": reason,
    }


def terminal_negative_authorized(
    *,
    work_item: Mapping[str, Any],
    assessment: Mapping[str, Any],
    authority: Mapping[str, Any] | None = None,
    provider_validator: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None,
    closure_authority: Any = None,
    requested_effect: str = "REFUTED_FULL",
) -> tuple[bool, str]:
    """Return whether an exact replayable provider authorizes exclusion.

    No current v1 assessor field can self-issue this authority.  A caller must
    supply a driver/provider artifact and a validator that replays it.  Merely
    naming a terminal kind, attaching a source location, or hashing prose is
    deliberately insufficient.
    """

    basis = str(assessment.get("evidence_basis") or "").strip().upper()
    if closure_authority is not None:
        # Import lazily to keep the pure schema modules acyclic.
        from closure_broker_v2 import (
            AUTHORIZED,
            resolve_central_negative_closure,
        )

        try:
            resolution = resolve_central_negative_closure(
                closure_authority,
                work_item=work_item,
                requested_effect=str(requested_effect or "REFUTED_FULL"),
            )
        except Exception:
            return False, "CENTRAL_NEGATIVE_CLOSURE_REPLAY_FAILED"
        if resolution.get("status") == AUTHORIZED:
            return True, "CENTRAL_REPLAYED_NEGATIVE_CLOSURE_AUTHORITY"
        reasons = resolution.get("debt_reasons")
        if isinstance(reasons, list) and reasons:
            return False, str(reasons[0])
        return False, "NO_PROVIDER_AUTHORITY"
    if authority is not None or provider_validator is not None:
        return False, "LEGACY_NEGATIVE_AUTHORITY_NOT_LIVE"
    if authority is None or provider_validator is None:
        return False, (
            "SUPPORTING_EVIDENCE_ONLY"
            if basis in SUPPORTING_NONTERMINAL_BASES
            else "NO_TYPED_NEGATIVE_CLOSURE_AUTHORITY"
        )
    kind = str(authority.get("authority_kind") or "").strip().upper()
    if kind not in TERMINAL_AUTHORITY_KINDS:
        return False, "UNSUPPORTED_NEGATIVE_CLOSURE_AUTHORITY"
    if authority.get("schema_version") != AUTHORITY_SCHEMA:
        return False, "NEGATIVE_CLOSURE_AUTHORITY_SCHEMA_MISMATCH"
    if authority.get("terminal_negative_authorized") is not True:
        return False, "NEGATIVE_CLOSURE_AUTHORITY_NOT_TERMINAL"
    if str(authority.get("work_item_id") or "") != str(
        work_item.get("work_item_id") or ""
    ):
        return False, "NEGATIVE_CLOSURE_WORK_BINDING_MISMATCH"
    candidate_id = str(
        work_item.get("candidate_negative_family_id")
        or work_item.get("candidate_id")
        or ""
    )
    if str(authority.get("candidate_id") or "") != candidate_id:
        return False, "NEGATIVE_CLOSURE_CANDIDATE_BINDING_MISMATCH"
    premises = work_item.get("candidate_premise_ids")
    if (
        not isinstance(premises, list)
        or authority.get("candidate_premise_ids") != premises
    ):
        return False, "NEGATIVE_CLOSURE_PREMISE_BINDING_MISMATCH"
    claimed_digest = authority.get("authority_digest")
    if not isinstance(claimed_digest, str) or not _HEX64.fullmatch(claimed_digest):
        return False, "NEGATIVE_CLOSURE_AUTHORITY_DIGEST_INVALID"
    unsigned = dict(authority)
    unsigned.pop("authority_digest", None)
    if hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest() != claimed_digest:
        return False, "NEGATIVE_CLOSURE_AUTHORITY_DIGEST_MISMATCH"
    try:
        replayed = provider_validator(authority)
    except Exception:
        replayed = None
    valid = isinstance(replayed, Mapping) and dict(replayed) == dict(authority)
    return (
        (True, "TYPED_NEGATIVE_CLOSURE_AUTHORITY")
        if valid
        else (False, "NEGATIVE_CLOSURE_PROVIDER_REPLAY_FAILED")
    )


__all__ = [
    "NEGATIVE_CLOSURE_LIVE_MODE",
    "SUPPORTING_NONTERMINAL_BASES",
    "TERMINAL_AUTHORITY_KINDS",
    "supporting_negative_resolution",
    "terminal_negative_authorized",
]
