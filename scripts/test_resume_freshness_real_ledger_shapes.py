"""Resume freshness pinned to the four shapes real DODO ledgers actually contain.

Measured on the untouched run46 ledger (died at depth, never resumed) and the
run47 ledger (paused by a provider rate limit at depth).  Before this fix a
resume of either run rewound EVERY completed phase and re-ran the audit from
recon; run47 died that way on 2026-09-20.

Shape census over run46's 787 drifted input bindings:

===========================================  =====  ====================
reason(s) recorded against the consumer       count  correct disposition
===========================================  =====  ====================
PRODUCER_AUTHORITY_MISMATCH, bytes UNCHANGED    746  keep (sibling cascade)
PRODUCER_AUTHORITY_*, bytes moved, run owns      22  keep (supersession)
CONTENT_HASH_CHANGED, run owns current bytes     19  keep (supersession)
===========================================  =====  ====================

The cascade class dominates and is the one that is pure noise: the consumer's
own bytes never moved.  It arises because a producer work unit commits several
outputs, a later same-run unit legitimately replaces ONE of them, and the
producer's whole-unit commit replay then fails for every consumer of the
untouched siblings.

A consumer is up to date iff the bytes it bound are still the bytes on disk
(its immediate inputs).  "A committed output was changed from outside the run"
is a separate property, checked per identity by the committed-output seal scan,
and that is what may rewind a completed phase.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import artifact_ledger as AL  # noqa: E402

RUN = "af554720-9577-431b-ad68-9531cae9fe51"
FOREIGN = "00000000-0000-4000-8000-000000000000"
COMPLETED = (
    "recon", "instantiate", "breadth", "rescan_prepare", "rescan",
    "inventory_prepare", "inventory_chunk_a", "inventory_chunk_b",
    "inventory_chunk_c", "inventory", "invariants", "invariants_p2",
)
PREPASS = "sc/thorough/evm/claude/recon/prepass"
MERGE = "sc/thorough/evm/claude/recon/canonical_merge"
CONSUMER = "sc/thorough/evm/claude/recon/worker.r1.attempt-0003"
DEPTH_UNIT = "sc/thorough/evm/claude/depth/worker.depth-da-iter2"
OLD = "a" * 64
NEW = "b" * 64


def _state(reasons, *, recorded_sha, current_sha, current_status,
           recorded_producer=MERGE, current_producer=MERGE,
           current_run=RUN):
    return {
        "reasons": sorted(reasons),
        "recorded_sha256": recorded_sha,
        "current_sha256": current_sha,
        "content_equal": bool(
            recorded_sha and current_sha and recorded_sha == current_sha
        ),
        "recorded_status": "ACTIVE",
        "recorded_producer_work_unit_key": recorded_producer,
        "recorded_producer_run_id": RUN,
        "current_status": current_status,
        "current_producer_work_unit_key": current_producer,
        "current_producer_run_id": current_run,
    }


def _classify(identity, state, *, unit=CONSUMER, owner=MERGE,
              owner_run=RUN, owner_status="ACTIVE", tampered=(),
              completed=COMPLETED):
    ledger = {
        "work_units": {
            unit: {"run_id": RUN, "semantic_status": "ACTIVE"},
            owner: {"run_id": owner_run, "semantic_status": "ACTIVE"},
        },
        "artifact_bindings": {
            identity: {
                "owner_key": owner,
                "run_id": owner_run,
                "status": owner_status,
                "sha256": state["current_sha256"],
            },
        },
    }
    drift = {
        "rows": [{
            "work_unit_key": unit,
            "changed_input_identities": [identity],
            "reasons": state["reasons"],
        }],
        "identity_states": {unit: {identity: state}},
    }
    tamper = {"rows": [], "tampered_identities": list(tampered)}
    return AL.classify_resume_semantic_drift(
        ledger, drift, tamper, run_id=RUN, completed_phases=list(completed),
    )


def _classes(result):
    return {row["drift_class"] for row in result["rows"]}


# --------------------------------------------------------------------------
# shape 1 (746/787 rows): producer receipt cascade, consumed bytes unchanged
# --------------------------------------------------------------------------

def test_sibling_receipt_cascade_with_unchanged_bytes_keeps_the_phase():
    identity = "scratchpad:attack_surface.md"
    result = _classify(identity, _state(
        ["PRODUCER_AUTHORITY_MISMATCH"],
        recorded_sha=OLD, current_sha=OLD,
        current_status="PRODUCER_AUTHORITY_MISMATCH",
    ))
    assert _classes(result) == {"INTRA_RUN_PRODUCER_RECEIPT_CASCADE"}
    assert result["external_phases"] == []
    assert result["producer_receipt_cascade_identities"] == [identity]


def test_cascade_class_is_not_external():
    assert (
        "INTRA_RUN_PRODUCER_RECEIPT_CASCADE"
        in AL.INTRA_RUN_RESUME_DRIFT_CLASSES
    )
    assert not (
        AL.INTRA_RUN_RESUME_DRIFT_CLASSES
        & AL.EXTERNAL_RESUME_DRIFT_CLASSES
    )


def test_cascade_shape_with_tampered_identity_is_still_external():
    """Positive control: the seal scan overrides the byte comparison."""
    identity = "scratchpad:attack_surface.md"
    result = _classify(
        identity,
        _state(
            ["PRODUCER_AUTHORITY_MISMATCH"],
            recorded_sha=OLD, current_sha=NEW,
            current_status="PRODUCER_AUTHORITY_MISMATCH",
        ),
        tampered=[identity],
    )
    assert _classes(result) == {"EXTERNAL_COMMITTED_OUTPUT_TAMPER"}
    assert result["external_phases"] == ["recon"]


# --------------------------------------------------------------------------
# shape 2 (22/787): bytes moved, this run still owns the current generation
# --------------------------------------------------------------------------

def test_superseded_generation_owned_by_this_run_keeps_the_phase():
    identity = "scratchpad:contract_inventory.md"
    result = _classify(identity, _state(
        ["PRODUCER_AUTHORITY_CHANGED", "PRODUCER_AUTHORITY_MISMATCH"],
        recorded_sha=OLD, current_sha=NEW,
        current_status="PRODUCER_AUTHORITY_MISMATCH",
        recorded_producer=PREPASS, current_producer=MERGE,
    ))
    assert _classes(result) == {"INTRA_RUN_SUPERSESSION"}
    assert result["external_phases"] == []


def test_superseded_generation_owned_by_a_foreign_run_is_external():
    """Positive control: another run's binding is never by-design supersession."""
    identity = "scratchpad:contract_inventory.md"
    result = _classify(
        identity,
        _state(
            ["PRODUCER_AUTHORITY_CHANGED", "PRODUCER_AUTHORITY_MISMATCH"],
            recorded_sha=OLD, current_sha=NEW,
            current_status="PRODUCER_AUTHORITY_MISMATCH",
            current_run=FOREIGN,
        ),
        owner_run=FOREIGN,
    )
    # An observed foreign producer outranks the ledger's own binding row, so
    # it is reported as the more precise external class.
    assert _classes(result) == {"EXTERNAL_FOREIGN_PRODUCER"}
    assert _classes(result) <= AL.EXTERNAL_RESUME_DRIFT_CLASSES
    assert result["external_phases"] == ["recon"]


def test_superseded_generation_with_no_live_owner_is_external():
    identity = "scratchpad:contract_inventory.md"
    result = _classify(
        identity,
        _state(
            ["PRODUCER_AUTHORITY_MISMATCH"],
            recorded_sha=OLD, current_sha=NEW,
            current_status="PRODUCER_AUTHORITY_MISMATCH",
        ),
        owner_status="SUPERSEDED",
    )
    assert _classes(result) == {"EXTERNAL_COMMITTED_OUTPUT_TAMPER"}


# --------------------------------------------------------------------------
# shape 3 (19/787): plain content change the run itself committed
# --------------------------------------------------------------------------

def test_content_change_committed_by_a_later_same_run_unit_keeps_the_phase():
    identity = "scratchpad:skill_dispatch.json"
    result = _classify(identity, _state(
        ["CONTENT_HASH_CHANGED"],
        recorded_sha=OLD, current_sha=NEW, current_status="ACTIVE",
        recorded_producer=PREPASS, current_producer=MERGE,
    ))
    assert _classes(result) == {"INTRA_RUN_SUPERSESSION"}
    assert result["external_phases"] == []


# --------------------------------------------------------------------------
# shape 4: the phase that was in progress at pause time
# --------------------------------------------------------------------------

def test_interrupted_phase_is_rearmed_never_rewound():
    identity = "scratchpad:blind_spot_a_findings.md"
    result = _classify(
        identity,
        _state(
            ["MISSING_AT_BINDING"],
            recorded_sha="", current_sha="", current_status="MISSING",
        ),
        unit=DEPTH_UNIT,
    )
    assert _classes(result) == {"UNARMED_WORK_UNIT"}
    assert result["external_phases"] == []
    assert result["unarmed_work_unit_keys"] == [DEPTH_UNIT]


# --------------------------------------------------------------------------
# the mutable checkpoint is never a content-hashed audit input
# --------------------------------------------------------------------------

def test_checkpoint_identity_is_run_control_state():
    result = _classify(AL.RUN_CONTROL_STATE_IDENTITY, _state(
        ["CONTENT_HASH_CHANGED"],
        recorded_sha=OLD, current_sha=NEW, current_status="ACTIVE",
    ))
    assert _classes(result) == {"RUN_CONTROL_STATE"}
    assert result["external_phases"] == []


def test_run_binding_projection_ignores_control_plane_churn():
    paused = {
        "run_id": RUN,
        "completed": ["recon", "breadth"],
        "rate_limited_at": "depth",
        "degraded": ["recon"],
        "audit_snapshot": {
            "schema": "plamen.audit-input-snapshot.v1",
            "snapshot_digest": "f" * 64,
            "components": {"source_scope": {"digest": "c" * 64}},
        },
    }
    resumed = dict(paused, completed=["recon", "breadth", "rescan"],
                   rate_limited_at=None, degraded=["recon", "breadth"])
    same = AL.run_binding_projection_bytes(
        json.dumps(paused).encode("utf-8")
    )
    assert same == AL.run_binding_projection_bytes(
        json.dumps(resumed).encode("utf-8")
    )
    # but a different run, or different audited inputs, still change it
    other_run = AL.run_binding_projection_bytes(
        json.dumps(dict(paused, run_id=FOREIGN)).encode("utf-8")
    )
    assert other_run != same
    moved = json.loads(json.dumps(paused))
    moved["audit_snapshot"]["components"]["source_scope"]["digest"] = "d" * 64
    assert AL.run_binding_projection_bytes(
        json.dumps(moved).encode("utf-8")
    ) != same
    assert AL.run_binding_projection_bytes(b"not json") is None


# --------------------------------------------------------------------------
# the real run47 record: every reason it recorded is a shape handled above
# --------------------------------------------------------------------------

_FIXTURE = _SCRIPTS / "_fixtures_run47_resume_invalidation.json"


@pytest.mark.skipif(not _FIXTURE.is_file(), reason="run47 fixture absent")
def test_run47_recorded_reasons_are_all_covered_shapes():
    payload = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    rows = payload["invalidation"]["input_drift_rows"]
    assert rows, "fixture must carry the real drift rows"
    reasons = {reason for row in rows for reason in row["reasons"]}
    assert reasons <= {
        "CONTENT_HASH_CHANGED",
        "PRODUCER_AUTHORITY_CHANGED",
        "PRODUCER_AUTHORITY_MISMATCH",
        "MISSING_AT_BINDING",
    }, reasons
    # the run47 record's own verdict, which this fix exists to prevent
    assert payload["invalidation"]["reason"] == "INPUT_DRIFT_WITH_UNTYPED_DESCENDANT"
    assert set(payload["invalidation"]["removed_completed_phases"]) <= set(COMPLETED)
    # every drifted identity is a scratchpad artifact of the same run
    for row in rows:
        for identity in row["changed_input_identities"]:
            assert identity.startswith("scratchpad:")
