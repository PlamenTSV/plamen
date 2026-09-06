"""Adversarial P1-M/P0-AF-v2 queue-adapter boundary fixtures.

These tests intentionally specify fail-closed properties that the first pure
adapter implementation does not yet satisfy.  They are review evidence, not a
second implementation of the adapter.
"""

from __future__ import annotations

import hashlib
import json
import os
from copy import deepcopy
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import authentication_role_authority as role_authority  # noqa: E402
import chain_tail_authority as chain_tail  # noqa: E402
import p0af_v2_queue_runtime as queue_runtime  # noqa: E402
import plamen_driver as driver  # noqa: E402
import test_chain_tail_compound_delivery_p0_t as chain_delivery_fixture  # noqa: E402
import test_p1_dm_live_driver_cutover as live_p1m  # noqa: E402
from compound_verification import (  # noqa: E402
    CompoundCandidate,
    ConstituentAuthorityBinding,
    compile_compound_work_plan,
)
from p0af_v2_queue_adapter import (  # noqa: E402
    CANDIDATE_FILE,
    ROUTE_DEBT_FILE,
    WORK_AUTHORITY_FILE,
    _candidate_from_record,
    plan_p0af_v2_queue_delivery,
)
from plamen_parsers import (  # noqa: E402
    _read_typed_queue_work_items,
    _typed_queue_item_legacy_row,
    _write_queue_subset_manifest,
    _typed_queue_items_from_rows,
    ensure_sc_verify_shard_manifests,
    parse_verification_queue_rows,
)
from queue_work_items import queue_records_to_json, render_queue_markdown  # noqa: E402
from queue_work_items import build_lineage_index  # noqa: E402
from queue_work_items import QueueWorkItem  # noqa: E402
from test_p0af_v2_queue_adapter_p1_m import (  # noqa: E402
    _artifacts,
    _canonical_ids,
    _payload_digest,
    _write_json,
)
from test_authentication_role_authority_p1_m import (  # noqa: E402
    _anchor as _real_anchor,
    _checkpoint as _real_checkpoint,
    _derived as _real_derived,
    _payload as _real_trace_payload,
)
from verification_method_compiler import (  # noqa: E402
    OPERATOR_PROPOSAL_SCHEMA,
    VerificationMethodError,
    build_verification_context_packets,
    compile_verification_method_dispatch,
    validate_operator_application_proposal,
)


FACT_AUTHORITY = "authentication_role_fact_authority.json"


def _live_p1m_producer(
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    config: dict[str, object] | None = None,
) -> tuple[dict[str, object], str]:
    """Run the real P1-M driver producer with only model transport stubbed."""

    live_p1m._checkpoint(root)
    live_p1m._graph(root)
    config = config or live_p1m._config(root)

    def execute_role(**_kwargs) -> int:
        (root / role_authority.TRACE_FILE).write_text(
            json.dumps(
                live_p1m._role_trace(root), indent=2, sort_keys=True
            ) + "\n",
            encoding="utf-8",
        )
        return 0

    monkeypatch.setattr(
        driver, "_execute_auxiliary_model_work_unit", execute_role
    )
    assert driver._run_authentication_role_boundary(
        root, config, live_p1m._phase("depth")
    ) == []
    composition = json.loads(
        (root / role_authority.COMPOSITION_FILE).read_text(encoding="utf-8")
    )
    live_p1m._canonical_ids(root)

    def execute_chain(**_kwargs) -> int:
        obligation = composition["obligations"][0]
        payload = {
            "schema_version": "plamen.arm_before_trust_chain_analysis.v1",
            "composition_digest": composition["composition_digest"],
            "operator_digest": "e" * 64,
            "candidates": [{
                "candidate_id": "MZO-CAND-ADVERSARIAL-LIVE",
                "obligation_id": obligation["obligation_id"],
                "obligation_digest": obligation["obligation_digest"],
                "constituent_fact_ids": obligation["constituent_fact_ids"],
                "disposition": "NOMINATED",
                "reachability_evidence": ["src/Auth.sol:L30"],
                "composition_result": "The typed halves compose in scope.",
                "harm_result": "Material harm needs independent verification.",
                "proof_authority": "NONE",
                "route": "P0_AF_V2_QUEUE_ADAPTER_REQUIRED",
            }],
        }
        payload["payload_digest"] = driver._stable_payload_digest(payload)
        (root / driver.ARM_BEFORE_TRUST_CHAIN_ANALYSIS_FILE).write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return 0

    monkeypatch.setattr(
        driver, "_execute_auxiliary_model_work_unit", execute_chain
    )
    assert driver._run_authentication_chain_consumer_boundary(
        root, config, live_p1m._phase("chain")
    ) == []
    work = json.loads(
        (root / driver.ARM_BEFORE_TRUST_COMPOUND_WORK_PLAN_FILE).read_text(
            encoding="utf-8"
        )
    )["compound_work_plan"]["work_items"][0]
    assert work["readiness"] == "READY"
    return config, str(work["subject_id"])


def _ordinary_queue(root: Path, ids: tuple[str, ...] = ("M-01",)) -> None:
    _write_queue_subset_manifest(
        root / "verification_queue.md",
        [
            {
                "queue #": str(index),
                "finding id": work_id,
                "severity": "Medium",
                "title": f"Independent ordinary work {work_id}",
                "bug class": "state-transition",
                "preferred tag": "CODE-TRACE",
                "location": f"findings_inventory.md:{index}",
                "primary artifact": "findings_inventory.md",
                "poc class": "structural",
            }
            for index, work_id in enumerate(ids, 1)
        ],
    )


def _live_runtime_ready(
    root: Path, monkeypatch: pytest.MonkeyPatch,
) -> tuple[dict[str, object], str]:
    config, p1m_id = _live_p1m_producer(root, monkeypatch)
    _ordinary_queue(root)
    return config, p1m_id


def _real_p1m_artifacts(root: Path) -> None:
    """Build the adapter tuple from the production P1-M fact provider."""

    _real_checkpoint(root)
    authority, _composition, _research, _projection = (
        role_authority.derive_authentication_role_authority(
            root,
            trace_payload=_real_trace_payload([_real_anchor(), _real_derived()]),
        )
    )
    _write_json(root / role_authority.AUTHORITY_FILE, authority)
    _canonical_ids(root)
    bindings = tuple(
        ConstituentAuthorityBinding.create(
            {
                "constituent_id": row["fact_id"],
                "constituent_kind": "EVIDENCE_FACT",
                "fact_digest": row["fact_digest"],
                "authority_digest": authority["authority_digest"],
                "source_artifact": role_authority.AUTHORITY_FILE,
            }
        )
        for row in authority["facts"]
    )
    candidate = CompoundCandidate.create(
        chain_id="CH-17",
        constituents=tuple(binding.constituent_id for binding in bindings),
        evidence_constituent_bindings=bindings,
        severity_upgrade_justified=True,
        ordering_edges=(),
        preconditions=("Both typed role facts are independently reachable.",),
        postconditions=("Independent execution must establish composed harm.",),
        combined_impact_claim="A bounded composition hypothesis requiring execution.",
        proposed_severity="Medium",
        source_lineage=("typed_composition.json:candidate=1",),
        coverage_lineage=("COVERAGE-0001",),
        pipeline="SC",
        mode="thorough",
    )
    candidate_payload = {
        "schema_version": "plamen.arm_before_trust_compound_candidates.v1",
        "source_analysis_digest": "d" * 64,
        "source_composition_digest": "e" * 64,
        "source_fact_authority_digest": authority["authority_digest"],
        "identity_denominator_artifact": "_canonical_finding_ids.json",
        "identity_denominator_digest": hashlib.sha256(
            (root / "_canonical_finding_ids.json").read_bytes()
        ).hexdigest(),
        "proof_authority": "NONE",
        "candidate_count": 1,
        "candidates": [candidate.to_record()],
    }
    candidate_payload["payload_digest"] = _payload_digest(candidate_payload)
    _write_json(root / CANDIDATE_FILE, candidate_payload)

    plan = compile_compound_work_plan(
        (candidate,),
        known_constituent_identities=(),
        known_evidence_constituents=bindings,
    ).to_record()
    work_payload = {
        "schema_version": "plamen.arm_before_trust_compound_work_authority.v1",
        "candidate_payload_digest": candidate_payload["payload_digest"],
        "proof_authority": "NONE",
        "compound_work_plan": plan,
    }
    work_payload["payload_digest"] = _payload_digest(work_payload)
    _write_json(root / WORK_AUTHORITY_FILE, work_payload)
    route = {
        "schema_version": "plamen.arm_before_trust_p0af_route_debt.v1",
        "status": "READY_PENDING_QUEUE_DELIVERY",
        "work_authority_digest": work_payload["payload_digest"],
        "ready_work_item_ids": ["CH-17"],
        "ordinary_verification_required": True,
        "route": "P0_AF_V2_QUEUE_ADAPTER_REQUIRED",
        "proof_authority": "NONE",
    }
    route["payload_digest"] = _payload_digest(route)
    _write_json(root / ROUTE_DEBT_FILE, route)


def _rewrite_as_hybrid_finding_and_fact_candidate(root: Path) -> None:
    """Write one valid v2 work item with one finding and one evidence fact."""

    finding_id = "FIND-01"
    fact_id = "AUTH-FACT-0001"
    _canonical_ids(root, (finding_id,))
    authority = json.loads((root / FACT_AUTHORITY).read_text(encoding="utf-8"))
    fact = next(row for row in authority["facts"] if row["fact_id"] == fact_id)
    binding = ConstituentAuthorityBinding.create(
        {
            "constituent_id": fact_id,
            "constituent_kind": "EVIDENCE_FACT",
            "fact_digest": fact["fact_digest"],
            "authority_digest": authority["authority_digest"],
            "source_artifact": FACT_AUTHORITY,
        }
    )
    candidate = CompoundCandidate.create(
        chain_id="CH-17",
        constituents=(finding_id, fact_id),
        evidence_constituent_bindings=(binding,),
        severity_upgrade_justified=True,
        ordering_edges=((finding_id, fact_id, "enables"),),
        preconditions=("The finding and typed fact are independently reachable.",),
        postconditions=("Independent execution must establish composed harm.",),
        combined_impact_claim="A bounded composition hypothesis requiring execution.",
        proposed_severity="Medium",
        source_lineage=("typed_composition.json:candidate=1",),
        coverage_lineage=("COVERAGE-0001",),
        pipeline="SC",
        mode="thorough",
    )
    candidate_payload = {
        "schema_version": "plamen.arm_before_trust_compound_candidates.v1",
        "source_analysis_digest": "d" * 64,
        "source_composition_digest": "e" * 64,
        "source_fact_authority_digest": authority["authority_digest"],
        "identity_denominator_artifact": "_canonical_finding_ids.json",
        "identity_denominator_digest": hashlib.sha256(
            (root / "_canonical_finding_ids.json").read_bytes()
        ).hexdigest(),
        "proof_authority": "NONE",
        "candidate_count": 1,
        "candidates": [candidate.to_record()],
    }
    candidate_payload["payload_digest"] = _payload_digest(candidate_payload)
    _write_json(root / CANDIDATE_FILE, candidate_payload)

    plan = compile_compound_work_plan(
        (candidate,),
        known_constituent_identities=(finding_id,),
        known_evidence_constituents=(binding,),
    ).to_record()
    work_payload = {
        "schema_version": "plamen.arm_before_trust_compound_work_authority.v1",
        "candidate_payload_digest": candidate_payload["payload_digest"],
        "proof_authority": "NONE",
        "compound_work_plan": plan,
    }
    work_payload["payload_digest"] = _payload_digest(work_payload)
    _write_json(root / WORK_AUTHORITY_FILE, work_payload)

    route = {
        "schema_version": "plamen.arm_before_trust_p0af_route_debt.v1",
        "status": "READY_PENDING_QUEUE_DELIVERY",
        "work_authority_digest": work_payload["payload_digest"],
        "ready_work_item_ids": ["CH-17"],
        "ordinary_verification_required": True,
        "route": "P0_AF_V2_QUEUE_ADAPTER_REQUIRED",
        "proof_authority": "NONE",
    }
    route["payload_digest"] = _payload_digest(route)
    _write_json(root / ROUTE_DEBT_FILE, route)


def _rewrite_with_equivalent_public_chain_alias(
    root: Path,
    *,
    chain_ids: tuple[str, ...] = ("CH-17", "CH-18"),
) -> None:
    candidate_payload = json.loads(
        (root / CANDIDATE_FILE).read_text(encoding="utf-8")
    )
    template = candidate_payload["candidates"][0]
    records = []
    for index, chain_id in enumerate(chain_ids, start=1):
        record = deepcopy(template)
        record["chain_id"] = chain_id
        record["source_lineage"] = [
            f"typed_composition.json:candidate={index}"
        ]
        records.append(record)
    candidate_payload["candidate_count"] = len(records)
    candidate_payload["candidates"] = records
    candidate_payload["payload_digest"] = _payload_digest(candidate_payload)
    _write_json(root / CANDIDATE_FILE, candidate_payload)

    candidates = tuple(
        _candidate_from_record(row) for row in candidate_payload["candidates"]
    )
    bindings = candidates[0].evidence_constituent_bindings
    plan = compile_compound_work_plan(
        candidates,
        known_constituent_identities=(),
        known_evidence_constituents=bindings,
    ).to_record()
    work_payload = {
        "schema_version": "plamen.arm_before_trust_compound_work_authority.v1",
        "candidate_payload_digest": candidate_payload["payload_digest"],
        "proof_authority": "NONE",
        "compound_work_plan": plan,
    }
    work_payload["payload_digest"] = _payload_digest(work_payload)
    _write_json(root / WORK_AUTHORITY_FILE, work_payload)
    ready = [
        row["subject_id"]
        for row in plan["work_items"]
        if row["readiness"] == "READY"
    ]
    route = {
        "schema_version": "plamen.arm_before_trust_p0af_route_debt.v1",
        "status": "READY_PENDING_QUEUE_DELIVERY",
        "work_authority_digest": work_payload["payload_digest"],
        "ready_work_item_ids": ready,
        "ordinary_verification_required": True,
        "route": "P0_AF_V2_QUEUE_ADAPTER_REQUIRED",
        "proof_authority": "NONE",
    }
    route["payload_digest"] = _payload_digest(route)
    _write_json(root / ROUTE_DEBT_FILE, route)


def _rewrite_with_many_fact_bindings(root: Path, *, count: int) -> None:
    """Build one valid candidate whose binding denominator is independently large."""

    _canonical_ids(root)
    fact_rows = [
        {"fact_id": f"AUTH-FACT-{index:06d}"}
        for index in range(1, count + 1)
    ]
    for row in fact_rows:
        row["fact_digest"] = _payload_digest(row)
    authority = {
        "schema_version": "plamen.authentication_role_fact_authority.v1",
        "facts": fact_rows,
    }
    authority["authority_digest"] = _payload_digest(authority)
    _write_json(root / FACT_AUTHORITY, authority)
    bindings = tuple(
        ConstituentAuthorityBinding.create(
            {
                "constituent_id": row["fact_id"],
                "constituent_kind": "EVIDENCE_FACT",
                "fact_digest": row["fact_digest"],
                "authority_digest": authority["authority_digest"],
                "source_artifact": FACT_AUTHORITY,
            }
        )
        for row in fact_rows
    )
    candidate = CompoundCandidate.create(
        chain_id="CH-17",
        constituents=tuple(binding.constituent_id for binding in bindings),
        evidence_constituent_bindings=bindings,
        severity_upgrade_justified=True,
        ordering_edges=(),
        preconditions=("Every typed constituent requires independent verification.",),
        postconditions=("Independent execution must establish composed harm.",),
        combined_impact_claim="A bounded composition hypothesis requiring execution.",
        proposed_severity="Medium",
        source_lineage=("typed_composition.json:candidate=1",),
        coverage_lineage=("COVERAGE-0001",),
        pipeline="SC",
        mode="thorough",
    )
    candidate_payload = {
        "schema_version": "plamen.arm_before_trust_compound_candidates.v1",
        "source_analysis_digest": "d" * 64,
        "source_composition_digest": "e" * 64,
        "source_fact_authority_digest": authority["authority_digest"],
        "identity_denominator_artifact": "_canonical_finding_ids.json",
        "identity_denominator_digest": hashlib.sha256(
            (root / "_canonical_finding_ids.json").read_bytes()
        ).hexdigest(),
        "proof_authority": "NONE",
        "candidate_count": 1,
        "candidates": [candidate.to_record()],
    }
    candidate_payload["payload_digest"] = _payload_digest(candidate_payload)
    _write_json(root / CANDIDATE_FILE, candidate_payload)
    plan = compile_compound_work_plan(
        (candidate,),
        known_constituent_identities=(),
        known_evidence_constituents=bindings,
    ).to_record()
    work_payload = {
        "schema_version": "plamen.arm_before_trust_compound_work_authority.v1",
        "candidate_payload_digest": candidate_payload["payload_digest"],
        "proof_authority": "NONE",
        "compound_work_plan": plan,
    }
    work_payload["payload_digest"] = _payload_digest(work_payload)
    _write_json(root / WORK_AUTHORITY_FILE, work_payload)
    route = {
        "schema_version": "plamen.arm_before_trust_p0af_route_debt.v1",
        "status": "READY_PENDING_QUEUE_DELIVERY",
        "work_authority_digest": work_payload["payload_digest"],
        "ready_work_item_ids": ["CH-17"],
        "ordinary_verification_required": True,
        "route": "P0_AF_V2_QUEUE_ADAPTER_REQUIRED",
        "proof_authority": "NONE",
    }
    route["payload_digest"] = _payload_digest(route)
    _write_json(root / ROUTE_DEBT_FILE, route)


def _rebind_candidate_downstream(root: Path, candidate_payload: dict) -> None:
    """Re-sign the downstream self-digests after a candidate-root mutation."""

    candidate_payload["payload_digest"] = _payload_digest(candidate_payload)
    _write_json(root / CANDIDATE_FILE, candidate_payload)
    work_payload = json.loads(
        (root / WORK_AUTHORITY_FILE).read_text(encoding="utf-8")
    )
    work_payload["candidate_payload_digest"] = candidate_payload["payload_digest"]
    work_payload["payload_digest"] = _payload_digest(work_payload)
    _write_json(root / WORK_AUTHORITY_FILE, work_payload)
    route = json.loads((root / ROUTE_DEBT_FILE).read_text(encoding="utf-8"))
    route["work_authority_digest"] = work_payload["payload_digest"]
    route["payload_digest"] = _payload_digest(route)
    _write_json(root / ROUTE_DEBT_FILE, route)


def test_declared_fact_digests_cannot_self_certify_changed_fact_semantics(
    tmp_path: Path,
) -> None:
    """A source row must be re-hashed; matching stale digest fields are not proof."""

    _real_p1m_artifacts(tmp_path)
    source = tmp_path / role_authority.AUTHORITY_FILE
    authority = json.loads(source.read_text(encoding="utf-8"))
    authority["facts"][0]["privileged_effect"] = "post-binding mutation"
    # Deliberately retain both declared digests.  The adapter must recompute
    # the fact and authority digests rather than compare attacker-controlled
    # declarations with one another.
    _write_json(source, authority)

    result = plan_p0af_v2_queue_delivery(tmp_path, ())

    assert result.queue_items == ()
    assert result.receipt is None
    assert result.debt is not None
    assert result.debt["error_code"] == "P0_AF_V2_INPUT_INVALID"


def test_candidate_source_digest_fields_must_be_actual_sha256_values(
    tmp_path: Path,
) -> None:
    """Unused lineage fields cannot masquerade as mechanically bound digests."""

    for field in ("source_analysis_digest", "source_composition_digest"):
        case_root = tmp_path / field
        case_root.mkdir()
        _artifacts(case_root)
        candidate_payload = json.loads(
            (case_root / CANDIDATE_FILE).read_text(encoding="utf-8")
        )
        candidate_payload[field] = "not-a-sha256"
        _rebind_candidate_downstream(case_root, candidate_payload)

        result = plan_p0af_v2_queue_delivery(case_root, ())

        assert result.queue_items == ()
        assert result.receipt is None
        assert result.debt is not None
        assert result.debt["error_code"] == "P0_AF_V2_INPUT_INVALID"


def test_duplicate_json_authority_keys_are_rejected_as_ambiguous(
    tmp_path: Path,
) -> None:
    """Canonical digests do not make a duplicate-key byte stream unambiguous."""

    _artifacts(tmp_path)
    path = tmp_path / CANDIDATE_FILE
    raw = path.read_text(encoding="utf-8")
    path.write_text(
        raw.replace(
            '"proof_authority": "NONE"',
            '"proof_authority": "GRANTED",\n  "proof_authority": "NONE"',
            1,
        ),
        encoding="utf-8",
    )

    result = plan_p0af_v2_queue_delivery(tmp_path, ())

    assert result.queue_items == ()
    assert result.receipt is None
    assert result.debt is not None
    assert result.debt["error_code"] == "P0_AF_V2_INPUT_INVALID"


def test_typed_boolean_fields_do_not_accept_integer_aliases(tmp_path: Path) -> None:
    """Python's True == 1 equality cannot weaken the on-disk JSON schema."""

    candidate_root = tmp_path / "candidate"
    candidate_root.mkdir()
    _artifacts(candidate_root)
    candidate_payload = json.loads(
        (candidate_root / CANDIDATE_FILE).read_text(encoding="utf-8")
    )
    candidate_payload["candidates"][0]["severity_upgrade_justified"] = 1
    _rebind_candidate_downstream(candidate_root, candidate_payload)

    candidate_result = plan_p0af_v2_queue_delivery(candidate_root, ())

    assert candidate_result.queue_items == ()
    assert candidate_result.receipt is None
    assert candidate_result.debt is not None

    route_root = tmp_path / "route"
    route_root.mkdir()
    _artifacts(route_root)
    route = json.loads((route_root / ROUTE_DEBT_FILE).read_text(encoding="utf-8"))
    route["ordinary_verification_required"] = 1
    route["payload_digest"] = _payload_digest(route)
    _write_json(route_root / ROUTE_DEBT_FILE, route)

    route_result = plan_p0af_v2_queue_delivery(route_root, ())

    assert route_result.queue_items == ()
    assert route_result.receipt is None
    assert route_result.debt is not None


def test_valid_clean_no_nomination_retires_stale_adapter_owned_rows(
    tmp_path: Path,
) -> None:
    """A current empty denominator cannot leave an obsolete owned job active."""

    _artifacts(tmp_path)
    prior_delivery = plan_p0af_v2_queue_delivery(tmp_path, ())
    prior = prior_delivery.queue_items
    assert [item.work_item_id for item in prior] == ["CH-17"]
    assert prior_delivery.receipt is not None

    _artifacts(tmp_path, with_work=False)
    result = plan_p0af_v2_queue_delivery(
        tmp_path,
        prior,
        prior_receipt=prior_delivery.receipt,
    )

    assert result.debt is None
    assert result.receipt is not None
    assert result.receipt["status"] == "CLEAN_NO_OP"
    assert result.receipt["ordinary_verification_required"] is False
    assert result.queue_items == ()
    assert result.receipt["queue_record_count"] == 0


def test_lexical_owned_shape_cannot_authorize_removing_an_unreceipted_row(
    tmp_path: Path,
) -> None:
    """Ownership must come from a prior delivery receipt, not spoofable fields."""

    _artifacts(tmp_path)
    foreign = QueueWorkItem.from_legacy_row(
        {
            "queue #": "1",
            "finding id": "M-99",
            "severity": "Medium",
            "title": "Independent work with a colliding classification",
            "evidence class": "p0af-v2-generator",
            "bug class": "chain-composition",
            "preferred tag": "CODE-TRACE",
            "location": "independent_authority.json",
            "primary artifact": [CANDIDATE_FILE, WORK_AUTHORITY_FILE],
            "poc class": "sequence",
        }
    )

    result = plan_p0af_v2_queue_delivery(tmp_path, (foreign,))

    assert result.debt is None
    assert {item.work_item_id for item in result.queue_items} == {"M-99", "CH-17"}
    assert result.receipt is not None
    assert result.receipt["ownership_debts"] == [
        "UNAUTHENTICATED_OWNERSHIP_LOOKALIKE:M-99"
    ]


def test_new_work_identity_cannot_collide_with_existing_alias_namespace(
    tmp_path: Path,
) -> None:
    """Checking only prior work-item IDs leaves the lineage join ambiguous."""

    _artifacts(tmp_path)
    foreign = QueueWorkItem.from_legacy_row(
        {
            "queue #": "1",
            "finding id": "M-01",
            "aliases": "CH-17",
            "severity": "Low",
            "title": "Independent pre-existing work",
            "bug class": "state-machine",
            "preferred tag": "CODE-TRACE",
            "location": "findings_inventory.md",
            "primary artifact": "findings_inventory.md",
            "poc class": "structural",
        }
    )

    result = plan_p0af_v2_queue_delivery(tmp_path, (foreign,))

    assert result.queue_items == (foreign,)
    assert result.receipt is None
    assert result.debt is not None
    assert result.debt["error_code"] == "P0_AF_V2_IDENTITY_COLLISION"


def test_new_alias_identity_cannot_collide_with_existing_work_identity(
    tmp_path: Path,
) -> None:
    """Alias/work collisions must be rejected in both namespace directions."""

    _artifacts(tmp_path)
    _rewrite_with_equivalent_public_chain_alias(tmp_path)
    foreign = QueueWorkItem.from_legacy_row(
        {
            "queue #": "1",
            "finding id": "CH-18",
            "severity": "Low",
            "title": "Independent pre-existing work",
            "bug class": "state-machine",
            "preferred tag": "CODE-TRACE",
            "location": "findings_inventory.md",
            "primary artifact": "findings_inventory.md",
            "poc class": "structural",
        }
    )

    result = plan_p0af_v2_queue_delivery(tmp_path, (foreign,))

    assert result.queue_items == (foreign,)
    assert result.receipt is None
    assert result.debt is not None
    assert result.debt["error_code"] == "P0_AF_V2_IDENTITY_COLLISION"


def test_hybrid_v2_work_cannot_drop_the_finding_constituent(
    tmp_path: Path,
) -> None:
    """Typed fact bindings must not erase ordinary finding constituents."""

    _artifacts(tmp_path)
    _rewrite_as_hybrid_finding_and_fact_candidate(tmp_path)

    result = plan_p0af_v2_queue_delivery(tmp_path, ())

    assert result.debt is None
    assert result.receipt is not None
    assert len(result.queue_items) == 1
    assert set(result.queue_items[0].constituents) == {
        "FIND-01",
        "AUTH-FACT-0001",
    }


def test_bound_fact_identity_cannot_alias_a_canonical_finding_identity(
    tmp_path: Path,
) -> None:
    """Typed fact/finding namespaces must be disjoint at the queue join."""

    _artifacts(tmp_path)
    _canonical_ids(tmp_path, ("AUTH-FACT-0001",))
    candidate_payload = json.loads(
        (tmp_path / CANDIDATE_FILE).read_text(encoding="utf-8")
    )
    candidate_payload["identity_denominator_digest"] = hashlib.sha256(
        (tmp_path / "_canonical_finding_ids.json").read_bytes()
    ).hexdigest()
    _rebind_candidate_downstream(tmp_path, candidate_payload)

    result = plan_p0af_v2_queue_delivery(tmp_path, ())

    assert result.queue_items == ()
    assert result.receipt is None
    assert result.debt is not None
    assert result.debt["error_code"] == "P0_AF_V2_IDENTITY_COLLISION"


def test_equivalent_public_chain_identity_remains_in_queue_lineage(
    tmp_path: Path,
) -> None:
    """Compiler alias relations must survive the verifier identity boundary."""

    _artifacts(tmp_path)
    _rewrite_with_equivalent_public_chain_alias(tmp_path)

    result = plan_p0af_v2_queue_delivery(tmp_path, ())

    assert result.debt is None
    assert len(result.queue_items) == 1
    assert result.queue_items[0].work_item_id == "CH-17"
    assert "CH-18" in result.queue_items[0].aliases
    assert build_lineage_index(result.queue_items).resolve_all("CH-18") == ("CH-17",)


def test_candidate_and_alias_denominators_have_an_explicit_cardinality_bound(
    tmp_path: Path,
) -> None:
    """Sub-byte-limit alias amplification still needs a deterministic row cap."""

    _artifacts(tmp_path)
    _rewrite_with_equivalent_public_chain_alias(
        tmp_path,
        chain_ids=tuple(f"CH-{index}" for index in range(1, 1026)),
    )

    result = plan_p0af_v2_queue_delivery(tmp_path, ())

    assert result.queue_items == ()
    assert result.receipt is None
    assert result.debt is not None
    assert result.debt["error_code"] == "P0_AF_V2_INPUT_INVALID"


def test_fact_binding_denominator_has_an_explicit_cardinality_bound(
    tmp_path: Path,
) -> None:
    """One candidate cannot bypass row caps with an unbounded fact join."""

    _rewrite_with_many_fact_bindings(tmp_path, count=1025)

    result = plan_p0af_v2_queue_delivery(tmp_path, ())

    assert result.queue_items == ()
    assert result.receipt is None
    assert result.debt is not None
    assert result.debt["error_code"] == "P0_AF_V2_INPUT_INVALID"


def test_singular_fact_authority_cannot_expand_to_copied_source_artifacts(
    tmp_path: Path,
) -> None:
    """One declared authority digest must bind one exact source artifact."""

    _artifacts(tmp_path)
    alternate = "authentication_role_fact_authority_copy.json"
    (tmp_path / alternate).write_bytes((tmp_path / FACT_AUTHORITY).read_bytes())
    candidate_payload = json.loads(
        (tmp_path / CANDIDATE_FILE).read_text(encoding="utf-8")
    )
    candidate_payload["candidates"][0]["evidence_constituent_bindings"][1][
        "source_artifact"
    ] = alternate
    candidate = _candidate_from_record(candidate_payload["candidates"][0])
    candidate_payload["payload_digest"] = _payload_digest(candidate_payload)
    _write_json(tmp_path / CANDIDATE_FILE, candidate_payload)
    plan = compile_compound_work_plan(
        (candidate,),
        known_constituent_identities=(),
        known_evidence_constituents=candidate.evidence_constituent_bindings,
    ).to_record()
    work_payload = {
        "schema_version": "plamen.arm_before_trust_compound_work_authority.v1",
        "candidate_payload_digest": candidate_payload["payload_digest"],
        "proof_authority": "NONE",
        "compound_work_plan": plan,
    }
    work_payload["payload_digest"] = _payload_digest(work_payload)
    _write_json(tmp_path / WORK_AUTHORITY_FILE, work_payload)
    route = json.loads((tmp_path / ROUTE_DEBT_FILE).read_text(encoding="utf-8"))
    route["work_authority_digest"] = work_payload["payload_digest"]
    route["payload_digest"] = _payload_digest(route)
    _write_json(tmp_path / ROUTE_DEBT_FILE, route)

    result = plan_p0af_v2_queue_delivery(tmp_path, ())

    assert result.queue_items == ()
    assert result.receipt is None
    assert result.debt is not None
    assert result.debt["error_code"] == "P0_AF_V2_INPUT_INVALID"


def test_authority_input_has_a_hard_byte_bound_before_json_decode(
    tmp_path: Path,
) -> None:
    """Bounded deterministic consumers must reject resource-amplification files."""

    _artifacts(tmp_path)
    path = tmp_path / FACT_AUTHORITY
    # JSON permits trailing whitespace, so the semantic declarations remain
    # unchanged while the unbounded read/decode cost is amplified.
    with path.open("ab") as handle:
        handle.write(b" " * (8 * 1024 * 1024))

    result = plan_p0af_v2_queue_delivery(tmp_path, ())

    assert result.queue_items == ()
    assert result.receipt is None
    assert result.debt is not None
    assert result.debt["error_code"] == "P0_AF_V2_INPUT_INVALID"


def test_authority_growth_between_stat_and_read_cannot_bypass_byte_bound(
    tmp_path: Path, monkeypatch,
) -> None:
    """The post-read byte count closes the unavoidable stat/open race."""

    _artifacts(tmp_path)
    target = tmp_path / FACT_AUTHORITY
    original_read_bytes = Path.read_bytes

    def grow_after_stat(path: Path) -> bytes:
        raw = original_read_bytes(path)
        if path == target:
            return raw + (b" " * (8 * 1024 * 1024))
        return raw

    monkeypatch.setattr(Path, "read_bytes", grow_after_stat)

    result = plan_p0af_v2_queue_delivery(tmp_path, ())

    assert result.queue_items == ()
    assert result.receipt is None
    assert result.debt is not None
    assert result.debt["error_code"] == "P0_AF_V2_INPUT_INVALID"


def test_verifier_dispatch_changes_if_a_primary_authority_changes(
    tmp_path: Path,
) -> None:
    """The exact fact/work bytes must be immutable verifier launch inputs."""

    _artifacts(tmp_path)
    delivery = plan_p0af_v2_queue_delivery(tmp_path, ())
    assert delivery.debt is None
    row = delivery.queue_items[0].to_dict()
    packets_before = build_verification_context_packets(
        rows=[row], scratchpad=tmp_path, project_root=tmp_path
    )
    dispatch_before = compile_verification_method_dispatch(
        pipeline="sc",
        ecosystem="evm",
        backend="claude",
        rows=[row],
        context_packets=packets_before,
        manifest_path="verification_queue.md",
        scratchpad_path=str(tmp_path),
        root=Path(__file__).resolve().parent.parent,
    )

    authority_path = tmp_path / FACT_AUTHORITY
    authority_path.write_bytes(authority_path.read_bytes() + b"\n")
    packets_after = build_verification_context_packets(
        rows=[row], scratchpad=tmp_path, project_root=tmp_path
    )
    dispatch_after = compile_verification_method_dispatch(
        pipeline="sc",
        ecosystem="evm",
        backend="claude",
        rows=[row],
        context_packets=packets_after,
        manifest_path="verification_queue.md",
        scratchpad_path=str(tmp_path),
        root=Path(__file__).resolve().parent.parent,
    )

    assert dispatch_after["dispatch_id"] != dispatch_before["dispatch_id"]


def test_authenticated_fact_locus_becomes_structured_source_context(
    tmp_path: Path,
) -> None:
    """Putting a locus only in `note` does not make it a compiler source seed."""

    _artifacts(tmp_path)
    delivery = plan_p0af_v2_queue_delivery(tmp_path, ())
    assert delivery.debt is None
    item = delivery.queue_items[0]

    assert any(
        record.artifact.replace("\\", "/") == "src/Auth.sol"
        and record.start_line == 10
        and record.end_line == 20
        and "fact=AUTH-FACT-0001" in (record.note or "")
        for record in item.location_records
    )
    packets = build_verification_context_packets(
        rows=[item.to_dict()], scratchpad=tmp_path, project_root=tmp_path
    )
    seeds = packets["packets"][0]["seed_locations"]
    assert "src/Auth.sol:10-20" in seeds


def test_missing_primary_authority_forces_unresolved_verifier_context(
    tmp_path: Path,
) -> None:
    """An unrelated graph hit cannot hide that an exact queue authority vanished."""

    _artifacts(tmp_path)
    delivery = plan_p0af_v2_queue_delivery(tmp_path, ())
    assert delivery.debt is None
    row = delivery.queue_items[0].to_dict()
    # Force a graph hit for the queue location while independently removing the
    # fact authority.  The graph is context, not a substitute for a declared
    # primary artifact.
    (tmp_path / "caller_map.md").write_text(
        f"references {CANDIDATE_FILE}\n", encoding="utf-8"
    )
    (tmp_path / FACT_AUTHORITY).unlink()

    packets = build_verification_context_packets(
        rows=[row], scratchpad=tmp_path, project_root=tmp_path
    )
    packet = packets["packets"][0]

    assert packet["primary_artifact_binding_complete"] is False
    assert packet["state"] == "CONTEXT_UNRESOLVED"


def test_operator_proposal_cannot_override_unresolved_compiler_context(
    tmp_path: Path,
) -> None:
    """A verifier self-claim cannot erase a missing exact authority binding."""

    _artifacts(tmp_path)
    delivery = plan_p0af_v2_queue_delivery(tmp_path, ())
    assert delivery.debt is None
    row = delivery.queue_items[0].to_dict()
    (tmp_path / FACT_AUTHORITY).unlink()
    packets = build_verification_context_packets(
        rows=[row], scratchpad=tmp_path, project_root=tmp_path
    )
    assert packets["packets"][0]["state"] == "CONTEXT_UNRESOLVED"
    dispatch = compile_verification_method_dispatch(
        pipeline="sc",
        ecosystem="evm",
        backend="claude",
        rows=[row],
        context_packets=packets,
        manifest_path="verification_queue.md",
        scratchpad_path=str(tmp_path),
        root=Path(__file__).resolve().parent.parent,
    )
    dispatch_row = dispatch["rows"][0]
    proposal = {
        "schema_version": OPERATOR_PROPOSAL_SCHEMA,
        "work_item_id": dispatch_row["work_item_id"],
        "method_dispatch_id": dispatch["dispatch_id"],
        "selected_module_hashes": dispatch_row["module_hashes"],
        "context_packet_digest": dispatch_row["context_packet_digest"],
        # This model-authored field must not supersede the mechanically compiled
        # context_state when no bounded expansion restored the missing artifact.
        "context_status": "RESOLVED",
        "context_expansion": [],
        "operators": [
            {
                "operator_id": operator_id,
                "status": "APPLIED",
                "evidence": [
                    {
                        "source": CANDIDATE_FILE,
                        "detail": "Bounded generic trace claimed by the verifier.",
                    }
                ],
                "predicate": None,
                "debt_code": None,
                "blocker_evidence": [],
            }
            for operator_id in dispatch_row["operator_ids"]
        ],
        "new_observations": [],
    }

    with pytest.raises(VerificationMethodError):
        validate_operator_application_proposal(
            proposal,
            dispatch=dispatch,
            verdict="REFUTED",
            root=Path(__file__).resolve().parent.parent,
        )


def test_oversized_reference_graph_is_not_read_before_context_degradation(
    tmp_path: Path, monkeypatch,
) -> None:
    """Primary-artifact bounds do not help if graph context is still unbounded."""

    _artifacts(tmp_path)
    delivery = plan_p0af_v2_queue_delivery(tmp_path, ())
    assert delivery.debt is None
    graph = tmp_path / "caller_map.md"
    with graph.open("wb") as handle:
        # Sparse on normal filesystems; large enough that no bounded context
        # compiler should materialize it merely to discover it is unusable.
        handle.truncate(128 * 1024 * 1024)
    original_read_bytes = Path.read_bytes

    def forbid_oversized_graph_read(path: Path) -> bytes:
        if path == graph:
            raise AssertionError("oversized reference graph was read")
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", forbid_oversized_graph_read)

    packets = build_verification_context_packets(
        rows=[delivery.queue_items[0].to_dict()],
        scratchpad=tmp_path,
        project_root=tmp_path,
    )

    assert packets["packets"][0]["state"] == "CONTEXT_UNRESOLVED"


def test_dynamic_verifier_records_exact_prelaunch_authority_before_execution() -> None:
    """Persisting contract JSON is not the same as recording/validating its bytes."""

    source = (Path(__file__).resolve().parent / "plamen_driver.py").read_text(
        encoding="utf-8"
    )
    start = source.index("def _run_dynamic_verifier_unit(")
    end = source.index("def _dynamic_verifier_phase_issues(", start)
    body = source[start:end]
    assert "_record_verifier_method_phase_io_authority(" in body
    contract = body.index("_write_verifier_method_phase_io_contracts(")
    record = body.index("_record_verifier_method_phase_io_authority(")
    execute = body.index("_execute_dynamic_verifier_launch(")

    assert contract < record < execute


def test_completed_dynamic_verifier_revalidates_prelaunch_inputs_on_resume() -> None:
    """A clean receipt cannot bypass current primary-artifact input validation."""

    source = (Path(__file__).resolve().parent / "plamen_driver.py").read_text(
        encoding="utf-8"
    )
    start = source.index("def _dynamic_verifier_unit_gate_issues(")
    end = source.index("def _write_dynamic_verifier_status(", start)
    body = source[start:end]

    assert (
        "_record_verifier_method_phase_io_authority(" in body
        or "validate_work_unit_inputs(" in body
    )


def test_live_dynamic_dispatch_cannot_reuse_stale_primary_artifact_bindings(
    tmp_path: Path,
) -> None:
    """Resume must rebind current primary bytes, not trust an old context packet."""

    from plamen_driver import _compile_dynamic_verifier_method_dispatch

    _artifacts(tmp_path)
    delivery = plan_p0af_v2_queue_delivery(tmp_path, ())
    assert delivery.debt is None
    (tmp_path / "verification_queue.work_items.json").write_text(
        queue_records_to_json(delivery.queue_items) + "\n",
        encoding="utf-8",
    )
    unit = SimpleNamespace(ordered_work_item_ids=("CH-17",))
    config = {
        "pipeline": "sc",
        "language": "evm",
        "cli_backend": "claude",
        "project_root": str(tmp_path),
    }
    before = _compile_dynamic_verifier_method_dispatch(
        tmp_path,
        config,
        unit,
        manifest_path=tmp_path / "verification_queue.md",
    )
    (tmp_path / FACT_AUTHORITY).unlink()

    try:
        after = _compile_dynamic_verifier_method_dispatch(
            tmp_path,
            config,
            unit,
            manifest_path=tmp_path / "verification_queue.md",
        )
    except Exception:
        # Rejecting stale persisted context is a valid fail-visible outcome.
        return

    assert after["dispatch_id"] != before["dispatch_id"]
    assert after["rows"][0]["context_state"] == "CONTEXT_UNRESOLVED"


def test_typed_delivery_round_trips_through_the_live_legacy_claude_queue_reader(
    tmp_path: Path,
) -> None:
    """The adapter output needs one lossless live projection, not parallel dialects."""

    _artifacts(tmp_path)
    delivery = plan_p0af_v2_queue_delivery(tmp_path, ())
    assert delivery.debt is None
    queue_path = tmp_path / "verification_queue.md"
    queue_path.write_text(
        render_queue_markdown(delivery.queue_items), encoding="utf-8"
    )

    legacy_rows = parse_verification_queue_rows(tmp_path)
    reconstructed = _typed_queue_items_from_rows(legacy_rows)

    assert reconstructed == delivery.queue_items


def test_live_claude_sc_queue_routing_consumes_real_p1m_producer_ledger(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The real producer ledger, runtime commit, and Claude sharder compose."""

    config, p1m_id = _live_runtime_ready(tmp_path, monkeypatch)

    safe, issues = driver._run_p0af_v2_live_queue_boundary(tmp_path, config)
    shards = ensure_sc_verify_shard_manifests(
        tmp_path, p0af_runtime_config=config
    )
    routed_ids = {
        str(row.get("finding id") or "")
        for rows in shards.values()
        for row in rows
    }

    assert safe is True
    assert issues == []
    assert {"M-01", p1m_id}.issubset(routed_ids)
    assert queue_runtime.validate_p0af_v2_queue_commit(tmp_path, config) == []


def test_adapter_shaped_queue_row_without_successor_is_not_consumable(
    tmp_path: Path,
) -> None:
    """Typed appearance alone cannot substitute for a live runtime receipt."""

    _artifacts(tmp_path)
    delivery = plan_p0af_v2_queue_delivery(tmp_path, ())
    assert delivery.receipt is not None
    _write_queue_subset_manifest(
        tmp_path / "verification_queue.md",
        [_typed_queue_item_legacy_row(delivery.queue_items[0])],
    )

    with pytest.raises(ValueError, match="P0-AF v2|adapter"):
        ensure_sc_verify_shard_manifests(
            tmp_path,
            p0af_runtime_config={
                "pipeline": "sc",
                "mode": "thorough",
                "language": "evm",
                "cli_backend": "claude",
                "project_root": str(tmp_path),
                "_run_id": "RUN-UNAUTHENTICATED",
            },
        )


@pytest.mark.parametrize(
    "publish_name",
    (*queue_runtime._PUBLISH_ORDER, "<journal-commit>"),
)
def test_each_partial_publish_boundary_is_unshardable_then_recovers_exactly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    publish_name: str,
) -> None:
    """No one of the seven fixed-path replacements may expose partial work."""

    config, p1m_id = _live_runtime_ready(tmp_path, monkeypatch)
    original_replace = os.replace
    interrupted = False
    journal_replacements = 0

    def interrupt_at_boundary(source, destination):
        nonlocal interrupted, journal_replacements
        source_path = Path(source)
        destination_path = Path(destination)
        if destination_path == tmp_path / queue_runtime.JOURNAL_FILE:
            journal_replacements += 1
            if (
                not interrupted
                and publish_name == "<journal-commit>"
                and journal_replacements == 2
            ):
                interrupted = True
                raise OSError("fixture interruption before COMMITTED journal")
        if (
            not interrupted
            and publish_name != "<journal-commit>"
            and destination_path == tmp_path / publish_name
            and "_p0af_v2_queue_transaction" in source_path.parts
        ):
            interrupted = True
            raise OSError(f"fixture interruption before {publish_name}")
        return original_replace(source, destination)

    monkeypatch.setattr(queue_runtime.os, "replace", interrupt_at_boundary)
    with pytest.raises(queue_runtime.P0AFV2QueueRuntimeError):
        queue_runtime.run_p0af_v2_queue_delivery(tmp_path, config)
    assert interrupted is True
    journal = json.loads(
        (tmp_path / queue_runtime.JOURNAL_FILE).read_text(encoding="utf-8")
    )
    assert journal["state"] == "PREPARED"

    # Sharding is a consumer, not a transaction-repair owner.  It must reject
    # every partial state, including boundaries before STATUS exists.
    with pytest.raises(ValueError) as rejected:
        ensure_sc_verify_shard_manifests(
            tmp_path, p0af_runtime_config=config
        )

    message = str(rejected.value)
    if publish_name in {
        "verification_queue.json",
        "verification_queue.work_items.json",
    }:
        assert message == (
            "typed queue/Markdown identity drift for verification_queue.md; "
            "refusing to guess which queue is executable"
        )
    else:
        assert any(
            token in message
            for token in ("P0-AF v2", "PREPARED", "transaction")
        )

    monkeypatch.setattr(queue_runtime.os, "replace", original_replace)
    recovered = queue_runtime.run_p0af_v2_queue_delivery(tmp_path, config)
    assert recovered.committed is True
    assert recovered.issues == ()
    shards = ensure_sc_verify_shard_manifests(
        tmp_path, p0af_runtime_config=config
    )
    assert {
        str(row.get("finding id") or "")
        for rows in shards.values()
        for row in rows
    } >= {"M-01", p1m_id}


def test_committed_bytes_repair_missing_adapter_ledger_after_hard_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A crash after COMMITTED but before ledger recording must be resumable."""

    config, _p1m_id = _live_runtime_ready(tmp_path, monkeypatch)

    def hard_crash(*_args, **_kwargs):
        raise KeyboardInterrupt("fixture crash before adapter output ledger")

    monkeypatch.setattr(queue_runtime, "_record_adapter_outputs", hard_crash)
    with pytest.raises(KeyboardInterrupt):
        queue_runtime.run_p0af_v2_queue_delivery(tmp_path, config)
    assert json.loads(
        (tmp_path / queue_runtime.JOURNAL_FILE).read_text(encoding="utf-8")
    )["state"] == "COMMITTED"

    monkeypatch.undo()
    resumed = queue_runtime.run_p0af_v2_queue_delivery(tmp_path, config)

    assert resumed.committed is True
    assert resumed.issues == ()
    assert queue_runtime.validate_p0af_v2_queue_commit(tmp_path, config) == []


def test_committed_ledger_repair_rejects_semantically_forged_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exact byte consistency is insufficient if receipt semantics are false."""

    config, _p1m_id = _live_runtime_ready(tmp_path, monkeypatch)

    def hard_crash(*_args, **_kwargs):
        raise KeyboardInterrupt("fixture crash before adapter output ledger")

    monkeypatch.setattr(queue_runtime, "_record_adapter_outputs", hard_crash)
    with pytest.raises(KeyboardInterrupt):
        queue_runtime.run_p0af_v2_queue_delivery(tmp_path, config)
    monkeypatch.undo()

    # Forge a fully self-consistent journal/status byte envelope whose active
    # receipt lies about the queue denominator.  Output-ledger repair must
    # independently replay the adapter contract instead of self-certifying it.
    receipt_path = tmp_path / queue_runtime.RECEIPT_FILE
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["queue_record_set_digest"] = "f" * 64
    receipt["payload_digest"] = queue_runtime._payload_digest(receipt)
    _write_json(receipt_path, receipt)

    journal_path = tmp_path / queue_runtime.JOURNAL_FILE
    journal = json.loads(journal_path.read_text(encoding="utf-8"))
    journal["destinations"][queue_runtime.RECEIPT_FILE] = (
        queue_runtime._bytes_record(receipt_path.read_bytes())
    )
    non_status = {
        name: journal["destinations"][name]
        for name in queue_runtime._PUBLISH_ORDER
        if name != queue_runtime.STATUS_FILE
    }
    transaction_id = queue_runtime._journal_transaction_id(
        run_id=journal["run_id"],
        upstream_digest=journal["upstream_work_unit_digest"],
        before_digest=journal["before_queue_digest"],
        after_digest=journal["after_queue_digest"],
        destinations=non_status,
    )
    journal["transaction_id"] = transaction_id

    status_path = tmp_path / queue_runtime.STATUS_FILE
    status = json.loads(status_path.read_text(encoding="utf-8"))
    status["transaction_id"] = transaction_id
    status["active_successor_sha256"] = hashlib.sha256(
        receipt_path.read_bytes()
    ).hexdigest()
    status["payload_digest"] = queue_runtime._payload_digest(status)
    _write_json(status_path, status)
    journal["destinations"][queue_runtime.STATUS_FILE] = (
        queue_runtime._bytes_record(status_path.read_bytes())
    )
    journal["payload_digest"] = queue_runtime._payload_digest(journal)
    _write_json(journal_path, journal)

    resumed = queue_runtime.run_p0af_v2_queue_delivery(tmp_path, config)

    assert resumed.committed is False
    assert resumed.issues
    assert queue_runtime.validate_p0af_v2_queue_commit(tmp_path, config)


def test_driver_does_not_authorize_sharding_after_invalid_committed_successor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A COMMITTED label is not sufficient when its exact successor is invalid."""

    config, _p1m_id = _live_runtime_ready(tmp_path, monkeypatch)
    assert queue_runtime.run_p0af_v2_queue_delivery(
        tmp_path, config
    ).committed is True
    status_path = tmp_path / queue_runtime.STATUS_FILE
    status = json.loads(status_path.read_text(encoding="utf-8"))
    status["after_queue_digest"] = "f" * 64
    _write_json(status_path, status)

    safe, issues = driver._run_p0af_v2_live_queue_boundary(tmp_path, config)

    assert safe is False
    assert issues


def test_driver_validates_existing_transaction_even_if_route_artifact_vanished(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing current source cannot bypass validation of an existing successor."""

    config, _p1m_id = _live_runtime_ready(tmp_path, monkeypatch)
    assert queue_runtime.run_p0af_v2_queue_delivery(
        tmp_path, config
    ).committed is True
    (tmp_path / ROUTE_DEBT_FILE).unlink()

    safe, issues = driver._run_p0af_v2_live_queue_boundary(tmp_path, config)

    assert safe is False
    assert issues


def test_valid_committed_adapter_debt_is_haltless_but_fail_visible(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A recall-preserving debt may shard ordinary work but cannot look clean."""

    config, p1m_id = _live_p1m_producer(tmp_path, monkeypatch)
    _write_queue_subset_manifest(
        tmp_path / "verification_queue.md",
        [{
            "queue #": "1",
            "finding id": "M-01",
            "severity": "Medium",
            "title": "Independent ordinary work",
            "bug class": "state-transition",
            "preferred tag": "CODE-TRACE",
            "location": "findings_inventory.md:1",
            "primary artifact": "findings_inventory.md",
            "poc class": "structural",
            # A foreign alias collision must preserve this row and retain the
            # P1-M nomination as explicit human-review delivery debt.
            "aliases": p1m_id,
        }],
    )

    safe, issues = driver._run_p0af_v2_live_queue_boundary(tmp_path, config)

    assert safe is True
    assert issues
    status = json.loads(
        (tmp_path / queue_runtime.STATUS_FILE).read_text(encoding="utf-8")
    )
    assert status["state"] == "COMPLETED_WITH_DEBT"
    assert status["active_successor"] == queue_runtime.DEBT_FILE
    assert _read_typed_queue_work_items(
        tmp_path / "verification_queue.md"
    )[0].work_item_id == "M-01"


def test_oversized_runtime_input_snapshot_is_rejected_before_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Semantic replay must retain the control-artifact size/TOCTOU boundary."""

    config, _p1m_id = _live_runtime_ready(tmp_path, monkeypatch)
    assert queue_runtime.run_p0af_v2_queue_delivery(
        tmp_path, config
    ).committed is True
    snapshot = tmp_path / queue_runtime.INPUT_SNAPSHOT_FILE
    with snapshot.open("r+b") as stream:
        stream.truncate(queue_runtime.MAX_CONTROL_BYTES + 1)
    original_read_text = Path.read_text
    snapshot_read = False

    def forbid_snapshot_read(path: Path, *args, **kwargs):
        nonlocal snapshot_read
        if path == snapshot:
            snapshot_read = True
            raise AssertionError("oversized snapshot was materialized")
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", forbid_snapshot_read)

    issues = queue_runtime.validate_p0af_v2_queue_commit(tmp_path, config)

    assert issues
    assert snapshot_read is False


def test_oversized_stale_snapshot_before_first_commit_is_not_materialized(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The no-journal input-snapshot drift branch has the same size boundary."""

    config, _p1m_id = _live_runtime_ready(tmp_path, monkeypatch)
    snapshot = tmp_path / queue_runtime.INPUT_SNAPSHOT_FILE
    with snapshot.open("wb") as stream:
        stream.truncate(queue_runtime.MAX_CONTROL_BYTES + 1)
    original_read_bytes = Path.read_bytes
    snapshot_read = False

    def forbid_snapshot_read(path: Path):
        nonlocal snapshot_read
        if path == snapshot:
            snapshot_read = True
            raise AssertionError("oversized stale snapshot was materialized")
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", forbid_snapshot_read)

    outcome = queue_runtime.run_p0af_v2_queue_delivery(tmp_path, config)

    assert outcome.committed is False
    assert outcome.issues
    assert snapshot_read is False


def test_oversized_committed_projection_is_rejected_before_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Committed validation must not materialize an oversized queue projection."""

    config, _p1m_id = _live_runtime_ready(tmp_path, monkeypatch)
    assert queue_runtime.run_p0af_v2_queue_delivery(
        tmp_path, config
    ).committed is True
    projection = tmp_path / "verification_queue.json"
    with projection.open("r+b") as stream:
        stream.truncate(queue_runtime.MAX_CONTROL_BYTES + 1)
    original_read_bytes = Path.read_bytes
    projection_read = False

    def forbid_projection_read(path: Path):
        nonlocal projection_read
        if path == projection:
            projection_read = True
            raise AssertionError("oversized committed projection was materialized")
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", forbid_projection_read)

    issues = queue_runtime.validate_p0af_v2_queue_commit(tmp_path, config)

    assert issues
    assert projection_read is False


def test_completed_queue_resume_detects_pending_p1m_route_without_successor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A half-cutover checkpoint must rewind queue routing, not lose READY work."""

    config, _p1m_id = _live_p1m_producer(tmp_path, monkeypatch)
    _ordinary_queue(tmp_path)
    (tmp_path / "findings_inventory.md").write_text(
        "# Findings Inventory\n\n"
        "### Finding [M-01]: ordinary finding\n"
        "**Severity**: Medium\n"
        "**Location**: src/State.sol:L1\n"
        "**Preferred Tag**: CODE-TRACE\n"
        "**Verdict**: CONFIRMED\n"
        "**Root Cause**: bounded fixture cause\n"
        "**Description**: bounded fixture description\n"
        "**Impact**: bounded fixture impact\n",
        encoding="utf-8",
    )
    phase = live_p1m._phase("sc_verify_queue")

    issues = driver._resume_phase_contract_issues(
        tmp_path,
        str(tmp_path),
        phase,
        mode="thorough",
        language="evm",
        pipeline="sc",
        backend="claude",
    )

    assert any("P0-AF" in issue or "P1-M" in issue for issue in issues)


def test_prepared_recovery_semantically_validates_stage_before_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A self-consistent PREPARED envelope cannot publish false successor bytes."""

    config, _p1m_id = _live_runtime_ready(tmp_path, monkeypatch)
    queue_before = {
        name: (tmp_path / name).read_bytes()
        for name in (
            "verification_queue.md",
            "verification_queue.json",
            "verification_queue.work_items.json",
        )
    }
    original_replace = os.replace
    interrupted = False

    def interrupt_first_publish(source, destination):
        nonlocal interrupted
        if (
            not interrupted
            and Path(destination) == tmp_path / "verification_queue.md"
            and "_p0af_v2_queue_transaction" in Path(source).parts
        ):
            interrupted = True
            raise OSError("fixture interruption before first publish")
        return original_replace(source, destination)

    monkeypatch.setattr(
        queue_runtime.os, "replace", interrupt_first_publish
    )
    with pytest.raises(queue_runtime.P0AFV2QueueRuntimeError):
        queue_runtime.run_p0af_v2_queue_delivery(tmp_path, config)
    monkeypatch.setattr(queue_runtime.os, "replace", original_replace)

    journal_path = tmp_path / queue_runtime.JOURNAL_FILE
    journal = json.loads(journal_path.read_text(encoding="utf-8"))
    stage = tmp_path / journal["stage_directory"]
    receipt_path = stage / queue_runtime.RECEIPT_FILE
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["queue_record_set_digest"] = "f" * 64
    receipt["payload_digest"] = queue_runtime._payload_digest(receipt)
    _write_json(receipt_path, receipt)
    journal["destinations"][queue_runtime.RECEIPT_FILE] = (
        queue_runtime._bytes_record(receipt_path.read_bytes())
    )
    transaction_id = queue_runtime._journal_transaction_id(
        run_id=journal["run_id"],
        upstream_digest=journal["upstream_work_unit_digest"],
        before_digest=journal["before_queue_digest"],
        after_digest=journal["after_queue_digest"],
        destinations={
            name: journal["destinations"][name]
            for name in queue_runtime._PUBLISH_ORDER
            if name != queue_runtime.STATUS_FILE
        },
    )
    journal["transaction_id"] = transaction_id
    staged_status = stage / queue_runtime.STATUS_FILE
    status = json.loads(staged_status.read_text(encoding="utf-8"))
    status["transaction_id"] = transaction_id
    status["active_successor_sha256"] = hashlib.sha256(
        receipt_path.read_bytes()
    ).hexdigest()
    status["payload_digest"] = queue_runtime._payload_digest(status)
    _write_json(staged_status, status)
    journal["destinations"][queue_runtime.STATUS_FILE] = (
        queue_runtime._bytes_record(staged_status.read_bytes())
    )
    journal["payload_digest"] = queue_runtime._payload_digest(journal)
    _write_json(journal_path, journal)

    outcome = queue_runtime.run_p0af_v2_queue_delivery(tmp_path, config)

    assert outcome.committed is False
    assert outcome.issues
    assert {
        name: (tmp_path / name).read_bytes() for name in queue_before
    } == queue_before


def test_prepared_recovery_validates_exact_adapter_inputs_before_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Semantically equivalent snapshot drift still invalidates exact PhaseIO."""

    config, _p1m_id = _live_runtime_ready(tmp_path, monkeypatch)
    queue_before = {
        name: (tmp_path / name).read_bytes()
        for name in (
            "verification_queue.md",
            "verification_queue.json",
            "verification_queue.work_items.json",
        )
    }
    original_commit = queue_runtime._commit_prepared

    def interrupt_after_prepare(*_args, **_kwargs):
        raise queue_runtime.P0AFV2QueueRuntimeError(
            "fixture interruption after PREPARED"
        )

    monkeypatch.setattr(
        queue_runtime, "_commit_prepared", interrupt_after_prepare
    )
    with pytest.raises(queue_runtime.P0AFV2QueueRuntimeError):
        queue_runtime.run_p0af_v2_queue_delivery(tmp_path, config)
    monkeypatch.setattr(queue_runtime, "_commit_prepared", original_commit)
    snapshot = tmp_path / queue_runtime.INPUT_SNAPSHOT_FILE
    snapshot.write_bytes(snapshot.read_bytes() + b" ")

    outcome = queue_runtime.run_p0af_v2_queue_delivery(tmp_path, config)

    assert outcome.committed is False
    assert outcome.issues
    assert {
        name: (tmp_path / name).read_bytes() for name in queue_before
    } == queue_before


def test_prepared_stage_directory_cannot_escape_scratchpad(tmp_path: Path) -> None:
    """A self-digested journal cannot turn resume into an out-of-tree move."""

    root = tmp_path / "scratch"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    destinations = {}
    for name in queue_runtime._PUBLISH_ORDER:
        raw = f"outside fixture {name}\n".encode("utf-8")
        (outside / name).write_bytes(raw)
        destinations[name] = queue_runtime._bytes_record(raw)
    journal = {
        "state": "PREPARED",
        "stage_directory": "../outside",
        "destinations": destinations,
        "publish_order": list(queue_runtime._PUBLISH_ORDER),
    }

    with pytest.raises(ValueError, match="stage|path|transaction"):
        queue_runtime._commit_prepared(root, journal)

    assert all((outside / name).is_file() for name in queue_runtime._PUBLISH_ORDER)
    assert not any((root / name).exists() for name in queue_runtime._PUBLISH_ORDER)


def test_legacy_and_p1m_compound_candidates_coexist_without_reownership(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Legacy CH and P1-M CH identities must remain disjoint and lossless."""

    config = live_p1m._config(tmp_path, backend="codex")
    config["scratchpad"] = str(tmp_path)
    config["_chain_state_resolution_initializes_tail"] = True
    (tmp_path / "findings_inventory.md").write_text(
        "# Findings Inventory\n", encoding="utf-8"
    )
    (tmp_path / "composition_coverage.md").write_text(
        "# Composition Coverage\n", encoding="utf-8"
    )
    (tmp_path / "chain_hypotheses.md").write_text(
        "# Chain Hypotheses\n", encoding="utf-8"
    )
    (tmp_path / "config.json").write_text(
        json.dumps(config, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    phase = chain_delivery_fixture._phase()
    init_contract, init_launch = (
        driver._chain_state_resolution_contract_and_launch(
            scratchpad=tmp_path,
            config=config,
            phase=phase,
        )
    )
    execute, init_issues = driver._arm_deterministic_driver_work_unit(
        scratchpad=tmp_path,
        project_root=tmp_path,
        contract=init_contract,
        launch=init_launch,
        run_id=str(config["_run_id"]),
    )
    assert execute is True
    assert init_issues == []
    tail_execute, tail_issues = driver._arm_chain_tail_initial_phase_io(
        scratchpad=tmp_path,
        config=config,
        phase=phase,
    )
    assert tail_execute is True
    assert tail_issues == []
    (tmp_path / "chain_state_resolution.json").write_text(
        '{"schema_version":"plamen.chain_state_resolution.v1"}\n',
        encoding="utf-8",
    )
    chain_tail.initialize_chain_tail(
        tmp_path,
        [chain_delivery_fixture._pair()],
        shard_size=1,
        activate_first_shard=False,
    )
    chain_delivery_fixture._materialize_state_resolution_denominator(tmp_path)
    assert driver._commit_chain_tail_initial_phase_io(
        scratchpad=tmp_path,
        config=config,
        phase=phase,
    ) == []
    assert driver._commit_deterministic_driver_work_unit(
        scratchpad=tmp_path,
        project_root=tmp_path,
        contract=init_contract,
        launch=init_launch,
        run_id=str(config["_run_id"]),
    ) == []
    assert driver._bind_typed_model_phase_inputs(phase, tmp_path, config) == []
    isolated = config["_chain_tail_active_isolated"]

    def run_legacy_shard(_phase, inner_config, _attempt):
        output = Path(inner_config["scratchpad"]) / "chain_iteration2.md"
        output.write_text(
            chain_delivery_fixture._composition_output(
                isolated["rows"][0],
                "## CH-77 composed transition",
                (
                    "CH-77 binds an exact postcondition to a dependent "
                    "precondition."
                ),
            ),
            encoding="utf-8",
        )
        return 0

    monkeypatch.setattr(driver, "run_phase", run_legacy_shard)
    assert driver._run_isolated_chain_tail_model_attempt(
        phase, config, 1
    ) == 0
    terminal_receipt, terminal_issues = (
        driver._run_chain_tail_final_reconcile_transaction(
            tmp_path, config, phase
        )
    )
    assert terminal_issues == []
    assert terminal_receipt["status"] == "COMPLETE"
    candidate_payload = json.loads(
        (tmp_path / chain_tail.COMPOSITION_CANDIDATES_NAME).read_text(
            encoding="utf-8"
        )
    )
    legacy_id = str(candidate_payload["candidates"][0]["chain_id"])
    assert legacy_id == "CH-77"

    config, p1m_id = _live_p1m_producer(
        tmp_path,
        monkeypatch,
        config=config,
    )
    assert p1m_id == "CH-223868"
    assert p1m_id != legacy_id
    _ordinary_queue(tmp_path, ("H-1", "M-1"))

    safe, issues = driver._run_p0af_v2_live_queue_boundary(tmp_path, config)
    shards = ensure_sc_verify_shard_manifests(
        tmp_path, p0af_runtime_config=config
    )
    routed = {
        str(item.get("finding id") or "")
        for rows in shards.values()
        for item in rows
    }

    assert safe is True
    assert issues == []
    assert routed >= {"H-1", "M-1", legacy_id, p1m_id}
    typed = _read_typed_queue_work_items(tmp_path / "verification_queue.md")
    by_id = {item.work_item_id: item for item in typed}
    assert by_id[legacy_id].evidence_class != "p0af-v2-generator"
    assert by_id[p1m_id].evidence_class == "p0af-v2-generator"
    legacy_receipt = json.loads(
        (tmp_path / "compound_verification_delivery_receipt.json").read_text(
            encoding="utf-8"
        )
    )
    p1m_receipt = json.loads(
        (tmp_path / queue_runtime.RECEIPT_FILE).read_text(encoding="utf-8")
    )
    assert legacy_receipt["delivered_work_item_ids"] == [legacy_id]
    assert legacy_receipt["owned_work_item_digests"] == {
        legacy_id: by_id[legacy_id].digest,
    }
    assert p1m_receipt["delivered_work_item_ids"] == [p1m_id]
    assert p1m_receipt["owned_work_item_digests"] == {
        p1m_id: by_id[p1m_id].digest,
    }
    assert not (tmp_path / "compound_verification_delivery_debt.json").exists()

    replay_paths = (
        "verification_queue.md",
        "verification_queue.json",
        "verification_queue.work_items.json",
        "compound_verification_delivery_receipt.json",
        queue_runtime.RECEIPT_FILE,
        queue_runtime.STATUS_FILE,
        queue_runtime.JOURNAL_FILE,
    )
    before_replay = {
        name: (tmp_path / name).read_bytes() for name in replay_paths
    }
    replay_safe, replay_issues = driver._run_p0af_v2_live_queue_boundary(
        tmp_path, config
    )
    replay_shards = ensure_sc_verify_shard_manifests(
        tmp_path, p0af_runtime_config=config
    )
    assert replay_safe is True
    assert replay_issues == []
    assert replay_shards == shards
    assert {
        name: (tmp_path / name).read_bytes() for name in replay_paths
    } == before_replay
