"""Fake-only tests: no Apple CLI, network, native broker, or subprocess call."""
from __future__ import annotations

from dataclasses import fields, replace
import hashlib
import os
from pathlib import Path
import sys
import threading

import pytest

import apple_egress_network as A


def _d(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _closure(**changes: object) -> A.NetworkClosure:
    values: dict[str, object] = {
        "attempt_id": "dodo-001",
        "run_identity": "run-dodo-001",
        "request_fingerprint_sha256": _d("request"),
        "config_sha256": _d("config"),
        "runtime_closure_sha256": _d("runtime"),
        "provider_provenance_sha256": _d("provider"),
        "egress_policy_sha256": _d("policy"),
        "egress_admission_sha256": _d("admission"),
        "proxy_endpoint_sha256": _d("proxy"),
        "credential_isolation_sha256": _d("credentials"),
        "broker_authority_sha256": _d("broker"),
    }
    values.update(changes)
    return A.NetworkClosure(**values)  # type: ignore[arg-type]


def _context() -> tuple[A.NetworkClosure, A.NetworkPlan]:
    closure = _closure()
    return closure, A.render_network_plan(closure)


def _active(
    closure: A.NetworkClosure, plan: A.NetworkPlan,
) -> A.EgressEvidence:
    return A.TEST_ONLY_egress_evidence(
        closure, plan, A.EgressState.ACTIVE, sequence=1
    )


def _revoked(
    closure: A.NetworkClosure, plan: A.NetworkPlan,
    active: A.EgressEvidence,
) -> A.EgressEvidence:
    return A.TEST_ONLY_egress_evidence(
        closure, plan, A.EgressState.REVOKED, sequence=3,
        prior_checkpoint_sha256=active.checkpoint_sha256,
    )


def _created() -> tuple[
    A.NetworkClosure, A.NetworkPlan, A.EgressEvidence,
    A.NetworkObservation, A.TEST_ONLY_Journal,
]:
    closure, plan = _context()
    active = _active(closure, plan)
    journal = A.TEST_ONLY_new_journal(closure)
    claim = A.TEST_ONLY_claim(
        journal, closure, plan, A.Operation.CREATE, "1" * 32
    )
    journal = A.TEST_ONLY_prepare_create(
        journal, closure, plan, claim, active,
        A.TEST_ONLY_observation(plan, present=False),
    )
    observation = A.TEST_ONLY_observation(plan)
    journal = A.TEST_ONLY_commit_create(
        journal, closure, plan, observation, active
    )
    return closure, plan, active, observation, journal


def _forge(value: object, **changes: object) -> object:
    forged = object.__new__(type(value))
    for item in fields(value):
        object.__setattr__(
            forged, item.name,
            changes.get(item.name, object.__getattribute__(value, item.name)),
        )
    return forged


def test_plan_is_deterministic_closed_and_attempt_bound() -> None:
    closure, plan = _context()
    assert plan == A.render_network_plan(closure)
    assert plan.network_name == "plamen-egress-" + closure.digest[:24]
    assert plan.internal is True
    assert plan.internal_isolation_sufficient is False
    assert plan.mode == "hostOnly"
    assert plan.plugin == "container-network-vmnet"
    assert plan.create_argv[:6] == (
        "/usr/local/bin/container", "network", "create", "--internal",
        "--subnet", plan.ipv4_subnet,
    )
    assert plan.create_argv[-3:] == (
        "--plugin", "container-network-vmnet", plan.network_name,
    )
    assert plan.inspect_argv == (
        "/usr/local/bin/container", "network", "inspect", plan.network_name,
    )
    assert plan.delete_argv == (
        "/usr/local/bin/container", "network", "delete", plan.network_name,
    )
    assert "--all" not in plan.delete_argv
    assert "--subnet-v6" not in plan.create_argv
    assert "--option" not in plan.create_argv
    label_rows = [
        plan.create_argv[index + 1]
        for index, item in enumerate(plan.create_argv) if item == "--label"
    ]
    assert label_rows == [f"{key}={value}" for key, value in plan.labels]


@pytest.mark.parametrize("field", [
    "attempt_id", "run_identity", "request_fingerprint_sha256",
    "config_sha256", "runtime_closure_sha256",
    "provider_provenance_sha256", "egress_policy_sha256",
    "egress_admission_sha256", "proxy_endpoint_sha256",
    "credential_isolation_sha256", "broker_authority_sha256",
])
def test_every_closure_field_changes_plan(field: str) -> None:
    closure, plan = _context()
    value = "other-001" if field in {"attempt_id", "run_identity"} else _d(field)
    changed = _closure(**{field: value})
    assert changed.digest != closure.digest
    assert A.render_network_plan(changed) != plan


@pytest.mark.parametrize("field,value", [
    ("attempt_id", "bad/value"),
    ("run_identity", ""),
    ("request_fingerprint_sha256", "0" * 63),
    ("proxy_endpoint_sha256", "G" * 64),
    ("broker_authority_sha256", 1),
])
def test_closure_rejects_noncanonical_inputs(field: str, value: object) -> None:
    with pytest.raises(A.NetworkConfigurationError):
        _closure(**{field: value})


@pytest.mark.parametrize("field,value", [
    ("network_name", "other"), ("ipv4_subnet", "8.8.8.0/28"),
    ("ipv4_gateway", "10.0.0.2"), ("plugin", "other"),
    ("mode", "shared"), ("internal", False),
    ("internal_isolation_sufficient", True),
    ("labels", (("io.plamen.provider", "other"),)),
    ("create_argv", ("evil", "network", "create", "x")),
    ("fingerprint_sha256", "f" * 64),
])
def test_plan_substitution_is_rejected(field: str, value: object) -> None:
    closure, plan = _context()
    forged = _forge(plan, **{field: value})
    with pytest.raises((A.NetworkConfigurationError, A.NetworkProtocolError)):
        A.validate_inspection(
            closure, forged, A.TEST_ONLY_observation(plan),
            expected_network_id=None,
        )


def test_exact_present_and_absent_inspection() -> None:
    closure, plan = _context()
    present = A.TEST_ONLY_observation(plan)
    absent = A.TEST_ONLY_observation(plan, present=False)
    assert A.validate_inspection(
        closure, plan, present, expected_network_id=present.network_id
    ) == present
    assert not A.validate_inspection(
        closure, plan, absent, expected_network_id=None
    ).present
    with pytest.raises(A.NetworkConfigurationError, match="absent"):
        replace(absent, network_name=plan.network_name)


@pytest.mark.parametrize("field,value", [
    ("network_name", "plamen-egress-other"),
    ("network_id", "other-network-object"),
    ("mode", "shared"),
    ("plugin", "other-plugin"),
    ("ipv4_subnet", "10.1.2.0/28"),
    ("ipv4_gateway", "10.1.2.1"),
    ("labels", (("io.plamen.provider", "other"),)),
])
def test_inspection_rejects_collision_or_schema_drift(
    field: str, value: object,
) -> None:
    closure, plan = _context()
    observation = A.TEST_ONLY_observation(plan)
    forged = _forge(observation, **{field: value})
    with pytest.raises((A.NetworkProtocolError, A.NetworkCollisionError)):
        A.validate_inspection(
            closure, plan, forged,
            expected_network_id=observation.network_id,
        )


def test_initial_existing_exact_network_is_still_collision() -> None:
    closure, plan = _context()
    active = _active(closure, plan)
    journal = A.TEST_ONLY_new_journal(closure)
    claim = A.TEST_ONLY_claim(
        journal, closure, plan, A.Operation.CREATE, "1" * 32
    )
    with pytest.raises(A.NetworkCollisionError):
        A.TEST_ONLY_prepare_create(
            journal, closure, plan, claim, active,
            A.TEST_ONLY_observation(plan),
        )


@pytest.mark.parametrize("field,value", [
    ("native_enforced", False),
    ("direct_ip_egress_denied", False),
    ("host_gateway_bypass_denied", False),
    ("proxy_attempt_authenticated", False),
    ("internal_alone_sufficient", True),
    ("proxy_kind", "PRIVATE_SHIM"),
    ("proxy_endpoint_sha256", "0" * 64),
    ("egress_admission_sha256", "0" * 64),
    ("attempt_id", "other-001"),
    ("checkpoint_sha256", "0" * 64),
])
def test_egress_proof_is_exact_and_internal_never_sufficient(
    field: str, value: object,
) -> None:
    closure, plan = _context()
    active = _active(closure, plan)
    with pytest.raises((A.NetworkConfigurationError, A.NetworkProtocolError)):
        changed = _forge(active, **{field: value})
        journal = A.TEST_ONLY_new_journal(closure)
        claim = A.TEST_ONLY_claim(
            journal, closure, plan, A.Operation.CREATE, "1" * 32
        )
        A.TEST_ONLY_prepare_create(
            journal, closure, plan, claim, changed,
            A.TEST_ONLY_observation(plan, present=False),
        )


def test_create_is_prepared_durably_before_effect_and_then_committed() -> None:
    closure, plan = _context()
    active = _active(closure, plan)
    journal = A.TEST_ONLY_new_journal(closure)
    claim = A.TEST_ONLY_claim(
        journal, closure, plan, A.Operation.CREATE, "1" * 32
    )
    prepared = A.TEST_ONLY_prepare_create(
        journal, closure, plan, claim, active,
        A.TEST_ONLY_observation(plan, present=False),
    )
    assert len(prepared.records) == 1
    assert prepared.records[-1].state is A.RecordState.PREPARED
    assert prepared.records[-1].durable is True
    committed = A.TEST_ONLY_commit_create(
        prepared, closure, plan, A.TEST_ONLY_observation(plan), active
    )
    assert committed.records[-1].state is A.RecordState.CREATED
    assert committed.records[-1].network_id == "plamen-network-object-001"


def test_create_without_preparation_is_ambiguous() -> None:
    closure, plan = _context()
    with pytest.raises(A.NetworkAmbiguousError):
        A.TEST_ONLY_commit_create(
            A.TEST_ONLY_new_journal(closure), closure, plan,
            A.TEST_ONLY_observation(plan), _active(closure, plan),
        )


def test_create_ack_loss_recovers_without_repeating_effect() -> None:
    closure, plan = _context()
    active = _active(closure, plan)
    journal = A.TEST_ONLY_new_journal(closure)
    claim = A.TEST_ONLY_claim(
        journal, closure, plan, A.Operation.CREATE, "1" * 32
    )
    prepared = A.TEST_ONLY_prepare_create(
        journal, closure, plan, claim, active,
        A.TEST_ONLY_observation(plan, present=False),
    )
    recovered = A.TEST_ONLY_recover(
        prepared, closure, plan, A.TEST_ONLY_observation(plan), active
    )
    assert recovered.records[-1].state is A.RecordState.CREATED
    fresh_active = A.TEST_ONLY_egress_evidence(
        closure, plan, A.EgressState.ACTIVE,
        sequence=active.sequence + 1,
        prior_checkpoint_sha256=active.checkpoint_sha256,
    )
    again = A.TEST_ONLY_recover(
        recovered, closure, plan, A.TEST_ONLY_observation(plan), fresh_active
    )
    assert again == recovered


@pytest.mark.parametrize("mutation", [
    "object", "native", "direct-ip", "gateway", "proxy", "stale", "rebound",
])
def test_created_recovery_requires_fresh_active_enforcement(mutation: str) -> None:
    closure, plan, active, observation, journal = _created()
    fresh: object = A.TEST_ONLY_egress_evidence(
        closure, plan, A.EgressState.ACTIVE,
        sequence=active.sequence + 1,
        prior_checkpoint_sha256=active.checkpoint_sha256,
    )
    if mutation == "object":
        fresh = object()
    elif mutation == "native":
        fresh = _forge(fresh, native_enforced=False)
    elif mutation == "direct-ip":
        fresh = _forge(fresh, direct_ip_egress_denied=False)
    elif mutation == "gateway":
        fresh = _forge(fresh, host_gateway_bypass_denied=False)
    elif mutation == "proxy":
        fresh = _forge(fresh, proxy_attempt_authenticated=False)
    elif mutation == "stale":
        fresh = active
    else:
        fresh = A.TEST_ONLY_egress_evidence(
            closure, plan, A.EgressState.ACTIVE,
            sequence=active.sequence + 1,
            prior_checkpoint_sha256=_d("unrelated-egress"),
        )
    with pytest.raises((A.NetworkConfigurationError, A.NetworkProtocolError)):
        A.TEST_ONLY_recover(journal, closure, plan, observation, fresh)  # type: ignore[arg-type]


def test_provably_unexecuted_create_recovery_aborts() -> None:
    closure, plan = _context()
    active = _active(closure, plan)
    empty = A.TEST_ONLY_new_journal(closure)
    claim = A.TEST_ONLY_claim(
        empty, closure, plan, A.Operation.CREATE, "1" * 32
    )
    prepared = A.TEST_ONLY_prepare_create(
        empty, closure, plan, claim, active,
        A.TEST_ONLY_observation(plan, present=False),
    )
    aborted = A.TEST_ONLY_recover(
        prepared, closure, plan,
        A.TEST_ONLY_observation(plan, present=False), active,
    )
    assert aborted.records[-1].state is A.RecordState.ABORTED

    fresh_active = A.TEST_ONLY_egress_evidence(
        closure, plan, A.EgressState.ACTIVE,
        sequence=active.sequence + 1,
        prior_checkpoint_sha256=active.checkpoint_sha256,
    )
    assert A.TEST_ONLY_recover(
        aborted, closure, plan, A.TEST_ONLY_observation(plan, present=False),
        fresh_active,
    ) == aborted
    with pytest.raises(A.NetworkAmbiguousError):
        A.TEST_ONLY_recover(
            aborted, closure, plan, A.TEST_ONLY_observation(plan), fresh_active
        )


def test_cross_attempt_journal_and_network_are_rejected() -> None:
    closure, plan, active, observation, journal = _created()
    other = _closure(attempt_id="dodo-002")
    other_plan = A.render_network_plan(other)
    with pytest.raises(A.NetworkProtocolError):
        A.TEST_ONLY_recover(journal, other, other_plan, observation, active)
    other_observation = A.TEST_ONLY_observation(other_plan)
    with pytest.raises(A.NetworkCollisionError):
        A.validate_inspection(
            closure, plan, other_observation, expected_network_id=None
        )


def test_claim_is_thread_process_sequence_and_one_shot_bound() -> None:
    closure, plan = _context()
    active = _active(closure, plan)
    journal = A.TEST_ONLY_new_journal(closure)
    claim = A.TEST_ONLY_claim(
        journal, closure, plan, A.Operation.CREATE, "1" * 32
    )
    for changes in (
        {"creator_pid": os.getpid() + 1},
        {"creator_thread": threading.get_ident() + 1},
        {"sequence": 2}, {"prior_checkpoint_sha256": "f" * 64},
    ):
        with pytest.raises(A.NetworkProtocolError):
            A.TEST_ONLY_prepare_create(
                journal, closure, plan, _forge(claim, **changes), active,
                A.TEST_ONLY_observation(plan, present=False),
            )
    prepared = A.TEST_ONLY_prepare_create(
        journal, closure, plan, claim, active,
        A.TEST_ONLY_observation(plan, present=False),
    )
    with pytest.raises(A.NetworkProtocolError):
        A.TEST_ONLY_prepare_create(
            prepared, closure, plan, claim, active,
            A.TEST_ONLY_observation(plan, present=False),
        )


def test_concurrent_first_use_claim_loser_cannot_enter() -> None:
    closure, plan = _context()
    active = _active(closure, plan)
    journal = A.TEST_ONLY_new_journal(closure)
    winner = A.TEST_ONLY_claim(
        journal, closure, plan, A.Operation.CREATE, "1" * 32
    )
    loser = A.TEST_ONLY_claim(
        journal, closure, plan, A.Operation.CREATE, "2" * 32
    )
    prepared = A.TEST_ONLY_prepare_create(
        journal, closure, plan, winner, active,
        A.TEST_ONLY_observation(plan, present=False),
    )
    with pytest.raises(A.NetworkProtocolError):
        A.TEST_ONLY_prepare_create(
            prepared, closure, plan, loser, active,
            A.TEST_ONLY_observation(plan, present=False),
        )


def test_delete_requires_new_revocation_and_no_attachments() -> None:
    closure, plan, active, observation, journal = _created()
    claim = A.TEST_ONLY_claim(
        journal, closure, plan, A.Operation.DELETE, "2" * 32
    )
    with pytest.raises(A.NetworkProtocolError):
        A.TEST_ONLY_prepare_delete(
            journal, closure, plan, claim, active, observation
        )
    revoked = _revoked(closure, plan, active)
    attached = A.TEST_ONLY_observation(
        plan, attached_container_ids=("plamen-dodo-001",)
    )
    with pytest.raises(A.NetworkProtocolError, match="ready"):
        A.TEST_ONLY_prepare_delete(
            journal, closure, plan, claim, revoked, attached
        )


def test_delete_extinction_and_ack_loss_recovery() -> None:
    closure, plan, active, observation, journal = _created()
    revoked = _revoked(closure, plan, active)
    claim = A.TEST_ONLY_claim(
        journal, closure, plan, A.Operation.DELETE, "2" * 32
    )
    prepared = A.TEST_ONLY_prepare_delete(
        journal, closure, plan, claim, revoked, observation
    )
    absent = A.TEST_ONLY_observation(plan, present=False)
    extinction = A.TEST_ONLY_extinction_evidence(
        closure, plan, observation.network_id, absent, revoked,
        sequence=prepared.records[-1].sequence + 1,
        prior_checkpoint_sha256=prepared.checkpoint,
    )
    deleted = A.TEST_ONLY_commit_delete(
        prepared, closure, plan, absent, revoked, extinction
    )
    assert deleted.records[-1].state is A.RecordState.DELETED
    fresh_revoked = A.TEST_ONLY_egress_evidence(
        closure, plan, A.EgressState.REVOKED,
        sequence=revoked.sequence + 1,
        prior_checkpoint_sha256=revoked.checkpoint_sha256,
    )
    assert A.TEST_ONLY_recover(
        deleted, closure, plan, absent, fresh_revoked, extinction=extinction
    ) == deleted
    recovered = A.TEST_ONLY_recover(
        prepared, closure, plan, absent, revoked, extinction=extinction
    )
    assert recovered.records[-1].state is A.RecordState.DELETED


def test_deleted_recovery_requires_fresh_revocation_and_stored_extinction() -> None:
    closure, plan, active, observation, journal = _created()
    revoked = _revoked(closure, plan, active)
    claim = A.TEST_ONLY_claim(
        journal, closure, plan, A.Operation.DELETE, "2" * 32
    )
    prepared = A.TEST_ONLY_prepare_delete(
        journal, closure, plan, claim, revoked, observation
    )
    absent = A.TEST_ONLY_observation(plan, present=False)
    extinction = A.TEST_ONLY_extinction_evidence(
        closure, plan, observation.network_id, absent, revoked,
        sequence=4, prior_checkpoint_sha256=prepared.checkpoint,
    )
    deleted = A.TEST_ONLY_commit_delete(
        prepared, closure, plan, absent, revoked, extinction
    )
    fresh = A.TEST_ONLY_egress_evidence(
        closure, plan, A.EgressState.REVOKED,
        sequence=revoked.sequence + 1,
        prior_checkpoint_sha256=revoked.checkpoint_sha256,
    )

    for bad_egress in (object(), revoked, _forge(fresh, native_enforced=False)):
        with pytest.raises((A.NetworkConfigurationError, A.NetworkProtocolError)):
            A.TEST_ONLY_recover(
                deleted, closure, plan, absent, bad_egress,  # type: ignore[arg-type]
                extinction=extinction,
            )
    with pytest.raises(A.NetworkProtocolError, match="extinction"):
        A.TEST_ONLY_recover(
            deleted, closure, plan, absent, fresh, extinction=None
        )
    with pytest.raises(A.NetworkProtocolError, match="extinction"):
        A.TEST_ONLY_recover(
            deleted, closure, plan, absent, fresh,
            extinction=_forge(extinction, checkpoint_sha256=_d("other")),
        )


@pytest.mark.parametrize("field,value", [
    ("attachments_absent", False), ("network_object_absent", False),
    ("plugin_process_extinct", False), ("native_cleanup_complete", False),
    ("network_id", "other-object"),
    ("egress_revocation_checkpoint_sha256", "0" * 64),
    ("prior_checkpoint_sha256", "0" * 64),
    ("checkpoint_sha256", "0" * 64),
])
def test_delete_rejects_forged_extinction(field: str, value: object) -> None:
    closure, plan, active, observation, journal = _created()
    revoked = _revoked(closure, plan, active)
    claim = A.TEST_ONLY_claim(
        journal, closure, plan, A.Operation.DELETE, "2" * 32
    )
    prepared = A.TEST_ONLY_prepare_delete(
        journal, closure, plan, claim, revoked, observation
    )
    absent = A.TEST_ONLY_observation(plan, present=False)
    extinction = A.TEST_ONLY_extinction_evidence(
        closure, plan, observation.network_id, absent, revoked,
        sequence=4, prior_checkpoint_sha256=prepared.checkpoint,
    )
    with pytest.raises((A.NetworkConfigurationError, A.NetworkProtocolError)):
        A.TEST_ONLY_commit_delete(
            prepared, closure, plan, absent, revoked,
            _forge(extinction, **{field: value}),
        )


def test_prepared_delete_never_retries_while_network_remains() -> None:
    closure, plan, active, observation, journal = _created()
    revoked = _revoked(closure, plan, active)
    claim = A.TEST_ONLY_claim(
        journal, closure, plan, A.Operation.DELETE, "2" * 32
    )
    prepared = A.TEST_ONLY_prepare_delete(
        journal, closure, plan, claim, revoked, observation
    )
    with pytest.raises(A.NetworkAmbiguousError):
        A.TEST_ONLY_recover(
            prepared, closure, plan, observation, revoked
        )


def test_journal_hash_chain_detects_rollback_and_mutation() -> None:
    closure, plan, active, _observation, journal = _created()
    forged_record = _forge(
        journal.records[-1], network_id="other-object"
    )
    with pytest.raises(A.NetworkConfigurationError, match="chain"):
        A.TEST_ONLY_Journal(
            closure.attempt_id, closure.digest,
            journal.records[:-1] + (forged_record,),
        )
    # A rolled-back CREATED record cannot be silently interpreted as clean.
    prepared = A.TEST_ONLY_Journal(
        closure.attempt_id, closure.digest, journal.records[:1]
    )
    recovered = A.TEST_ONLY_recover(
        prepared, closure, plan, A.TEST_ONLY_observation(plan), active
    )
    assert recovered.records[-1].state is A.RecordState.CREATED


def test_recovery_without_journal_never_adopts_existing_network() -> None:
    closure, plan = _context()
    with pytest.raises(A.NetworkCollisionError):
        A.TEST_ONLY_recover(
            A.TEST_ONLY_new_journal(closure), closure, plan,
            A.TEST_ONLY_observation(plan), _active(closure, plan),
        )


def _deleted() -> tuple[
    A.NetworkClosure, A.NetworkPlan, A.TEST_ONLY_Journal,
]:
    closure, plan, active, observation, journal = _created()
    revoked = _revoked(closure, plan, active)
    claim = A.TEST_ONLY_claim(
        journal, closure, plan, A.Operation.DELETE, "2" * 32
    )
    prepared = A.TEST_ONLY_prepare_delete(
        journal, closure, plan, claim, revoked, observation
    )
    absent = A.TEST_ONLY_observation(plan, present=False)
    extinction = A.TEST_ONLY_extinction_evidence(
        closure, plan, observation.network_id, absent, revoked,
        sequence=4, prior_checkpoint_sha256=prepared.checkpoint,
    )
    return closure, plan, A.TEST_ONLY_commit_delete(
        prepared, closure, plan, absent, revoked, extinction
    )


def test_native_lifecycle_projection_matches_final_broker_v2_subset() -> None:
    closure, plan, journal = _deleted()
    projected = A.TEST_ONLY_native_lifecycle_projections(journal, closure, plan)
    assert tuple(item.frame_type for item in projected) == (
        A.BrokerV2FrameType.CLI_PREPARE,
        A.BrokerV2FrameType.CLI_COMMITTED,
        A.BrokerV2FrameType.REVOKE_PREPARE,
        A.BrokerV2FrameType.REVOKED,
    )
    assert tuple(int(item.frame_type) for item in projected) == (
        0x0010, 0x0011, 0x0040, 0x0041,
    )
    assert tuple(item.direction for item in projected) == (
        "EXTENSION_TO_BROKER", "BROKER_TO_EXTENSION",
        "EXTENSION_TO_BROKER", "BROKER_TO_EXTENSION",
    )
    required_fds = (
        A.BROKER_V2_FD_APPLE_CLI_EXECUTABLE,
        A.BROKER_V2_FD_JOURNAL_DIRECTORY,
    )
    assert tuple(item.fd_purposes for item in projected) == (
        required_fds, (), required_fds, (),
    )
    assert tuple(item.operation_nonce for item in projected) == (
        "1" * 32, "1" * 32, "2" * 32, "2" * 32,
    )
    assert tuple(item.journal_sequence for item in projected) == (1, 2, 3, 4)
    assert all(
        item.missing_commitments == A.NATIVE_PROJECTION_MISSING_COMMITMENTS
        and item.native_dispatch_supported is False
        and item.authority_class == A.TEST_ONLY_AUTHORITY_CLASS
        for item in projected
    )
    assert A.TEST_ONLY_validate_native_lifecycle_projections(
        journal, closure, plan, projected
    ) == projected


def test_aborted_create_projects_a_committed_non_effect_result() -> None:
    closure, plan = _context()
    active = _active(closure, plan)
    journal = A.TEST_ONLY_new_journal(closure)
    claim = A.TEST_ONLY_claim(
        journal, closure, plan, A.Operation.CREATE, "1" * 32
    )
    prepared = A.TEST_ONLY_prepare_create(
        journal, closure, plan, claim, active,
        A.TEST_ONLY_observation(plan, present=False),
    )
    aborted = A.TEST_ONLY_recover(
        prepared, closure, plan,
        A.TEST_ONLY_observation(plan, present=False), active,
    )
    projected = A.TEST_ONLY_native_lifecycle_projections(aborted, closure, plan)
    assert projected[-1].state is A.RecordState.ABORTED
    assert projected[-1].frame_type is A.BrokerV2FrameType.CLI_COMMITTED
    assert projected[-1].direction == "BROKER_TO_EXTENSION"
    assert projected[-1].fd_purposes == ()


@pytest.mark.parametrize(("field", "value"), [
    ("abi_schema", "plamen.native-broker.v1"),
    ("protocol_version", 1),
    ("frame_type", A.BrokerV2FrameType.CLI_COMMITTED),
    ("frame_name", "CLI_COMMITTED"),
    ("direction", "BROKER_TO_EXTENSION"),
    ("operation", A.Operation.DELETE),
    ("state", A.RecordState.CREATED),
    ("attempt_id", "other-001"),
    ("closure_sha256", "0" * 64),
    ("network_name", "other-network"),
    ("network_id", "other-object"),
    ("plan_sha256", "0" * 64),
    ("claim_sha256", "0" * 64),
    ("operation_nonce", "f" * 32),
    ("observation_sha256", "0" * 64),
    ("egress_checkpoint_sha256", "0" * 64),
    ("egress_sequence", 2),
    ("journal_sequence", 2),
    ("prior_journal_checkpoint_sha256", "f" * 64),
    ("journal_checkpoint_sha256", "f" * 64),
    ("fd_purposes", ()),
    ("missing_commitments", ("image_closure_sha256",)),
    ("native_dispatch_supported", True),
    ("projection_sha256", "f" * 64),
    ("authority_class", "PRODUCTION"),
])
def test_every_native_lifecycle_projection_mutation_is_rejected(
    field: str, value: object,
) -> None:
    closure, plan = _context()
    active = _active(closure, plan)
    empty = A.TEST_ONLY_new_journal(closure)
    claim = A.TEST_ONLY_claim(
        empty, closure, plan, A.Operation.CREATE, "1" * 32
    )
    journal = A.TEST_ONLY_prepare_create(
        empty, closure, plan, claim, active,
        A.TEST_ONLY_observation(plan, present=False),
    )
    projected = A.TEST_ONLY_native_lifecycle_projections(journal, closure, plan)
    forged = (_forge(projected[0], **{field: value}),)
    with pytest.raises((A.NetworkConfigurationError, A.NetworkProtocolError)):
        A.TEST_ONLY_validate_native_lifecycle_projections(
            journal, closure, plan, forged
        )


def test_native_operation_nonce_is_durable_and_hash_chain_bound() -> None:
    closure, plan, _active_evidence, _observation, journal = _created()
    assert tuple(record.operation_nonce for record in journal.records) == (
        "1" * 32, "1" * 32,
    )
    forged = _forge(journal.records[-1], operation_nonce="f" * 32)
    with pytest.raises(A.NetworkConfigurationError, match="chain"):
        A.TEST_ONLY_Journal(
            closure.attempt_id, closure.digest,
            journal.records[:-1] + (forged,),
        )


@pytest.mark.parametrize("changes", [
    {"operation": A.Operation.DELETE, "state": A.RecordState.DELETED},
    {"operation_nonce": "f" * 32},
    {"egress_sequence": 2},
])
def test_rehashed_semantic_journal_forgery_is_rejected(
    changes: dict[str, object],
) -> None:
    closure, _plan, _active_evidence, _observation, journal = _created()
    draft = _forge(
        journal.records[-1], **changes, checkpoint_sha256="0" * 64
    )
    forged = _forge(
        draft, checkpoint_sha256=A._json_digest(draft.document)
    )
    with pytest.raises(A.NetworkConfigurationError):
        A.TEST_ONLY_Journal(
            closure.attempt_id, closure.digest,
            journal.records[:-1] + (forged,),
        )


def test_rehashed_cross_plan_journal_cannot_be_projected() -> None:
    closure, plan, _active_evidence, _observation, journal = _created()
    first = _forge(
        journal.records[0], plan_sha256="f" * 64,
        checkpoint_sha256="0" * 64,
    )
    first = _forge(first, checkpoint_sha256=A._json_digest(first.document))
    second = _forge(
        journal.records[1], plan_sha256="f" * 64,
        prior_checkpoint_sha256=first.checkpoint_sha256,
        checkpoint_sha256="0" * 64,
    )
    second = _forge(second, checkpoint_sha256=A._json_digest(second.document))
    forged = A.TEST_ONLY_Journal(
        closure.attempt_id, closure.digest, (first, second)
    )
    with pytest.raises(A.NetworkProtocolError, match="network plan"):
        A.TEST_ONLY_native_lifecycle_projections(forged, closure, plan)


def test_native_abi_constants_equal_the_shared_header() -> None:
    assert A.NATIVE_MODULE_NAME == "_plamen_native_supervisor"
    assert A.NATIVE_ABI_SCHEMA == "plamen.native-broker.v2"
    assert A.NATIVE_PRODUCTION_ACQUISITION == (
        "HARD_STOP_PENDING_NATIVE_LAUNCHER_AND_DURABLE_BROKER_SERVICE"
    )
    assert A.BROKER_V2_PROTOCOL_VERSION == 2
    assert A.BROKER_V2_FRAME_HEADER_SIZE == 196
    assert A.BROKER_V2_MAX_SCM_RIGHTS_FDS == 16
    assert A.BROKER_V2_FD_APPLE_CLI_EXECUTABLE == 0x0001
    assert A.BROKER_V2_FD_JOURNAL_DIRECTORY == 0x0002
    header = (
        Path(__file__).resolve().parents[1]
        / "native" / "include" / "plamen_broker_v2.h"
    ).read_text()
    for literal in (
        "PLAMEN_BROKER_V2_VERSION 2U",
        "PLAMEN_BROKER_V2_HEADER_SIZE 196U",
        "PLAMEN_BROKER_V2_MAX_FDS 16U",
        "PLAMEN_BROKER_V2_CLI_PREPARE = 0x0010",
        "PLAMEN_BROKER_V2_CLI_COMMITTED = 0x0011",
        "PLAMEN_BROKER_V2_REVOKE_PREPARE = 0x0040",
        "PLAMEN_BROKER_V2_REVOKED = 0x0041",
        "PLAMEN_BROKER_V2_FD_APPLE_CLI_EXECUTABLE = 0x0001",
        "PLAMEN_BROKER_V2_FD_JOURNAL_DIRECTORY = 0x0002",
    ):
        assert literal in header


class Evil:
    def __getattribute__(self, _name: str) -> object:
        raise AssertionError("caller object was touched")

    def __eq__(self, _other: object) -> bool:
        raise AssertionError("caller equality was invoked")


def test_production_factory_hardstops_before_caller_touch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delitem(sys.modules, A.NATIVE_MODULE_NAME, raising=False)
    with pytest.raises(A.NativeBrokerUnavailable):
        A.open_apple_egress_network(Evil(), Evil())  # type: ignore[arg-type]


def test_forged_wrapper_hardstops_before_plan_touch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delitem(sys.modules, A.NATIVE_MODULE_NAME, raising=False)
    wrapper = object.__new__(A.AppleEgressNetwork)
    object.__setattr__(wrapper, "_closure", Evil())
    object.__setattr__(wrapper, "_capability", Evil())
    for method in (wrapper.create, wrapper.inspect, wrapper.delete, wrapper.recover):
        with pytest.raises(A.NativeBrokerUnavailable):
            method(Evil())  # type: ignore[arg-type]


def test_fake_python_native_module_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = type(sys)(A.NATIVE_MODULE_NAME)
    fake.NativeAuthorityConsumer = type("NativeAuthorityConsumer", (), {})
    fake.AppleEgressNetworkCapability = type("AppleEgressNetworkCapability", (), {})
    fake.AppleEgressNetworkCallCapability = type("AppleEgressNetworkCallCapability", (), {})
    monkeypatch.setitem(sys.modules, A.NATIVE_MODULE_NAME, fake)
    with pytest.raises(A.NativeBrokerUnavailable):
        A.open_apple_egress_network(Evil(), Evil())  # type: ignore[arg-type]


def test_final_abi_shaped_python_module_is_still_rejected_before_caller_touch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    origin = "/tmp/" + A.NATIVE_MODULE_NAME + A.importlib.machinery.EXTENSION_SUFFIXES[0]
    loader = A.importlib.machinery.ExtensionFileLoader(A.NATIVE_MODULE_NAME, origin)
    fake = A.types.ModuleType(A.NATIVE_MODULE_NAME)
    fake.__file__ = origin
    fake.__spec__ = A.importlib.machinery.ModuleSpec(
        A.NATIVE_MODULE_NAME, loader, origin=origin,
    )
    fake.TEST_ONLY_BUILD = False
    fake.BROKER_V2_ABI_SCHEMA = A.NATIVE_ABI_SCHEMA
    fake.BROKER_V2_PRODUCTION_ACQUISITION = A.NATIVE_PRODUCTION_ACQUISITION
    fake.BROKER_V2_PROTOCOL_VERSION = A.BROKER_V2_PROTOCOL_VERSION
    fake.BROKER_V2_FRAME_HEADER_SIZE = A.BROKER_V2_FRAME_HEADER_SIZE
    fake.BROKER_V2_MAX_SCM_RIGHTS_FDS = A.BROKER_V2_MAX_SCM_RIGHTS_FDS

    def consume_once(self: object) -> None:
        raise AssertionError("forged native method was called")

    for name in (
        "BrokerV2AuthorityConsumer", "SupervisorAuthorities",
        "ProviderAuthority", "NetworkReceiptProjection",
    ):
        forged_type = type(name, (), {"consume_once": consume_once})
        forged_type.__module__ = A.NATIVE_MODULE_NAME
        setattr(fake, name, forged_type)
    monkeypatch.setitem(sys.modules, A.NATIVE_MODULE_NAME, fake)
    with pytest.raises(A.NativeBrokerUnavailable):
        A.open_apple_egress_network(Evil(), Evil())  # type: ignore[arg-type]


def test_no_test_only_authority_is_public_or_production() -> None:
    assert all(not name.startswith("TEST_ONLY") for name in A.__all__)
    closure, plan = _context()
    evidence = _active(closure, plan)
    claim = A.TEST_ONLY_claim(
        A.TEST_ONLY_new_journal(closure), closure, plan,
        A.Operation.CREATE, "1" * 32,
    )
    assert evidence.authority_class == A.TEST_ONLY_AUTHORITY_CLASS
    assert claim.authority_class == A.TEST_ONLY_AUTHORITY_CLASS
    assert "TEST_ONLY_NON_AUTHORITY" in repr(evidence)


def test_module_is_inert_and_contains_no_live_execution_lane() -> None:
    source = Path(A.__file__).read_text()
    assert "import subprocess" not in source
    assert "subprocess." not in source
    assert "os.system" not in source
    assert "Popen" not in source
    assert "_AUTHORITY_REGISTRY" not in source
    assert "--internal`` selects a host-only topology" in source
    assert "does *not* prove credential isolation" in source
    assert "_native_types()\n    if type(native_consumer)" in source
