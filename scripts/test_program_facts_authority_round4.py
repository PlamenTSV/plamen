"""PF-AUTH-01 R4 semantic-replay authority regressions.

These probes fault-inject through visible names and reflection-constructed data
carriers to ensure production authority comes from semantic replay, not a
seal, caller code-object identity, or issuance-table membership.  They do not
model arbitrary code execution or loaded-code/closure mutation inside the
Python orchestrator TCB: an attacker able to rewrite the validator defeats
every Python gate and must instead be excluded by OS/process and code-integrity
controls.
"""

from __future__ import annotations

import concurrent.futures
import copy
import gc
import pickle

import pytest

import program_facts_methodology_authority as methodology_api
import program_facts_provider_api as provider_api
import program_facts_provider_registry as registry_api
from program_facts_provider_api import (
    ProgramFactsProviderAPIError,
    validate_provider_plan,
    validate_provider_result,
)
from program_facts_provider_registry import (
    ProgramFactsProviderRegistryError,
    load_program_facts_provider_registry,
)
from test_program_facts_registry_api_authority_blockers import (
    _capture_and_load,
    _context,
    _observed,
    _parsed_result,
    _structural_plan,
)


def test_methodology_raw_issuer_and_seal_are_not_authority_surfaces() -> None:
    for name in (
        "_CAPTURE_SEAL",
        "_IssuedMethodologyAuthority",
        "_issue_methodology_authority",
        "_claim_methodology_authority",
    ):
        assert not hasattr(methodology_api, name)


def test_reflection_duplicate_must_replay_exact_capture_at_registry_sink() -> None:
    authority, _registry = _capture_and_load()
    with pytest.raises(TypeError):
        methodology_api.InstalledMethodologyAuthority()

    exact_duplicate = object.__new__(
        methodology_api.InstalledMethodologyAuthority
    )
    for name in methodology_api.InstalledMethodologyAuthority.__slots__:
        if name != "__weakref__":
            object.__setattr__(
                exact_duplicate, name, getattr(authority, name)
            )
    exact_registry = load_program_facts_provider_registry(
        installed_authority=exact_duplicate
    )
    assert exact_registry.production_authority_established
    assert (
        exact_registry.methodology_capture_digest
        == _registry.methodology_capture_digest
    )

    # Exact semantic data may replay independently; object identity is not the
    # authority boundary.  Any change must fail at the real production loader.
    duplicate = object.__new__(methodology_api.InstalledMethodologyAuthority)
    for name in methodology_api.InstalledMethodologyAuthority.__slots__:
        if name != "__weakref__":
            object.__setattr__(duplicate, name, getattr(authority, name))
    object.__setattr__(duplicate, "_capture_digest", "f" * 64)
    with pytest.raises(
        ProgramFactsProviderRegistryError,
        match="capture|drift|mutation|substitution",
    ):
        load_program_facts_provider_registry(installed_authority=duplicate)

    for operation in (
        lambda: copy.copy(authority),
        lambda: copy.deepcopy(authority),
        lambda: pickle.dumps(authority),
    ):
        with pytest.raises(TypeError):
            operation()


def test_registry_recording_tombstone_cannot_mint_production() -> None:
    registry, _context_value, _observed_value, _plan = _structural_plan()
    summary = registry_api._loaded_registry_issuance_preimage(registry)
    assert summary is not None

    def attacker_loader() -> str:
        try:
            registry_api._record_loaded_registry(registry, summary)
        except Exception as exc:
            return f"{type(exc).__name__}:{exc}"
        return "UNEXPECTED_SUCCESS"

    original_loader = registry_api._load_registry_bytes
    try:
        registry_api._load_registry_bytes = attacker_loader
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            outcomes = tuple(pool.map(lambda _: attacker_loader(), range(128)))
    finally:
        registry_api._load_registry_bytes = original_loader

    assert all(
        item.startswith("TypeError:provider registry issuance is internal")
        for item in outcomes
    )
    assert registry.production_authority_established is False

    # Bypass the common parser's mutable caller-name guard.  The loader still
    # has to reject a self-asserted capture digest at semantic replay.
    _authority, production = _capture_and_load()
    original_public_loader = registry_api.load_program_facts_provider_registry
    original_common_loader = registry_api._load_registry_bytes

    def attacker_common_loader():
        return original_common_loader(
            production.canonical_bytes,
            expected_registry_digest=None,
            max_bytes=registry_api.DEFAULT_MAX_REGISTRY_BYTES,
            source_identity=production.source_identity,
            authority_state=registry_api.INSTALLED_PRODUCTION_AUTHORITY,
            snapshot_digest=production.snapshot_digest,
            source_scope_digest=production.source_scope_digest,
            audit_run_id=production.audit_run_id,
            methodology_capture_digest="f" * 64,
            methodology_checkpoint_bytes=(
                production._methodology_checkpoint_bytes
            ),
            phase_io_input_bytes=production.phase_io_input_bytes,
        )

    try:
        registry_api.load_program_facts_provider_registry = (
            attacker_common_loader
        )
        with pytest.raises(
            ProgramFactsProviderRegistryError,
            match="parent capture drift",
        ):
            attacker_common_loader()
    finally:
        registry_api.load_program_facts_provider_registry = (
            original_public_loader
        )


def test_mutable_compile_global_cannot_mint_ready_or_cross_sinks() -> None:
    _structural_registry, context, observed, structural_plan = (
        _structural_plan()
    )
    forged_plan = copy.copy(structural_plan)
    _authority, production_registry = _capture_and_load()
    original_compile = provider_api.compile_provider_plan

    def attacker_issuer() -> None:
        provider_api._record_compiled_plan(
            forged_plan,
            registry=production_registry,
            structural_test_only=False,
        )

    try:
        provider_api.compile_provider_plan = attacker_issuer
        with pytest.raises(
            TypeError,
            match="provider plan issuance is internal",
        ):
            attacker_issuer()
    finally:
        provider_api.compile_provider_plan = original_compile

    # Even bypassing the compatibility caller guard on the internal compiler
    # can only alter anti-accident metadata; no replay binding is minted.
    original_impl = provider_api._compile_provider_plan_impl
    try:
        provider_api._compile_provider_plan_impl = attacker_issuer
        attacker_issuer()
    finally:
        provider_api._compile_provider_plan_impl = original_impl

    forged = provider_api._plan_decision(
        plan=forged_plan,
        debts_value=(),
    )
    assert forged.ready is False
    replayed = validate_provider_plan(
        forged_plan,
        registry=production_registry,
        context=context,
        observed_identity=observed,
        allowed_license_classifications=("MIT",),
        source_manifest_authority=None,
    )
    assert replayed.ready is False
    assert replayed.structurally_valid is False

    raw = b'{"facts":[]}\n'
    result = _parsed_result(forged_plan, raw)
    with pytest.raises(
        ProgramFactsProviderAPIError,
        match="parent plan|authority",
    ):
        validate_provider_result(
            result,
            plan=forged_plan,
            raw_output=raw,
            registry=production_registry,
            context=context,
            observed_identity=observed,
            allowed_license_classifications=("MIT",),
            source_manifest_authority=None,
        )


def test_plan_decision_copy_object_new_and_concurrency_never_upgrade() -> None:
    registry, context, observed, plan = _structural_plan()
    decision = provider_api.compile_provider_plan(
        registry=registry,
        provider_id=plan.provider_id,
        provider_run_id=plan.provider_run_id,
        context=context,
        observed_identity=observed,
        argv=plan.argv,
        resources=plan.resources,
        allowed_license_classifications=("MIT",),
        source_manifest_authority=None,
    )
    assert decision.structurally_valid

    forged = object.__new__(provider_api.ProviderPlanDecision)
    for name in provider_api.ProviderPlanDecision.__slots__:
        if name != "__weakref__":
            object.__setattr__(forged, name, getattr(decision, name))
    object.__setattr__(forged, "_production_ready", True)
    object.__setattr__(
        forged,
        "_issuance_digest",
        forged._current_issuance_digest(),
    )

    def observe() -> tuple[bool, bool]:
        return forged.ready, forged.structurally_valid

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        outcomes = tuple(pool.map(lambda _: observe(), range(128)))
    assert outcomes == ((False, False),) * 128
    assert copy.copy(decision).ready is False


def test_plan_weak_identity_churn_never_reuses_authority() -> None:
    registry, context, observed, plan = _structural_plan()
    copied_plan = copy.copy(plan)
    assert provider_api._plan_authority_state(copied_plan) is None

    # Exercise weak-key cleanup and allocator churn while the non-issued copy
    # remains live.  It must never acquire another plan's issuance metadata.
    for index in range(128):
        current = provider_api.compile_provider_plan(
            registry=registry,
            provider_id=plan.provider_id,
            provider_run_id=f"fixture.compiler.run-{index + 1}",
            context=context,
            observed_identity=observed,
            argv=plan.argv,
            resources=plan.resources,
            allowed_license_classifications=("MIT",),
            source_manifest_authority=None,
        )
        assert current.structurally_valid
        del current
        if index % 32 == 0:
            gc.collect()

    assert provider_api._plan_authority_state(copied_plan) is None
    assert provider_api._plan_decision(
        plan=copied_plan,
        debts_value=(),
    ).ready is False
