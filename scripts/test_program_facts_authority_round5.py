"""PF-AUTH-01 R5 intact-TCB semantic-replay regression.

Module-global monkeypatching here is defense-in-depth fault injection.  It does
not claim resistance to arbitrary mutation of loaded code or closure cells
inside the Python orchestrator TCB.
"""

from __future__ import annotations

import copy

import program_facts_provider_api as provider_api
from test_program_facts_registry_api_authority_blockers import (
    _capture_and_load,
    _structural_plan,
)


def test_mutable_compiler_record_and_replay_binding_cannot_mint_ready() -> None:
    """Keep the malicious compiler installed through readiness and the sink."""

    _structural_registry, context, observed, structural_plan = (
        _structural_plan()
    )
    _authority, production_registry = _capture_and_load()
    forged_plan = copy.copy(structural_plan)
    original_impl = provider_api._compile_provider_plan_impl
    original_replayer = provider_api._replay_plan_decision_authority
    original_source_parent_validator = (
        provider_api._validate_source_manifest_parent
    )
    holder: dict[str, object | None] = {"decision": None}

    def attacker_impl(**kwargs):
        del kwargs
        if holder["decision"] is None:
            provider_api._record_compiled_plan(
                forged_plan,
                registry=production_registry,
                structural_test_only=False,
            )
            return None
        return holder["decision"]

    try:
        provider_api._compile_provider_plan_impl = attacker_impl
        attacker_impl()
        binding = provider_api._PlanReplayBinding(
            registry=production_registry,
            provider_id=forged_plan.provider_id,
            provider_run_id=forged_plan.provider_run_id,
            context=context,
            observed_identity=observed,
            argv=forged_plan.argv,
            resources=forged_plan.resources,
            allowed_license_classifications=("MIT",),
            source_manifest_authority=None,
            audit_snapshot_authority=None,
            source_project_root=None,
            source_config=None,
            expected_source_ledger_binding=None,
            observed_configuration_inputs=(),
            fallback_from_provider_id=forged_plan.fallback_from_provider_id,
        )
        holder["decision"] = provider_api._plan_decision(
            plan=forged_plan,
            debts_value=(),
            replay_binding=binding,
        )
        assert (
            provider_api._plan_authority_state(forged_plan)
            == provider_api.INSTALLED_PRODUCTION_AUTHORITY
        )
        assert holder["decision"].ready is False

        sink = provider_api.validate_provider_plan(
            forged_plan,
            registry=production_registry,
            context=context,
            observed_identity=observed,
            allowed_license_classifications=("MIT",),
            source_manifest_authority=None,
        )
        assert sink.ready is False
        assert sink.structurally_valid is False

        provider_api._replay_plan_decision_authority = (
            lambda _decision: provider_api.INSTALLED_PRODUCTION_AUTHORITY
        )
        provider_api._validate_source_manifest_parent = (
            lambda *_args, **_kwargs: True
        )
        assert holder["decision"].ready is False
        assert sink.ready is False
    finally:
        provider_api._compile_provider_plan_impl = original_impl
        provider_api._replay_plan_decision_authority = original_replayer
        provider_api._validate_source_manifest_parent = (
            original_source_parent_validator
        )
