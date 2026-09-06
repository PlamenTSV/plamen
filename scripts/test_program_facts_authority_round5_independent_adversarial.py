"""Independent R5 adversarial probes for Program Facts plan authority."""

from __future__ import annotations

import copy
from collections.abc import Iterator

import pytest

import program_facts_provider_api as provider_api
from test_program_facts_registry_api_authority_blockers import (
    _capture_and_load,
    _structural_plan,
)


@pytest.fixture
def _tcb_mutation_exploit_result() -> Iterator[bool]:
    """Prepare the TCB-code-mutation exploit outside the expected failure."""

    compiler_cell = None
    honest_compiler = None
    original_impl = provider_api._compile_provider_plan_impl

    try:
        try:
            _structural_registry, context, observed, structural_plan = (
                _structural_plan()
            )
            _authority, production_registry = _capture_and_load()
            forged_plan = copy.copy(structural_plan)
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
            decision = provider_api._plan_decision(
                plan=forged_plan,
                debts_value=(),
                replay_binding=binding,
                candidate_state=provider_api.INSTALLED_PRODUCTION_AUTHORITY,
            )
            holder["decision"] = decision
            if decision.ready is not False:
                raise RuntimeError(
                    "exploit precondition failed: the unmodified semantic "
                    "replayer accepted the forged decision"
                )

            replayer = provider_api._replay_plan_decision_authority
            closure = dict(
                zip(replayer.__code__.co_freevars, replayer.__closure__)
            )
            compiler_cell = closure["semantic_compiler"]
            honest_compiler = compiler_cell.cell_contents

            def reflected_compiler(**kwargs):
                del kwargs
                return provider_api._ProviderPlanSemanticReplay(
                    plan=decision.plan,
                    debts=decision.debts,
                    authority_state=(
                        provider_api.INSTALLED_PRODUCTION_AUTHORITY
                    ),
                )

            compiler_cell.cell_contents = reflected_compiler
            if compiler_cell.cell_contents is not reflected_compiler:
                raise RuntimeError(
                    "exploit precondition failed: semantic compiler closure "
                    "cell was not replaced"
                )
            mutated_ready = decision.ready
        except AssertionError as exc:
            raise RuntimeError(
                "TCB mutation exploit setup raised an unexpected assertion"
            ) from exc

        yield mutated_ready
    finally:
        if compiler_cell is not None and honest_compiler is not None:
            compiler_cell.cell_contents = honest_compiler
        provider_api._compile_provider_plan_impl = original_impl


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason=provider_api.TCB_CODE_MUTATION_DISPOSITION,
)
def test_lexically_captured_semantic_compiler_is_not_reflection_mutable(
    _tcb_mutation_exploit_result: bool,
) -> None:
    """Document that rewriting TCB closure code defeats a Python-only gate."""

    assert _tcb_mutation_exploit_result is False
