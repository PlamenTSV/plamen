"""PF-AUTH-01 R6 trust-boundary and untrusted-data regressions."""

from __future__ import annotations

import copy
from types import MappingProxyType

import pytest

import program_facts_provider_api as provider_api
from test_program_facts_registry_api_authority_blockers import (
    _capture_and_load,
    _structural_plan,
)


def test_program_facts_tcb_boundary_is_exact_and_explicit() -> None:
    boundary = provider_api.PROGRAM_FACTS_TRUST_BOUNDARY
    assert isinstance(boundary, MappingProxyType)
    assert set(boundary) == {
        "schema_version",
        "trusted_computing_base",
        "untrusted_surfaces",
        "out_of_threat_model",
        "required_external_controls",
    }
    assert boundary["schema_version"] == (
        "plamen.program_facts_trust_boundary.v1"
    )
    assert set(boundary["trusted_computing_base"]) == {
        "python_orchestrator_process",
        "python_interpreter_and_loaded_dependencies",
        "loaded_code_objects_and_closure_cells",
        "installed_methodology_files_and_exact_capture",
        "deterministic_gate_and_semantic_replay_code",
    }
    assert set(boundary["untrusted_surfaces"]) == {
        "worker_process_outputs",
        "provider_process_outputs",
        "model_outputs",
        "configuration_bytes",
        "artifact_and_protocol_bytes",
        "reflection_constructed_data_carriers",
    }
    assert set(boundary["out_of_threat_model"]) == {
        "arbitrary_code_execution_inside_the_tcb",
        "loaded_code_or_closure_cell_mutation",
        "interpreter_or_gate_code_replacement",
    }
    assert set(boundary["required_external_controls"]) == {
        "os_process_isolation",
        "code_and_package_integrity",
        "installed_methodology_access_control",
    }
    assert provider_api.TCB_CODE_MUTATION_DISPOSITION == (
        "OUT_OF_THREAT_MODEL_TCB_CODE_MUTATION_REQUIRES_OS_PROCESS_INTEGRITY"
    )
    with pytest.raises(TypeError):
        boundary["out_of_threat_model"] = ()


def test_untrusted_serialized_and_reflected_values_cannot_mint_ready() -> None:
    structural_registry, context, observed, structural_plan = (
        _structural_plan()
    )
    _authority, production_registry = _capture_and_load()

    serialized_plan = provider_api.ProviderPlan.from_bytes(
        structural_plan.canonical_bytes()
    )
    replayed = provider_api.validate_provider_plan(
        serialized_plan,
        registry=production_registry,
        context=context,
        observed_identity=observed,
        allowed_license_classifications=("MIT",),
        source_manifest_authority=None,
    )
    assert replayed.ready is False
    assert replayed.structurally_valid is False

    tampered = serialized_plan.to_dict()
    tampered["completion_authority"] = "FORGED_COMPLETE"
    with pytest.raises(
        provider_api.ProgramFactsProviderAPIError,
        match="completion authority",
    ):
        provider_api.ProviderPlan.from_dict(tampered)

    structural_decision = provider_api.compile_provider_plan(
        registry=structural_registry,
        provider_id=structural_plan.provider_id,
        provider_run_id=structural_plan.provider_run_id,
        context=context,
        observed_identity=observed,
        argv=structural_plan.argv,
        resources=structural_plan.resources,
        allowed_license_classifications=("MIT",),
        source_manifest_authority=None,
    )
    assert structural_decision.structurally_valid
    reflected = object.__new__(provider_api.ProviderPlanDecision)
    for name in provider_api.ProviderPlanDecision.__slots__:
        if name != "__weakref__":
            object.__setattr__(
                reflected,
                name,
                copy.copy(getattr(structural_decision, name)),
            )
    object.__setattr__(reflected, "_production_ready", True)
    object.__setattr__(
        reflected,
        "_issuance_digest",
        reflected._current_issuance_digest(),
    )
    assert reflected.ready is False
    assert reflected.structurally_valid is False
