from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import hashlib

import pytest

from program_facts_evm_provider import (
    EVM_CAPABILITY_IDS,
    EvmNormalizationOutcome,
    EvmProgramFactsProviderError,
    emit_evm_unavailable_sidecars,
    normalize_evm_slither,
    parse_evm_slither_raw,
    plan_evm_slither,
)
from program_facts_provider_api import (
    FactContribution,
    ProgramFactsProviderAPIError,
    ProviderResources,
    ZeroPositiveAccounting,
    validate_fact_contribution,
)
from program_facts_types import canonical_json_bytes
from test_program_facts_evm_provider_stage2 import (
    H0,
    H1,
    H2,
    H7,
    SOURCE,
    _context as _evm_context,
    _observed as _evm_observed,
    _plan as _evm_plan,
    _raw_bytes,
    _registry as _evm_registry,
    _source,
    _source_manifest,
    _variant,
)
from test_program_facts_provider_api import (
    PFB,
    _context as _api_context,
    _plan as _api_plan,
    _result as _api_result,
)


PFB_SECOND = "PFB-" + "b" * 24
API_RAW = b'{"facts":[],"nodes":[]}\n'


def _zero_contribution_for_variants(plan, result) -> FactContribution:
    variant_ids = tuple(sorted(plan.build_variant_ids))
    zero = ZeroPositiveAccounting(
        capability_id="fixture.calls.v1",
        result_digest=result.result_digest,
        source_authority_digest=result.source_authority_digest,
        denominators=tuple(
            {
                "build_variant_id": variant_id,
                "denominator_kind": "fixture.call_sites.v1",
                "denominator_ids": [],
            }
            for variant_id in variant_ids
        ),
    )
    return FactContribution(
        audit_run_id=plan.audit_run_id,
        methodology_authority_digest=plan.methodology_authority_digest,
        registry_digest=plan.registry_digest,
        context_digest=plan.context_digest,
        source_manifest_digest=plan.source_manifest_digest,
        source_authority_digest=plan.source_authority_digest,
        plan_id=plan.plan_id,
        result_digest=result.result_digest,
        provider_id=plan.provider_id,
        provider_run_id=plan.provider_run_id,
        build_variant_ids=variant_ids,
        capability_ids=("fixture.calls.v1",),
        nodes=(),
        occurrences=(),
        facts=(),
        debt_codes=(),
        capability_accounting=(
            {
                "capability_id": "fixture.calls.v1",
                "disposition": "PARSED",
                "emitted_fact_ids": [],
                "debt_codes": [],
                "zero_positive_accounting": zero.to_dict(),
            },
        ),
    )


def _validate_zero_contribution(contribution, *, registry, context, observed, plan, result):
    return validate_fact_contribution(
        contribution,
        plan=plan,
        result=result,
        registry=registry,
        context=context,
        observed_identity=observed,
        raw_output=API_RAW,
        allowed_license_classifications=("MIT",),
        source_manifest_authority=None,
    )


def _second_evm_variant() -> dict[str, object]:
    first = _variant()
    semantic = {
        key: deepcopy(value)
        for key, value in first.items()
        if key not in {"build_variant_id", "variant_digest"}
    }
    semantic["profile"] = "checkpoint-a-second"
    digest = hashlib.sha256(canonical_json_bytes(semantic)).hexdigest()
    return {
        "build_variant_id": f"PFB-{digest[:24]}",
        **semantic,
        "variant_digest": digest,
    }


def _audit_snapshot() -> dict[str, object]:
    return {
        "snapshot_digest": H0,
        "source_scope_digest": H1,
        "audit_config_digest": H0,
        "methodology_digest": H7,
        "toolchain_digest": H2,
    }


def _phase_io() -> dict[str, object]:
    return {
        "contract_digest": H0,
        "launch_digest": H1,
        "input_set_digest": H2,
        "work_unit_key": (
            "sc/thorough/evm/claude/recon/program_facts_bake"
        ),
        "ledger_binding_state": "PRECOMMIT",
        "ledger_record_digest": "",
    }


def test_multi_build_variant_zero_accounting_requires_the_exact_matrix() -> None:
    context = replace(
        _api_context(),
        build_variant_ids=tuple(sorted((PFB, PFB_SECOND))),
    )
    registry, context, observed, decision = _api_plan(context=context)
    plan = decision.plan
    assert decision.structurally_valid is True
    assert plan is not None
    result = _api_result(plan, API_RAW)
    contribution = _zero_contribution_for_variants(plan, result)

    accepted = _validate_zero_contribution(
        contribution,
        registry=registry,
        context=context,
        observed=observed,
        plan=plan,
        result=result,
    )
    zero = accepted.capability_accounting[0]["zero_positive_accounting"]
    assert tuple(
        row["build_variant_id"] for row in zero["denominators"]
    ) == tuple(sorted((PFB, PFB_SECOND)))

    missing = ZeroPositiveAccounting(
        capability_id="fixture.calls.v1",
        result_digest=result.result_digest,
        source_authority_digest=result.source_authority_digest,
        denominators=(
            {
                "build_variant_id": PFB,
                "denominator_kind": "fixture.call_sites.v1",
                "denominator_ids": [],
            },
        ),
    )
    wire = contribution.to_dict()
    wire["capability_accounting"][0][
        "zero_positive_accounting"
    ] = missing.to_dict()
    forged = replace(
        contribution,
        capability_accounting=tuple(wire["capability_accounting"]),
    )
    with pytest.raises(
        ProgramFactsProviderAPIError,
        match="build-variant denominator.*total",
    ):
        _validate_zero_contribution(
            forged,
            registry=registry,
            context=context,
            observed=observed,
            plan=plan,
            result=result,
        )


def test_unavailable_multi_build_matrix_is_total_unique_and_non_authorizing() -> None:
    first = _variant()
    second = _second_evm_variant()
    variants = [first, second]
    variant_ids = tuple(
        sorted(str(row["build_variant_id"]) for row in variants)
    )
    context = replace(_evm_context(), build_variant_ids=variant_ids)
    snapshot = _audit_snapshot()
    phase_io = _phase_io()
    source_manifest = _source_manifest()
    source_id = str(_source()["source_file_id"])
    source_bytes = {source_id: SOURCE}

    emission = emit_evm_unavailable_sidecars(
        context=context,
        source_manifest=source_manifest,
        source_bytes_by_id=source_bytes,
        build_variants=variants,
        audit_snapshot=snapshot,
        phase_io=phase_io,
        reason="ANALYSIS_TIMEOUT",
        explanation="Checkpoint-A multi-variant unavailable fixture.",
    )
    before = dict(emission.sidecars)
    expected_pairs = {
        (capability_id, variant_id)
        for capability_id in EVM_CAPABILITY_IDS
        for variant_id in variant_ids
    }
    coverage_pairs = {
        (str(row["capability_id"]), str(row["build_variant_id"]))
        for row in emission.payload["coverage"]
    }
    debt_pairs = {
        (str(row["capability_id"]), str(row["build_variant_id"]))
        for row in emission.debt["debts"]
        if row["provider_id"]
    }
    assert coverage_pairs == expected_pairs
    assert debt_pairs == expected_pairs
    assert len(emission.payload["coverage"]) == len(expected_pairs)
    assert len(
        [row for row in emission.debt["debts"] if row["provider_id"]]
    ) == len(expected_pairs)
    assert {row["status"] for row in emission.payload["coverage"]} == {
        "UNKNOWN"
    }
    assert emission.receipt["status"] == "FAILED"
    assert emission.production_authority_established is False
    assert emission.consumer_activation is False

    variants[0]["profile"] = "late-mutation"
    snapshot["snapshot_digest"] = "f" * 64
    phase_io["ledger_binding_state"] = "COMMITTED"
    source_manifest["eligible_files"][0]["source_sha256"] = "f" * 64
    source_bytes[source_id] = b"contract Mutated {}\n"
    assert dict(emission.sidecars) == before


def test_evm_parser_contract_stays_one_variant_per_provisional_plan() -> None:
    first = _variant()
    second = _second_evm_variant()
    context = replace(
        _evm_context(),
        build_variant_ids=tuple(
            sorted(
                (
                    str(first["build_variant_id"]),
                    str(second["build_variant_id"]),
                )
            )
        ),
    )
    registry = _evm_registry()
    observed = _evm_observed(registry, context)
    with pytest.raises(
        EvmProgramFactsProviderError,
        match="one build variant",
    ):
        plan_evm_slither(
            registry=registry,
            provider_run_id="evm.slither.typed.run-checkpoint-a",
            context=context,
            observed_identity=observed,
            argv=("slither", "--json", "-"),
            resources=ProviderResources(
                time_seconds=600,
                memory_bytes=1073741824,
                input_bytes=1048576,
                output_bytes=1048576,
            ),
            allowed_license_classifications=("AGPL-3.0-only",),
            source_manifest_authority=None,
        )


def test_normalization_and_composer_facing_carrier_break_nested_aliases() -> None:
    registry, context, observed, plan = _evm_plan()
    raw = _raw_bytes(plan)
    carrier = parse_evm_slither_raw(raw, plan)
    manifest = _source_manifest()
    source_id = str(_source()["source_file_id"])
    source_bytes = {source_id: SOURCE}

    outcome = normalize_evm_slither(
        carrier,
        raw=raw,
        plan=plan,
        registry=registry,
        context=context,
        observed_identity=observed,
        source_manifest=manifest,
        source_bytes_by_id=source_bytes,
        allowed_license_classifications=("AGPL-3.0-only",),
        source_manifest_authority=None,
    )
    outcome_before = outcome.canonical_bytes()
    wire = outcome.to_dict()
    replayed = EvmNormalizationOutcome.from_dict(wire)
    replayed_before = replayed.canonical_bytes()

    manifest["eligible_files"][0]["source_sha256"] = "f" * 64
    source_bytes[source_id] = b"contract LateMutation {}\n"
    wire["denominator_decisions"][0]["expected_source_file_ids"].clear()
    wire["contribution"]["facts"][0]["context"][
        "dominating_predicates"
    ].append("forged")
    wire["original_carrier"]["parsed_payload"]["facts"].clear()

    assert outcome.canonical_bytes() == outcome_before
    assert replayed.canonical_bytes() == replayed_before
    assert replayed.to_dict() != wire
