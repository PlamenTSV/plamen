from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import hashlib

import pytest

from program_facts_provider_api import (
    CapabilityRequest,
    EnvironmentBinding,
    FactContribution,
    ObservedProviderIdentity,
    PlatformIdentity,
    ProgramFactsProviderAPIError,
    ProviderContext,
    ProviderPlan,
    ProviderResources,
    ProviderResult,
    ToolchainIdentity,
    compile_provider_plan,
    validate_fact_contribution,
    validate_provider_plan,
    validate_provider_result,
)
from program_facts_provider_registry import (
    ProviderPolicyDebtCode,
    STRUCTURAL_TEST_ONLY,
    load_program_facts_provider_registry_bytes,
)
from program_facts_types import canonical_file_bytes
from test_program_facts_provider_registry import (
    H0,
    H1,
    H2,
    H3,
    H5,
    synthetic_provider,
    synthetic_registry,
)


H6 = "6" * 64
H7 = "7" * 64
PFB = "PFB-" + "a" * 24


def _registry(*providers):
    return load_program_facts_provider_registry_bytes(
        canonical_file_bytes(synthetic_registry(*providers)),
        authority_mode=STRUCTURAL_TEST_ONLY,
    )


def _context(
    *,
    platform: PlatformIdentity | None = None,
    environment: tuple[EnvironmentBinding, ...] | None = None,
    maximum_precision: str = "EXACT",
) -> ProviderContext:
    return ProviderContext(
        audit_run_id="run-fixture-0",
        methodology_authority_digest=H7,
        snapshot_digest=H0,
        source_scope_digest=H1,
        source_manifest_digest=H2,
        source_authority_digest=H3,
        ecosystem="evm",
        languages=("solidity",),
        build_variant_ids=(PFB,),
        capability_requests=(
            CapabilityRequest("fixture.calls.v1", maximum_precision),
        ),
        toolchains=(ToolchainIdentity("solc", "0.8.28", H6),),
        platform=platform or PlatformIdentity("linux", "amd64"),
        environment=environment
        if environment is not None
        else (EnvironmentBinding("LANG", H7),),
        working_directory_root_id="root-0",
    )


def _observed(
    registry,
    *,
    platform: PlatformIdentity | None = None,
    checksum: str = H3,
    license_classification: str = "MIT",
) -> ObservedProviderIdentity:
    return ObservedProviderIdentity(
        registry_digest=registry.registry_digest,
        provider_schema_version=(
            "plamen.program_facts_provider.fixture.compiler.primary.v1"
        ),
        adapter_module="fixture_program_facts_provider",
        adapter_symbol="plan_fixture_provider",
        parser_callable="parse_fixture_raw",
        parser_source_digest=H1,
        raw_schema_digest=H0,
        tool_kind="EXECUTABLE",
        tool_name="fixture-tool",
        command="fixture-tool",
        module="",
        executable_sha256=H2,
        module_sha256="",
        distribution_kind="python-wheel",
        distribution_name="fixture-tool",
        distribution_version="1.2.3",
        distribution_checksum=checksum,
        distribution_module_source_digest="",
        version_output="fixture-tool 1.2.3",
        license_classification=license_classification,
        platform=platform or PlatformIdentity("linux", "amd64"),
        installation_mode="PREINSTALLED_VERIFIED",
        installation_lock_identity="rules/provider-fixture.lock",
        installation_lock_digest=H5,
    )


def _resources(**changes) -> ProviderResources:
    values = {
        "time_seconds": 60,
        "memory_bytes": 268435456,
        "input_bytes": 1048576,
        "output_bytes": 2097152,
    }
    values.update(changes)
    return ProviderResources(**values)


def _plan(
    *,
    registry=None,
    context=None,
    observed=None,
    allowed_licenses=("MIT",),
    resources=None,
):
    registry = registry or _registry()
    context = context or _context()
    observed = observed or _observed(registry, platform=context.platform)
    decision = compile_provider_plan(
        registry=registry,
        provider_id="fixture.compiler.primary",
        provider_run_id="fixture.compiler.run-0",
        context=context,
        observed_identity=observed,
        argv=("fixture-tool", "--json", "-"),
        resources=resources or _resources(),
        allowed_license_classifications=allowed_licenses,
        source_manifest_authority=None,
    )
    return registry, context, observed, decision


def _result(plan, raw: bytes = b'{"facts":[]}\n') -> ProviderResult:
    return ProviderResult(
        audit_run_id=plan.audit_run_id,
        methodology_authority_digest=plan.methodology_authority_digest,
        registry_digest=plan.registry_digest,
        context_digest=plan.context_digest,
        source_manifest_digest=plan.source_manifest_digest,
        source_authority_digest=plan.source_authority_digest,
        plan_id=plan.plan_id,
        provider_id=plan.provider_id,
        provider_run_id=plan.provider_run_id,
        result_state="PROVISIONAL_PARSED",
        raw_output_sha256=hashlib.sha256(raw).hexdigest(),
        raw_output_size=len(raw),
        raw_schema_digest=H0,
        parser_callable="parse_fixture_raw",
        parser_source_digest=H1,
        capabilities_parsed=("fixture.calls.v1",),
        capabilities_partial=(),
        capabilities_unavailable=(),
        capability_diagnostics=(),
    )


def test_context_and_plan_are_deterministic_exact_and_replayable() -> None:
    registry, context, observed, decision = _plan()
    assert decision.ready is False
    assert decision.structurally_valid is True
    assert {
        debt.code for debt in decision.debts
    } == {ProviderPolicyDebtCode.STRUCTURAL_TEST_ONLY}
    plan = decision.plan
    assert plan is not None
    assert ProviderContext.from_dict(context.to_dict()).canonical_bytes() == (
        context.canonical_bytes()
    )
    assert ProviderContext.from_bytes(context.canonical_bytes()).to_dict() == (
        context.to_dict()
    )
    assert ProviderPlan.from_dict(plan.to_dict()).canonical_bytes() == (
        plan.canonical_bytes()
    )
    assert ProviderPlan.from_bytes(plan.canonical_bytes()).to_dict() == (
        plan.to_dict()
    )
    assert b'"LANG"' in plan.canonical_bytes()
    assert b'"value"' not in plan.canonical_bytes()
    assert b"C:\\\\" not in plan.canonical_bytes()
    with pytest.raises(TypeError):
        plan.tool_identity["command"] = "drifted"

    replay = validate_provider_plan(
        plan.to_dict(),
        registry=registry,
        context=context,
        observed_identity=observed,
        allowed_license_classifications=("MIT",),
        source_manifest_authority=None,
    )
    assert replay.structurally_valid is True
    assert replay.plan.to_dict() == plan.to_dict()

    drifted = plan.to_dict()
    drifted["unknown"] = True
    with pytest.raises(ProgramFactsProviderAPIError, match="unknown|schema"):
        ProviderPlan.from_dict(drifted)
    with pytest.raises(ProgramFactsProviderAPIError, match="duplicate"):
        ProviderPlan.from_bytes(b'{"schema_version":"x","schema_version":"y"}')


def test_per_run_toolchain_identity_accepts_exact_context_and_binds_replay() -> None:
    provider = synthetic_provider()
    toolchain = provider["toolchain_ranges"][0]
    del toolchain["identity_digest"]
    toolchain["identity_policy"] = "RECEIPT_EXACT_PER_RUN"
    registry = _registry(provider)
    context = _context()
    observed = _observed(registry, platform=context.platform)

    decision = _plan(
        registry=registry,
        context=context,
        observed=observed,
    )[3]

    assert decision.structurally_valid is True
    assert decision.plan is not None
    assert decision.plan.toolchains == context.toolchains
    assert {
        debt.code for debt in decision.debts
    } == {ProviderPolicyDebtCode.STRUCTURAL_TEST_ONLY}

    drifted = replace(
        context,
        toolchains=(ToolchainIdentity("solc", "0.9.0", H6),),
    )
    rejected = _plan(
        registry=registry,
        context=drifted,
        observed=observed,
    )[3]
    assert rejected.plan is None
    assert ProviderPolicyDebtCode.UNSUPPORTED_TOOLCHAIN in {
        debt.code for debt in rejected.debts
    }


@pytest.mark.parametrize(
    "context, observed_factory, allowed_licenses, expected_codes",
    [
        (
            _context(platform=PlatformIdentity("macos", "arm64")),
            lambda registry: _observed(
                registry, platform=PlatformIdentity("macos", "arm64")
            ),
            ("MIT",),
            {
                ProviderPolicyDebtCode.UNSUPPORTED_OS,
                ProviderPolicyDebtCode.UNSUPPORTED_ARCHITECTURE,
            },
        ),
        (
            _context(platform=PlatformIdentity("linux", "arm64")),
            lambda registry: _observed(
                registry, platform=PlatformIdentity("linux", "arm64")
            ),
            ("MIT",),
            {ProviderPolicyDebtCode.UNSUPPORTED_ARCHITECTURE},
        ),
        (
            _context(),
            lambda registry: _observed(
                registry, license_classification="GPL-3.0-only"
            ),
            ("MIT",),
            {ProviderPolicyDebtCode.LICENSE_OR_DISTRIBUTION_RESTRICTED},
        ),
        (
            _context(),
            lambda registry: _observed(registry, checksum="9" * 64),
            ("MIT",),
            {ProviderPolicyDebtCode.DISTRIBUTION_CHECKSUM_MISMATCH},
        ),
    ],
)
def test_platform_license_and_checksum_mismatch_are_typed_blocking_debt(
    context, observed_factory, allowed_licenses, expected_codes
) -> None:
    registry = _registry()
    decision = _plan(
        registry=registry,
        context=context,
        observed=observed_factory(registry),
        allowed_licenses=allowed_licenses,
    )[3]

    assert decision.ready is False
    assert decision.plan is None
    codes = {debt.code for debt in decision.debts}
    assert expected_codes <= codes
    assert all(debt.blocks_reuse for debt in decision.debts)
    assert all(
        debt.terminal_negative_authority is False for debt in decision.debts
    )


@pytest.mark.parametrize(
    "changes, expected_code",
    [
        (
            {"registry_digest": "9" * 64},
            ProviderPolicyDebtCode.REGISTRY_DIGEST_MISMATCH,
        ),
        (
            {"adapter_module": "drifted_provider"},
            ProviderPolicyDebtCode.ADAPTER_BINDING_DRIFT,
        ),
        (
            {"parser_source_digest": "9" * 64},
            ProviderPolicyDebtCode.PARSER_DIGEST_DRIFT,
        ),
        (
            {"raw_schema_digest": "9" * 64},
            ProviderPolicyDebtCode.RAW_SCHEMA_DIGEST_DRIFT,
        ),
        (
            {"tool_name": "drifted-tool"},
            ProviderPolicyDebtCode.TOOL_IDENTITY_DRIFT,
        ),
        (
            {"executable_sha256": "9" * 64},
            ProviderPolicyDebtCode.EXECUTABLE_DIGEST_DRIFT,
        ),
        (
            {
                "distribution_version": "1.2.4",
                "version_output": "fixture-tool 1.2.4",
            },
            ProviderPolicyDebtCode.PROVIDER_VERSION_DRIFT,
        ),
        (
            {"installation_lock_digest": "9" * 64},
            ProviderPolicyDebtCode.INSTALL_POLICY_DRIFT,
        ),
    ],
)
def test_every_identity_binding_drift_is_typed_debt(
    changes, expected_code
) -> None:
    registry = _registry()
    context = _context()
    observed = replace(_observed(registry), **changes)
    decision = _plan(
        registry=registry,
        context=context,
        observed=observed,
    )[3]

    assert decision.ready is False
    assert expected_code in {debt.code for debt in decision.debts}


@pytest.mark.parametrize(
    "environment, expected_code",
    [
        (
            (
                EnvironmentBinding("API_TOKEN", H6, is_secret=True),
                EnvironmentBinding("LANG", H7),
            ),
            ProviderPolicyDebtCode.ENVIRONMENT_SECRET_FORBIDDEN,
        ),
        (
            (
                EnvironmentBinding("DEBUG", H6),
                EnvironmentBinding("LANG", H7),
            ),
            ProviderPolicyDebtCode.ENVIRONMENT_POLICY_BROADENING,
        ),
        (
            (),
            ProviderPolicyDebtCode.ENVIRONMENT_POLICY_BROADENING,
        ),
    ],
)
def test_environment_secret_extra_and_missing_required_are_never_clean(
    environment, expected_code
) -> None:
    registry = _registry()
    context = _context(environment=environment)
    decision = _plan(
        registry=registry,
        context=context,
        observed=_observed(registry, platform=context.platform),
    )[3]

    assert decision.ready is False
    assert expected_code in {debt.code for debt in decision.debts}


def test_capability_and_resource_overclaim_are_typed_debt() -> None:
    provider = synthetic_provider(maximum_precision="SYNTACTIC")
    registry = _registry(provider)
    context = _context(maximum_precision="EXACT")
    decision = _plan(
        registry=registry,
        context=context,
        observed=_observed(registry),
        resources=_resources(output_bytes=2097153),
    )[3]

    assert decision.ready is False
    assert {
        ProviderPolicyDebtCode.CAPABILITY_FIDELITY_OVERCLAIM,
        ProviderPolicyDebtCode.RESOURCE_POLICY_BROADENING,
    } <= {debt.code for debt in decision.debts}


def test_provider_result_is_provisional_exact_and_raw_byte_bound() -> None:
    registry, context, observed, decision = _plan()
    plan = decision.plan
    assert plan is not None
    raw = b'{"facts":[]}\n'
    result = _result(plan, raw)

    validated = validate_provider_result(
        result.to_dict(),
        plan=plan,
        raw_output=raw,
        registry=registry,
        context=context,
        observed_identity=observed,
        allowed_license_classifications=("MIT",),
        source_manifest_authority=None,
    )
    assert validated.to_dict() == result.to_dict()
    assert ProviderResult.from_dict(result.to_dict()).canonical_bytes() == (
        result.canonical_bytes()
    )
    assert ProviderResult.from_bytes(result.canonical_bytes()).to_dict() == (
        result.to_dict()
    )

    with pytest.raises(ProgramFactsProviderAPIError, match="raw output"):
        validate_provider_result(
            result,
            plan=plan,
            raw_output=b'{"facts":["tampered"]}\n',
            registry=registry,
            context=context,
            observed_identity=observed,
            allowed_license_classifications=("MIT",),
            source_manifest_authority=None,
        )


def test_caller_cannot_mint_success_completion_or_unknown_result_fields() -> None:
    plan = _plan()[3].plan
    assert plan is not None
    result = _result(plan)

    for field, value in (
        ("result_state", "SUCCESS"),
        ("completion_authority", "COMPLETED"),
        ("success", True),
    ):
        forged = result.to_dict()
        forged[field] = value
        with pytest.raises(
            ProgramFactsProviderAPIError,
            match="success|completion|unknown|state|schema",
        ):
            ProviderResult.from_dict(forged)


def _unknown_node(node_id: str, build_variant_id: str) -> dict[str, object]:
    return {
        "node_id": node_id,
        "kind": "UNKNOWN_TARGET",
        "qualified_name": f"unknown::{node_id}",
        "display_name": "unknown",
        "build_variant_id": build_variant_id,
        "signature": {
            "canonical": "",
            "language_specific": {},
            "signature_fact_ref": "",
        },
        "attributes": [],
        "reason": "synthetic fixture target",
    }


def _fact(
    *,
    plan,
    precision: str,
) -> dict[str, object]:
    return {
        "fact_id": "PFF-" + "c" * 24,
        "relation_kind": "RESOLVED_STATIC_CALL",
        "subject_id": "PFN-" + "a" * 24,
        "object_id": "PFN-" + "b" * 24,
        "occurrence_ids": [],
        "build_variant_id": PFB,
        "provider_run_id": plan.provider_run_id,
        "capability_id": "fixture.calls.v1",
        "provenance_origin": "AST",
        "precision": precision,
        "coverage_scope": "FUNCTION",
        "structural_confidence": (
            "PROVIDER_EXACT" if precision == "EXACT" else "SOURCE_FALLBACK"
        ),
        "context": {
            "call_dispatch": "UNKNOWN",
            "analysis_algorithm": "",
            "root_set_digest": "",
            "dominating_predicates": [],
            "host_semantic_kind": "",
        },
        "semantic_authority": "ADDITIVE_PROPOSAL_ONLY",
        "attestations": [plan.provider_run_id],
    }


def _contribution(plan, result, *, precision: str) -> FactContribution:
    fact = _fact(plan=plan, precision=precision)
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
        build_variant_ids=(PFB,),
        capability_ids=("fixture.calls.v1",),
        nodes=(
            _unknown_node("PFN-" + "a" * 24, PFB),
            _unknown_node("PFN-" + "b" * 24, PFB),
        ),
        occurrences=(),
        facts=(fact,),
        debt_codes=(),
        capability_accounting=(
            {
                "capability_id": "fixture.calls.v1",
                "disposition": "PARSED",
                "emitted_fact_ids": [fact["fact_id"]],
                "debt_codes": [],
            },
        ),
    )


def test_fact_contribution_replays_exact_rows_and_stays_provisional() -> None:
    registry, context_value, observed_value, decision = _plan()
    plan = decision.plan
    assert plan is not None
    result = validate_provider_result(
        _result(plan),
        plan=plan,
        raw_output=b'{"facts":[]}\n',
        registry=registry,
        context=context_value,
        observed_identity=observed_value,
        allowed_license_classifications=("MIT",),
        source_manifest_authority=None,
    )
    contribution = _contribution(plan, result, precision="EXACT")

    validated = validate_fact_contribution(
        contribution.to_dict(),
        plan=plan,
        result=result,
        registry=registry,
        context=context_value,
        observed_identity=observed_value,
        raw_output=b'{"facts":[]}\n',
        allowed_license_classifications=("MIT",),
        source_manifest_authority=None,
    )
    assert validated.to_dict() == contribution.to_dict()
    assert FactContribution.from_bytes(
        contribution.canonical_bytes()
    ).to_dict() == contribution.to_dict()
    assert (
        validated.to_dict()["completion_authority"]
        == "PROVISIONAL_NO_PUBLICATION_AUTHORITY"
    )
    with pytest.raises(TypeError):
        validated.facts[0]["precision"] = "SYNTACTIC"
    forged = contribution.to_dict()
    forged["authority"]["can_certify_clean"] = True
    with pytest.raises(ProgramFactsProviderAPIError, match="authority"):
        FactContribution.from_dict(forged)


def test_fact_contribution_cannot_overclaim_capability_precision() -> None:
    provider = synthetic_provider(maximum_precision="SYNTACTIC")
    registry = _registry(provider)
    context = _context(maximum_precision="SYNTACTIC")
    plan = _plan(
        registry=registry,
        context=context,
        observed=_observed(registry),
    )[3].plan
    assert plan is not None
    result = validate_provider_result(
        _result(plan),
        plan=plan,
        raw_output=b'{"facts":[]}\n',
        registry=registry,
        context=context,
        observed_identity=_observed(registry),
        allowed_license_classifications=("MIT",),
        source_manifest_authority=None,
    )
    contribution = _contribution(plan, result, precision="EXACT")

    with pytest.raises(
        ProgramFactsProviderAPIError, match="precision.*registry|fidelity"
    ):
        validate_fact_contribution(
            contribution,
            plan=plan,
            result=result,
            registry=registry,
            context=context,
            observed_identity=_observed(registry),
            raw_output=b'{"facts":[]}\n',
            allowed_license_classifications=("MIT",),
            source_manifest_authority=None,
        )


def test_fact_contribution_rejects_unknown_fields_and_dangling_references() -> None:
    registry, context_value, observed_value, decision = _plan()
    plan = decision.plan
    assert plan is not None
    result = _result(plan)
    contribution = _contribution(plan, result, precision="EXACT")

    forged = contribution.to_dict()
    forged["facts"][0]["unknown"] = True
    with pytest.raises(ProgramFactsProviderAPIError, match="schema violation"):
        FactContribution.from_dict(forged)

    forged = contribution.to_dict()
    forged["facts"][0]["subject_id"] = "PFN-" + "d" * 24
    forged = FactContribution(
        audit_run_id=forged["audit_run_id"],
        methodology_authority_digest=forged[
            "methodology_authority_digest"
        ],
        registry_digest=forged["registry_digest"],
        context_digest=forged["context_digest"],
        source_manifest_digest=forged["source_manifest_digest"],
        source_authority_digest=forged["source_authority_digest"],
        plan_id=forged["plan_id"],
        result_digest=forged["result_digest"],
        provider_id=forged["provider_id"],
        provider_run_id=forged["provider_run_id"],
        build_variant_ids=tuple(forged["build_variant_ids"]),
        capability_ids=tuple(forged["capability_ids"]),
        nodes=tuple(forged["nodes"]),
        occurrences=tuple(forged["occurrences"]),
        facts=tuple(forged["facts"]),
        debt_codes=tuple(forged["debt_codes"]),
        capability_accounting=tuple(forged["capability_accounting"]),
    )
    with pytest.raises(ProgramFactsProviderAPIError, match="dangling"):
        validate_fact_contribution(
            forged,
            plan=plan,
            result=result,
            registry=registry,
            context=context_value,
            observed_identity=observed_value,
            raw_output=b'{"facts":[]}\n',
            allowed_license_classifications=("MIT",),
            source_manifest_authority=None,
        )
