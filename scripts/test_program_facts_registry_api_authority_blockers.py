from __future__ import annotations

import copy
from copy import deepcopy
import hashlib
import json
from types import MappingProxyType

import pytest

from audit_snapshot import (
    SNAPSHOT_SCHEMA,
    build_methodology_snapshot_component,
)
from program_facts_methodology_authority import (
    PROGRAM_FACTS_METHODOLOGY_INPUT_PATHS,
    InstalledMethodologyAuthority,
    ProgramFactsMethodologyAuthorityError,
    capture_installed_program_facts_methodology_authority,
)
from program_facts_provider_api import (
    CapabilityRequest,
    EnvironmentBinding,
    FactContribution,
    ObservedProviderIdentity,
    PlatformIdentity,
    ProgramFactsProviderAPIError,
    ProviderContext,
    ProviderPlan,
    ProviderPlanDecision,
    ProviderResources,
    ProviderResult,
    ToolchainIdentity,
    compile_provider_plan,
    validate_fact_contribution,
    validate_provider_plan,
    validate_provider_result,
)
from program_facts_provider_registry import (
    LoadedProgramFactsProviderRegistry,
    ProgramFactsProviderRegistryError,
    ProviderPolicyDebt,
    ProviderPolicyDebtCode,
    ProviderRegistryDecision,
    STRUCTURAL_TEST_ONLY,
    load_program_facts_provider_registry,
    load_program_facts_provider_registry_bytes,
)
from program_facts_source_manifest import (
    ParsedProgramFactsSourceManifest,
)
from program_facts_types import canonical_file_bytes, canonical_json_bytes
from test_program_facts_provider_registry import (
    H0,
    H1,
    H2,
    H3,
    H5,
    synthetic_registry,
    synthetic_provider,
)


H6 = "6" * 64
H7 = "7" * 64
PFB = "PFB-" + "a" * 24
RUN_ID = "12345678-1234-4234-8234-123456789abc"


def _audit_snapshot() -> dict[str, object]:
    root = __file__
    implementation_root = __import__("pathlib").Path(root).resolve().parents[1]
    unsigned = {
        "schema": SNAPSHOT_SCHEMA,
        "components": {
            "source_scope": {
                "digest": H1,
                "path_set_digest": H2,
                "file_count": 1,
                "byte_count": 1,
                "language": "solidity",
                "pipeline": "sc",
                "git_head": "UNAVAILABLE",
                "coverage_limitations": [],
            },
            "audit_config": {"digest": H3, "field_count": 1},
            "methodology": build_methodology_snapshot_component(
                implementation_root
            ),
            "toolchain": {
                "digest": H5,
                "path_set_digest": H6,
                "file_count": 1,
                "byte_count": 1,
            },
        },
    }
    return {
        **unsigned,
        "snapshot_digest": hashlib.sha256(
            canonical_json_bytes(unsigned)
        ).hexdigest(),
    }


def _capture_and_load():
    authority = capture_installed_program_facts_methodology_authority(
        canonical_file_bytes(
            {"audit_snapshot": _audit_snapshot(), "run_id": RUN_ID}
        )
    )
    registry = load_program_facts_provider_registry(
        installed_authority=authority
    )
    return authority, registry


def _structural_registry():
    return load_program_facts_provider_registry_bytes(
        canonical_file_bytes(synthetic_registry()),
        authority_mode=STRUCTURAL_TEST_ONLY,
    )


def _context(
    *,
    methodology_authority_digest: str = H7,
    source_manifest_digest: str = H2,
    maximum_precision: str = "EXACT",
    toolchains: tuple[ToolchainIdentity, ...] | None = None,
) -> ProviderContext:
    return ProviderContext(
        audit_run_id=RUN_ID,
        methodology_authority_digest=methodology_authority_digest,
        snapshot_digest=H0,
        source_scope_digest=H1,
        source_manifest_digest=source_manifest_digest,
        source_authority_digest=H3,
        ecosystem="evm",
        languages=("solidity",),
        build_variant_ids=(PFB,),
        capability_requests=(
            CapabilityRequest("fixture.calls.v1", maximum_precision),
        ),
        toolchains=toolchains
        or (ToolchainIdentity("solc", "0.8.28", H6),),
        platform=PlatformIdentity("linux", "amd64"),
        environment=(EnvironmentBinding("LANG", H7),),
        working_directory_root_id="root-0",
    )


def _observed(registry) -> ObservedProviderIdentity:
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
        distribution_checksum=H3,
        distribution_module_source_digest="",
        version_output="fixture-tool 1.2.3",
        license_classification="MIT",
        platform=PlatformIdentity("linux", "amd64"),
        installation_mode="PREINSTALLED_VERIFIED",
        installation_lock_identity="rules/provider-fixture.lock",
        installation_lock_digest=H5,
    )


def _resources() -> ProviderResources:
    return ProviderResources(
        time_seconds=60,
        memory_bytes=268435456,
        input_bytes=1048576,
        output_bytes=2097152,
    )


def _structural_plan(*, maximum_precision: str = "EXACT"):
    registry = _structural_registry()
    context = _context(maximum_precision=maximum_precision)
    observed = _observed(registry)
    decision = compile_provider_plan(
        registry=registry,
        provider_id="fixture.compiler.primary",
        provider_run_id="fixture.compiler.run-0",
        context=context,
        observed_identity=observed,
        argv=("fixture-tool", "--json", "-"),
        resources=_resources(),
        allowed_license_classifications=("MIT",),
        source_manifest_authority=None,
    )
    assert decision.structurally_valid
    assert decision.plan is not None
    return registry, context, observed, decision.plan


def _parsed_result(plan: ProviderPlan, raw: bytes) -> ProviderResult:
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
        raw_schema_digest=plan.raw_binding["raw_schema_digest"],
        parser_callable=plan.raw_binding["parser_callable"],
        parser_source_digest=plan.raw_binding["parser_source_digest"],
        capabilities_parsed=("fixture.calls.v1",),
        capabilities_partial=(),
        capabilities_unavailable=(),
        capability_diagnostics=(),
    )


def test_installed_methodology_capture_is_one_shot_exact_and_phaseio_shaped() -> None:
    authority, registry = _capture_and_load()
    assert isinstance(authority, InstalledMethodologyAuthority)
    assert registry.production_authority_established is True
    assert tuple(registry.phase_io_input_bytes) == (
        PROGRAM_FACTS_METHODOLOGY_INPUT_PATHS
    )
    assert all(
        raw.endswith(b"\n")
        for raw in registry.phase_io_input_bytes.values()
    )
    with pytest.raises(
        ProgramFactsProviderRegistryError, match="one-shot|consumed"
    ):
        load_program_facts_provider_registry(installed_authority=authority)


def test_arbitrary_bytes_direct_constructors_and_duck_types_cannot_mint_ready() -> None:
    structural = _structural_registry()
    assert structural.production_authority_established is False
    assert structural.provider("fixture.compiler.primary").ready is False

    with pytest.raises((TypeError, AttributeError)):
        LoadedProgramFactsProviderRegistry()
    with pytest.raises(TypeError):
        ProviderPolicyDebt(
            ProviderPolicyDebtCode.UNKNOWN_PROVIDER,
            "fixture.compiler.primary",
            blocks_reuse=False,
            terminal_negative_authority=True,
        )
    with pytest.raises(TypeError):
        ProviderRegistryDecision({}, ())
    with pytest.raises(TypeError):
        ProviderPlanDecision(None, ())

    class Duck:
        registry_digest = structural.registry_digest
        providers = structural.providers

        @property
        def __class__(self):
            return LoadedProgramFactsProviderRegistry

    with pytest.raises(
        ProgramFactsProviderAPIError, match="installed|authority|registry"
    ):
        compile_provider_plan(
            registry=Duck(),
            provider_id="fixture.compiler.primary",
            provider_run_id="fixture.compiler.run-0",
            context=_context(),
            observed_identity=_observed(structural),
            argv=("fixture-tool", "--json", "-"),
            resources=_resources(),
            allowed_license_classifications=("MIT",),
            source_manifest_authority=None,
        )


def test_structural_registry_cannot_compile_and_unreviewed_argv_is_debt() -> None:
    registry = _structural_registry()
    for argv, structurally_valid in (
        (("fixture-tool", "--json", "-"), True),
        ((
            "fixture-tool",
            "--json",
            "-",
            "--config=unreviewed.json",
            "--ignore-all",
        ), False),
    ):
        decision = compile_provider_plan(
            registry=registry,
            provider_id="fixture.compiler.primary",
            provider_run_id="fixture.compiler.run-0",
            context=_context(),
            observed_identity=_observed(registry),
            argv=argv,
            resources=_resources(),
            allowed_license_classifications=("MIT",),
            source_manifest_authority=None,
        )
        assert decision.ready is False
        assert decision.structurally_valid is structurally_valid
        assert (decision.plan is not None) is structurally_valid
        assert decision.debts


def test_toolchain_digest_and_exact_denominator_are_reviewed() -> None:
    value = synthetic_registry()
    for toolchains in (
        (ToolchainIdentity("solc", "0.8.28", H7),),
        (
            ToolchainIdentity("rustc", "1.80.0", H7),
            ToolchainIdentity("solc", "0.8.28", H6),
        ),
    ):
        registry = load_program_facts_provider_registry_bytes(
            canonical_file_bytes(value),
            authority_mode=STRUCTURAL_TEST_ONLY,
        )
        decision = compile_provider_plan(
            registry=registry,
            provider_id="fixture.compiler.primary",
            provider_run_id="fixture.compiler.run-0",
            context=_context(toolchains=toolchains),
            observed_identity=_observed(registry),
            argv=("fixture-tool", "--json", "-"),
            resources=_resources(),
            allowed_license_classifications=("MIT",),
            source_manifest_authority=None,
        )
        assert decision.ready is False


def test_schema_rejects_every_omitted_closed_property() -> None:
    value = synthetic_registry()
    removals = (
        (value, "release_state"),
        (value["providers"][0], "provider_schema_version"),
        (value["providers"][0], "tool_identity"),
        (value["providers"][0], "environment_policy"),
        (value["providers"][0], "install_policy"),
        (value["providers"][0]["capabilities"][0], "allowed_provenance_origins"),
        (value["providers"][0]["capabilities"][0], "allowed_relation_kinds"),
        (value["providers"][0]["capabilities"][0], "host_semantic_authority"),
    )
    for owner, field in removals:
        candidate = deepcopy(value)
        # Re-find the matching nested owner in the copy.
        if owner is value:
            target = candidate
        elif owner is value["providers"][0]:
            target = candidate["providers"][0]
        else:
            target = candidate["providers"][0]["capabilities"][0]
        del target[field]
        with pytest.raises(ProgramFactsProviderRegistryError, match="schema"):
            load_program_facts_provider_registry_bytes(
                canonical_file_bytes(candidate),
                authority_mode=STRUCTURAL_TEST_ONLY,
            )


def test_mutated_installed_authority_and_registry_fail_replay() -> None:
    authority = capture_installed_program_facts_methodology_authority(
        canonical_file_bytes(
            {"audit_snapshot": _audit_snapshot(), "run_id": RUN_ID}
        )
    )
    object.__setattr__(authority, "_capture_digest", H0)
    with pytest.raises(
        ProgramFactsProviderRegistryError, match="mutation|digest|binding"
    ):
        load_program_facts_provider_registry(installed_authority=authority)


def test_result_dispositions_require_scoped_diagnostics_and_total_contribution() -> None:
    raw = b'{"facts":[]}\n'
    plan_id = "PFP-" + "a" * 24
    with pytest.raises(
        ProgramFactsProviderAPIError, match="diagnostic|debt|unavailable"
    ):
        ProviderResult(
            audit_run_id=RUN_ID,
            methodology_authority_digest=H7,
            registry_digest=H0,
            context_digest=H1,
            source_manifest_digest=H2,
            source_authority_digest=H3,
            plan_id=plan_id,
            provider_id="fixture.compiler.primary",
            provider_run_id="fixture.compiler.run-0",
            result_state="PROVISIONAL_PARSED",
            raw_output_sha256=hashlib.sha256(raw).hexdigest(),
            raw_output_size=len(raw),
            raw_schema_digest=H0,
            parser_callable="parse_fixture_raw",
            parser_source_digest=H1,
            capabilities_parsed=(),
            capabilities_partial=(),
            capabilities_unavailable=("fixture.calls.v1",),
            capability_diagnostics=(),
        )


def test_precision_is_capped_by_the_request_not_only_registry() -> None:
    # The full contribution fixture remains structural until a provider is
    # installed.  This assertion locks the comparison helper's public policy.
    assert (
        __import__("program_facts_provider_api").maximum_effective_precision(
            "EXACT", "SYNTACTIC", ""
        )
        == "SYNTACTIC"
    )

    from test_program_facts_provider_api import _contribution

    registry, context, observed, plan = _structural_plan(
        maximum_precision="SYNTACTIC"
    )
    raw = b'{"facts":[]}\n'
    result = _parsed_result(plan, raw)
    contribution = _contribution(plan, result, precision="EXACT")
    with pytest.raises(
        ProgramFactsProviderAPIError,
        match="request|precision|fidelity",
    ):
        validate_fact_contribution(
            contribution,
            plan=plan,
            result=result,
            registry=registry,
            context=context,
            observed_identity=observed,
            raw_output=raw,
            allowed_license_classifications=("MIT",),
            source_manifest_authority=None,
        )


def test_plan_result_contribution_parent_splices_and_post_validation_mutation_fail() -> None:
    from dataclasses import replace
    from test_program_facts_provider_api import _contribution

    registry, context, observed, plan = _structural_plan()
    raw = b'{"facts":[]}\n'

    spliced = replace(
        plan,
        registry_digest=H3,
        context_digest=H5,
        raw_binding={
            "raw_schema_digest": H6,
            "parser_callable": "parse_spliced_raw",
            "parser_source_digest": H7,
        },
        tool_identity={
            **dict(plan.tool_identity),
            "executable_sha256": H7,
        },
    )
    result = _parsed_result(spliced, raw)
    contribution = _contribution(spliced, result, precision="EXACT")
    replay = validate_provider_plan(
        spliced,
        registry=registry,
        context=context,
        observed_identity=observed,
        allowed_license_classifications=("MIT",),
        source_manifest_authority=None,
    )
    assert replay.ready is False
    assert replay.structurally_valid is False
    assert replay.plan is None
    with pytest.raises(
        ProgramFactsProviderAPIError, match="parent plan|authority"
    ):
        validate_provider_result(
            result,
            plan=spliced,
            raw_output=raw,
            registry=registry,
            context=context,
            observed_identity=observed,
            allowed_license_classifications=("MIT",),
            source_manifest_authority=None,
        )
    with pytest.raises(
        ProgramFactsProviderAPIError, match="parent plan|authority"
    ):
        validate_fact_contribution(
            contribution,
            plan=spliced,
            result=result,
            registry=registry,
            context=context,
            observed_identity=observed,
            raw_output=raw,
            allowed_license_classifications=("MIT",),
            source_manifest_authority=None,
        )

    # ``frozen=True`` is not an authority boundary: object.__setattr__ is
    # deliberately adversarially replayed here.
    object.__setattr__(plan, "registry_digest", H7)
    mutated = validate_provider_plan(
        plan,
        registry=registry,
        context=context,
        observed_identity=observed,
        allowed_license_classifications=("MIT",),
        source_manifest_authority=None,
    )
    assert not (mutated.ready or mutated.structurally_valid)


def test_partial_unavailable_and_zero_emission_are_totally_reconciled() -> None:
    registry, context, observed, plan = _structural_plan()
    raw = b'{"facts":[]}\n'
    degraded = ProviderResult(
        audit_run_id=plan.audit_run_id,
        methodology_authority_digest=plan.methodology_authority_digest,
        registry_digest=plan.registry_digest,
        context_digest=plan.context_digest,
        source_manifest_digest=plan.source_manifest_digest,
        source_authority_digest=plan.source_authority_digest,
        plan_id=plan.plan_id,
        provider_id=plan.provider_id,
        provider_run_id=plan.provider_run_id,
        result_state="PROVISIONAL_DEGRADED",
        raw_output_sha256=hashlib.sha256(raw).hexdigest(),
        raw_output_size=len(raw),
        raw_schema_digest=plan.raw_binding["raw_schema_digest"],
        parser_callable=plan.raw_binding["parser_callable"],
        parser_source_digest=plan.raw_binding["parser_source_digest"],
        capabilities_parsed=(),
        capabilities_partial=("fixture.calls.v1",),
        capabilities_unavailable=(),
        capability_diagnostics=(
            {
                "capability_id": "fixture.calls.v1",
                "disposition": "PARTIAL",
                "diagnostic_codes": ["OUTPUT_TRUNCATED"],
                "debt_codes": ["CAPABILITY_PARTIAL"],
            },
        ),
    )
    validated = validate_provider_result(
        degraded,
        plan=plan,
        raw_output=raw,
        registry=registry,
        context=context,
        observed_identity=observed,
        allowed_license_classifications=("MIT",),
        source_manifest_authority=None,
    )
    contribution = FactContribution(
        audit_run_id=plan.audit_run_id,
        methodology_authority_digest=plan.methodology_authority_digest,
        registry_digest=plan.registry_digest,
        context_digest=plan.context_digest,
        source_manifest_digest=plan.source_manifest_digest,
        source_authority_digest=plan.source_authority_digest,
        plan_id=plan.plan_id,
        result_digest=validated.result_digest,
        provider_id=plan.provider_id,
        provider_run_id=plan.provider_run_id,
        build_variant_ids=plan.build_variant_ids,
        capability_ids=("fixture.calls.v1",),
        nodes=(),
        occurrences=(),
        facts=(),
        debt_codes=("CAPABILITY_PARTIAL",),
        capability_accounting=(
            {
                "capability_id": "fixture.calls.v1",
                "disposition": "PARTIAL",
                "emitted_fact_ids": [],
                "debt_codes": ["CAPABILITY_PARTIAL"],
            },
        ),
    )
    assert validate_fact_contribution(
        contribution,
        plan=plan,
        result=validated,
        registry=registry,
        context=context,
        observed_identity=observed,
        raw_output=raw,
        allowed_license_classifications=("MIT",),
        source_manifest_authority=None,
    ).to_dict() == contribution.to_dict()
    from dataclasses import replace

    with pytest.raises(
        ProgramFactsProviderAPIError, match="mechanical vocabulary"
    ):
        replace(
            contribution,
            debt_codes=("SUBSTITUTED_DEBT",),
            capability_accounting=(
                {
                    "capability_id": "fixture.calls.v1",
                    "disposition": "PARTIAL",
                    "emitted_fact_ids": [],
                    "debt_codes": ["SUBSTITUTED_DEBT"],
                },
            ),
        )

    parsed = _parsed_result(plan, raw)
    vanished = FactContribution(
        audit_run_id=plan.audit_run_id,
        methodology_authority_digest=plan.methodology_authority_digest,
        registry_digest=plan.registry_digest,
        context_digest=plan.context_digest,
        source_manifest_digest=plan.source_manifest_digest,
        source_authority_digest=plan.source_authority_digest,
        plan_id=plan.plan_id,
        result_digest=parsed.result_digest,
        provider_id=plan.provider_id,
        provider_run_id=plan.provider_run_id,
        build_variant_ids=plan.build_variant_ids,
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
            },
        ),
    )
    with pytest.raises(
        ProgramFactsProviderAPIError, match="disappeared|emitted facts|debt"
    ):
        validate_fact_contribution(
            vanished,
            plan=plan,
            result=parsed,
            registry=registry,
            context=context,
            observed_identity=observed,
            raw_output=raw,
            allowed_license_classifications=("MIT",),
            source_manifest_authority=None,
        )


def test_methodology_capture_rejects_reparse_and_has_no_execution_side_effects(
    tmp_path, monkeypatch
) -> None:
    import ast
    import program_facts_methodology_authority as authority_module

    target = tmp_path / "bound.json"
    target.write_bytes(b"{}\n")
    monkeypatch.setattr(
        authority_module,
        "_is_reparse",
        lambda path: path.name == "bound.json",
    )
    with pytest.raises(
        ProgramFactsMethodologyAuthorityError, match="symlink|reparse"
    ):
        authority_module._stable_read(
            tmp_path, "bound.json", max_bytes=1024
        )

    tree = ast.parse(
        (
            __import__("pathlib").Path(authority_module.__file__)
            .read_text(encoding="utf-8")
        )
    )
    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        (node.module or "").split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert not imported & {"subprocess", "socket", "requests", "importlib"}


def test_public_mapping_replay_cannot_establish_source_parent_authority() -> None:
    with pytest.raises((TypeError, AttributeError)):
        ParsedProgramFactsSourceManifest(
            record={},
            canonical_bytes=b"{}",
            authority_digest=H0,
            file_sha256=H1,
        )._parent_authority_proof = object()


def test_empty_capability_denominators_cannot_form_a_contribution_chain() -> None:
    from dataclasses import replace
    from test_program_facts_provider_api import _contribution

    registry, context, _observed_value, plan = _structural_plan()
    raw = b'{"facts":[]}\n'
    result = _parsed_result(plan, raw)
    contribution = _contribution(plan, result, precision="EXACT")

    with pytest.raises(ProgramFactsProviderAPIError, match="must not be empty"):
        replace(context, capability_requests=())
    with pytest.raises(ProgramFactsProviderAPIError, match="must not be empty"):
        replace(
            result,
            capabilities_parsed=(),
            capabilities_partial=(),
            capabilities_unavailable=(),
        )
    with pytest.raises(ProgramFactsProviderAPIError, match="must not be empty"):
        replace(
            contribution,
            capability_ids=(),
            facts=(),
            capability_accounting=(),
        )
    assert registry.production_authority_established is False


def test_issued_decisions_and_debts_detect_object_setattr_mutation() -> None:
    registry = _structural_registry()
    selection = registry.provider("fixture.compiler.primary")
    debt = selection.debts[0]
    object.__setattr__(debt, "detail", "post-issuance mutation")
    with pytest.raises(
        ProgramFactsProviderRegistryError, match="forged|mutated"
    ):
        _ = debt.debt_id

    context = _context()
    decision = compile_provider_plan(
        registry=registry,
        provider_id="fixture.compiler.primary",
        provider_run_id="fixture.compiler.run-0",
        context=context,
        observed_identity=_observed(registry),
        argv=("fixture-tool", "--json", "-"),
        resources=_resources(),
        allowed_license_classifications=("MIT",),
        source_manifest_authority=None,
    )
    assert decision.structurally_valid
    assert decision.plan is not None
    object.__setattr__(decision.plan, "registry_digest", H7)
    assert decision.structurally_valid is False
    assert decision.ready is False


def test_production_registry_replays_every_captured_methodology_input() -> None:
    _authority, registry = _capture_and_load()
    phase_inputs = dict(registry.phase_io_input_bytes)
    schema_identity = PROGRAM_FACTS_METHODOLOGY_INPUT_PATHS[-1]
    phase_inputs[schema_identity] = b"{}\n"
    object.__setattr__(
        registry,
        "_phase_io_input_bytes",
        MappingProxyType(phase_inputs),
    )

    assert registry.production_authority_established is False
    with pytest.raises(
        ProgramFactsProviderRegistryError,
        match="schema|methodology|binding",
    ):
        registry.provider("fixture.compiler.primary")


def test_structural_fallback_still_requires_the_reviewed_edge_and_cap() -> None:
    from dataclasses import replace

    primary = synthetic_provider("fixture.compiler.primary")
    fallback = synthetic_provider(
        "fixture.compiler.source_fallback",
        maximum_precision="SYNTACTIC",
    )
    primary["fallback"] = {
        "provider_id": "fixture.compiler.source_fallback",
        "maximum_precision": "SYNTACTIC",
    }
    registry = load_program_facts_provider_registry_bytes(
        canonical_file_bytes(synthetic_registry(primary, fallback)),
        authority_mode=STRUCTURAL_TEST_ONLY,
    )
    context = _context(maximum_precision="SYNTACTIC")
    observed_fallback = replace(
        _observed(registry),
        provider_schema_version=(
            "plamen.program_facts_provider."
            "fixture.compiler.source_fallback.v1"
        ),
    )
    reviewed = compile_provider_plan(
        registry=registry,
        provider_id="fixture.compiler.source_fallback",
        provider_run_id="fixture.compiler.run-0",
        context=context,
        observed_identity=observed_fallback,
        argv=("fixture-tool", "--json", "-"),
        resources=_resources(),
        allowed_license_classifications=("MIT",),
        source_manifest_authority=None,
        fallback_from_provider_id="fixture.compiler.primary",
    )
    assert reviewed.structurally_valid

    unreviewed = compile_provider_plan(
        registry=registry,
        provider_id="fixture.compiler.primary",
        provider_run_id="fixture.compiler.run-0",
        context=context,
        observed_identity=_observed(registry),
        argv=("fixture-tool", "--json", "-"),
        resources=_resources(),
        allowed_license_classifications=("MIT",),
        source_manifest_authority=None,
        fallback_from_provider_id="fixture.compiler.source_fallback",
    )
    assert not unreviewed.structurally_valid
    assert ProviderPolicyDebtCode.FALLBACK_POLICY_MISMATCH in {
        debt.code for debt in unreviewed.debts
    }


def test_methodology_one_shot_cannot_be_reset_through_instance_state() -> None:
    authority, _registry = _capture_and_load()
    with pytest.raises(AttributeError):
        object.__setattr__(authority, "_state", object())
    with pytest.raises(
        ProgramFactsProviderRegistryError, match="one-shot|consumed"
    ):
        load_program_facts_provider_registry(installed_authority=authority)


def test_copied_decisions_and_debts_cannot_recompute_public_authority() -> None:
    registry = _structural_registry()
    selection = registry.provider("fixture.compiler.primary")

    forged_debt = copy.copy(selection.debts[0])
    object.__setattr__(forged_debt, "code", ProviderPolicyDebtCode.UNKNOWN_PROVIDER)
    object.__setattr__(forged_debt, "provider_id", "forged.provider")
    object.__setattr__(
        forged_debt,
        "_issuance_digest",
        forged_debt._current_issuance_digest(),
    )
    with pytest.raises(
        ProgramFactsProviderRegistryError, match="forged|mutated|issued"
    ):
        _ = forged_debt.debt_id

    forged = copy.copy(selection)
    object.__setattr__(forged, "provider", {"provider_id": "forged.provider"})
    object.__setattr__(forged, "debts", ())
    object.__setattr__(forged, "_production_ready", True)
    object.__setattr__(
        forged,
        "_issuance_digest",
        forged._current_issuance_digest(),
    )
    assert forged.ready is False

    _registry_value, _context_value, _observed_value, plan = _structural_plan()
    plan_decision = compile_provider_plan(
        registry=_registry_value,
        provider_id="fixture.compiler.primary",
        provider_run_id="fixture.compiler.run-0",
        context=_context_value,
        observed_identity=_observed_value,
        argv=("fixture-tool", "--json", "-"),
        resources=_resources(),
        allowed_license_classifications=("MIT",),
        source_manifest_authority=None,
    )
    assert plan_decision.structurally_valid
    forged_plan_decision = copy.copy(plan_decision)
    object.__setattr__(forged_plan_decision, "plan", plan)
    object.__setattr__(forged_plan_decision, "debts", ())
    object.__setattr__(forged_plan_decision, "_production_ready", True)
    object.__setattr__(
        forged_plan_decision,
        "_issuance_digest",
        forged_plan_decision._current_issuance_digest(),
    )
    assert forged_plan_decision.ready is False
    assert forged_plan_decision.structurally_valid is False


def test_stateful_argv_sequence_is_normalized_once_before_review() -> None:
    class StatefulArgv:
        def __init__(self) -> None:
            self.iterations = 0

        def __iter__(self):
            self.iterations += 1
            if self.iterations == 1:
                return iter(("fixture-tool", "--json", "-"))
            return iter(("fixture-tool", "--evil", "owned"))

    registry = _structural_registry()
    argv = StatefulArgv()
    decision = compile_provider_plan(
        registry=registry,
        provider_id="fixture.compiler.primary",
        provider_run_id="fixture.compiler.run-0",
        context=_context(),
        observed_identity=_observed(registry),
        argv=argv,
        resources=_resources(),
        allowed_license_classifications=("MIT",),
        source_manifest_authority=None,
    )
    assert decision.structurally_valid
    assert decision.plan is not None
    assert decision.plan.argv == ("fixture-tool", "--json", "-")
    assert argv.iterations == 1


def test_fake_mechanical_debt_codes_are_rejected_at_protocol_boundaries() -> None:
    registry, _context_value, _observed_value, plan = _structural_plan()
    raw = b'{"facts":[]}\n'
    with pytest.raises(ProgramFactsProviderAPIError, match="debt code"):
        ProviderResult(
            audit_run_id=plan.audit_run_id,
            methodology_authority_digest=plan.methodology_authority_digest,
            registry_digest=plan.registry_digest,
            context_digest=plan.context_digest,
            source_manifest_digest=plan.source_manifest_digest,
            source_authority_digest=plan.source_authority_digest,
            plan_id=plan.plan_id,
            provider_id=plan.provider_id,
            provider_run_id=plan.provider_run_id,
            result_state="PROVISIONAL_DEGRADED",
            raw_output_sha256=hashlib.sha256(raw).hexdigest(),
            raw_output_size=len(raw),
            raw_schema_digest=plan.raw_binding["raw_schema_digest"],
            parser_callable=plan.raw_binding["parser_callable"],
            parser_source_digest=plan.raw_binding["parser_source_digest"],
            capabilities_parsed=(),
            capabilities_partial=("fixture.calls.v1",),
            capabilities_unavailable=(),
            capability_diagnostics=(
                {
                    "capability_id": "fixture.calls.v1",
                    "disposition": "PARTIAL",
                    "diagnostic_codes": ["OUTPUT_TRUNCATED"],
                    "debt_codes": ["TOTALLY_FAKE_DEBT"],
                },
            ),
        )
    assert registry.production_authority_established is False


def test_production_capture_digest_rejects_self_consistent_schema_substitution() -> None:
    _authority, registry = _capture_and_load()
    phase_inputs = dict(registry.phase_io_input_bytes)
    schema_identity = PROGRAM_FACTS_METHODOLOGY_INPUT_PATHS[-1]
    schema = json.loads(phase_inputs[schema_identity])
    schema["title"] = str(schema["title"]) + " substituted"
    substituted_schema = canonical_file_bytes(schema)
    phase_inputs[schema_identity] = substituted_schema

    package_identity = PROGRAM_FACTS_METHODOLOGY_INPUT_PATHS[0]
    package = json.loads(phase_inputs[package_identity])
    schema_row = next(
        row
        for row in package["schemas"]
        if row["phase_io_identity"] == schema_identity
    )
    schema_row["sha256"] = hashlib.sha256(substituted_schema).hexdigest()
    schema_row["size_bytes"] = len(substituted_schema)
    revision_preimage = {
        "methodology_component_digest": package["audit_snapshot"][
            "methodology_component"
        ]["digest"],
        "toolchain_component_digest": package["audit_snapshot"][
            "toolchain_component_digest"
        ],
        "registry_file_sha256": package["registry"]["file_sha256"],
        "sources": package["implementation_sources"],
        "schemas": package["schemas"],
        "version_file_sha256": package["package_identity"][
            "version_file_sha256"
        ],
    }
    package["package_identity"]["revision_identity"] = hashlib.sha256(
        canonical_json_bytes(revision_preimage)
    ).hexdigest()
    unsigned = dict(package)
    unsigned.pop("package_sha256")
    package["package_sha256"] = hashlib.sha256(
        canonical_json_bytes(unsigned)
    ).hexdigest()
    phase_inputs[package_identity] = canonical_file_bytes(package)

    object.__setattr__(registry, "_phase_io_input_bytes", phase_inputs)
    assert registry.production_authority_established is False
    with pytest.raises(
        ProgramFactsProviderRegistryError, match="capture|substitut|binding"
    ):
        registry.captured_schema_bytes(schema_identity.rsplit("/", 1)[-1])


def test_source_authority_digest_is_exact_across_protocol_chain() -> None:
    from dataclasses import replace
    from test_program_facts_provider_api import _contribution

    registry, context, observed, plan = _structural_plan()
    raw = b'{"facts":[]}\n'
    result = _parsed_result(plan, raw)
    contribution = _contribution(plan, result, precision="EXACT")
    assert (
        context.source_authority_digest
        == plan.source_authority_digest
        == result.source_authority_digest
        == contribution.source_authority_digest
    )

    for value, parser in (
        (context.to_dict(), ProviderContext.from_dict),
        (plan.to_dict(), ProviderPlan.from_dict),
        (result.to_dict(), ProviderResult.from_dict),
        (contribution.to_dict(), FactContribution.from_dict),
    ):
        value.pop("source_authority_digest")
        with pytest.raises(
            ProgramFactsProviderAPIError,
            match="source_authority_digest|schema drift",
        ):
            parser(value)

    substituted_plan = replace(plan, source_authority_digest=H5)
    decision = validate_provider_plan(
        substituted_plan,
        registry=registry,
        context=context,
        observed_identity=observed,
        allowed_license_classifications=("MIT",),
        source_manifest_authority=None,
    )
    assert not (decision.ready or decision.structurally_valid)

    substituted_result = replace(result, source_authority_digest=H5)
    with pytest.raises(ProgramFactsProviderAPIError, match="binding"):
        validate_provider_result(
            substituted_result,
            plan=plan,
            raw_output=raw,
            registry=registry,
            context=context,
            observed_identity=observed,
            allowed_license_classifications=("MIT",),
            source_manifest_authority=None,
        )

    substituted_contribution = replace(
        contribution,
        source_authority_digest=H5,
    )
    with pytest.raises(ProgramFactsProviderAPIError, match="binding"):
        validate_fact_contribution(
            substituted_contribution,
            plan=plan,
            result=result,
            registry=registry,
            context=context,
            observed_identity=observed,
            raw_output=raw,
            allowed_license_classifications=("MIT",),
            source_manifest_authority=None,
        )


def test_replayed_source_parent_binds_public_authority_digest_and_snapshot(
    tmp_path,
    monkeypatch,
) -> None:
    import audit_snapshot as snapshot_module
    import program_facts_provider_api as provider_api
    import program_facts_source_manifest as manifest_module
    from program_facts_source_manifest import (
        build_program_facts_source_manifest,
        capture_program_facts_audit_snapshot_authority,
        replay_program_facts_source_manifest,
    )
    from test_program_facts_source_manifest import _fixture

    monkeypatch.setattr(
        snapshot_module.shutil,
        "which",
        lambda _command: None,
    )
    monkeypatch.setattr(
        manifest_module,
        "_selector_source_digest",
        lambda: H6,
    )
    project, _source, config, _snapshot = _fixture(tmp_path)
    snapshot = snapshot_module.build_audit_snapshot(
        config,
        __import__("pathlib").Path(__file__).resolve().parents[1],
    )
    captured = build_program_facts_source_manifest(config, snapshot)
    snapshot_authority = capture_program_facts_audit_snapshot_authority(
        snapshot,
        config=config,
    )
    replayed = replay_program_facts_source_manifest(
        captured.canonical_bytes,
        expected_snapshot_digest=snapshot["snapshot_digest"],
        expected_source_scope_digest=snapshot["components"]["source_scope"][
            "digest"
        ],
        source_bytes_by_id=captured.source_bytes_by_id,
        excluded_source_bytes_by_identity=(
            captured.excluded_source_bytes_by_identity
        ),
        capture_capability=captured.capture_capability,
    )
    context = _context(
        source_manifest_digest=replayed.manifest_digest,
    )
    context = __import__("dataclasses").replace(
        context,
        snapshot_digest=snapshot["snapshot_digest"],
        source_scope_digest=snapshot["components"]["source_scope"]["digest"],
        source_authority_digest=replayed.authority_digest,
    )
    assert provider_api._validate_source_manifest_parent(
        replayed,
        context=context,
        audit_snapshot_authority=snapshot_authority,
        project_root=project,
        config=config,
    )
    assert not provider_api._validate_source_manifest_parent(
        replayed,
        context=__import__("dataclasses").replace(
            context,
            source_authority_digest=H5,
        ),
        audit_snapshot_authority=snapshot_authority,
        project_root=project,
        config=config,
    )
    assert not provider_api._validate_source_manifest_parent(
        replayed,
        context=__import__("dataclasses").replace(
            context,
            snapshot_digest=H5,
        ),
        audit_snapshot_authority=snapshot_authority,
        project_root=project,
        config=config,
    )


def test_reflection_constructed_values_are_not_validator_issued() -> None:
    import program_facts_methodology_authority as methodology_api
    import program_facts_provider_api as provider_api
    import program_facts_provider_registry as registry_api

    assert not hasattr(methodology_api, "_ISSUED_AUTHORITIES")
    assert not hasattr(methodology_api, "_CONSUMED_AUTHORITIES")
    assert not hasattr(registry_api, "_ISSUED_DEBTS")
    assert not hasattr(registry_api, "_ISSUED_DECISIONS")
    assert not hasattr(registry_api, "_ISSUED_REGISTRIES")
    assert not hasattr(provider_api, "_ISSUED_PLANS")
    assert not hasattr(provider_api, "_ISSUED_PLAN_DECISIONS")

    debt = ProviderPolicyDebt._create(
        seal=registry_api._DEBT_SEAL,
        code=ProviderPolicyDebtCode.UNKNOWN_PROVIDER,
        provider_id="forged.provider",
    )
    with pytest.raises(
        ProgramFactsProviderRegistryError, match="forged|mutated|issued"
    ):
        _ = debt.debt_id

    decision = ProviderRegistryDecision._create(
        seal=registry_api._DECISION_SEAL,
        provider={"provider_id": "forged.provider"},
        debts=(),
        production_ready=True,
    )
    assert decision.ready is False

    _registry_value, _context_value, _observed_value, plan = _structural_plan()
    plan_decision = ProviderPlanDecision._create(
        seal=provider_api._PLAN_DECISION_SEAL,
        plan=plan,
        debts=(),
        production_ready=True,
    )
    assert plan_decision.ready is False
