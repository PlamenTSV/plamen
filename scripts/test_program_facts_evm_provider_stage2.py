from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import hashlib
import inspect
import json
import random

import pytest

from program_facts_evm_provider import (
    EVM_CAPABILITY_IDS,
    EVM_PROVIDER_ID,
    EvmProgramFactsProviderError,
    EvmProviderLimits,
    emit_evm_unavailable_sidecars,
    normalize_evm_slither,
    parse_evm_slither_raw,
    plan_evm_slither,
)
from program_facts_provider_api import (
    CapabilityRequest,
    ObservedProviderIdentity,
    ParsedProviderOutput,
    PlatformIdentity,
    ProviderContext,
    ProviderResources,
    ToolchainIdentity,
)
from program_facts_provider_registry import (
    STRUCTURAL_TEST_ONLY,
    load_program_facts_provider_registry_bytes,
)
from program_facts_types import (
    ProgramFactsTypeError,
    canonical_file_bytes,
    canonical_json_bytes,
    derive_source_manifest_digest,
    derive_stable_id,
    validate_program_facts_bundle_structural_test_only,
)
from test_program_facts_provider_registry import (
    synthetic_provider,
    synthetic_registry,
)


H0 = "0" * 64
H1 = "1" * 64
H2 = "2" * 64
H3 = "3" * 64
H4 = "4" * 64
H5 = "5" * 64
H6 = "6" * 64
H7 = "7" * 64
RAW_SCHEMA = "plamen.evm_slither_raw.v1"
EVM_RELATION_FIXTURE_KINDS = (
    "CONTAINS",
    "DECLARES",
    "INHERITS_OR_IMPLEMENTS",
    "EXACT_CFG_EDGE",
    "EXACT_CFG_DOMINATES",
    "EXACT_CFG_POST_DOMINATES",
    "MAY_DEPENDENCY_FUNCTION",
    "MAY_DEPENDENCY_CONTRACT",
    "RESOLVED_STATIC_CALL",
    "MAY_REACH_CHA",
    "MAY_REACH_RTA",
    "MAY_REACH_VTA",
    "UNRESOLVED_DYNAMIC_CALL",
    "READS_STATE",
    "WRITES_STATE",
    "SYNTACTIC_SINK",
    "AUTH_CHECK_OCCURRENCE",
    "VALUE_TRANSFER_OCCURRENCE",
    "CREATE_OCCURRENCE",
)
UNAVAILABLE_REASON_CASES = (
    (
        "PROVIDER_UNSUPPORTED_ECOSYSTEM",
        "UNSUPPORTED",
        "UNAVAILABLE",
        False,
        False,
    ),
    (
        "UNSUPPORTED_HOST_SEMANTICS",
        "UNSUPPORTED",
        "UNAVAILABLE",
        False,
        False,
    ),
    (
        "LICENSE_OR_DISTRIBUTION_RESTRICTED",
        "UNSUPPORTED",
        "UNAVAILABLE",
        False,
        False,
    ),
    ("PROVIDER_UNAVAILABLE", "UNKNOWN", "UNAVAILABLE", True, True),
    (
        "PROVIDER_IDENTITY_UNBOUND",
        "UNKNOWN",
        "UNAVAILABLE",
        False,
        True,
    ),
    ("PROVIDER_VERSION_DRIFT", "UNKNOWN", "UNAVAILABLE", False, True),
    ("EXECUTABLE_DIGEST_DRIFT", "UNKNOWN", "UNAVAILABLE", False, True),
    ("PARSER_DIGEST_DRIFT", "UNKNOWN", "UNAVAILABLE", False, True),
    ("STALE_SNAPSHOT", "UNKNOWN", "STALE", True, True),
    ("SOURCE_CHANGED_DURING_RUN", "UNKNOWN", "STALE", True, True),
    ("ANALYSIS_TIMEOUT", "UNKNOWN", "FAILED", True, True),
    ("OUTPUT_TRUNCATED", "UNKNOWN", "FAILED", True, True),
    ("RESOURCE_LIMIT", "UNKNOWN", "FAILED", True, True),
    ("RAW_OUTPUT_MALFORMED", "UNKNOWN", "FAILED", True, True),
    (
        "BUILD_CONFIGURATION_UNRESOLVED",
        "UNKNOWN",
        "FAILED",
        True,
        True,
    ),
    ("BUILD_FAILED", "UNKNOWN", "FAILED", True, True),
    ("BUILD_PARTIAL", "UNKNOWN", "FAILED", True, True),
    (
        "WORKER_TRANSACTION_INCOMPLETE",
        "UNKNOWN",
        "FAILED",
        True,
        True,
    ),
    (
        "PHASE_IO_INCORPORATION_FAILED",
        "UNKNOWN",
        "FAILED",
        True,
        True,
    ),
    ("OS_PROCESS_SCOPE_UNPROVEN", "UNKNOWN", "FAILED", True, True),
)
SOURCE = (
    b"contract Vault {\n"
    b"    uint256 x;\n"
    b"    function f() external { x; }\n"
    b"}\n"
)
SOURCE_2 = b"contract Receiver { function g() external {} }\n"


def _source() -> dict[str, object]:
    binding = {
        "source_scope_digest": H1,
        "path": "src/Vault.sol",
        "source_sha256": hashlib.sha256(SOURCE).hexdigest(),
        "scope_class": "PRODUCTION",
    }
    return {
        "source_file_id": derive_stable_id("PFS", binding),
        "path": binding["path"],
        "path_casefold_key": "src/vault.sol",
        "source_sha256": binding["source_sha256"],
        "size_bytes": len(SOURCE),
        "language": "solidity",
        "scope_class": binding["scope_class"],
        "physical_identity_digest": H2,
    }


def _source_manifest() -> dict[str, object]:
    source = _source()
    value: dict[str, object] = {
        "policy_version": "plamen.program_facts_source_scope.v1",
        "eligible_files": [source],
        "excluded_files": [],
        "file_count": 1,
        "byte_count": len(SOURCE),
        "manifest_digest": H0,
    }
    value["manifest_digest"] = derive_source_manifest_digest(value)
    return value


def _second_source() -> dict[str, object]:
    binding = {
        "source_scope_digest": H1,
        "path": "src/Receiver.sol",
        "source_sha256": hashlib.sha256(SOURCE_2).hexdigest(),
        "scope_class": "PRODUCTION",
    }
    return {
        "source_file_id": derive_stable_id("PFS", binding),
        "path": binding["path"],
        "path_casefold_key": "src/receiver.sol",
        "source_sha256": binding["source_sha256"],
        "size_bytes": len(SOURCE_2),
        "language": "solidity",
        "scope_class": binding["scope_class"],
        "physical_identity_digest": H3,
    }


def _two_source_manifest() -> dict[str, object]:
    files = sorted(
        [_source(), _second_source()],
        key=lambda row: row["source_file_id"],
    )
    value: dict[str, object] = {
        "policy_version": "plamen.program_facts_source_scope.v1",
        "eligible_files": files,
        "excluded_files": [],
        "file_count": 2,
        "byte_count": len(SOURCE) + len(SOURCE_2),
        "manifest_digest": H0,
    }
    value["manifest_digest"] = derive_source_manifest_digest(value)
    return value


def _variant() -> dict[str, object]:
    semantic = {
        "ecosystem": "evm",
        "build_system": "foundry",
        "build_root_id": "root-0",
        "manifest_digests": [{"path": "foundry.toml", "sha256": H1}],
        "dependency_closure_digest": H1,
        "compiler_identity_digest": H2,
        "profile": "default",
        "features": [],
        "tags": [],
        "remappings": [],
        "defines": [],
        "target_triples": [],
        "generated_source_policy": "BOUND_INCLUDED",
    }
    digest = hashlib.sha256(canonical_json_bytes(semantic)).hexdigest()
    return {
        "build_variant_id": f"PFB-{digest[:24]}",
        **semantic,
        "variant_digest": digest,
    }


def _capabilities() -> list[dict[str, object]]:
    relations = {
        "evm.slither.calls.v1": [
            "MAY_REACH_CHA",
            "MAY_REACH_RTA",
            "MAY_REACH_VTA",
            "RESOLVED_STATIC_CALL",
            "UNRESOLVED_DYNAMIC_CALL",
        ],
        "evm.slither.cfg.v1": [
            "EXACT_CFG_DOMINATES",
            "EXACT_CFG_EDGE",
            "EXACT_CFG_POST_DOMINATES",
        ],
        "evm.slither.dependencies.v1": [
            "MAY_DEPENDENCY_CONTRACT",
            "MAY_DEPENDENCY_FUNCTION",
        ],
        "evm.slither.sinks.v1": [
            "AUTH_CHECK_OCCURRENCE",
            "CREATE_OCCURRENCE",
            "SYNTACTIC_SINK",
            "VALUE_TRANSFER_OCCURRENCE",
        ],
        "evm.slither.state.v1": ["READS_STATE", "WRITES_STATE"],
        "evm.slither.structure.v1": [
            "CONTAINS",
            "DECLARES",
            "INHERITS_OR_IMPLEMENTS",
        ],
    }
    provenance = {
        "evm.slither.calls.v1": ["AST", "BYTECODE", "COMPILER_IR"],
        "evm.slither.cfg.v1": ["COMPILER_IR", "SSA"],
        "evm.slither.dependencies.v1": ["AST", "COMPILER_IR", "SSA"],
        "evm.slither.sinks.v1": ["AST", "COMPILER_IR", "SOURCE_PARSE"],
        "evm.slither.state.v1": ["AST", "COMPILER_IR", "SSA"],
        "evm.slither.structure.v1": ["AST", "INDEX_REFERENCE"],
    }
    return [
        {
            "capability_id": capability_id,
            "maximum_precision": (
                "MAY" if capability_id.endswith("dependencies.v1") else "EXACT"
            ),
            "allowed_provenance_origins": provenance[capability_id],
            "allowed_relation_kinds": relations[capability_id],
            "host_semantic_authority": False,
        }
        for capability_id in EVM_CAPABILITY_IDS
    ]


def _registry():
    provider = synthetic_provider(EVM_PROVIDER_ID)
    provider.update(
        {
            "provider_schema_version": (
                "plamen.program_facts_provider.evm.slither.typed.v1"
            ),
            "adapter": {
                "module": "program_facts_evm_provider",
                "symbol": "plan_evm_slither",
            },
            "supported_ecosystems": ["evm"],
            "supported_languages": ["solidity"],
            "toolchain_ranges": [
                {
                    "toolchain": "solc",
                    "version_range": ">=0.8,<0.9",
                    "identity_digest": H2,
                }
            ],
            "capabilities": _capabilities(),
            "raw_binding": {
                "raw_schema_digest": H0,
                "parser_callable": "parse_evm_slither_raw",
                "parser_source_digest": H1,
            },
            "tool_identity": {
                "kind": "EXECUTABLE",
                "name": "slither-analyzer",
                "command": "slither",
                "module": "",
                "executable_sha256": H2,
                "module_sha256": "",
            },
            "invocation_policy": {
                "argv_template": ["slither", "--json", "-"],
                "typed_substitutions": [],
                "configuration_inputs": [],
            },
            "expected_version_syntax": r"^slither 0\.11\.3$",
            "distribution": {
                "kind": "python-wheel",
                "name": "slither-analyzer",
                "version": "0.11.3",
                "checksum": H3,
                "module_source_digest": "",
            },
            "license_classification": "AGPL-3.0-only",
            "limits": {
                "time_seconds": 600,
                "memory_bytes": 1073741824,
                "input_bytes": 1048576,
                "output_bytes": 1048576,
            },
            "supported_platforms": [
                {"os": "linux", "architectures": ["amd64"]},
                {"os": "windows", "architectures": ["amd64"]},
            ],
            "installation_provenance": {
                "kind": "checked-lock",
                "source": "requirements-provider-evm.lock",
                "digest": H5,
            },
            "environment_policy": {
                "inheritance": "DENY_BY_DEFAULT",
                "allowed_names": [],
                "required_names": [],
                "forbidden_secret_names": ["API_TOKEN", "SECRET"],
                "allow_secret_values": False,
                "value_digest_required": True,
            },
            "install_policy": {
                "mode": "PREINSTALLED_VERIFIED",
                "network_allowed": False,
                "mutable_reference_allowed": False,
                "installer": "pip",
                "lock_identity": "requirements-provider-evm.lock",
                "lock_digest": H5,
            },
        }
    )
    return load_program_facts_provider_registry_bytes(
        canonical_file_bytes(synthetic_registry(provider)),
        authority_mode=STRUCTURAL_TEST_ONLY,
    )


def _context(
    *,
    platform: PlatformIdentity = PlatformIdentity("linux", "amd64"),
    source_manifest: dict[str, object] | None = None,
) -> ProviderContext:
    source_manifest = source_manifest or _source_manifest()
    return ProviderContext(
        audit_run_id="stage2-evm-fixture",
        methodology_authority_digest=H7,
        snapshot_digest=H0,
        source_scope_digest=H1,
        source_manifest_digest=str(source_manifest["manifest_digest"]),
        source_authority_digest=H6,
        ecosystem="evm",
        languages=("solidity",),
        build_variant_ids=(str(_variant()["build_variant_id"]),),
        capability_requests=tuple(
            CapabilityRequest(
                capability_id,
                "MAY" if capability_id.endswith("dependencies.v1") else "EXACT",
            )
            for capability_id in EVM_CAPABILITY_IDS
        ),
        toolchains=(ToolchainIdentity("solc", "0.8.28", H2),),
        platform=platform,
        environment=(),
        working_directory_root_id="root-0",
    )


def _observed(registry, context: ProviderContext) -> ObservedProviderIdentity:
    return ObservedProviderIdentity(
        registry_digest=registry.registry_digest,
        provider_schema_version=(
            "plamen.program_facts_provider.evm.slither.typed.v1"
        ),
        adapter_module="program_facts_evm_provider",
        adapter_symbol="plan_evm_slither",
        parser_callable="parse_evm_slither_raw",
        parser_source_digest=H1,
        raw_schema_digest=H0,
        tool_kind="EXECUTABLE",
        tool_name="slither-analyzer",
        command="slither",
        module="",
        executable_sha256=H2,
        module_sha256="",
        distribution_kind="python-wheel",
        distribution_name="slither-analyzer",
        distribution_version="0.11.3",
        distribution_checksum=H3,
        distribution_module_source_digest="",
        version_output="slither 0.11.3",
        license_classification="AGPL-3.0-only",
        platform=context.platform,
        installation_mode="PREINSTALLED_VERIFIED",
        installation_lock_identity="requirements-provider-evm.lock",
        installation_lock_digest=H5,
    )


def _plan(
    *,
    platform: PlatformIdentity | None = None,
    source_manifest: dict[str, object] | None = None,
):
    registry = _registry()
    context = _context(
        platform=platform or PlatformIdentity("linux", "amd64"),
        source_manifest=source_manifest,
    )
    observed = _observed(registry, context)
    decision = plan_evm_slither(
        registry=registry,
        provider_run_id="evm.slither.typed.run-0",
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
    assert decision.structurally_valid is True
    assert decision.ready is False
    assert decision.plan is not None
    return registry, context, observed, decision.plan


def _source_ref(start: int, end: int) -> dict[str, object]:
    source = _source()
    return {
        "source_file_id": source["source_file_id"],
        "path": source["path"],
        "start_byte": start,
        "end_byte": end,
    }


def _raw(plan) -> dict[str, object]:
    variant_id = str(_variant()["build_variant_id"])
    source_id = str(_source()["source_file_id"])
    nodes = [
        {
            "local_id": "contract",
            "kind": "CONTRACT",
            "qualified_name": "Vault",
            "display_name": "Vault",
            "canonical_signature": "contract Vault",
            "attributes": [],
            "source": _source_ref(0, len(SOURCE)),
            "reason": "",
        },
        {
            "local_id": "function",
            "kind": "FUNCTION",
            "qualified_name": "Vault.f()",
            "display_name": "f",
            "canonical_signature": "f()",
            "attributes": ["external"],
            "source": _source_ref(36, 64),
            "reason": "",
        },
        {
            "local_id": "state",
            "kind": "STATE_SYMBOL",
            "qualified_name": "Vault.x",
            "display_name": "x",
            "canonical_signature": "uint256 x",
            "attributes": [],
            "source": _source_ref(21, 30),
            "reason": "",
        },
        {
            "local_id": "block.0",
            "kind": "BASIC_BLOCK",
            "qualified_name": "Vault.f()::block.0",
            "display_name": "block.0",
            "canonical_signature": "f()#block.0",
            "attributes": [],
            "source": _source_ref(36, 61),
            "reason": "",
        },
        {
            "local_id": "block.1",
            "kind": "BASIC_BLOCK",
            "qualified_name": "Vault.f()::block.1",
            "display_name": "block.1",
            "canonical_signature": "f()#block.1",
            "attributes": [],
            "source": _source_ref(60, 64),
            "reason": "",
        },
        {
            "local_id": "unknown",
            "kind": "UNKNOWN_TARGET",
            "qualified_name": "unknown::dynamic",
            "display_name": "unknown",
            "canonical_signature": "",
            "attributes": [],
            "source": None,
            "reason": "unresolved dynamic target",
        },
    ]
    occurrences = [
        {
            "local_id": "call",
            "kind": "CALL_SITE",
            "enclosing_local_id": "function",
            "source": _source_ref(60, 61),
            "ir_binding": {},
        },
        {
            "local_id": "read",
            "kind": "READ_SITE",
            "enclosing_local_id": "function",
            "source": _source_ref(60, 61),
            "ir_binding": {},
        },
        {
            "local_id": "sink",
            "kind": "SINK_SITE",
            "enclosing_local_id": "function",
            "source": _source_ref(60, 61),
            "ir_binding": {},
        },
        {
            "local_id": "branch",
            "kind": "BRANCH_PREDICATE",
            "enclosing_local_id": "function",
            "source": _source_ref(60, 61),
            "ir_binding": {},
        },
    ]

    def fact(
        capability_id: str,
        relation_kind: str,
        subject: str,
        object_: str,
        occurrence_ids: list[str],
        *,
        precision: str = "EXACT",
        dispatch: str = "UNKNOWN",
        algorithm: str = "",
        provenance: str = "AST",
        confidence: str | None = None,
    ) -> dict[str, object]:
        return {
            "capability_id": capability_id,
            "relation_kind": relation_kind,
            "subject_local_id": subject,
            "object_local_id": object_,
            "occurrence_local_ids": occurrence_ids,
            "provenance_origin": provenance,
            "precision": precision,
            "coverage_scope": "FUNCTION",
            "structural_confidence": confidence
            or ("PROVIDER_MAY" if precision == "MAY" else "PROVIDER_EXACT"),
            "context": {
                "call_dispatch": dispatch,
                "analysis_algorithm": algorithm,
                "root_set_digest": "",
                "dominating_predicates": [],
                "host_semantic_kind": "",
            },
        }

    facts = [
        fact(
            "evm.slither.calls.v1",
            "RESOLVED_STATIC_CALL",
            "function",
            "function",
            ["call"],
            dispatch="INTERNAL",
        ),
        fact(
            "evm.slither.cfg.v1",
            "EXACT_CFG_EDGE",
            "block.0",
            "block.1",
            ["branch"],
            provenance="COMPILER_IR",
            algorithm="slither.cfg.v1",
        ),
        fact(
            "evm.slither.dependencies.v1",
            "MAY_DEPENDENCY_FUNCTION",
            "function",
            "state",
            ["read"],
            precision="MAY",
            algorithm="slither.data-dependency.v1",
        ),
        fact(
            "evm.slither.sinks.v1",
            "SYNTACTIC_SINK",
            "function",
            "unknown",
            ["sink"],
            precision="SYNTACTIC",
            confidence="SOURCE_FALLBACK",
        ),
        fact(
            "evm.slither.state.v1",
            "READS_STATE",
            "function",
            "state",
            ["read"],
        ),
        fact(
            "evm.slither.structure.v1",
            "CONTAINS",
            "function",
            "block.0",
            [],
        ),
        fact(
            "evm.slither.structure.v1",
            "CONTAINS",
            "function",
            "block.1",
            [],
        ),
    ]
    return {
        "schema_version": RAW_SCHEMA,
        "plan_id": plan.plan_id,
        "provider_run_id": plan.provider_run_id,
        "source_manifest_digest": plan.source_manifest_digest,
        "build_variant_id": variant_id,
        "tool": {
            "name": plan.tool_identity["name"],
            "executable_or_module_digest": plan.tool_identity[
                "executable_sha256"
            ],
            "distribution_name": plan.distribution["name"],
            "distribution_version": plan.distribution["version"],
            "distribution_checksum": plan.distribution["checksum"],
            "version_output": plan.version_output,
            "parser_source_digest": plan.raw_binding["parser_source_digest"],
            "raw_schema_digest": plan.raw_binding["raw_schema_digest"],
            "toolchains": [item.to_dict() for item in plan.toolchains],
        },
        "compiled_source_file_ids": [source_id],
        "capability_dispositions": [
            {
                "capability_id": capability_id,
                "disposition": "PARSED",
                "diagnostic_codes": [],
                "debt_codes": [],
            }
            for capability_id in EVM_CAPABILITY_IDS
        ],
        "nodes": nodes,
        "occurrences": occurrences,
        "facts": facts,
        "debts": [],
        "zero_positive_denominators": [],
    }


def _single_relation_raw(plan, relation_kind: str) -> dict[str, object]:
    value = _raw(plan)
    for local_id, kind in (
        ("write", "WRITE_SITE"),
        ("auth", "AUTH_SITE"),
        ("transfer", "TRANSFER_SITE"),
        ("create", "CREATE_SITE"),
    ):
        value["occurrences"].append(
            {
                "local_id": local_id,
                "kind": kind,
                "enclosing_local_id": "function",
                "source": _source_ref(60, 61),
                "ir_binding": {},
            }
        )
    value["nodes"].append(
        {
            "local_id": "interface",
            "kind": "INTERFACE",
            "qualified_name": "IVault",
            "display_name": "IVault",
            "canonical_signature": "interface IVault",
            "attributes": [],
            "source": _source_ref(0, len(SOURCE)),
            "reason": "",
        }
    )
    cases = {
        "CONTAINS": (
            "evm.slither.structure.v1",
            "function",
            "block.0",
            [],
            "AST",
            "EXACT",
            "PROVIDER_EXACT",
            "UNKNOWN",
            "",
            "",
        ),
        "DECLARES": (
            "evm.slither.structure.v1",
            "contract",
            "function",
            [],
            "AST",
            "EXACT",
            "PROVIDER_EXACT",
            "UNKNOWN",
            "",
            "",
        ),
        "INHERITS_OR_IMPLEMENTS": (
            "evm.slither.structure.v1",
            "contract",
            "interface",
            [],
            "AST",
            "EXACT",
            "PROVIDER_EXACT",
            "UNKNOWN",
            "",
            "",
        ),
        "EXACT_CFG_EDGE": (
            "evm.slither.cfg.v1",
            "block.0",
            "block.1",
            ["branch"],
            "COMPILER_IR",
            "EXACT",
            "PROVIDER_EXACT",
            "UNKNOWN",
            "slither.cfg.v1",
            "",
        ),
        "EXACT_CFG_DOMINATES": (
            "evm.slither.cfg.v1",
            "block.0",
            "block.1",
            [],
            "SSA",
            "EXACT",
            "PROVIDER_EXACT",
            "UNKNOWN",
            "slither.dominators.v1",
            "",
        ),
        "EXACT_CFG_POST_DOMINATES": (
            "evm.slither.cfg.v1",
            "block.1",
            "block.0",
            [],
            "SSA",
            "EXACT",
            "PROVIDER_EXACT",
            "UNKNOWN",
            "slither.post-dominators.v1",
            "",
        ),
        "MAY_DEPENDENCY_FUNCTION": (
            "evm.slither.dependencies.v1",
            "function",
            "state",
            ["read"],
            "SSA",
            "MAY",
            "PROVIDER_MAY",
            "UNKNOWN",
            "slither.data-dependency.v1",
            "",
        ),
        "MAY_DEPENDENCY_CONTRACT": (
            "evm.slither.dependencies.v1",
            "contract",
            "state",
            ["read"],
            "SSA",
            "MAY",
            "PROVIDER_MAY",
            "UNKNOWN",
            "slither.contract-dependency.v1",
            "",
        ),
        "RESOLVED_STATIC_CALL": (
            "evm.slither.calls.v1",
            "function",
            "function",
            ["call"],
            "AST",
            "EXACT",
            "PROVIDER_EXACT",
            "INTERNAL",
            "",
            "",
        ),
        "MAY_REACH_CHA": (
            "evm.slither.calls.v1",
            "function",
            "function",
            ["call"],
            "COMPILER_IR",
            "MAY",
            "PROVIDER_MAY",
            "INTERNAL",
            "slither.cha.v1",
            H0,
        ),
        "MAY_REACH_RTA": (
            "evm.slither.calls.v1",
            "function",
            "function",
            ["call"],
            "COMPILER_IR",
            "MAY",
            "PROVIDER_MAY",
            "INTERNAL",
            "slither.rta.v1",
            H0,
        ),
        "MAY_REACH_VTA": (
            "evm.slither.calls.v1",
            "function",
            "function",
            ["call"],
            "COMPILER_IR",
            "MAY",
            "PROVIDER_MAY",
            "INTERNAL",
            "slither.vta.v1",
            H0,
        ),
        "UNRESOLVED_DYNAMIC_CALL": (
            "evm.slither.calls.v1",
            "function",
            "unknown",
            ["call"],
            "AST",
            "MAY",
            "PROVIDER_MAY",
            "DYNAMIC",
            "slither.dynamic-dispatch.v1",
            "",
        ),
        "READS_STATE": (
            "evm.slither.state.v1",
            "function",
            "state",
            ["read"],
            "AST",
            "EXACT",
            "PROVIDER_EXACT",
            "UNKNOWN",
            "",
            "",
        ),
        "WRITES_STATE": (
            "evm.slither.state.v1",
            "function",
            "state",
            ["write"],
            "AST",
            "EXACT",
            "PROVIDER_EXACT",
            "UNKNOWN",
            "",
            "",
        ),
        "SYNTACTIC_SINK": (
            "evm.slither.sinks.v1",
            "function",
            "unknown",
            ["sink"],
            "SOURCE_PARSE",
            "SYNTACTIC",
            "SOURCE_FALLBACK",
            "UNKNOWN",
            "",
            "",
        ),
        "AUTH_CHECK_OCCURRENCE": (
            "evm.slither.sinks.v1",
            "function",
            "state",
            ["auth"],
            "SOURCE_PARSE",
            "SYNTACTIC",
            "SOURCE_FALLBACK",
            "UNKNOWN",
            "",
            "",
        ),
        "VALUE_TRANSFER_OCCURRENCE": (
            "evm.slither.sinks.v1",
            "function",
            "unknown",
            ["transfer"],
            "AST",
            "EXACT",
            "PROVIDER_EXACT",
            "HIGH_LEVEL",
            "",
            "",
        ),
        "CREATE_OCCURRENCE": (
            "evm.slither.sinks.v1",
            "function",
            "contract",
            ["create"],
            "AST",
            "EXACT",
            "PROVIDER_EXACT",
            "CREATE",
            "",
            "",
        ),
    }
    (
        capability_id,
        subject,
        object_,
        occurrences,
        provenance,
        precision,
        confidence,
        dispatch,
        algorithm,
        root_set,
    ) = cases[relation_kind]
    supporting = [
        row
        for row in value["facts"]
        if row["capability_id"] == "evm.slither.structure.v1"
    ]
    template = deepcopy(value["facts"][0])
    template.update(
        {
            "capability_id": capability_id,
            "relation_kind": relation_kind,
            "subject_local_id": subject,
            "object_local_id": object_,
            "occurrence_local_ids": occurrences,
            "provenance_origin": provenance,
            "precision": precision,
            "structural_confidence": confidence,
        }
    )
    template["context"].update(
        {
            "call_dispatch": dispatch,
            "analysis_algorithm": algorithm,
            "root_set_digest": root_set,
            "dominating_predicates": [],
        }
    )
    value["facts"] = (
        supporting
        if relation_kind == "CONTAINS"
        else [*supporting, template]
    )
    if relation_kind == "CONTAINS":
        value["facts"][0] = template
        value["facts"].append(supporting[1])
    return value


def _raw_bytes(plan, value: dict[str, object] | None = None) -> bytes:
    return canonical_file_bytes(value or _raw(plan))


def _normalize_fixture(raw_value: dict[str, object] | None = None):
    registry, context, observed, plan = _plan()
    raw = _raw_bytes(plan, raw_value)
    result = parse_evm_slither_raw(raw, plan)
    outcome = normalize_evm_slither(
        result,
        raw=raw,
        plan=plan,
        registry=registry,
        context=context,
        observed_identity=observed,
        source_manifest=_source_manifest(),
        source_bytes_by_id={str(_source()["source_file_id"]): SOURCE},
        allowed_license_classifications=("AGPL-3.0-only",),
        source_manifest_authority=None,
    )
    return registry, context, observed, plan, result, outcome


def _zero_positive_raw(
    plan,
    capability_id: str = "evm.slither.cfg.v1",
) -> dict[str, object]:
    value = _raw(plan)
    value["facts"] = [
        row
        for row in value["facts"]
        if row["capability_id"] != capability_id
    ]
    value["zero_positive_denominators"] = [
        {
            "capability_id": capability_id,
            "build_variant_id": value["build_variant_id"],
            "denominator_kind": (
                f"{capability_id}.eligible-source-files.v1"
            ),
            "node_local_ids": [],
            "source_file_ids": [str(_source()["source_file_id"])],
        }
    ]
    return value


def _emit_unavailable(reason: str):
    return emit_evm_unavailable_sidecars(
        context=_context(),
        source_manifest=_source_manifest(),
        source_bytes_by_id={str(_source()["source_file_id"]): SOURCE},
        build_variants=(_variant(),),
        audit_snapshot={
            "snapshot_digest": H0,
            "source_scope_digest": H1,
            "audit_config_digest": H0,
            "methodology_digest": H7,
            "toolchain_digest": H2,
        },
        phase_io={
            "contract_digest": H0,
            "launch_digest": H1,
            "input_set_digest": H2,
            "work_unit_key": (
                "sc/thorough/evm/claude/recon/program_facts_bake"
            ),
            "ledger_binding_state": "PRECOMMIT",
            "ledger_record_digest": "",
        },
        reason=reason,
        explanation=f"Fixture for {reason}.",
    )


def test_stage2_plan_is_structural_only_and_does_not_launch_a_provider() -> None:
    _registry_value, _context_value, _observed_value, plan = _plan()
    assert plan.provider_id == EVM_PROVIDER_ID
    assert plan.to_dict()["network_during_bake"] is False
    assert plan.to_dict()["completion_authority"] == (
        "PROVISIONAL_NO_PUBLICATION_AUTHORITY"
    )


def test_parse_and_normalize_emit_only_additive_typed_facts() -> None:
    _registry_value, _context_value, _observed, _plan_value, result, outcome = (
        _normalize_fixture()
    )
    contribution = outcome.contribution
    assert result.result.result_state == "PROVISIONAL_PARSED"
    assert len(contribution.facts) == len(_raw(_plan()[3])["facts"])
    assert contribution.debt_codes == ()
    assert all(
        fact["semantic_authority"] == "ADDITIVE_PROPOSAL_ONLY"
        for fact in contribution.facts
    )
    encoded = contribution.canonical_bytes()
    for forbidden in (
        b'"finding"',
        b'"severity"',
        b'"safe"',
        b'"can_suppress":true',
        b'"can_demote":true',
        b'"can_refute":true',
        b'"can_certify_clean":true',
    ):
        assert forbidden not in encoded


def test_parsed_carrier_is_immutable_and_raw_replay_bound() -> None:
    registry, context, observed, plan = _plan()
    raw = _raw_bytes(plan)
    carrier = parse_evm_slither_raw(raw, plan)
    assert carrier.result.raw_output_sha256 == hashlib.sha256(raw).hexdigest()
    with pytest.raises(TypeError):
        carrier.parsed_payload["facts"] = ()

    substituted = carrier.to_dict()["parsed_payload"]
    substituted["facts"][0]["relation_kind"] = "CONTAINS"
    forged = ParsedProviderOutput(
        result=carrier.result,
        parsed_payload_schema=carrier.parsed_payload_schema,
        parsed_payload=substituted,
    )
    with pytest.raises(EvmProgramFactsProviderError, match="replay|carrier"):
        normalize_evm_slither(
            forged,
            raw=raw,
            plan=plan,
            registry=registry,
            context=context,
            observed_identity=observed,
            source_manifest=_source_manifest(),
            source_bytes_by_id={str(_source()["source_file_id"]): SOURCE},
            allowed_license_classifications=("AGPL-3.0-only",),
            source_manifest_authority=None,
        )


def test_exact_zero_positive_capability_is_accounted_without_fake_debt() -> None:
    registry, context, observed, plan = _plan()
    capability_id = "evm.slither.cfg.v1"
    value = _zero_positive_raw(plan, capability_id)
    raw = _raw_bytes(plan, value)
    carrier = parse_evm_slither_raw(raw, plan)
    outcome = normalize_evm_slither(
        carrier,
        raw=raw,
        plan=plan,
        registry=registry,
        context=context,
        observed_identity=observed,
        source_manifest=_source_manifest(),
        source_bytes_by_id={str(_source()["source_file_id"]): SOURCE},
        allowed_license_classifications=("AGPL-3.0-only",),
        source_manifest_authority=None,
    )
    contribution = outcome.contribution
    row = next(
        item
        for item in contribution.capability_accounting
        if item["capability_id"] == capability_id
    )
    zero = row["zero_positive_accounting"]
    assert row["disposition"] == "PARSED"
    assert row["emitted_fact_ids"] == ()
    assert row["debt_codes"] == ()
    assert contribution.debt_codes == ()
    assert zero["denominators"][0]["denominator_count"] == 1
    assert zero["denominators"][0]["denominator_precision"] == "EXACT"
    assert zero["authority"] == {
        "semantic_authority": "ACCOUNTING_ONLY",
        "terminal_negative_authority": False,
        "can_suppress": False,
        "can_demote": False,
        "can_refute": False,
        "can_mark_examined": False,
        "can_certify_clean": False,
    }


@pytest.mark.parametrize(
    ("mutate", "affected", "reason_code"),
    [
        (
            lambda value: value.update({"compiled_source_file_ids": []}),
            set(EVM_CAPABILITY_IDS),
            "COMPILED_SOURCE_DENOMINATOR_MISMATCH",
        ),
        (
            lambda value: value["zero_positive_denominators"][0].update(
                {"source_file_ids": []}
            ),
            {"evm.slither.cfg.v1"},
            "ZERO_POSITIVE_SOURCE_DENOMINATOR_MISMATCH",
        ),
        (
            lambda value: value["zero_positive_denominators"][0].update(
                {"denominator_kind": "evm.slither.cfg.v1.provider-picked.v1"}
            ),
            {"evm.slither.cfg.v1"},
            "ZERO_POSITIVE_DENOMINATOR_KIND_MISMATCH",
        ),
        (
            lambda value: value["zero_positive_denominators"][0].update(
                {"build_variant_id": "PFB-" + "f" * 24}
            ),
            {"evm.slither.cfg.v1"},
            "ZERO_POSITIVE_BUILD_VARIANT_MISMATCH",
        ),
        (
            lambda value: value.update({"zero_positive_denominators": []}),
            {"evm.slither.cfg.v1"},
            "ZERO_POSITIVE_DENOMINATOR_MISSING",
        ),
        (
            lambda value: value["zero_positive_denominators"][0].update(
                {"node_local_ids": ["function"]}
            ),
            {"evm.slither.cfg.v1"},
            "ZERO_POSITIVE_NODE_DENOMINATOR_NONEMPTY",
        ),
    ],
)
def test_authoritative_denominator_mismatch_is_bound_and_degrades_without_loss(
    mutate,
    affected: set[str],
    reason_code: str,
) -> None:
    registry, context, observed, plan = _plan()
    value = _zero_positive_raw(plan)
    mutate(value)
    raw = _raw_bytes(plan, value)
    carrier = parse_evm_slither_raw(raw, plan)
    outcome = normalize_evm_slither(
        carrier,
        raw=raw,
        plan=plan,
        registry=registry,
        context=context,
        observed_identity=observed,
        source_manifest=_source_manifest(),
        source_bytes_by_id={str(_source()["source_file_id"]): SOURCE},
        allowed_license_classifications=("AGPL-3.0-only",),
        source_manifest_authority=None,
    )
    assert set(outcome.effective_result.capabilities_partial) == affected
    assert set(outcome.effective_result.capabilities_parsed) == (
        set(EVM_CAPABILITY_IDS) - affected
    )
    assert len(outcome.contribution.facts) == len(value["facts"])
    assert outcome.contribution.result_digest == (
        outcome.effective_result.result_digest
    )
    assert outcome.original_carrier.carrier_digest == carrier.carrier_digest
    assert outcome.source_input_binding_digest
    assert any(
        decision["capability_id"] in affected
        and reason_code in decision["reason_codes"]
        for decision in outcome.denominator_decisions
    )
    assert {
        proposal["capability_id"] for proposal in outcome.debt_proposals
    } == affected
    assert {
        proposal["status"] for proposal in outcome.coverage_proposals
    } <= {"PARTIAL", "UNKNOWN"}
    assert all(
        proposal["semantic_authority"] == "ADDITIVE_PROPOSAL_ONLY"
        and proposal["terminal_negative_authority"] is False
        for proposal in (
            *outcome.debt_proposals,
            *outcome.coverage_proposals,
        )
    )


def test_strict_subset_of_two_source_build_denominator_degrades_all_capabilities() -> None:
    manifest = _two_source_manifest()
    registry, context, observed, plan = _plan(source_manifest=manifest)
    value = _raw(plan)
    assert value["compiled_source_file_ids"] == [
        str(_source()["source_file_id"])
    ]
    raw = _raw_bytes(plan, value)
    carrier = parse_evm_slither_raw(raw, plan)
    outcome = normalize_evm_slither(
        carrier,
        raw=raw,
        plan=plan,
        registry=registry,
        context=context,
        observed_identity=observed,
        source_manifest=manifest,
        source_bytes_by_id={
            str(_source()["source_file_id"]): SOURCE,
            str(_second_source()["source_file_id"]): SOURCE_2,
        },
        allowed_license_classifications=("AGPL-3.0-only",),
        source_manifest_authority=None,
    )
    assert set(outcome.effective_result.capabilities_partial) == set(
        EVM_CAPABILITY_IDS
    )
    assert all(
        decision["reason_codes"]
        == ("COMPILED_SOURCE_DENOMINATOR_MISMATCH",)
        for decision in outcome.denominator_decisions
    )
    assert all(
        tuple(decision["expected_source_file_ids"])
        == tuple(
            sorted(
                (
                    str(_source()["source_file_id"]),
                    str(_second_source()["source_file_id"]),
                )
            )
        )
        for decision in outcome.denominator_decisions
    )


def test_nonempty_project_cannot_be_relabelled_as_six_exact_empty_capabilities() -> None:
    registry, context, observed, plan = _plan()
    value = _raw(plan)
    value.update(
        {
            "compiled_source_file_ids": [],
            "nodes": [],
            "occurrences": [],
            "facts": [],
            "debts": [],
            "zero_positive_denominators": [
                {
                    "capability_id": capability_id,
                    "build_variant_id": value["build_variant_id"],
                    "denominator_kind": (
                        f"{capability_id}.eligible-source-files.v1"
                    ),
                    "node_local_ids": [],
                    "source_file_ids": [],
                }
                for capability_id in EVM_CAPABILITY_IDS
            ],
        }
    )
    raw = _raw_bytes(plan, value)
    carrier = parse_evm_slither_raw(raw, plan)
    outcome = normalize_evm_slither(
        carrier,
        raw=raw,
        plan=plan,
        registry=registry,
        context=context,
        observed_identity=observed,
        source_manifest=_source_manifest(),
        source_bytes_by_id={str(_source()["source_file_id"]): SOURCE},
        allowed_license_classifications=("AGPL-3.0-only",),
        source_manifest_authority=None,
    )
    assert outcome.effective_result.capabilities_parsed == ()
    assert set(outcome.effective_result.capabilities_partial) == set(
        EVM_CAPABILITY_IDS
    )
    assert outcome.contribution.facts == ()
    assert {
        row["status"] for row in outcome.coverage_proposals
    } == {"UNKNOWN"}
    assert all(
        "zero_positive_accounting" not in row
        for row in outcome.contribution.capability_accounting
    )


def test_normalization_outcome_rejects_component_swap_mutations() -> None:
    outcome = _normalize_fixture()[5]
    assert type(outcome).from_dict(outcome.to_dict()).to_dict() == (
        outcome.to_dict()
    )
    assert type(outcome).from_bytes(outcome.canonical_bytes()).to_dict() == (
        outcome.to_dict()
    )
    with pytest.raises(TypeError):
        outcome.denominator_decisions[0]["status"] = "MISMATCH"
    with pytest.raises(TypeError):
        outcome.contribution.facts[0]["precision"] = "MAY"
    for mutate in (
        lambda value: value["original_carrier"].update(
            {"carrier_digest": H0}
        ),
        lambda value: value["denominator_decisions"][0].update(
            {"expected_source_file_ids": []}
        ),
        lambda value: value["effective_result"].update(
            {"result_digest": H0}
        ),
        lambda value: value["contribution"].update(
            {"result_digest": H0}
        ),
        lambda value: value["coverage_proposals"].append(
            {
                "schema_version": "plamen.evm_coverage_proposal.v1",
                "capability_id": "evm.slither.cfg.v1",
            }
        ),
    ):
        wire = outcome.to_dict()
        mutate(wire)
        with pytest.raises(
            (EvmProgramFactsProviderError, ProgramFactsTypeError, ValueError)
        ):
            type(outcome).from_dict(wire)

    plan = _plan()[3]
    degraded_value = _zero_positive_raw(plan)
    degraded_value["zero_positive_denominators"] = []
    degraded = _normalize_fixture(degraded_value)[5]
    for kwargs in (
        {"original_carrier": degraded.original_carrier},
        {"denominator_decisions": degraded.denominator_decisions},
        {"effective_result": degraded.effective_result},
        {"contribution": degraded.contribution},
        {"debt_proposals": degraded.debt_proposals},
        {"coverage_proposals": degraded.coverage_proposals},
    ):
        with pytest.raises((EvmProgramFactsProviderError, ValueError)):
            replace(outcome, **kwargs)


def test_source_mapping_is_snapshotted_once_before_normalization() -> None:
    registry, context, observed, plan = _plan()
    raw = _raw_bytes(plan)
    carrier = parse_evm_slither_raw(raw, plan)
    source_id = str(_source()["source_file_id"])
    alternate = bytearray(SOURCE)
    alternate[60:61] = b"!"

    class SplitView(dict):
        def items(self):
            return ((source_id, SOURCE),)

        def __getitem__(self, key):
            assert key == source_id
            return bytes(alternate)

    outcome = normalize_evm_slither(
        carrier,
        raw=raw,
        plan=plan,
        registry=registry,
        context=context,
        observed_identity=observed,
        source_manifest=_source_manifest(),
        source_bytes_by_id=SplitView(),
        allowed_license_classifications=("AGPL-3.0-only",),
        source_manifest_authority=None,
    )
    expected = hashlib.sha256(SOURCE[60:61]).hexdigest()
    assert {
        row["source_binding"]["statement_sha256"]
        for row in outcome.contribution.occurrences
    } == {expected}


def test_zero_positive_denominator_is_nonduplicated_and_structurally_typed() -> None:
    plan = _plan()[3]
    for mutation, match in (
        (
            lambda value: value["zero_positive_denominators"].append(
                deepcopy(value["zero_positive_denominators"][0])
            ),
            "duplicated",
        ),
        (
            lambda value: value["zero_positive_denominators"][0].update(
                {"capability_id": "evm.slither.not-requested.v1"}
            ),
            "outside",
        ),
    ):
        value = _raw(plan)
        capability_id = "evm.slither.cfg.v1"
        value["facts"] = [
            row
            for row in value["facts"]
            if row["capability_id"] != capability_id
        ]
        value["zero_positive_denominators"] = [
            {
                "capability_id": capability_id,
                "build_variant_id": value["build_variant_id"],
                "denominator_kind": (
                    f"{capability_id}.eligible-source-files.v1"
                ),
                "node_local_ids": [],
                "source_file_ids": [str(_source()["source_file_id"])],
            }
        ]
        mutation(value)
        with pytest.raises(EvmProgramFactsProviderError, match=match):
            parse_evm_slither_raw(_raw_bytes(plan, value), plan)


def test_raw_iteration_order_does_not_change_normalized_contribution() -> None:
    _registry_value, _context_value, _observed, plan, _result, first_outcome = (
        _normalize_fixture()
    )
    shuffled = _raw(plan)
    for key in ("nodes", "occurrences", "facts", "capability_dispositions"):
        shuffled[key] = list(reversed(shuffled[key]))
    second_outcome = _normalize_fixture(shuffled)[5]
    first = first_outcome.contribution
    second = second_outcome.contribution
    # Raw-output provenance is intentionally byte-bound, so result/contribution
    # digests differ.  Portable semantic rows must not depend on tool iteration.
    assert first.nodes == second.nodes
    assert first.occurrences == second.occurrences
    assert first.facts == second.facts
    assert first.capability_accounting == second.capability_accounting


def test_fifty_randomized_provider_orders_preserve_semantic_rows() -> None:
    baseline = _normalize_fixture()[5].contribution
    plan = _plan()[3]
    for seed in range(50):
        rng = random.Random(seed)
        value = _raw(plan)
        for key in (
            "nodes",
            "occurrences",
            "facts",
            "capability_dispositions",
            "debts",
            "zero_positive_denominators",
        ):
            rng.shuffle(value[key])
        candidate = _normalize_fixture(value)[5].contribution
        assert candidate.nodes == baseline.nodes
        assert candidate.occurrences == baseline.occurrences
        assert candidate.facts == baseline.facts
        assert candidate.capability_accounting == (
            baseline.capability_accounting
        )


def test_windows_and_linux_positive_semantic_rows_are_portable() -> None:
    linux = _normalize_fixture()[5].contribution
    registry, context, observed, plan = _plan(
        platform=PlatformIdentity("windows", "amd64")
    )
    raw = _raw_bytes(plan)
    result = parse_evm_slither_raw(raw, plan)
    windows_outcome = normalize_evm_slither(
        result,
        raw=raw,
        plan=plan,
        registry=registry,
        context=context,
        observed_identity=observed,
        source_manifest=_source_manifest(),
        source_bytes_by_id={str(_source()["source_file_id"]): SOURCE},
        allowed_license_classifications=("AGPL-3.0-only",),
        source_manifest_authority=None,
    )
    windows = windows_outcome.contribution
    assert windows.nodes == linux.nodes
    assert windows.occurrences == linux.occurrences
    assert windows.facts == linux.facts
    assert windows.capability_accounting == linux.capability_accounting


@pytest.mark.parametrize(
    "mutate, match",
    [
        (
            lambda value: value.update({"finding": "H-01"}),
            "unknown|closed|field",
        ),
        (
            lambda value: value["facts"][0].update({"severity": "High"}),
            "unknown|closed|field",
        ),
        (
            lambda value: value["tool"].update({"version_output": "drifted"}),
            "tool|version|provenance",
        ),
        (
            lambda value: value.update({"plan_id": "PFP-" + "f" * 24}),
            "plan",
        ),
        (
            lambda value: value["facts"][0].update({"precision": "EXACT\n"}),
            "precision|enum",
        ),
        (
            lambda value: value["facts"][0].update(
                {"relation_kind": "HOST_SEMANTIC_SINK"}
            ),
            "host-semantic",
        ),
        (
            lambda value: value["facts"][0]["context"].update(
                {"host_semantic_kind": "solana.account"}
            ),
            "host-semantic",
        ),
        (
            lambda value: value["facts"][2]["context"].update(
                {"analysis_algorithm": ""}
            ),
            "algorithm",
        ),
    ],
)
def test_closed_raw_schema_and_exact_provenance_reject_overclaim(
    mutate,
    match: str,
) -> None:
    _registry_value, _context_value, _observed, plan = _plan()
    value = _raw(plan)
    mutate(value)
    with pytest.raises(EvmProgramFactsProviderError, match=match):
        parse_evm_slither_raw(_raw_bytes(plan, value), plan)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value["facts"][0].update(
            {"object_local_id": "unknown"}
        ),
        lambda value: value["facts"][1].update(
            {"subject_local_id": "function"}
        ),
        lambda value: value["facts"][3].update(
            {
                "precision": "EXACT",
                "structural_confidence": "PROVIDER_EXACT",
            }
        ),
        lambda value: value["facts"][0].update(
            {"occurrence_local_ids": ["read"]}
        ),
        lambda value: value["facts"][1].update(
            {"provenance_origin": "AST"}
        ),
        lambda value: value["facts"][4].update(
            {"structural_confidence": "UNKNOWN"}
        ),
        lambda value: value["facts"][0]["context"].update(
            {"call_dispatch": "UNKNOWN"}
        ),
        lambda value: value["facts"][4]["context"].update(
            {"dominating_predicates": ["read"]}
        ),
        lambda value: value["facts"][4]["context"].update(
            {"dominating_predicates": ["branch"]}
        ),
        lambda value: value["facts"][5].update(
            {"occurrence_local_ids": ["call"]}
        ),
        lambda value: value["facts"][2].update(
            {"object_local_id": "unknown"}
        ),
        lambda value: value["facts"][4].update(
            {"object_local_id": "function"}
        ),
        lambda value: value["facts"][3].update(
            {
                "relation_kind": "CREATE_OCCURRENCE",
                "precision": "EXACT",
                "structural_confidence": "PROVIDER_EXACT",
            }
        ),
    ],
)
def test_closed_relation_semantics_reject_cross_field_contradictions(
    mutate,
) -> None:
    plan = _plan()[3]
    value = _raw(plan)
    mutate(value)
    with pytest.raises(EvmProgramFactsProviderError, match="semantic|relation"):
        parse_evm_slither_raw(_raw_bytes(plan, value), plan)


@pytest.mark.parametrize(
    "relation_kind",
    EVM_RELATION_FIXTURE_KINDS,
)
def test_every_evm_relation_semantics_row_has_positive_and_negative_fixture(
    relation_kind: str,
) -> None:
    plan = _plan()[3]
    value = _single_relation_raw(plan, relation_kind)
    assert parse_evm_slither_raw(_raw_bytes(plan, value), plan)
    target = next(
        row for row in value["facts"] if row["relation_kind"] == relation_kind
    )
    target["capability_id"] = (
        "evm.slither.cfg.v1"
        if target["capability_id"] != "evm.slither.cfg.v1"
        else "evm.slither.calls.v1"
    )
    with pytest.raises(EvmProgramFactsProviderError, match="semantic"):
        parse_evm_slither_raw(_raw_bytes(plan, value), plan)


def test_relation_fixture_denominator_matches_closed_provider_table() -> None:
    import program_facts_evm_provider as provider_module

    assert set(EVM_RELATION_FIXTURE_KINDS) == set(
        provider_module._RELATION_SEMANTICS
    )


def test_dominating_predicate_requires_branch_kind_ir_provenance_and_scope() -> None:
    plan = _plan()[3]
    value = _raw(plan)
    state_fact = value["facts"][4]
    state_fact["provenance_origin"] = "SSA"
    state_fact["context"]["dominating_predicates"] = ["branch"]
    assert parse_evm_slither_raw(_raw_bytes(plan, value), plan)

    out_of_scope = deepcopy(value)
    branch = next(
        row
        for row in out_of_scope["occurrences"]
        if row["local_id"] == "branch"
    )
    branch["enclosing_local_id"] = "contract"
    with pytest.raises(EvmProgramFactsProviderError, match="semantic|scope"):
        parse_evm_slither_raw(_raw_bytes(plan, out_of_scope), plan)


@pytest.mark.parametrize(
    "raw, match",
    [
        (
            b'{"schema_version":"x","schema_version":"y"}\n',
            "duplicate|raw",
        ),
        (b"# markdown is not a typed provider result\n", "JSON|raw"),
        (b'{"n":1.5}\n', "float|raw|schema"),
        (b"\xef\xbb\xbf{}\n", "BOM|raw|schema"),
        (b"\xff\n", "UTF|raw"),
    ],
)
def test_malformed_json_markdown_float_bom_and_utf8_are_rejected(
    raw: bytes,
    match: str,
) -> None:
    plan = _plan()[3]
    with pytest.raises(EvmProgramFactsProviderError, match=match):
        parse_evm_slither_raw(raw, plan)


@pytest.mark.parametrize(
    "path",
    [
        "../src/Vault.sol",
        "/src/Vault.sol",
        "C:/src/Vault.sol",
        "src\\Vault.sol",
        "src/vault.sol",
        "src/Va\u0301ult.sol",
    ],
)
def test_source_paths_are_exact_portable_nfc_and_case_sensitive(path: str) -> None:
    plan = _plan()[3]
    value = _raw(plan)
    value["nodes"][0]["source"]["path"] = path
    try:
        raw = _raw_bytes(plan, value)
    except ProgramFactsTypeError as exc:
        assert "NFC" in str(exc)
        return
    try:
        result = parse_evm_slither_raw(raw, plan)
    except EvmProgramFactsProviderError as exc:
        assert any(token in str(exc).lower() for token in ("path", "nfc", "raw"))
        return
    registry, context, observed, _plan_value = _plan()
    with pytest.raises(EvmProgramFactsProviderError, match="path|source|NFC|case"):
        normalize_evm_slither(
            result,
            raw=raw,
            plan=plan,
            registry=registry,
            context=context,
            observed_identity=observed,
            source_manifest=_source_manifest(),
            source_bytes_by_id={str(_source()["source_file_id"]): SOURCE},
            allowed_license_classifications=("AGPL-3.0-only",),
            source_manifest_authority=None,
        )


def test_dangling_local_reference_and_duplicate_local_ids_are_rejected() -> None:
    for mutation, match in (
        (
            lambda value: value["facts"][0].update(
                {"subject_local_id": "missing"}
            ),
            "dangling",
        ),
        (
            lambda value: value["nodes"].append(deepcopy(value["nodes"][0])),
            "duplicate",
        ),
    ):
        registry, context, observed, plan = _plan()
        value = _raw(plan)
        mutation(value)
        raw = _raw_bytes(plan, value)
        try:
            result = parse_evm_slither_raw(raw, plan)
        except EvmProgramFactsProviderError as exc:
            assert match in str(exc)
            continue
        with pytest.raises(EvmProgramFactsProviderError, match=match):
            normalize_evm_slither(
                result,
                raw=raw,
                plan=plan,
                registry=registry,
                context=context,
                observed_identity=observed,
                source_manifest=_source_manifest(),
                source_bytes_by_id={str(_source()["source_file_id"]): SOURCE},
                allowed_license_classifications=("AGPL-3.0-only",),
                source_manifest_authority=None,
            )


def test_partial_capability_requires_visible_debt_and_preserves_other_facts() -> None:
    registry, context, observed, plan = _plan()
    value = _raw(plan)
    partial = value["capability_dispositions"][0]
    partial.update(
        {
            "disposition": "PARTIAL",
            "diagnostic_codes": ["ZERO_POSITIVE_OBSERVATIONS"],
            "debt_codes": ["CAPABILITY_PARTIAL"],
        }
    )
    value["facts"] = [
        row
        for row in value["facts"]
        if row["capability_id"] != partial["capability_id"]
    ]
    value["debts"] = [
        {
            "reason": "CAPABILITY_PARTIAL",
            "capability_id": partial["capability_id"],
            "scope_local_ids": ["function"],
            "explanation": "Provider completed but emitted no positive rows.",
            "evidence_refs": [],
            "retryable": True,
            "blocks_reuse": False,
        }
    ]
    raw = _raw_bytes(plan, value)
    result = parse_evm_slither_raw(raw, plan)
    outcome = normalize_evm_slither(
        result,
        raw=raw,
        plan=plan,
        registry=registry,
        context=context,
        observed_identity=observed,
        source_manifest=_source_manifest(),
        source_bytes_by_id={str(_source()["source_file_id"]): SOURCE},
        allowed_license_classifications=("AGPL-3.0-only",),
        source_manifest_authority=None,
    )
    contribution = outcome.contribution
    assert "CAPABILITY_PARTIAL" in contribution.debt_codes
    assert len(contribution.facts) == (
        len(_raw(plan)["facts"])
        - sum(
            1
            for row in _raw(plan)["facts"]
            if row["capability_id"] == partial["capability_id"]
        )
    )
    assert {
        row["disposition"] for row in contribution.capability_accounting
    } == {"PARSED", "PARTIAL"}


def test_resource_ceilings_bound_raw_bytes_rows_and_nesting() -> None:
    plan = _plan()[3]
    raw = _raw_bytes(plan)
    with pytest.raises(EvmProgramFactsProviderError, match="byte|limit"):
        parse_evm_slither_raw(
            raw,
            plan,
            limits=EvmProviderLimits(
                max_raw_bytes=len(raw) - 1,
                max_records=100,
                max_string_bytes=4096,
                max_nesting=20,
            ),
        )


def test_custom_parser_limits_are_narrowing_only_on_parse_and_normalize() -> None:
    registry, context, observed, plan = _plan()
    raw = _raw_bytes(plan)
    widened = EvmProviderLimits(
        max_raw_bytes=int(plan.resources.output_bytes) + 1,
        max_records=250_000,
        max_string_bytes=1 * 1024 * 1024,
        max_nesting=64,
    )
    with pytest.raises(EvmProgramFactsProviderError, match="widen|limit|plan"):
        parse_evm_slither_raw(raw, plan, limits=widened)
    oversized_value = _raw(plan)
    oversized_value["nodes"][0]["display_name"] = "x" * (
        int(plan.resources.output_bytes) + 1
    )
    oversized_raw = _raw_bytes(plan, oversized_value)
    assert len(oversized_raw) > int(plan.resources.output_bytes)
    with pytest.raises(EvmProgramFactsProviderError, match="widen|limit|plan"):
        parse_evm_slither_raw(oversized_raw, plan, limits=widened)
    carrier = parse_evm_slither_raw(raw, plan)
    with pytest.raises(EvmProgramFactsProviderError, match="widen|limit|plan"):
        normalize_evm_slither(
            carrier,
            raw=raw,
            plan=plan,
            registry=registry,
            context=context,
            observed_identity=observed,
            source_manifest=_source_manifest(),
            source_bytes_by_id={str(_source()["source_file_id"]): SOURCE},
            allowed_license_classifications=("AGPL-3.0-only",),
            source_manifest_authority=None,
            limits=widened,
        )
    narrowed = EvmProviderLimits(
        max_raw_bytes=len(raw),
        max_records=250_000,
        max_string_bytes=1 * 1024 * 1024,
        max_nesting=64,
    )
    assert parse_evm_slither_raw(raw, plan, limits=narrowed).result
    value = _raw(plan)
    value["nodes"] = value["nodes"] * 4
    with pytest.raises(EvmProgramFactsProviderError, match="record|limit"):
        parse_evm_slither_raw(
            _raw_bytes(plan, value),
            plan,
            limits=EvmProviderLimits(
                max_raw_bytes=1048576,
                max_records=10,
                max_string_bytes=4096,
                max_nesting=20,
            ),
        )
    deeply_nested = _raw(plan)
    deeply_nested["facts"][0]["context"]["dominating_predicates"] = [
        [[[[["too-deep"]]]]]
    ]
    with pytest.raises(EvmProgramFactsProviderError, match="nest|depth|schema"):
        parse_evm_slither_raw(
            _raw_bytes(plan, deeply_nested),
            plan,
            limits=EvmProviderLimits(
                max_raw_bytes=1048576,
                max_records=100,
                max_string_bytes=4096,
                max_nesting=4,
            ),
        )


def test_version_drift_is_plan_debt_not_provider_execution() -> None:
    registry = _registry()
    context = _context()
    observed = replace(
        _observed(registry, context),
        distribution_version="0.11.4",
        version_output="slither 0.11.4",
    )
    decision = plan_evm_slither(
        registry=registry,
        provider_run_id="evm.slither.typed.run-0",
        context=context,
        observed_identity=observed,
        argv=("slither", "--json", "-"),
        resources=ProviderResources(600, 1073741824, 1048576, 1048576),
        allowed_license_classifications=("AGPL-3.0-only",),
        source_manifest_authority=None,
    )
    assert decision.ready is False
    assert decision.plan is None
    assert any("VERSION_DRIFT" in debt.code.name for debt in decision.debts)


def test_unavailable_provider_still_emits_valid_three_sidecar_bundle() -> None:
    context = _context()
    emission = emit_evm_unavailable_sidecars(
        context=context,
        source_manifest=_source_manifest(),
        source_bytes_by_id={str(_source()["source_file_id"]): SOURCE},
        build_variants=(_variant(),),
        audit_snapshot={
            "snapshot_digest": H0,
            "source_scope_digest": H1,
            "audit_config_digest": H0,
            "methodology_digest": H7,
            "toolchain_digest": H2,
        },
        phase_io={
            "contract_digest": H0,
            "launch_digest": H1,
            "input_set_digest": H2,
            "work_unit_key": (
                "sc/thorough/evm/claude/recon/program_facts_bake"
            ),
            "ledger_binding_state": "PRECOMMIT",
            "ledger_record_digest": "",
        },
        reason="PROVIDER_UNAVAILABLE",
        explanation="Pinned Slither provider was not available.",
    )
    assert set(emission.sidecars) == {
        "mechanical_program_facts.v1.json",
        "mechanical_program_facts_receipt.v1.json",
        "mechanical_program_facts_debt.v1.json",
    }
    assert emission.production_authority_established is False
    assert emission.consumer_activation is False
    assert not emission.payload["facts"]
    assert {
        row["status"] for row in emission.payload["coverage"]
    } == {"UNKNOWN"}
    assert emission.receipt["status"] == "UNAVAILABLE"
    assert len(emission.debt["debts"]) == len(EVM_CAPABILITY_IDS)
    assert all(
        raw.endswith(b"\n") and not raw.startswith(b"\xef\xbb\xbf")
        for raw in emission.sidecars.values()
    )

    bundle = validate_program_facts_bundle_structural_test_only(
        authority_mode=STRUCTURAL_TEST_ONLY,
        payload=emission.payload,
        debt=emission.debt,
        receipt=emission.receipt,
        payload_file_bytes=emission.sidecars[
            "mechanical_program_facts.v1.json"
        ],
        debt_file_bytes=emission.sidecars[
            "mechanical_program_facts_debt.v1.json"
        ],
        receipt_file_bytes=emission.sidecars[
            "mechanical_program_facts_receipt.v1.json"
        ],
        source_bytes_by_id={str(_source()["source_file_id"]): SOURCE},
        source_authority_digest=H6,
    )
    assert bundle.production_authority_established is False


@pytest.mark.parametrize(
    (
        "reason",
        "coverage_status",
        "receipt_status",
        "retryable",
        "blocks_reuse",
    ),
    UNAVAILABLE_REASON_CASES,
)
def test_unavailable_reason_policy_is_closed_truthful_and_source_scoped(
    reason: str,
    coverage_status: str,
    receipt_status: str,
    retryable: bool,
    blocks_reuse: bool,
) -> None:
    emission = _emit_unavailable(reason)
    provider_debts = [
        row for row in emission.debt["debts"] if row["provider_id"]
    ]
    assert {row["status"] for row in emission.payload["coverage"]} == {
        coverage_status
    }
    assert emission.receipt["status"] == receipt_status
    assert {row["retryable"] for row in provider_debts} == {retryable}
    assert {row["blocks_reuse"] for row in provider_debts} == {
        blocks_reuse
    }
    source_id = str(_source()["source_file_id"])
    assert all(source_id in row["scope_ids"] for row in provider_debts)
    assert emission.debt["summary"]["affected_source_file_ids"] == (
        source_id,
    )
    assert emission.debt["summary"]["has_blocking_reuse_debt"] is (
        blocks_reuse
    )


def test_unavailable_reason_policy_rejects_unclassified_reason() -> None:
    with pytest.raises(EvmProgramFactsProviderError, match="closed|policy"):
        _emit_unavailable("CAPABILITY_PARTIAL")


def test_unavailable_reason_fixture_denominator_matches_closed_policy() -> None:
    import program_facts_evm_provider as provider_module

    assert {row[0] for row in UNAVAILABLE_REASON_CASES} == set(
        provider_module._UNAVAILABLE_REASON_POLICY
    )


def test_source_bytes_toctou_is_rejected_before_sidecars_can_validate() -> None:
    context = _context()
    with pytest.raises(EvmProgramFactsProviderError, match="source|digest|bytes"):
        emit_evm_unavailable_sidecars(
            context=context,
            source_manifest=_source_manifest(),
            source_bytes_by_id={
                str(_source()["source_file_id"]): SOURCE + b"// mutation\n"
            },
            build_variants=(_variant(),),
            audit_snapshot={
                "snapshot_digest": H0,
                "source_scope_digest": H1,
                "audit_config_digest": H0,
                "methodology_digest": H7,
                "toolchain_digest": H2,
            },
            phase_io={
                "contract_digest": H0,
                "launch_digest": H1,
                "input_set_digest": H2,
                "work_unit_key": (
                    "sc/thorough/evm/claude/recon/program_facts_bake"
                ),
                "ledger_binding_state": "PRECOMMIT",
                "ledger_record_digest": "",
            },
            reason="PROVIDER_UNAVAILABLE",
            explanation="Pinned Slither provider was not available.",
        )


def test_physical_identity_alias_rejects_symlink_reparse_or_hardlink_denominator() -> None:
    manifest = _source_manifest()
    alias = deepcopy(manifest["eligible_files"][0])
    alias["path"] = "src/Alias.sol"
    alias["path_casefold_key"] = "src/alias.sol"
    alias["source_file_id"] = derive_stable_id(
        "PFS",
        {
            "source_scope_digest": H1,
            "path": alias["path"],
            "source_sha256": alias["source_sha256"],
            "scope_class": alias["scope_class"],
        },
    )
    # The exact same physical identity is the source-authority signal for an
    # alias through a symlink, junction/reparse point, or hardlink.
    manifest["eligible_files"].append(alias)
    manifest["eligible_files"].sort(key=lambda row: row["source_file_id"])
    manifest["file_count"] = 2
    manifest["byte_count"] = len(SOURCE) * 2
    manifest["manifest_digest"] = derive_source_manifest_digest(manifest)
    context = replace(
        _context(),
        source_manifest_digest=str(manifest["manifest_digest"]),
    )
    with pytest.raises(
        EvmProgramFactsProviderError,
        match="symlink|reparse|hardlink|physical",
    ):
        emit_evm_unavailable_sidecars(
            context=context,
            source_manifest=manifest,
            source_bytes_by_id={
                str(_source()["source_file_id"]): SOURCE,
                str(alias["source_file_id"]): SOURCE,
            },
            build_variants=(_variant(),),
            audit_snapshot={
                "snapshot_digest": H0,
                "source_scope_digest": H1,
                "audit_config_digest": H0,
                "methodology_digest": H7,
                "toolchain_digest": H2,
            },
            phase_io={
                "contract_digest": H0,
                "launch_digest": H1,
                "input_set_digest": H2,
                "work_unit_key": (
                    "sc/thorough/evm/claude/recon/program_facts_bake"
                ),
                "ledger_binding_state": "PRECOMMIT",
                "ledger_record_digest": "",
            },
            reason="PROVIDER_UNAVAILABLE",
            explanation="Pinned Slither provider was not available.",
        )


def test_empty_source_project_is_explicit_unsupported_not_clean() -> None:
    empty_manifest: dict[str, object] = {
        "policy_version": "plamen.program_facts_source_scope.v1",
        "eligible_files": [],
        "excluded_files": [],
        "file_count": 0,
        "byte_count": 0,
        "manifest_digest": H0,
    }
    empty_manifest["manifest_digest"] = derive_source_manifest_digest(
        empty_manifest
    )
    context = replace(
        _context(),
        source_manifest_digest=str(empty_manifest["manifest_digest"]),
    )
    emission = emit_evm_unavailable_sidecars(
        context=context,
        source_manifest=empty_manifest,
        source_bytes_by_id={},
        build_variants=(_variant(),),
        audit_snapshot={
            "snapshot_digest": H0,
            "source_scope_digest": H1,
            "audit_config_digest": H0,
            "methodology_digest": H7,
            "toolchain_digest": H2,
        },
        phase_io={
            "contract_digest": H0,
            "launch_digest": H1,
            "input_set_digest": H2,
            "work_unit_key": (
                "sc/thorough/evm/claude/recon/program_facts_bake"
            ),
            "ledger_binding_state": "PRECOMMIT",
            "ledger_record_digest": "",
        },
        reason="PROVIDER_UNAVAILABLE",
        explanation="No eligible Solidity source was available to the provider.",
    )
    assert emission.payload["source_files"] == ()
    assert emission.payload["facts"] == ()
    assert emission.debt["debts"]
    assert {
        row["status"] for row in emission.payload["coverage"]
    } == {"UNKNOWN"}


def test_windows_and_linux_unavailable_payload_bytes_are_identical() -> None:
    def emit(platform: PlatformIdentity):
        return emit_evm_unavailable_sidecars(
            context=_context(platform=platform),
            source_manifest=_source_manifest(),
            source_bytes_by_id={str(_source()["source_file_id"]): SOURCE},
            build_variants=(_variant(),),
            audit_snapshot={
                "snapshot_digest": H0,
                "source_scope_digest": H1,
                "audit_config_digest": H0,
                "methodology_digest": H7,
                "toolchain_digest": H2,
            },
            phase_io={
                "contract_digest": H0,
                "launch_digest": H1,
                "input_set_digest": H2,
                "work_unit_key": (
                    "sc/thorough/evm/claude/recon/program_facts_bake"
                ),
                "ledger_binding_state": "PRECOMMIT",
                "ledger_record_digest": "",
            },
            reason="PROVIDER_UNAVAILABLE",
            explanation="Pinned Slither provider was not available.",
        )

    windows = emit(PlatformIdentity("windows", "amd64"))
    linux = emit(PlatformIdentity("linux", "amd64"))
    assert windows.sidecars[
        "mechanical_program_facts.v1.json"
    ] == linux.sidecars["mechanical_program_facts.v1.json"]
    assert windows.sidecars[
        "mechanical_program_facts_debt.v1.json"
    ] == linux.sidecars["mechanical_program_facts_debt.v1.json"]


def test_provider_module_has_no_execution_filesystem_markdown_or_network_lane() -> None:
    import program_facts_evm_provider as provider_module

    source = inspect.getsource(provider_module)
    for forbidden in (
        "subprocess",
        "Popen(",
        "os.system",
        "requests.",
        "urllib.",
        "slither.slither",
        "markdown",
        "write_text(",
        "write_bytes(",
        "open(",
    ):
        assert forbidden not in source


def test_returned_documents_are_recursively_immutable() -> None:
    emission = emit_evm_unavailable_sidecars(
        context=_context(),
        source_manifest=_source_manifest(),
        source_bytes_by_id={str(_source()["source_file_id"]): SOURCE},
        build_variants=(_variant(),),
        audit_snapshot={
            "snapshot_digest": H0,
            "source_scope_digest": H1,
            "audit_config_digest": H0,
            "methodology_digest": H7,
            "toolchain_digest": H2,
        },
        phase_io={
            "contract_digest": H0,
            "launch_digest": H1,
            "input_set_digest": H2,
            "work_unit_key": (
                "sc/thorough/evm/claude/recon/program_facts_bake"
            ),
            "ledger_binding_state": "PRECOMMIT",
            "ledger_record_digest": "",
        },
        reason="PROVIDER_UNAVAILABLE",
        explanation="Pinned Slither provider was not available.",
    )
    with pytest.raises(TypeError):
        emission.payload["ecosystem"] = "mixed"
    with pytest.raises(TypeError):
        emission.payload["snapshot_ref"]["snapshot_digest"] = H7
    with pytest.raises(TypeError):
        emission.sidecars["new.json"] = b"{}\n"


def test_empty_compiled_denominator_degrades_and_retains_positive_rows() -> None:
    registry, context, observed, plan = _plan()
    value = _raw(plan)
    value["compiled_source_file_ids"] = []
    raw = _raw_bytes(plan, value)
    result = parse_evm_slither_raw(raw, plan)
    outcome = normalize_evm_slither(
        result,
        raw=raw,
        plan=plan,
        registry=registry,
        context=context,
        observed_identity=observed,
        source_manifest=_source_manifest(),
        source_bytes_by_id={str(_source()["source_file_id"]): SOURCE},
        allowed_license_classifications=("AGPL-3.0-only",),
        source_manifest_authority=None,
    )
    assert set(outcome.effective_result.capabilities_partial) == set(
        EVM_CAPABILITY_IDS
    )
    assert len(outcome.contribution.facts) == len(value["facts"])
