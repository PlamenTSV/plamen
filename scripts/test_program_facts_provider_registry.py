from __future__ import annotations

from copy import deepcopy
import hashlib

import pytest

from program_facts_provider_registry import (
    DEFAULT_REGISTRY_PATH,
    NO_PROVIDER_AUTHORITY,
    ProgramFactsProviderRegistryError,
    ProviderPolicyDebtCode,
    STRUCTURAL_TEST_ONLY,
    load_program_facts_provider_registry_bytes,
)
from program_facts_types import canonical_file_bytes, canonical_json_bytes


H0 = "0" * 64
H1 = "1" * 64
H2 = "2" * 64
H3 = "3" * 64
H4 = "4" * 64
H5 = "5" * 64


def synthetic_provider(
    provider_id: str = "fixture.compiler.primary",
    *,
    maximum_precision: str = "EXACT",
) -> dict[str, object]:
    return {
        "provider_id": provider_id,
        "provider_schema_version": (
            f"plamen.program_facts_provider.{provider_id}.v1"
        ),
        "adapter": {
            "module": "fixture_program_facts_provider",
            "symbol": "plan_fixture_provider",
        },
        "supported_ecosystems": ["evm"],
        "supported_languages": ["solidity"],
        "toolchain_ranges": [
            {
                "toolchain": "solc",
                "version_range": ">=0.8,<0.9",
                "identity_digest": "6" * 64,
            }
        ],
        "capabilities": [
            {
                "capability_id": "fixture.calls.v1",
                "maximum_precision": maximum_precision,
                "allowed_provenance_origins": ["AST"],
                "allowed_relation_kinds": ["RESOLVED_STATIC_CALL"],
                "host_semantic_authority": False,
            }
        ],
        "raw_binding": {
            "raw_schema_digest": H0,
            "parser_callable": "parse_fixture_raw",
            "parser_source_digest": H1,
        },
        "tool_identity": {
            "kind": "EXECUTABLE",
            "name": "fixture-tool",
            "command": "fixture-tool",
            "module": "",
            "executable_sha256": H2,
            "module_sha256": "",
        },
        "invocation_policy": {
            "argv_template": ["fixture-tool", "--json", "-"],
            "typed_substitutions": [],
            "configuration_inputs": [],
        },
        "resolution_policy": "PINNED_DISTRIBUTION",
        "expected_version_syntax": r"^fixture-tool 1\.2\.3$",
        "distribution": {
            "kind": "python-wheel",
            "name": "fixture-tool",
            "version": "1.2.3",
            "checksum": H3,
            "module_source_digest": "",
        },
        "license_classification": "MIT",
        "limits": {
            "time_seconds": 60,
            "memory_bytes": 268435456,
            "input_bytes": 1048576,
            "output_bytes": 2097152,
        },
        "supported_platforms": [
            {"os": "linux", "architectures": ["amd64"]},
            {"os": "windows", "architectures": ["amd64"]},
        ],
        "fallback": {},
        "authority": {
            "semantic_authority": "ADDITIVE_PROPOSAL_ONLY",
            "terminal_negative_authority": False,
            "can_suppress": False,
            "can_demote": False,
            "can_refute": False,
            "can_mark_examined": False,
            "can_certify_clean": False,
        },
        "installation_provenance": {
            "kind": "checked-lock",
            "source": "rules/provider-fixture.lock",
            "digest": H5,
        },
        "environment_policy": {
            "inheritance": "DENY_BY_DEFAULT",
            "allowed_names": ["LANG"],
            "required_names": ["LANG"],
            "forbidden_secret_names": ["API_TOKEN", "SECRET"],
            "allow_secret_values": False,
            "value_digest_required": True,
        },
        "install_policy": {
            "mode": "PREINSTALLED_VERIFIED",
            "network_allowed": False,
            "mutable_reference_allowed": False,
            "installer": "pip",
            "lock_identity": "rules/provider-fixture.lock",
            "lock_digest": H5,
        },
        "supply_chain_policy": {
            "network_during_bake": False,
            "pinned": True,
            "checksum_required": True,
        },
    }


def synthetic_registry(*providers: dict[str, object]) -> dict[str, object]:
    rows = list(providers or (synthetic_provider(),))
    rows.sort(key=lambda row: str(row["provider_id"]))
    return {
        "schema_version": "plamen.program_facts_provider_registry.v1",
        "release_state": "REVIEWED_PROVIDER_AUTHORITY",
        "providers": rows,
    }


def _load(value: dict[str, object]):
    return load_program_facts_provider_registry_bytes(
        canonical_file_bytes(value),
        authority_mode=STRUCTURAL_TEST_ONLY,
    )


def test_shipped_registry_has_exact_evm_emit_only_row_and_hash_freeze() -> None:
    registry = load_program_facts_provider_registry_bytes(
        DEFAULT_REGISTRY_PATH.read_bytes(),
        authority_mode=STRUCTURAL_TEST_ONLY,
    )

    assert registry.release_state == "REVIEWED_PROVIDER_AUTHORITY"
    assert tuple(row["provider_id"] for row in registry.providers) == (
        "evm.slither.typed",
    )
    assert registry.registry_digest == (
        "64336aa1a3764312f82f7b670172195d6fd96202d703572ee129805757b22069"
    )
    assert registry.file_sha256 == (
        "c1e52834e46e85b36dce7ba11de8f1cfd47f487335724eb05fe65976c18e3318"
    )
    assert registry.canonical_bytes == DEFAULT_REGISTRY_PATH.read_bytes()
    assert registry.canonical_bytes == canonical_file_bytes(registry.to_dict())

    decision = registry.provider("evm.slither.typed")
    assert decision.ready is False
    assert decision.provider is not None
    assert (
        decision.debts[0].code
        is ProviderPolicyDebtCode.STRUCTURAL_TEST_ONLY
    )
    assert decision.debts[0].blocks_reuse is True
    assert decision.debts[0].terminal_negative_authority is False


def test_synthetic_reviewed_registry_replays_canonical_bytes_and_digest() -> None:
    value = synthetic_registry()
    registry = _load(value)
    expected = hashlib.sha256(canonical_json_bytes(value)).hexdigest()

    assert registry.registry_digest == expected
    assert registry.provider("fixture.compiler.primary").ready is False
    assert (
        registry.provider("fixture.compiler.primary").debts[0].code
        is ProviderPolicyDebtCode.STRUCTURAL_TEST_ONLY
    )
    assert registry.to_dict() == value
    with pytest.raises(TypeError):
        registry.value["release_state"] = NO_PROVIDER_AUTHORITY
    with pytest.raises(TypeError):
        registry.providers[0]["provider_id"] = "mutated.provider"

    replay = load_program_facts_provider_registry_bytes(
        registry.canonical_bytes,
        authority_mode=STRUCTURAL_TEST_ONLY,
        expected_registry_digest="sha256:" + expected,
    )
    assert replay.canonical_bytes == registry.canonical_bytes
    with pytest.raises(ProgramFactsProviderRegistryError, match="digest"):
        load_program_facts_provider_registry_bytes(
            registry.canonical_bytes,
            authority_mode=STRUCTURAL_TEST_ONLY,
            expected_registry_digest=H4,
        )


def test_toolchain_range_can_bind_exact_identity_per_run() -> None:
    provider = synthetic_provider()
    toolchain = provider["toolchain_ranges"][0]
    del toolchain["identity_digest"]
    toolchain["identity_policy"] = "RECEIPT_EXACT_PER_RUN"

    registry = _load(synthetic_registry(provider))

    assert registry.providers[0]["toolchain_ranges"] == (
        {
            "toolchain": "solc",
            "version_range": ">=0.8,<0.9",
            "identity_policy": "RECEIPT_EXACT_PER_RUN",
        },
    )


@pytest.mark.parametrize("mode", ("both", "neither", "unknown"))
def test_toolchain_identity_policy_is_closed_and_unambiguous(mode: str) -> None:
    provider = synthetic_provider()
    toolchain = provider["toolchain_ranges"][0]
    if mode in {"neither", "unknown"}:
        del toolchain["identity_digest"]
    if mode in {"both", "unknown"}:
        toolchain["identity_policy"] = (
            "UNREVIEWED"
            if mode == "unknown"
            else "RECEIPT_EXACT_PER_RUN"
        )

    with pytest.raises(
        ProgramFactsProviderRegistryError,
        match="toolchain|identity",
    ):
        _load(synthetic_registry(provider))


@pytest.mark.parametrize(
    "mutation, message",
    [
        (
            lambda value: value.update(
                {"schema_version": "plamen.program_facts_provider_registry.v2"}
            ),
            "schema",
        ),
        (
            lambda value: value.update({"unknown": True}),
            "schema|unknown",
        ),
        (
            lambda value: value["providers"].append(
                deepcopy(value["providers"][0])
            ),
            "duplicate",
        ),
        (
            lambda value: value["providers"][0]["distribution"].update(
                {"version": "latest"}
            ),
            "schema|mutable|unpinned",
        ),
        (
            lambda value: value["providers"][0][
                "supply_chain_policy"
            ].update({"pinned": False}),
            "pinned",
        ),
        (
            lambda value: value["providers"][0]["distribution"].update(
                {"checksum": ""}
            ),
            "checksum",
        ),
        (
            lambda value: value["providers"][0][
                "environment_policy"
            ]["allowed_names"].append("API_TOKEN"),
            "sorted|secret|forbidden",
        ),
        (
            lambda value: value["providers"][0]["install_policy"].update(
                {"mutable_reference_allowed": True}
            ),
            "schema|immutable|installation",
        ),
    ],
)
def test_registry_rejects_schema_drift_mutable_pins_and_policy_broadening(
    mutation, message
) -> None:
    value = synthetic_registry()
    mutation(value)
    with pytest.raises(ProgramFactsProviderRegistryError, match=message):
        _load(value)


def test_registry_rejects_capability_specific_fallback_precision_broadening() -> None:
    primary = synthetic_provider("fixture.compiler.primary")
    fallback = synthetic_provider(
        "fixture.compiler.source_fallback",
        maximum_precision="SYNTACTIC",
    )
    primary["fallback"] = {
        "provider_id": "fixture.compiler.source_fallback",
        "maximum_precision": "EXACT",
    }
    value = synthetic_registry(primary, fallback)

    with pytest.raises(
        ProgramFactsProviderRegistryError,
        match="fallback.*precision|fallback authority",
    ):
        _load(value)


def test_raw_registry_parser_rejects_noncanonical_and_duplicate_json_keys() -> None:
    with pytest.raises(ProgramFactsProviderRegistryError, match="canonical"):
        load_program_facts_provider_registry_bytes(
            b'{ "providers": [], "release_state": "NO_PROVIDER_AUTHORITY", '
            b'"schema_version": "plamen.program_facts_provider_registry.v1" }\n',
            authority_mode=STRUCTURAL_TEST_ONLY,
        )
    with pytest.raises(ProgramFactsProviderRegistryError, match="duplicate"):
        load_program_facts_provider_registry_bytes(
            b'{"providers":[],"providers":[],"release_state":'
            b'"NO_PROVIDER_AUTHORITY","schema_version":'
            b'"plamen.program_facts_provider_registry.v1"}\n',
            authority_mode=STRUCTURAL_TEST_ONLY,
        )
