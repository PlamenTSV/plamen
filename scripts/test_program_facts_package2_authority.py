from __future__ import annotations

from copy import deepcopy
import hashlib

import pytest

import program_facts_types as program_facts_module
from program_facts_types import (
    ProgramFactsPayload,
    ProgramFactsTypeError,
    canonical_file_bytes,
    canonical_json_bytes,
    derive_debt_id,
    derive_fact_id,
    derive_node_id,
    derive_occurrence_id,
    derive_program_facts_reuse_key,
    derive_source_manifest_digest,
    derive_stable_id,
    signed_payload,
    validate_program_facts_bundle as _validate_production_program_facts_bundle,
    validate_program_facts_bundle_structural_test_only as _validate_program_facts_bundle,
    validate_program_facts_debt,
    validate_program_facts_payload,
    validate_program_facts_provider_registry,
    validate_program_facts_receipt,
)
from test_program_facts_provider_registry import (
    synthetic_provider,
    synthetic_registry,
)


H0 = "0" * 64
H1 = "1" * 64
H2 = "2" * 64
SOURCE_BYTES = b"contract C {\n    function f() external {}\n}\n"


def validate_program_facts_bundle(**kwargs):
    """Keep package-2 fixtures explicit while production requires the binding."""

    kwargs.setdefault(
        "source_authority_digest",
        (
            kwargs["receipt"]["source_authority_digest"]
            if kwargs.get("receipt") is not None
            else H2
        ),
    )
    kwargs["authority_mode"] = "STRUCTURAL_TEST_ONLY"
    return _validate_program_facts_bundle(**kwargs)


def _authority() -> dict[str, object]:
    return {
        "semantic_authority": "ADDITIVE_PROPOSAL_ONLY",
        "terminal_negative_authority": False,
        "can_suppress": False,
        "can_demote": False,
        "can_refute": False,
        "can_mark_examined": False,
        "can_certify_clean": False,
    }


def _source() -> dict[str, object]:
    binding = {
        "source_scope_digest": H1,
        "path": "src/C.sol",
        "source_sha256": hashlib.sha256(SOURCE_BYTES).hexdigest(),
        "scope_class": "PRODUCTION",
    }
    return {
        "source_file_id": derive_stable_id("PFS", binding),
        "path": binding["path"],
        "path_casefold_key": "src/c.sol",
        "source_sha256": binding["source_sha256"],
        "size_bytes": len(SOURCE_BYTES),
        "language": "solidity",
        "scope_class": binding["scope_class"],
        "physical_identity_digest": H2,
    }


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


def _binding(source_id: str, start: int, end: int) -> dict[str, object]:
    def line_col(offset: int) -> tuple[int, int]:
        prefix = SOURCE_BYTES[:offset]
        return prefix.count(b"\n") + 1, len(prefix.rsplit(b"\n", 1)[-1])

    start_line, start_column = line_col(start)
    end_line, end_column = line_col(end)
    return {
        "source_file_id": source_id,
        "start_byte": start,
        "end_byte": end,
        "start_line": start_line,
        "start_column": start_column,
        "end_line": end_line,
        "end_column": end_column,
        "statement_sha256": hashlib.sha256(SOURCE_BYTES[start:end]).hexdigest(),
    }


def _node(source: dict[str, object], variant: dict[str, object]) -> dict[str, object]:
    row: dict[str, object] = {
        "node_id": "PFN-" + "0" * 24,
        "kind": "FUNCTION",
        "qualified_name": "C.f()",
        "display_name": "f",
        "build_variant_id": variant["build_variant_id"],
        "source_binding": _binding(str(source["source_file_id"]), 17, 41),
        "signature": {
            "canonical": "f()",
            "language_specific": {},
            "signature_fact_ref": "",
        },
        "attributes": [],
    }
    row["node_id"] = derive_node_id("evm", row)
    return row


def _occurrence(
    source: dict[str, object], node: dict[str, object]
) -> dict[str, object]:
    row: dict[str, object] = {
        "occurrence_id": "PFO-" + "0" * 24,
        "kind": "RETURN_SITE",
        "enclosing_node_id": node["node_id"],
        "source_binding": _binding(str(source["source_file_id"]), 39, 39),
        "ir_binding": {},
    }
    row["occurrence_id"] = derive_occurrence_id(row)
    return row


def _fact(
    variant: dict[str, object],
    node: dict[str, object],
    occurrence: dict[str, object],
) -> dict[str, object]:
    row: dict[str, object] = {
        "fact_id": "PFF-" + "0" * 24,
        "relation_kind": "CONTAINS",
        "subject_id": node["node_id"],
        "object_id": node["node_id"],
        "occurrence_ids": [occurrence["occurrence_id"]],
        "build_variant_id": variant["build_variant_id"],
        "provider_run_id": "evm.slither.run-0",
        "capability_id": "evm.slither.calls.v1",
        "provenance_origin": "COMPILER_IR",
        "precision": "EXACT",
        "coverage_scope": "FUNCTION",
        "structural_confidence": "PROVIDER_EXACT",
        "context": {
            "call_dispatch": "INTERNAL",
            "analysis_algorithm": "",
            "root_set_digest": "",
            "dominating_predicates": [],
            "host_semantic_kind": "",
        },
        "semantic_authority": "ADDITIVE_PROPOSAL_ONLY",
        "attestations": ["evm.slither.run-0"],
    }
    row["fact_id"] = derive_fact_id(row)
    return row


def _coverage(
    source: dict[str, object],
    variant: dict[str, object],
    *,
    status: str = "FULL",
    debt_ids: list[str] | None = None,
) -> dict[str, object]:
    eligible = [str(source["source_file_id"])]
    semantic = {
        "capability_id": "evm.slither.calls.v1",
        "build_variant_id": variant["build_variant_id"],
        "status": status,
        "eligible_source_file_ids": eligible,
        "covered_source_file_ids": eligible if status == "FULL" else [],
        "excluded_source_file_ids": [],
        "unresolved_debt_ids": list(debt_ids or []),
        "denominator_digest": hashlib.sha256(
            canonical_json_bytes(
                {
                    "eligible_source_file_ids": eligible,
                    "excluded_source_file_ids": [],
                }
            )
        ).hexdigest(),
        "terminal_negative_authority": False,
    }
    return {"coverage_id": derive_stable_id("PFC", semantic), **semantic}


def _payload() -> dict[str, object]:
    source = _source()
    variant = _variant()
    node = _node(source, variant)
    occurrence = _occurrence(source, node)
    unsigned = {
        "schema_version": "plamen.mechanical_program_facts.v1",
        "canonicalization_version": "plamen.canonical_json.v1",
        "authority": _authority(),
        "snapshot_ref": {
            "snapshot_digest": H0,
            "source_scope_digest": H1,
            "source_manifest_digest": _source_manifest(source)["manifest_digest"],
        },
        "ecosystem": "evm",
        "build_variants": [variant],
        "source_files": [source],
        "provider_capability_refs": ["evm.slither.calls.v1"],
        "nodes": [node],
        "occurrences": [occurrence],
        "facts": [_fact(variant, node, occurrence)],
        "coverage": [_coverage(source, variant)],
    }
    return signed_payload(unsigned, "payload_sha256")


def _empty_debt() -> dict[str, object]:
    return signed_payload(
        {
            "schema_version": "plamen.mechanical_program_facts_debt.v1",
            "snapshot_digest": H0,
            "source_manifest_digest": _source_manifest(_source())["manifest_digest"],
            "authority": "MANDATORY_REVIEW_NO_NEGATIVE_INFERENCE",
            "debts": [],
            "summary": {
                "by_reason": {},
                "affected_capabilities": [],
                "affected_source_file_ids": [],
                "has_blocking_reuse_debt": False,
            },
        },
        "debt_sha256",
    )


def _registry() -> dict[str, object]:
    provider = synthetic_provider("evm.slither.provider")
    provider.update(
        {
            "adapter": {
                "module": "program_facts_providers.evm_slither",
                "symbol": "plan_evm_slither",
            },
            "toolchain_ranges": [
                {
                    "toolchain": "solc",
                    "version_range": ">=0.8,<0.9",
                    "identity_digest": H2,
                }
            ],
            "capabilities": [
                {
                    "capability_id": "evm.slither.calls.v1",
                    "maximum_precision": "EXACT",
                    "allowed_provenance_origins": ["AST"],
                    "allowed_relation_kinds": ["RESOLVED_STATIC_CALL"],
                    "host_semantic_authority": False,
                }
            ],
            "raw_binding": {
                "raw_schema_digest": H0,
                "parser_callable": "parse_evm_slither_raw",
                "parser_source_digest": H1,
            },
            "tool_identity": {
                "kind": "EXECUTABLE",
                "name": "slither",
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
                "checksum": H2,
                "module_source_digest": "",
            },
            "license_classification": "AGPL-3.0",
            "limits": {
                "time_seconds": 600,
                "memory_bytes": 1073741824,
                "input_bytes": 1048576,
                "output_bytes": 1048576,
            },
            "supported_platforms": [
                {"os": "windows", "architectures": ["amd64"]}
            ],
            "installation_provenance": {
                "kind": "checked-lock",
                "source": "requirements-provider.txt",
                "digest": H2,
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
                "lock_identity": "requirements-provider.txt",
                "lock_digest": H2,
            },
        }
    )
    return synthetic_registry(provider)


def _source_manifest(source: dict[str, object]) -> dict[str, object]:
    value: dict[str, object] = {
        "policy_version": "plamen.program_facts_source_scope.v1",
        "eligible_files": [deepcopy(source)],
        "excluded_files": [],
        "file_count": 1,
        "byte_count": len(SOURCE_BYTES),
        "manifest_digest": H0,
    }
    value["manifest_digest"] = derive_source_manifest_digest(value)
    return value


def _receipt(
    payload: dict[str, object],
    debt: dict[str, object],
    registry: dict[str, object],
) -> dict[str, object]:
    source = payload["source_files"][0]
    variant = payload["build_variants"][0]
    registry_digest = hashlib.sha256(canonical_json_bytes(registry)).hexdigest()
    facts_bytes = canonical_file_bytes(payload)
    debt_bytes = canonical_file_bytes(debt)
    unsigned = {
        "schema_version": "plamen.mechanical_program_facts_receipt.v1",
        "run_id": "fixture-run",
        "status": "WRITTEN",
        "audit_snapshot": {
            "snapshot_digest": H0,
            "source_scope_digest": H1,
            "audit_config_digest": H0,
            "methodology_digest": H1,
            "toolchain_digest": H2,
        },
        "source_authority_digest": H2,
        "source_manifest": _source_manifest(source),
        "build_attempts": [
            {
                "build_variant_id": variant["build_variant_id"],
                "variant_digest": variant["variant_digest"],
                "build_root_id": "root-0",
                "build_root_path": "",
                "manifest_digests": [{"path": "foundry.toml", "sha256": H1}],
                "lockfile_digests": [],
                "dependency_closure_digest": H1,
                "toolchain_identities": [
                    {"name": "solc", "version": "0.8.28", "identity_digest": H2}
                ],
                "target_triples": [],
                "profile": "default",
                "features": [],
                "tags": [],
                "remappings": [],
                "defines": [],
                "package_selection": [],
                "generated_source_policy": "BOUND_INCLUDED",
                "eligible_source_file_ids": [source["source_file_id"]],
                "compiled_source_file_ids": [source["source_file_id"]],
                "excluded_source_file_ids": [],
                "failed_source_file_ids": [],
                "stdout_cas_ref": "sha256:" + H0,
                "stderr_cas_ref": "sha256:" + H1,
                "stdout_truncated": False,
                "stderr_truncated": False,
                "outcome": "SUCCEEDED",
                "debt_ids": [],
            }
        ],
        "provider_runs": [
            {
                "provider_run_id": "evm.slither.run-0",
                "provider_id": "evm.slither.provider",
                "provider_schema_version": "v1",
                "provider_registry_digest": registry_digest,
                "implementation_digest": H2,
                "executable_or_module_digest": H2,
                "version_output": "slither 0.11.3",
                "version_output_digest": hashlib.sha256(
                    b"slither 0.11.3"
                ).hexdigest(),
                "parser_callable": "parse_evm_slither_raw",
                "parser_source_digest": H1,
                "raw_schema_digest": H0,
                "argv": ["slither", "--json", "-"],
                "allowed_environment": [],
                "working_directory_root_id": "root-0",
                "platform": {
                    "os": "windows",
                    "architecture": "amd64",
                    "runtime_versions": [],
                    "locale": "C",
                    "filesystem_case_sensitive": False,
                },
                "build_variant_ids": [variant["build_variant_id"]],
                "capabilities_requested": ["evm.slither.calls.v1"],
                "capabilities_emitted": ["evm.slither.calls.v1"],
                "capabilities_unavailable": [],
                "capabilities_partial": [],
                "input_ceiling_bytes": 1048576,
                "output_ceiling_bytes": 1048576,
                "timeout_seconds": 600,
                "output_truncated": False,
                "cancelled": False,
                "worker_transaction_ref_ids": ["wt-ref-0"],
                "debt_ids": [],
            }
        ],
        "worker_transaction_refs": [
            {
                "ref_id": "wt-ref-0",
                "provider_run_id": "evm.slither.run-0",
                "work_plan_digest": H0,
                "arm_digest": H1,
                "completion_digest": H2,
                "debt_digest": "",
                "cas_manifest_digest": H0,
                "incorporation_digest": H1,
                "status": "COMPLETED",
                "process_scope_active_zero": True,
            }
        ],
        "phase_io": {
            "contract_digest": H0,
            "launch_digest": H1,
            "input_set_digest": H2,
            "work_unit_key": (
                "sc/thorough/evm/claude/recon/program_facts_bake"
            ),
            "ledger_binding_state": "PRECOMMIT",
            "ledger_record_digest": "",
        },
        "artifacts": {
            "facts": {
                "path": "mechanical_program_facts.v1.json",
                "document_sha256": payload["payload_sha256"],
                "file_sha256": hashlib.sha256(facts_bytes).hexdigest(),
                "size": len(facts_bytes),
            },
            "debt": {
                "path": "mechanical_program_facts_debt.v1.json",
                "document_sha256": debt["debt_sha256"],
                "file_sha256": hashlib.sha256(debt_bytes).hexdigest(),
                "size": len(debt_bytes),
            },
        },
        "reuse_key": H0,
    }
    unsigned["reuse_key"] = derive_program_facts_reuse_key(
        payload=payload,
        receipt=unsigned,
    )
    return signed_payload(unsigned, "receipt_sha256")


def _valid_bundle() -> tuple[
    dict[str, object],
    dict[str, object],
    dict[str, object],
    dict[str, object],
]:
    payload = _payload()
    debt = _empty_debt()
    registry = _registry()
    receipt = _receipt(payload, debt, registry)
    return payload, debt, receipt, registry


def _source_bytes_for(
    payload: dict[str, object],
) -> dict[str, bytes]:
    return {
        str(payload["source_files"][0]["source_file_id"]): SOURCE_BYTES
    }


def _resign_receipt(receipt: dict[str, object]) -> dict[str, object]:
    return signed_payload(receipt, "receipt_sha256")


def _resign_payload(payload: dict[str, object]) -> dict[str, object]:
    return signed_payload(payload, "payload_sha256")


def _refresh_artifacts(
    receipt: dict[str, object],
    payload: dict[str, object],
    debt: dict[str, object],
) -> None:
    facts_bytes = canonical_file_bytes(payload)
    debt_bytes = canonical_file_bytes(debt)
    receipt["artifacts"]["facts"].update(
        {
            "document_sha256": payload["payload_sha256"],
            "file_sha256": hashlib.sha256(facts_bytes).hexdigest(),
            "size": len(facts_bytes),
        }
    )
    receipt["artifacts"]["debt"].update(
        {
            "document_sha256": debt["debt_sha256"],
            "file_sha256": hashlib.sha256(debt_bytes).hexdigest(),
            "size": len(debt_bytes),
        }
    )


def test_valid_package2_bundle_binds_exact_bytes_and_source_replay() -> None:
    payload, debt, receipt, registry = _valid_bundle()
    bundle = validate_program_facts_bundle(
        payload=payload,
        debt=debt,
        receipt=receipt,
        payload_file_bytes=canonical_file_bytes(payload),
        debt_file_bytes=canonical_file_bytes(debt),
        receipt_file_bytes=canonical_file_bytes(receipt),
        source_bytes_by_id={str(payload["source_files"][0]["source_file_id"]): SOURCE_BYTES},
        provider_registry=registry,
    )
    assert bundle.receipt.value["status"] == "WRITTEN"


@pytest.mark.parametrize("field", ["document_sha256", "file_sha256", "size"])
def test_bundle_rejects_forged_receipt_artifact_binding(field: str) -> None:
    payload, debt, receipt, registry = _valid_bundle()
    receipt["artifacts"]["facts"][field] = 1 if field == "size" else H2
    receipt = _resign_receipt(receipt)
    with pytest.raises(ProgramFactsTypeError, match="artifact"):
        validate_program_facts_bundle(
            payload=payload,
            debt=debt,
            receipt=receipt,
            payload_file_bytes=canonical_file_bytes(payload),
            debt_file_bytes=canonical_file_bytes(debt),
            receipt_file_bytes=canonical_file_bytes(receipt),
            source_bytes_by_id=_source_bytes_for(payload),
            source_authority_digest=receipt["source_authority_digest"],
            provider_registry=registry,
        )


def test_bundle_rejects_noncanonical_actual_file_bytes_even_if_mapping_is_valid() -> None:
    payload, debt, receipt, registry = _valid_bundle()
    pretty = (b"{\n" + canonical_json_bytes(payload)[1:-1] + b"\n}\n")
    receipt["artifacts"]["facts"]["file_sha256"] = hashlib.sha256(pretty).hexdigest()
    receipt["artifacts"]["facts"]["size"] = len(pretty)
    receipt = _resign_receipt(receipt)
    with pytest.raises(ProgramFactsTypeError, match="canonical"):
        validate_program_facts_bundle(
            payload=payload,
            debt=debt,
            receipt=receipt,
            payload_file_bytes=pretty,
            debt_file_bytes=canonical_file_bytes(debt),
            receipt_file_bytes=canonical_file_bytes(receipt),
            source_bytes_by_id=_source_bytes_for(payload),
            provider_registry=registry,
        )


def test_bundle_rejects_noncanonical_receipt_file_bytes() -> None:
    payload, debt, receipt, registry = _valid_bundle()
    pretty_receipt = b"{\n" + canonical_json_bytes(receipt)[1:-1] + b"\n}\n"
    with pytest.raises(ProgramFactsTypeError, match="canonical"):
        validate_program_facts_bundle(
            payload=payload,
            debt=debt,
            receipt=receipt,
            payload_file_bytes=canonical_file_bytes(payload),
            debt_file_bytes=canonical_file_bytes(debt),
            receipt_file_bytes=pretty_receipt,
            source_bytes_by_id=_source_bytes_for(payload),
            provider_registry=registry,
        )


@pytest.mark.parametrize("field", ["file_count", "byte_count", "manifest_digest"])
def test_receipt_replays_source_manifest_counts_bytes_and_digest(field: str) -> None:
    payload, debt, receipt, _registry_value = _valid_bundle()
    receipt["source_manifest"][field] = (
        2 if field != "manifest_digest" else H0
    )
    receipt = _resign_receipt(receipt)
    with pytest.raises(ProgramFactsTypeError, match="source manifest"):
        validate_program_facts_receipt(receipt)


def test_bundle_requires_exact_payload_manifest_row_parity() -> None:
    payload, debt, receipt, registry = _valid_bundle()
    receipt["source_manifest"]["eligible_files"][0]["language"] = "vyper"
    receipt["source_manifest"]["manifest_digest"] = derive_source_manifest_digest(
        receipt["source_manifest"]
    )
    payload["snapshot_ref"]["source_manifest_digest"] = receipt["source_manifest"][
        "manifest_digest"
    ]
    payload = _resign_payload(payload)
    debt["source_manifest_digest"] = receipt["source_manifest"]["manifest_digest"]
    debt = signed_payload(debt, "debt_sha256")
    _refresh_artifacts(receipt, payload, debt)
    receipt["reuse_key"] = derive_program_facts_reuse_key(
        payload=payload,
        receipt=receipt,
    )
    receipt = _resign_receipt(receipt)
    with pytest.raises(ProgramFactsTypeError, match="manifest.*payload"):
        validate_program_facts_bundle(
            payload=payload,
            debt=debt,
            receipt=receipt,
            payload_file_bytes=canonical_file_bytes(payload),
            debt_file_bytes=canonical_file_bytes(debt),
            receipt_file_bytes=canonical_file_bytes(receipt),
            source_bytes_by_id=_source_bytes_for(payload),
            provider_registry=registry,
        )


@pytest.mark.parametrize(
    "mutation, message",
    [
        ("build_outside_denominator", "build.*denominator"),
        ("unknown_provider", "provider"),
        ("capability_not_total", "capabilit"),
        ("dangling_worker_ref", "worker"),
        ("completed_without_completion", "completion"),
        ("nonzero_process_scope", "process"),
    ],
)
def test_receipt_rejects_build_provider_worker_authority_gaps(
    mutation: str, message: str
) -> None:
    payload, debt, receipt, registry = _valid_bundle()
    if mutation == "build_outside_denominator":
        receipt["build_attempts"][0]["failed_source_file_ids"] = [
            "PFS-" + "f" * 24
        ]
    elif mutation == "unknown_provider":
        receipt["provider_runs"][0]["provider_id"] = "evm.unknown.provider"
    elif mutation == "capability_not_total":
        receipt["provider_runs"][0]["capabilities_emitted"] = []
    elif mutation == "dangling_worker_ref":
        receipt["provider_runs"][0]["worker_transaction_ref_ids"] = ["wt-missing"]
    elif mutation == "completed_without_completion":
        receipt["worker_transaction_refs"][0]["completion_digest"] = ""
    elif mutation == "nonzero_process_scope":
        receipt["worker_transaction_refs"][0]["process_scope_active_zero"] = False
    receipt = _resign_receipt(receipt)
    with pytest.raises(ProgramFactsTypeError, match=message):
        validate_program_facts_bundle(
            payload=payload,
            debt=debt,
            receipt=receipt,
            payload_file_bytes=canonical_file_bytes(payload),
            debt_file_bytes=canonical_file_bytes(debt),
            receipt_file_bytes=canonical_file_bytes(receipt),
            source_bytes_by_id=_source_bytes_for(payload),
            provider_registry=registry,
        )


@pytest.mark.parametrize("kind", ["node", "occurrence", "fact"])
def test_payload_rejects_self_consistent_but_semantically_wrong_stable_id(
    kind: str,
) -> None:
    payload = _payload()
    row_key = {"node": "nodes", "occurrence": "occurrences", "fact": "facts"}[kind]
    id_key = {"node": "node_id", "occurrence": "occurrence_id", "fact": "fact_id"}[
        kind
    ]
    payload[row_key][0][id_key] = {
        "node": "PFN-",
        "occurrence": "PFO-",
        "fact": "PFF-",
    }[kind] + "f" * 24
    # Repair references so this is an ID-derivation test, not a dangling-ref test.
    if kind == "node":
        wrong = payload["nodes"][0]["node_id"]
        payload["occurrences"][0]["enclosing_node_id"] = wrong
        payload["facts"][0]["subject_id"] = wrong
        payload["facts"][0]["object_id"] = wrong
        payload["occurrences"][0]["occurrence_id"] = derive_occurrence_id(
            payload["occurrences"][0]
        )
        payload["facts"][0]["occurrence_ids"] = [
            payload["occurrences"][0]["occurrence_id"]
        ]
        payload["facts"][0]["fact_id"] = derive_fact_id(payload["facts"][0])
    elif kind == "occurrence":
        payload["facts"][0]["occurrence_ids"] = [payload["occurrences"][0][id_key]]
        payload["facts"][0]["fact_id"] = derive_fact_id(payload["facts"][0])
    payload = _resign_payload(payload)
    with pytest.raises(ProgramFactsTypeError, match=f"{kind} ID"):
        validate_program_facts_payload(
            payload,
            source_bytes_by_id=_source_bytes_for(payload),
        )


def test_debt_id_is_semantic_and_deterministic() -> None:
    row: dict[str, object] = {
        "debt_id": "PFD-" + "0" * 24,
        "reason": "CAPABILITY_PARTIAL",
        "scope_ids": ["PFS-" + "a" * 24],
        "provider_id": "evm.slither.provider",
        "capability_id": "evm.slither.calls.v1",
        "build_variant_id": str(_variant()["build_variant_id"]),
        "explanation": "Provider emitted a partial relation set.",
        "evidence_refs": ["sha256:" + H0],
        "retryable": True,
        "blocks_reuse": True,
        "terminal_negative_authority": False,
    }
    row["debt_id"] = derive_debt_id(row)
    debt = signed_payload(
        {
            "schema_version": "plamen.mechanical_program_facts_debt.v1",
            "snapshot_digest": H0,
            "source_manifest_digest": _source_manifest(_source())["manifest_digest"],
            "authority": "MANDATORY_REVIEW_NO_NEGATIVE_INFERENCE",
            "debts": [row],
            "summary": {
                "by_reason": {"CAPABILITY_PARTIAL": 1},
                "affected_capabilities": ["evm.slither.calls.v1"],
                "affected_source_file_ids": ["PFS-" + "a" * 24],
                "has_blocking_reuse_debt": True,
            },
        },
        "debt_sha256",
    )
    validate_program_facts_debt(debt)
    debt["debts"][0]["debt_id"] = "PFD-" + "f" * 24
    debt = signed_payload(debt, "debt_sha256")
    with pytest.raises(ProgramFactsTypeError, match="debt ID"):
        validate_program_facts_debt(debt)


def test_semantic_ids_exclude_display_prose_and_provider_attempt_identity() -> None:
    source = _source()
    variant = _variant()
    node = _node(source, variant)
    node_changed = deepcopy(node)
    node_changed["display_name"] = "human-facing alias"
    node_changed["attributes"] = ["display-only"]
    assert derive_node_id("evm", node_changed) == node["node_id"]

    occurrence = _occurrence(source, node)
    fact = _fact(variant, node, occurrence)
    fact_changed = deepcopy(fact)
    fact_changed["provider_run_id"] = "evm.slither.run-9"
    fact_changed["attestations"] = ["evm.slither.run-9"]
    assert derive_fact_id(fact_changed) == fact["fact_id"]

    debt_row: dict[str, object] = {
        "debt_id": "PFD-" + "0" * 24,
        "reason": "CAPABILITY_PARTIAL",
        "scope_ids": [str(variant["build_variant_id"])],
        "provider_id": "evm.slither.provider",
        "capability_id": "evm.slither.calls.v1",
        "build_variant_id": variant["build_variant_id"],
        "explanation": "first wording",
        "evidence_refs": [],
        "retryable": True,
        "blocks_reuse": False,
        "terminal_negative_authority": False,
    }
    first = derive_debt_id(debt_row)
    debt_row["explanation"] = "same obligation, edited display prose"
    assert derive_debt_id(debt_row) == first


@pytest.mark.parametrize(
    "mutation, message",
    [
        ("span_past_end", "span"),
        ("statement_hash", "statement"),
        ("line_column", "line/column"),
        ("source_hash", "source.*digest"),
    ],
)
def test_source_bytes_replay_span_hash_and_line_columns(
    mutation: str, message: str
) -> None:
    payload = _payload()
    source_id = str(payload["source_files"][0]["source_file_id"])
    if mutation == "span_past_end":
        payload["nodes"][0]["source_binding"]["end_byte"] = len(SOURCE_BYTES) + 1
    elif mutation == "statement_hash":
        payload["nodes"][0]["source_binding"]["statement_sha256"] = H0
    elif mutation == "line_column":
        payload["nodes"][0]["source_binding"]["start_column"] += 1
    else:
        payload["source_files"][0]["source_sha256"] = H0
        # Keep source identity internally self-consistent to exercise byte replay.
        binding = {
            "source_scope_digest": H1,
            "path": payload["source_files"][0]["path"],
            "source_sha256": H0,
            "scope_class": payload["source_files"][0]["scope_class"],
        }
        payload["source_files"][0]["source_file_id"] = derive_stable_id("PFS", binding)
        replacement = payload["source_files"][0]["source_file_id"]
        payload["nodes"][0]["source_binding"]["source_file_id"] = replacement
        payload["occurrences"][0]["source_binding"]["source_file_id"] = replacement
        payload["nodes"][0]["node_id"] = derive_node_id("evm", payload["nodes"][0])
        payload["occurrences"][0]["enclosing_node_id"] = payload["nodes"][0]["node_id"]
        payload["occurrences"][0]["occurrence_id"] = derive_occurrence_id(
            payload["occurrences"][0]
        )
        payload["facts"][0]["subject_id"] = payload["nodes"][0]["node_id"]
        payload["facts"][0]["object_id"] = payload["nodes"][0]["node_id"]
        payload["facts"][0]["occurrence_ids"] = [
            payload["occurrences"][0]["occurrence_id"]
        ]
        payload["facts"][0]["fact_id"] = derive_fact_id(payload["facts"][0])
        payload["coverage"][0]["eligible_source_file_ids"] = [replacement]
        payload["coverage"][0]["covered_source_file_ids"] = [replacement]
        payload["coverage"][0]["denominator_digest"] = hashlib.sha256(
            canonical_json_bytes(
                {
                    "eligible_source_file_ids": [replacement],
                    "excluded_source_file_ids": [],
                }
            )
        ).hexdigest()
        semantic = {
            key: value
            for key, value in payload["coverage"][0].items()
            if key != "coverage_id"
        }
        payload["coverage"][0]["coverage_id"] = derive_stable_id("PFC", semantic)
        source_id = str(replacement)
    payload = _resign_payload(payload)
    with pytest.raises(ProgramFactsTypeError, match=message):
        validate_program_facts_payload(
            payload, source_bytes_by_id={source_id: SOURCE_BYTES}
        )


def test_partial_coverage_requires_total_visible_debt() -> None:
    payload = _payload()
    payload["coverage"][0]["status"] = "PARTIAL"
    payload["coverage"][0]["covered_source_file_ids"] = []
    payload["coverage"][0]["unresolved_debt_ids"] = []
    semantic = {
        key: value
        for key, value in payload["coverage"][0].items()
        if key != "coverage_id"
    }
    payload["coverage"][0]["coverage_id"] = derive_stable_id("PFC", semantic)
    payload = _resign_payload(payload)
    with pytest.raises(ProgramFactsTypeError, match="PARTIAL.*debt"):
        validate_program_facts_payload(
            payload,
            source_bytes_by_id=_source_bytes_for(payload),
        )


def test_provider_registry_is_semantically_closed_not_schema_only() -> None:
    registry = _registry()
    validate_program_facts_provider_registry(registry)
    registry["providers"][0]["capabilities"].append(
        deepcopy(registry["providers"][0]["capabilities"][0])
    )
    with pytest.raises(ProgramFactsTypeError, match="duplicate"):
        validate_program_facts_provider_registry(registry)

    registry = _registry()
    registry["providers"][0]["supply_chain_policy"]["pinned"] = False
    with pytest.raises(ProgramFactsTypeError, match="pinned"):
        validate_program_facts_provider_registry(registry)


def test_validated_wrappers_are_deeply_immutable_and_receipt_is_mandatory() -> None:
    payload, debt, receipt, registry = _valid_bundle()
    bundle = validate_program_facts_bundle(
        payload=payload,
        debt=debt,
        receipt=receipt,
        payload_file_bytes=canonical_file_bytes(payload),
        debt_file_bytes=canonical_file_bytes(debt),
        receipt_file_bytes=canonical_file_bytes(receipt),
        source_bytes_by_id=_source_bytes_for(payload),
        provider_registry=registry,
    )
    with pytest.raises(TypeError):
        bundle.payload.value["ecosystem"] = "mixed"
    with pytest.raises(TypeError):
        bundle.payload.value["snapshot_ref"]["snapshot_digest"] = H2
    with pytest.raises(ProgramFactsTypeError, match="receipt"):
        validate_program_facts_bundle(
            payload=payload,
            debt=debt,
            receipt=None,
            payload_file_bytes=canonical_file_bytes(payload),
            debt_file_bytes=canonical_file_bytes(debt),
            receipt_file_bytes=b"",
            source_bytes_by_id=_source_bytes_for(payload),
        )


def test_field_aware_portability_rejects_opaque_root_host_paths() -> None:
    payload = _payload()
    payload["build_variants"][0]["build_root_id"] = r"C:\Users\alice\repo"
    semantic = {
        key: value
        for key, value in payload["build_variants"][0].items()
        if key not in {"build_variant_id", "variant_digest"}
    }
    digest = hashlib.sha256(canonical_json_bytes(semantic)).hexdigest()
    payload["build_variants"][0]["variant_digest"] = digest
    payload["build_variants"][0]["build_variant_id"] = f"PFB-{digest[:24]}"
    payload = _resign_payload(payload)
    with pytest.raises(ProgramFactsTypeError, match="build_root_id"):
        validate_program_facts_payload(
            payload,
            source_bytes_by_id=_source_bytes_for(payload),
        )


def test_receipt_reuse_key_is_exact_not_presence_or_version_text() -> None:
    payload, debt, receipt, registry = _valid_bundle()
    receipt["reuse_key"] = H0
    receipt = _resign_receipt(receipt)
    with pytest.raises(ProgramFactsTypeError, match="reuse key"):
        validate_program_facts_bundle(
            payload=payload,
            debt=debt,
            receipt=receipt,
            payload_file_bytes=canonical_file_bytes(payload),
            debt_file_bytes=canonical_file_bytes(debt),
            receipt_file_bytes=canonical_file_bytes(receipt),
            source_bytes_by_id=_source_bytes_for(payload),
            provider_registry=registry,
        )


def test_registry_caps_fact_precision_and_execution_platform() -> None:
    payload, debt, receipt, registry = _valid_bundle()
    registry["providers"][0]["capabilities"][0]["maximum_precision"] = "MAY"
    registry_digest = hashlib.sha256(canonical_json_bytes(registry)).hexdigest()
    receipt["provider_runs"][0]["provider_registry_digest"] = registry_digest
    receipt["reuse_key"] = derive_program_facts_reuse_key(
        payload=payload,
        receipt=receipt,
    )
    receipt = _resign_receipt(receipt)
    with pytest.raises(ProgramFactsTypeError, match="precision"):
        validate_program_facts_bundle(
            payload=payload,
            debt=debt,
            receipt=receipt,
            payload_file_bytes=canonical_file_bytes(payload),
            debt_file_bytes=canonical_file_bytes(debt),
            receipt_file_bytes=canonical_file_bytes(receipt),
            source_bytes_by_id=_source_bytes_for(payload),
            provider_registry=registry,
        )

    payload, debt, receipt, registry = _valid_bundle()
    receipt["provider_runs"][0]["platform"]["architecture"] = "arm64"
    receipt = _resign_receipt(receipt)
    with pytest.raises(ProgramFactsTypeError, match="platform"):
        validate_program_facts_bundle(
            payload=payload,
            debt=debt,
            receipt=receipt,
            payload_file_bytes=canonical_file_bytes(payload),
            debt_file_bytes=canonical_file_bytes(debt),
            receipt_file_bytes=canonical_file_bytes(receipt),
            source_bytes_by_id=_source_bytes_for(payload),
            provider_registry=registry,
        )


def test_unreferenced_debt_cannot_disappear_from_total_accounting() -> None:
    payload, _debt_value, receipt, registry = _valid_bundle()
    variant_id = str(payload["build_variants"][0]["build_variant_id"])
    row: dict[str, object] = {
        "debt_id": "PFD-" + "0" * 24,
        "reason": "CAPABILITY_PARTIAL",
        "scope_ids": [str(payload["source_files"][0]["source_file_id"])],
        "provider_id": "evm.slither.provider",
        "capability_id": "evm.slither.calls.v1",
        "build_variant_id": variant_id,
        "explanation": "This row is deliberately absent from every authority link.",
        "evidence_refs": [],
        "retryable": True,
        "blocks_reuse": False,
        "terminal_negative_authority": False,
    }
    row["debt_id"] = derive_debt_id(row)
    debt = signed_payload(
        {
            "schema_version": "plamen.mechanical_program_facts_debt.v1",
            "snapshot_digest": H0,
            "source_manifest_digest": payload["snapshot_ref"][
                "source_manifest_digest"
            ],
            "authority": "MANDATORY_REVIEW_NO_NEGATIVE_INFERENCE",
            "debts": [row],
            "summary": {
                "by_reason": {"CAPABILITY_PARTIAL": 1},
                "affected_capabilities": ["evm.slither.calls.v1"],
                "affected_source_file_ids": [
                    str(payload["source_files"][0]["source_file_id"])
                ],
                "has_blocking_reuse_debt": False,
            },
        },
        "debt_sha256",
    )
    _refresh_artifacts(receipt, payload, debt)
    receipt = _resign_receipt(receipt)
    with pytest.raises(
        ProgramFactsTypeError,
        match="debt accounting|coverage accounting",
    ):
        validate_program_facts_bundle(
            payload=payload,
            debt=debt,
            receipt=receipt,
            payload_file_bytes=canonical_file_bytes(payload),
            debt_file_bytes=canonical_file_bytes(debt),
            receipt_file_bytes=canonical_file_bytes(receipt),
            source_bytes_by_id=_source_bytes_for(payload),
            provider_registry=registry,
        )


def test_legitimate_partial_provider_bundle_is_degraded_not_rejected() -> None:
    payload, _empty, receipt, registry = _valid_bundle()
    source_id = str(payload["source_files"][0]["source_file_id"])
    variant_id = str(payload["build_variants"][0]["build_variant_id"])
    row: dict[str, object] = {
        "debt_id": "PFD-" + "0" * 24,
        "reason": "CAPABILITY_PARTIAL",
        "scope_ids": [source_id],
        "provider_id": "evm.slither.provider",
        "capability_id": "evm.slither.calls.v1",
        "build_variant_id": variant_id,
        "explanation": "Provider completed but its semantic denominator was partial.",
        "evidence_refs": [],
        "retryable": True,
        "blocks_reuse": False,
        "terminal_negative_authority": False,
    }
    row["debt_id"] = derive_debt_id(row)
    debt_id = str(row["debt_id"])
    debt = signed_payload(
        {
            "schema_version": "plamen.mechanical_program_facts_debt.v1",
            "snapshot_digest": H0,
            "source_manifest_digest": payload["snapshot_ref"][
                "source_manifest_digest"
            ],
            "authority": "MANDATORY_REVIEW_NO_NEGATIVE_INFERENCE",
            "debts": [row],
            "summary": {
                "by_reason": {"CAPABILITY_PARTIAL": 1},
                "affected_capabilities": ["evm.slither.calls.v1"],
                "affected_source_file_ids": [source_id],
                "has_blocking_reuse_debt": False,
            },
        },
        "debt_sha256",
    )
    coverage = payload["coverage"][0]
    coverage["status"] = "PARTIAL"
    coverage["covered_source_file_ids"] = []
    coverage["unresolved_debt_ids"] = [debt_id]
    coverage["coverage_id"] = derive_stable_id(
        "PFC",
        {key: value for key, value in coverage.items() if key != "coverage_id"},
    )
    payload = _resign_payload(payload)
    provider = receipt["provider_runs"][0]
    provider["capabilities_emitted"] = []
    provider["capabilities_partial"] = ["evm.slither.calls.v1"]
    provider["debt_ids"] = [debt_id]
    receipt["status"] = "DEGRADED"
    _refresh_artifacts(receipt, payload, debt)
    receipt["reuse_key"] = derive_program_facts_reuse_key(
        payload=payload,
        receipt=receipt,
    )
    receipt = _resign_receipt(receipt)
    bundle = validate_program_facts_bundle(
        payload=payload,
        debt=debt,
        receipt=receipt,
        payload_file_bytes=canonical_file_bytes(payload),
        debt_file_bytes=canonical_file_bytes(debt),
        receipt_file_bytes=canonical_file_bytes(receipt),
        source_bytes_by_id=_source_bytes_for(payload),
        provider_registry=registry,
    )
    assert bundle.receipt.value["status"] == "DEGRADED"
    assert len(bundle.payload.value["facts"]) == 1


def test_source_byte_input_is_an_exact_denominator_not_a_partial_hint() -> None:
    payload = _payload()
    with pytest.raises(ProgramFactsTypeError, match="exactly match"):
        validate_program_facts_payload(payload, source_bytes_by_id={})
    with pytest.raises(ProgramFactsTypeError, match="exactly match"):
        validate_program_facts_payload(
            payload,
            source_bytes_by_id={
                str(payload["source_files"][0]["source_file_id"]): SOURCE_BYTES,
                "PFS-" + "f" * 24: b"",
            },
        )


def test_signature_fact_ref_is_not_an_unvalidated_string_escape() -> None:
    payload = _payload()
    payload["nodes"][0]["signature"]["signature_fact_ref"] = "PFF-" + "f" * 24
    payload["nodes"][0]["node_id"] = derive_node_id("evm", payload["nodes"][0])
    payload["occurrences"][0]["enclosing_node_id"] = payload["nodes"][0]["node_id"]
    payload["occurrences"][0]["occurrence_id"] = derive_occurrence_id(
        payload["occurrences"][0]
    )
    payload["facts"][0]["subject_id"] = payload["nodes"][0]["node_id"]
    payload["facts"][0]["object_id"] = payload["nodes"][0]["node_id"]
    payload["facts"][0]["occurrence_ids"] = [
        payload["occurrences"][0]["occurrence_id"]
    ]
    payload["facts"][0]["fact_id"] = derive_fact_id(payload["facts"][0])
    payload = _resign_payload(payload)
    with pytest.raises(ProgramFactsTypeError, match="signature.*dangling"):
        validate_program_facts_payload(
            payload,
            source_bytes_by_id=_source_bytes_for(payload),
        )


def test_direct_wrapper_construction_validates_and_deep_freezes() -> None:
    payload = _payload()
    wrapper = ProgramFactsPayload(
        payload,
        source_bytes_by_id=_source_bytes_for(payload),
    )
    payload["ecosystem"] = "mixed"
    assert wrapper.value["ecosystem"] == "evm"
    with pytest.raises(TypeError):
        wrapper.value["ecosystem"] = "mixed"

    invalid = _payload()
    invalid["payload_sha256"] = H0
    with pytest.raises(ProgramFactsTypeError, match="digest"):
        ProgramFactsPayload(
            invalid,
            source_bytes_by_id=_source_bytes_for(invalid),
        )


# Independent-review attack fixtures.  These intentionally exercise the
# public authority surfaces, not private helpers or later PhaseIO/provider
# execution observations.


def test_public_canonical_payload_authority_requires_exact_source_bytes() -> None:
    payload = _payload()
    with pytest.raises((TypeError, ProgramFactsTypeError), match="source"):
        validate_program_facts_payload(payload, source_bytes_by_id=None)
    with pytest.raises((TypeError, ProgramFactsTypeError), match="source"):
        ProgramFactsPayload(payload)


def test_provider_run_opaque_identity_digests_are_not_self_authority() -> None:
    payload, debt, receipt, registry = _valid_bundle()
    run = receipt["provider_runs"][0]
    run["implementation_digest"] = "f" * 64
    run["executable_or_module_digest"] = "e" * 64
    run["version_output_digest"] = "d" * 64
    receipt["reuse_key"] = derive_program_facts_reuse_key(
        payload=payload,
        receipt=receipt,
    )
    receipt = _resign_receipt(receipt)
    with pytest.raises(ProgramFactsTypeError, match="identity|executable|version"):
        validate_program_facts_bundle(
            payload=payload,
            debt=debt,
            receipt=receipt,
            payload_file_bytes=canonical_file_bytes(payload),
            debt_file_bytes=canonical_file_bytes(debt),
            receipt_file_bytes=canonical_file_bytes(receipt),
            source_bytes_by_id={
                str(payload["source_files"][0]["source_file_id"]): SOURCE_BYTES
            },
            provider_registry=registry,
        )


@pytest.mark.parametrize(
    "mutation, message",
    [
        ("language", "language"),
        ("limits", "ceiling|limit|timeout"),
        ("toolchain", "toolchain|version"),
    ],
)
def test_provider_execution_must_fit_registry_authority(
    mutation: str,
    message: str,
) -> None:
    payload, debt, receipt, registry = _valid_bundle()
    if mutation == "language":
        registry["providers"][0]["supported_languages"] = ["vyper"]
    elif mutation == "limits":
        run = receipt["provider_runs"][0]
        run["input_ceiling_bytes"] = 10**12
        run["output_ceiling_bytes"] = 10**12
        run["timeout_seconds"] = 10**9
    else:
        registry["providers"][0]["toolchain_ranges"][0]["version_range"] = ">=1,<2"
    receipt["provider_runs"][0]["provider_registry_digest"] = hashlib.sha256(
        canonical_json_bytes(registry)
    ).hexdigest()
    receipt["reuse_key"] = derive_program_facts_reuse_key(
        payload=payload,
        receipt=receipt,
    )
    receipt = _resign_receipt(receipt)
    with pytest.raises(ProgramFactsTypeError, match=message):
        validate_program_facts_bundle(
            payload=payload,
            debt=debt,
            receipt=receipt,
            payload_file_bytes=canonical_file_bytes(payload),
            debt_file_bytes=canonical_file_bytes(debt),
            receipt_file_bytes=canonical_file_bytes(receipt),
            source_bytes_by_id={
                str(payload["source_files"][0]["source_file_id"]): SOURCE_BYTES
            },
            provider_registry=registry,
        )


@pytest.mark.parametrize("mutation", ["language", "toolchain"])
def test_fact_authority_cannot_be_laundered_through_another_provider_run(
    mutation: str,
) -> None:
    payload, debt, receipt, registry = _valid_bundle()
    second_provider = deepcopy(registry["providers"][0])
    second_provider["provider_id"] = "evm.slither.second-provider"
    registry["providers"].append(second_provider)
    registry["providers"] = sorted(
        registry["providers"],
        key=lambda row: row["provider_id"],
    )
    first_provider = next(
        row
        for row in registry["providers"]
        if row["provider_id"] == "evm.slither.provider"
    )
    if mutation == "language":
        first_provider["supported_languages"] = ["vyper"]
    else:
        first_provider["toolchain_ranges"][0]["version_range"] = ">=1,<2"
    registry_digest = hashlib.sha256(
        canonical_json_bytes(registry)
    ).hexdigest()

    first_run = receipt["provider_runs"][0]
    first_run["provider_registry_digest"] = registry_digest
    second_run = deepcopy(first_run)
    second_run["provider_run_id"] = "evm.slither.run-1"
    second_run["provider_id"] = "evm.slither.second-provider"
    second_run["worker_transaction_ref_ids"] = ["wt-ref-1"]
    receipt["provider_runs"] = sorted(
        [first_run, second_run],
        key=lambda row: row["provider_run_id"],
    )
    second_transaction = deepcopy(receipt["worker_transaction_refs"][0])
    second_transaction["ref_id"] = "wt-ref-1"
    second_transaction["provider_run_id"] = "evm.slither.run-1"
    receipt["worker_transaction_refs"] = sorted(
        [receipt["worker_transaction_refs"][0], second_transaction],
        key=lambda row: row["ref_id"],
    )
    receipt["reuse_key"] = derive_program_facts_reuse_key(
        payload=payload,
        receipt=receipt,
    )
    receipt = _resign_receipt(receipt)
    with pytest.raises(
        ProgramFactsTypeError,
        match="fact.*(language|toolchain)|provider.*fact",
    ):
        validate_program_facts_bundle(
            payload=payload,
            debt=debt,
            receipt=receipt,
            payload_file_bytes=canonical_file_bytes(payload),
            debt_file_bytes=canonical_file_bytes(debt),
            receipt_file_bytes=canonical_file_bytes(receipt),
            source_bytes_by_id=_source_bytes_for(payload),
            provider_registry=registry,
        )


def test_reuse_key_binds_audit_authority_and_per_provider_capability_assignment() -> None:
    payload, _debt_value, receipt, _registry_value = _valid_bundle()
    original = derive_program_facts_reuse_key(payload=payload, receipt=receipt)
    receipt["audit_snapshot"]["audit_config_digest"] = "a" * 64
    receipt["audit_snapshot"]["methodology_digest"] = "b" * 64
    receipt["audit_snapshot"]["toolchain_digest"] = "c" * 64
    assert derive_program_facts_reuse_key(payload=payload, receipt=receipt) != original

    payload, _debt_value, receipt, _registry_value = _valid_bundle()
    payload["provider_capability_refs"] = [
        "evm.slither.calls.v1",
        "evm.slither.reads.v1",
    ]
    second = deepcopy(receipt["provider_runs"][0])
    second["provider_run_id"] = "evm.slither.run-1"
    second["provider_id"] = "evm.slither.second-provider"
    second["capabilities_requested"] = ["evm.slither.reads.v1"]
    second["capabilities_emitted"] = ["evm.slither.reads.v1"]
    second["worker_transaction_ref_ids"] = ["wt-ref-1"]
    receipt["provider_runs"][0]["capabilities_requested"] = [
        "evm.slither.calls.v1"
    ]
    receipt["provider_runs"][0]["capabilities_emitted"] = [
        "evm.slither.calls.v1"
    ]
    receipt["provider_runs"].append(second)
    receipt["provider_runs"] = sorted(
        receipt["provider_runs"], key=lambda row: row["provider_run_id"]
    )
    first_assignment_key = derive_program_facts_reuse_key(
        payload=payload,
        receipt=receipt,
    )
    receipt["provider_runs"][0]["capabilities_requested"] = [
        "evm.slither.reads.v1"
    ]
    receipt["provider_runs"][0]["capabilities_emitted"] = [
        "evm.slither.reads.v1"
    ]
    receipt["provider_runs"][1]["capabilities_requested"] = [
        "evm.slither.calls.v1"
    ]
    receipt["provider_runs"][1]["capabilities_emitted"] = [
        "evm.slither.calls.v1"
    ]
    assert (
        derive_program_facts_reuse_key(payload=payload, receipt=receipt)
        != first_assignment_key
    )


def test_reuse_key_binds_execution_identity_to_each_capability_assignment() -> None:
    payload, _debt_value, receipt, _registry_value = _valid_bundle()
    payload["provider_capability_refs"] = [
        "evm.slither.calls.v1",
        "evm.slither.reads.v1",
    ]
    first = receipt["provider_runs"][0]
    first["capabilities_requested"] = ["evm.slither.calls.v1"]
    first["capabilities_emitted"] = ["evm.slither.calls.v1"]
    second = deepcopy(first)
    second["provider_run_id"] = "evm.slither.run-1"
    second["capabilities_requested"] = ["evm.slither.reads.v1"]
    second["capabilities_emitted"] = ["evm.slither.reads.v1"]
    second["implementation_digest"] = "a" * 64
    second["executable_or_module_digest"] = "b" * 64
    second["version_output_digest"] = "c" * 64
    receipt["provider_runs"] = [first, second]
    before = derive_program_facts_reuse_key(
        payload=payload,
        receipt=receipt,
    )
    for field in (
        "implementation_digest",
        "executable_or_module_digest",
        "version_output_digest",
    ):
        receipt["provider_runs"][0][field], receipt["provider_runs"][1][field] = (
            receipt["provider_runs"][1][field],
            receipt["provider_runs"][0][field],
        )
    assert derive_program_facts_reuse_key(payload=payload, receipt=receipt) != before


def test_coverage_requires_total_capability_by_variant_matrix() -> None:
    payload = _payload()
    first_variant = payload["build_variants"][0]
    second_variant = deepcopy(first_variant)
    second_variant["profile"] = "release"
    semantic_variant = {
        key: value
        for key, value in second_variant.items()
        if key not in {"build_variant_id", "variant_digest"}
    }
    variant_digest = hashlib.sha256(
        canonical_json_bytes(semantic_variant)
    ).hexdigest()
    second_variant["variant_digest"] = variant_digest
    second_variant["build_variant_id"] = f"PFB-{variant_digest[:24]}"
    payload["build_variants"] = sorted(
        [first_variant, second_variant],
        key=lambda row: row["build_variant_id"],
    )
    payload["provider_capability_refs"] = [
        "evm.slither.calls.v1",
        "evm.slither.reads.v1",
    ]
    second_coverage = deepcopy(payload["coverage"][0])
    second_coverage["capability_id"] = "evm.slither.reads.v1"
    second_coverage["build_variant_id"] = second_variant["build_variant_id"]
    second_coverage["coverage_id"] = derive_stable_id(
        "PFC",
        {
            key: value
            for key, value in second_coverage.items()
            if key != "coverage_id"
        },
    )
    payload["coverage"] = sorted(
        [payload["coverage"][0], second_coverage],
        key=lambda row: row["coverage_id"],
    )
    payload = _resign_payload(payload)
    with pytest.raises(ProgramFactsTypeError, match="matrix|capability.*variant"):
        validate_program_facts_payload(
            payload,
            source_bytes_by_id={
                str(payload["source_files"][0]["source_file_id"]): SOURCE_BYTES
            },
        )


def test_fact_occurrence_must_share_the_fact_build_variant() -> None:
    payload = _payload()
    second_variant = deepcopy(payload["build_variants"][0])
    second_variant["profile"] = "release"
    semantic_variant = {
        key: value
        for key, value in second_variant.items()
        if key not in {"build_variant_id", "variant_digest"}
    }
    variant_digest = hashlib.sha256(
        canonical_json_bytes(semantic_variant)
    ).hexdigest()
    second_variant["variant_digest"] = variant_digest
    second_variant["build_variant_id"] = f"PFB-{variant_digest[:24]}"
    payload["build_variants"] = sorted(
        [payload["build_variants"][0], second_variant],
        key=lambda row: row["build_variant_id"],
    )

    second_node = deepcopy(payload["nodes"][0])
    second_node["build_variant_id"] = second_variant["build_variant_id"]
    second_node["node_id"] = derive_node_id("evm", second_node)
    second_occurrence = deepcopy(payload["occurrences"][0])
    second_occurrence["enclosing_node_id"] = second_node["node_id"]
    second_occurrence["occurrence_id"] = derive_occurrence_id(
        second_occurrence
    )
    payload["nodes"] = sorted(
        [payload["nodes"][0], second_node],
        key=lambda row: row["node_id"],
    )
    payload["occurrences"] = sorted(
        [payload["occurrences"][0], second_occurrence],
        key=lambda row: row["occurrence_id"],
    )
    payload["facts"][0]["occurrence_ids"] = [
        second_occurrence["occurrence_id"]
    ]
    payload["facts"][0]["fact_id"] = derive_fact_id(payload["facts"][0])

    second_coverage = deepcopy(payload["coverage"][0])
    second_coverage["build_variant_id"] = second_variant[
        "build_variant_id"
    ]
    second_coverage["coverage_id"] = derive_stable_id(
        "PFC",
        {
            key: value
            for key, value in second_coverage.items()
            if key != "coverage_id"
        },
    )
    payload["coverage"] = sorted(
        [payload["coverage"][0], second_coverage],
        key=lambda row: row["coverage_id"],
    )
    payload = _resign_payload(payload)
    with pytest.raises(ProgramFactsTypeError, match="occurrence.*variant"):
        validate_program_facts_payload(
            payload,
            source_bytes_by_id=_source_bytes_for(payload),
        )


@pytest.mark.parametrize(
    "scope_ids",
    [[], [r"C:\Users\alice\repo\C.sol"]],
)
def test_capability_partial_debt_requires_typed_portable_bindings(
    scope_ids: list[str],
) -> None:
    row: dict[str, object] = {
        "debt_id": "PFD-" + "0" * 24,
        "reason": "CAPABILITY_PARTIAL",
        "scope_ids": scope_ids,
        "provider_id": "",
        "capability_id": "",
        "build_variant_id": "",
        "explanation": "Unbound partiality must not authorize negative inference.",
        "evidence_refs": [],
        "retryable": True,
        "blocks_reuse": False,
        "terminal_negative_authority": False,
    }
    row["debt_id"] = derive_debt_id(row)
    debt = signed_payload(
        {
            "schema_version": "plamen.mechanical_program_facts_debt.v1",
            "snapshot_digest": H0,
            "source_manifest_digest": _source_manifest(_source())[
                "manifest_digest"
            ],
            "authority": "MANDATORY_REVIEW_NO_NEGATIVE_INFERENCE",
            "debts": [row],
            "summary": {
                "by_reason": {"CAPABILITY_PARTIAL": 1},
                "affected_capabilities": [],
                "affected_source_file_ids": [],
                "has_blocking_reuse_debt": False,
            },
        },
        "debt_sha256",
    )
    with pytest.raises(ProgramFactsTypeError, match="CAPABILITY_PARTIAL|scope|portable"):
        validate_program_facts_debt(debt)


def test_capability_partial_debt_rejects_untyped_opaque_scope() -> None:
    row: dict[str, object] = {
        "debt_id": "PFD-" + "0" * 24,
        "reason": "CAPABILITY_PARTIAL",
        "scope_ids": ["arbitrary.opaque"],
        "provider_id": "evm.slither.provider",
        "capability_id": "evm.slither.calls.v1",
        "build_variant_id": str(_variant()["build_variant_id"]),
        "explanation": "A partial capability must bind a typed Program Facts scope.",
        "evidence_refs": [],
        "retryable": True,
        "blocks_reuse": False,
        "terminal_negative_authority": False,
    }
    row["debt_id"] = derive_debt_id(row)
    debt = signed_payload(
        {
            "schema_version": "plamen.mechanical_program_facts_debt.v1",
            "snapshot_digest": H0,
            "source_manifest_digest": _source_manifest(_source())[
                "manifest_digest"
            ],
            "authority": "MANDATORY_REVIEW_NO_NEGATIVE_INFERENCE",
            "debts": [row],
            "summary": {
                "by_reason": {"CAPABILITY_PARTIAL": 1},
                "affected_capabilities": ["evm.slither.calls.v1"],
                "affected_source_file_ids": [],
                "has_blocking_reuse_debt": False,
            },
        },
        "debt_sha256",
    )
    with pytest.raises(ProgramFactsTypeError, match="typed.*scope|Program Facts"):
        validate_program_facts_debt(debt)


@pytest.mark.parametrize(
    "host_path",
    [
        r"C:\Users\alice\repo",
        r"\\server\share\repo",
        "/root/repo",
        "/opt/repo",
        "/workspace/repo",
        "~/repo",
        '"/workspace/repo"',
        "file:///opt/repo",
        "nested=/root/repo",
    ],
)
def test_non_pf_debt_scope_rejects_embedded_host_path(host_path: str) -> None:
    row: dict[str, object] = {
        "debt_id": "PFD-" + "0" * 24,
        "reason": "STALE_SNAPSHOT",
        "scope_ids": [f"scope={host_path}"],
        "provider_id": "",
        "capability_id": "",
        "build_variant_id": "",
        "explanation": "Stale state must use a portable typed scope.",
        "evidence_refs": [],
        "retryable": True,
        "blocks_reuse": True,
        "terminal_negative_authority": False,
    }
    row["debt_id"] = derive_debt_id(row)
    debt = signed_payload(
        {
            "schema_version": "plamen.mechanical_program_facts_debt.v1",
            "snapshot_digest": H0,
            "source_manifest_digest": _source_manifest(_source())[
                "manifest_digest"
            ],
            "authority": "MANDATORY_REVIEW_NO_NEGATIVE_INFERENCE",
            "debts": [row],
            "summary": {
                "by_reason": {"STALE_SNAPSHOT": 1},
                "affected_capabilities": [],
                "affected_source_file_ids": [],
                "has_blocking_reuse_debt": True,
            },
        },
        "debt_sha256",
    )
    with pytest.raises(ProgramFactsTypeError, match="portable|host|scope"):
        validate_program_facts_debt(debt)


def test_full_coverage_requires_a_provider_run_targeting_each_build_variant() -> None:
    payload, debt, receipt, registry = _valid_bundle()
    second_variant = deepcopy(payload["build_variants"][0])
    second_variant["profile"] = "release"
    semantic_variant = {
        key: value
        for key, value in second_variant.items()
        if key not in {"build_variant_id", "variant_digest"}
    }
    variant_digest = hashlib.sha256(
        canonical_json_bytes(semantic_variant)
    ).hexdigest()
    second_variant["variant_digest"] = variant_digest
    second_variant["build_variant_id"] = f"PFB-{variant_digest[:24]}"
    payload["build_variants"] = sorted(
        [payload["build_variants"][0], second_variant],
        key=lambda row: row["build_variant_id"],
    )
    second_coverage = deepcopy(payload["coverage"][0])
    second_coverage["build_variant_id"] = second_variant[
        "build_variant_id"
    ]
    second_coverage["coverage_id"] = derive_stable_id(
        "PFC",
        {
            key: value
            for key, value in second_coverage.items()
            if key != "coverage_id"
        },
    )
    payload["coverage"] = sorted(
        [payload["coverage"][0], second_coverage],
        key=lambda row: row["coverage_id"],
    )
    payload = _resign_payload(payload)

    second_build = deepcopy(receipt["build_attempts"][0])
    second_build["build_variant_id"] = second_variant["build_variant_id"]
    second_build["variant_digest"] = second_variant["variant_digest"]
    second_build["profile"] = second_variant["profile"]
    receipt["build_attempts"] = sorted(
        [receipt["build_attempts"][0], second_build],
        key=lambda row: row["build_variant_id"],
    )
    _refresh_artifacts(receipt, payload, debt)
    receipt["reuse_key"] = derive_program_facts_reuse_key(
        payload=payload,
        receipt=receipt,
    )
    receipt = _resign_receipt(receipt)
    with pytest.raises(ProgramFactsTypeError, match="provider.*variant|variant.*provider"):
        validate_program_facts_bundle(
            payload=payload,
            debt=debt,
            receipt=receipt,
            payload_file_bytes=canonical_file_bytes(payload),
            debt_file_bytes=canonical_file_bytes(debt),
            receipt_file_bytes=canonical_file_bytes(receipt),
            source_bytes_by_id=_source_bytes_for(payload),
            provider_registry=registry,
        )


def test_receipt_argv_and_payload_remapping_reject_host_paths() -> None:
    for host_path in (
        r"C:\Users\alice\private\input.sol",
        r"\\server\share\repo",
        "/root/repo",
        "/opt/private/deps",
        "/workspace/repo",
        "~/repo",
    ):
        _payload_value, _debt_value, receipt, registry = _valid_bundle()
        receipt["provider_runs"][0]["argv"] = [
            "slither",
            f"--root={host_path}",
        ]
        receipt = _resign_receipt(receipt)
        with pytest.raises(ProgramFactsTypeError, match="argv|host path|portable"):
            validate_program_facts_receipt(
                receipt,
                provider_registry=registry,
            )
    for argument in (
        r'--root="C:\Users\alice\repo"',
        r'--root="\\server\share\repo"',
        '--root="/root/repo"',
        "--root=file:///root/repo",
        "--remap=@oz/=/workspace/repo/lib",
        "--define=ROOT=/opt/repo",
    ):
        _payload_value, _debt_value, receipt, registry = _valid_bundle()
        receipt["provider_runs"][0]["argv"] = ["slither", argument]
        receipt = _resign_receipt(receipt)
        with pytest.raises(ProgramFactsTypeError, match="argv|host path|portable"):
            validate_program_facts_receipt(
                receipt,
                provider_registry=registry,
            )

    for host_path in (
        r"C:\Users\alice\private\deps",
        r"\\server\share\repo",
        "/opt/private/deps",
        "/root/repo/lib",
        "/workspace/repo/lib",
        "~/repo/lib",
        '"/root/repo/lib"',
        "file:///opt/repo/lib",
        "nested=/workspace/repo/lib",
    ):
        payload = _payload()
        variant = payload["build_variants"][0]
        variant["remappings"] = [f"@oz/={host_path}"]
        semantic_variant = {
            key: value
            for key, value in variant.items()
            if key not in {"build_variant_id", "variant_digest"}
        }
        digest = hashlib.sha256(canonical_json_bytes(semantic_variant)).hexdigest()
        variant["variant_digest"] = digest
        variant["build_variant_id"] = f"PFB-{digest[:24]}"
        node = payload["nodes"][0]
        node["build_variant_id"] = variant["build_variant_id"]
        node["node_id"] = derive_node_id("evm", node)
        occurrence = payload["occurrences"][0]
        occurrence["enclosing_node_id"] = node["node_id"]
        occurrence["occurrence_id"] = derive_occurrence_id(occurrence)
        fact = payload["facts"][0]
        fact["subject_id"] = node["node_id"]
        fact["object_id"] = node["node_id"]
        fact["occurrence_ids"] = [occurrence["occurrence_id"]]
        fact["build_variant_id"] = variant["build_variant_id"]
        fact["fact_id"] = derive_fact_id(fact)
        coverage = payload["coverage"][0]
        coverage["build_variant_id"] = variant["build_variant_id"]
        coverage["coverage_id"] = derive_stable_id(
            "PFC",
            {
                key: value
                for key, value in coverage.items()
                if key != "coverage_id"
            },
        )
        payload = _resign_payload(payload)
        with pytest.raises(ProgramFactsTypeError, match="remapping|host path|portable"):
            validate_program_facts_payload(
                payload,
                source_bytes_by_id={
                    str(payload["source_files"][0]["source_file_id"]): SOURCE_BYTES
                },
            )

    registry = _registry()
    registry["providers"][0]["installation_provenance"][
        "source"
    ] = "source=file:///opt/provider"
    with pytest.raises(ProgramFactsTypeError, match="provenance|host path"):
        validate_program_facts_provider_registry(registry)


@pytest.mark.parametrize(
    "host_identity",
    [
        r"C:\Users\alice\run",
        r"\\server\share\run",
        "/root/run",
        "~/run",
    ],
)
@pytest.mark.parametrize(
    "identity_field",
    ["run_id", "provider_run_id", "worker_ref_id"],
)
def test_receipt_opaque_identities_reject_host_paths(
    identity_field: str,
    host_identity: str,
) -> None:
    payload, debt, receipt, registry = _valid_bundle()
    if identity_field == "run_id":
        receipt["run_id"] = host_identity
    elif identity_field == "provider_run_id":
        payload["facts"] = []
        payload = _resign_payload(payload)
        receipt["provider_runs"][0]["provider_run_id"] = host_identity
        receipt["worker_transaction_refs"][0][
            "provider_run_id"
        ] = host_identity
    else:
        receipt["provider_runs"][0][
            "worker_transaction_ref_ids"
        ] = [host_identity]
        receipt["worker_transaction_refs"][0]["ref_id"] = host_identity
    _refresh_artifacts(receipt, payload, debt)
    receipt["reuse_key"] = derive_program_facts_reuse_key(
        payload=payload,
        receipt=receipt,
    )
    receipt = _resign_receipt(receipt)
    with pytest.raises(
        ProgramFactsTypeError,
        match="identity|host path|portable|provider_run_id|ref_id|run_id",
    ):
        validate_program_facts_bundle(
            payload=payload,
            debt=debt,
            receipt=receipt,
            payload_file_bytes=canonical_file_bytes(payload),
            debt_file_bytes=canonical_file_bytes(debt),
            receipt_file_bytes=canonical_file_bytes(receipt),
            source_bytes_by_id=_source_bytes_for(payload),
            provider_registry=registry,
        )


def test_bundle_constructor_has_no_importable_cross_validation_bypass() -> None:
    payload, debt, receipt, registry = _valid_bundle()
    debt["snapshot_digest"] = "f" * 64
    debt = signed_payload(debt, "debt_sha256")
    _refresh_artifacts(receipt, payload, debt)
    receipt = _resign_receipt(receipt)
    assert not hasattr(
        program_facts_module,
        "_BUNDLE_VALIDATION_TOKEN",
    )
    with pytest.raises(ProgramFactsTypeError, match="snapshot"):
        program_facts_module.StructuralProgramFactsBundle(
            payload=payload,
            debt=debt,
            receipt=receipt,
            payload_file_bytes=canonical_file_bytes(payload),
            debt_file_bytes=canonical_file_bytes(debt),
            receipt_file_bytes=canonical_file_bytes(receipt),
            source_bytes_by_id=_source_bytes_for(payload),
            source_authority_digest=receipt["source_authority_digest"],
            provider_registry=registry,
        )


def test_source_authority_digest_is_required_in_receipt_and_bundle_api() -> None:
    payload, debt, receipt, registry = _valid_bundle()
    omitted = deepcopy(receipt)
    omitted.pop("source_authority_digest")
    omitted = _resign_receipt(omitted)
    with pytest.raises(ProgramFactsTypeError, match="source_authority_digest"):
        validate_program_facts_receipt(
            omitted,
            provider_registry=registry,
        )
    with pytest.raises(TypeError, match="source_manifest_authority"):
        _validate_production_program_facts_bundle(
            payload=payload,
            debt=debt,
            receipt=receipt,
            payload_file_bytes=canonical_file_bytes(payload),
            debt_file_bytes=canonical_file_bytes(debt),
            receipt_file_bytes=canonical_file_bytes(receipt),
            source_bytes_by_id=_source_bytes_for(payload),
            provider_registry=registry,
        )
    with pytest.raises(ProgramFactsTypeError, match="exact replayed"):
        _validate_production_program_facts_bundle(
            payload=payload,
            debt=debt,
            receipt=receipt,
            payload_file_bytes=canonical_file_bytes(payload),
            debt_file_bytes=canonical_file_bytes(debt),
            receipt_file_bytes=canonical_file_bytes(receipt),
            source_bytes_by_id=_source_bytes_for(payload),
            source_manifest_authority=receipt["source_authority_digest"],
            provider_registry=None,
        )


def test_source_authority_substitution_changes_reuse_and_fails_bundle_parent() -> None:
    payload, debt, receipt, registry = _valid_bundle()
    original_reuse = receipt["reuse_key"]
    substituted = deepcopy(receipt)
    substituted["source_authority_digest"] = "f" * 64
    substituted["reuse_key"] = derive_program_facts_reuse_key(
        payload=payload,
        receipt=substituted,
    )
    assert substituted["reuse_key"] != original_reuse
    substituted = _resign_receipt(substituted)
    with pytest.raises(ProgramFactsTypeError, match="source-authority"):
        _validate_program_facts_bundle(
            authority_mode="STRUCTURAL_TEST_ONLY",
            payload=payload,
            debt=debt,
            receipt=substituted,
            payload_file_bytes=canonical_file_bytes(payload),
            debt_file_bytes=canonical_file_bytes(debt),
            receipt_file_bytes=canonical_file_bytes(substituted),
            source_bytes_by_id=_source_bytes_for(payload),
            source_authority_digest=receipt["source_authority_digest"],
            provider_registry=registry,
        )
