from __future__ import annotations

from dataclasses import replace

import pytest

import program_facts_driver_integration as integration
from program_facts_driver_integration import ProgramFactsDriverIntegrationError
from program_facts_evm_provider import (
    EVM_CAPABILITY_IDS,
    emit_evm_unavailable_sidecars,
)
from program_facts_provider_api import ProgramFactsProviderAPIError
from program_facts_provider_registry import STRUCTURAL_TEST_ONLY
from program_facts_types import (
    validate_program_facts_bundle_structural_test_only,
)
import test_program_facts_evm_provider_stage2 as evm_fixture


H1 = "1" * 64
H2 = "2" * 64


def _workspace(*, admission_state: str, signed_runtime_authority: object) -> dict:
    return {
        "receipt_sha256": H1,
        "build_variant": {
            "build_system": "foundry",
            "profile": "default",
            "features": [],
            "tags": [],
            "remappings": [],
            "defines": [],
            "target_triples": [],
            "generated_source_policy": "BOUND_EXCLUDED",
            "manifests": [
                {
                    "rooted_alias": "project:foundry.toml",
                    "sha256": H1,
                    "size": 1,
                }
            ],
        },
        "build_root": {
            "rooted_alias": "project:.",
            "descriptor_sha256": H2,
        },
        "root_relation": {"relation_sha256": H1},
        "dependency_closure": {"closure_sha256": H2},
        "solc_identity": {"tool_row_sha256": H1},
        "tools": [
            {
                "tool_id": "solc",
                "admission_state": admission_state,
                "signed_runtime_authority": signed_runtime_authority,
            }
        ],
    }


def test_unadmitted_solc_is_absent_observation_not_fake_version() -> None:
    variant, compiler = integration._workspace_build_variant(
        _workspace(
            admission_state="UNADMITTED",
            signed_runtime_authority=None,
        )
    )

    assert compiler is None
    assert variant["compiler_identity_digest"] == H1
    assert variant["build_root_id"].startswith("PFW-")
    assert variant["manifest_digests"] == [
        {"path": "foundry.toml", "sha256": H1}
    ]
    assert "UNAVAILABLE" not in variant.values()


@pytest.mark.parametrize(
    ("target", "field"),
    (
        ("workspace", "receipt_sha256"),
        ("build_root", "descriptor_sha256"),
        ("root_relation", "relation_sha256"),
    ),
)
def test_workspace_root_identity_rejects_malformed_authority_binding(
    target: str,
    field: str,
) -> None:
    workspace = _workspace(
        admission_state="UNADMITTED",
        signed_runtime_authority=None,
    )
    if target == "workspace":
        workspace[field] = "not-a-digest"
    else:
        workspace[target][field] = "not-a-digest"
    with pytest.raises(
        ProgramFactsDriverIntegrationError,
        match="workspace root authority is malformed",
    ):
        integration._workspace_build_variant(workspace)


@pytest.mark.parametrize(
    "manifest",
    (
        {"rooted_alias": "project:../foundry.toml", "sha256": H1, "size": 1},
        {"rooted_alias": "host:foundry.toml", "sha256": H1, "size": 1},
        {"rooted_alias": "project:foundry.toml", "sha256": "bad", "size": 1},
        {"rooted_alias": "project:foundry.toml", "sha256": H1, "size": True},
        {"rooted_alias": "project:foundry.toml", "sha256": H1},
    ),
)
def test_workspace_manifest_projection_rejects_malformed_rows(
    manifest: dict,
) -> None:
    workspace = _workspace(
        admission_state="UNADMITTED",
        signed_runtime_authority=None,
    )
    workspace["build_variant"]["manifests"] = [manifest]
    with pytest.raises(
        ProgramFactsDriverIntegrationError,
        match="workspace manifest",
    ):
        integration._workspace_build_variant(workspace)


def test_workspace_manifest_projection_preserves_rooted_relative_path() -> None:
    workspace = _workspace(
        admission_state="UNADMITTED",
        signed_runtime_authority=None,
    )
    workspace["build_variant"]["manifests"] = [
        {
            "rooted_alias": "project:contracts/foundry.toml",
            "sha256": H1,
            "size": 1,
        }
    ]
    variant, _compiler = integration._workspace_build_variant(workspace)
    assert variant["manifest_digests"] == [
        {"path": "contracts/foundry.toml", "sha256": H1}
    ]


def test_admitted_solc_retains_exact_numeric_identity() -> None:
    _variant, compiler = integration._workspace_build_variant(
        _workspace(
            admission_state="ADMITTED",
            signed_runtime_authority={"version": "0.8.28"},
        )
    )

    assert compiler is not None
    assert compiler.to_dict() == {
        "name": "solc",
        "version": "0.8.28",
        "identity_digest": H1,
    }


def test_admitted_nonnumeric_version_remains_fail_closed() -> None:
    with pytest.raises(
        ProgramFactsProviderAPIError,
        match="toolchain version must be a dotted numeric version",
    ):
        integration._workspace_build_variant(
            _workspace(
                admission_state="ADMITTED",
                signed_runtime_authority={"version": "UNAVAILABLE"},
            )
        )


def test_unadmitted_solc_cannot_carry_signed_runtime_authority() -> None:
    with pytest.raises(
        ProgramFactsDriverIntegrationError,
        match="unadmitted workspace solc carries signed runtime authority",
    ):
        integration._workspace_build_variant(
            _workspace(
                admission_state="UNADMITTED",
                signed_runtime_authority={"version": "0.8.28"},
            )
        )


def test_absent_toolchain_roundtrips_as_typed_zero_fact_debt() -> None:
    context = replace(evm_fixture._context(), toolchains=())
    source = evm_fixture._source()
    emission = emit_evm_unavailable_sidecars(
        context=context,
        source_manifest=evm_fixture._source_manifest(),
        source_bytes_by_id={str(source["source_file_id"]): evm_fixture.SOURCE},
        build_variants=(evm_fixture._variant(),),
        audit_snapshot={
            "snapshot_digest": evm_fixture.H0,
            "source_scope_digest": evm_fixture.H1,
            "audit_config_digest": evm_fixture.H0,
            "methodology_digest": evm_fixture.H7,
            "toolchain_digest": evm_fixture.H2,
        },
        phase_io={
            "contract_digest": evm_fixture.H0,
            "launch_digest": evm_fixture.H1,
            "input_set_digest": evm_fixture.H2,
            "work_unit_key": (
                "sc/thorough/evm/claude/recon/program_facts_bake"
            ),
            "ledger_binding_state": "PRECOMMIT",
            "ledger_record_digest": "",
        },
        reason="PROVIDER_UNAVAILABLE",
        explanation=(
            "The workspace compiler has no admitted execution authority."
        ),
    )

    assert context.toolchains == ()
    assert emission.receipt["status"] == "UNAVAILABLE"
    assert not emission.payload["facts"]
    assert len(emission.debt["debts"]) == len(EVM_CAPABILITY_IDS)
    assert {row["reason"] for row in emission.debt["debts"]} == {
        "PROVIDER_UNAVAILABLE"
    }
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
        source_bytes_by_id={
            str(source["source_file_id"]): evm_fixture.SOURCE
        },
        source_authority_digest=evm_fixture.H6,
    )
    assert bundle.receipt.value["status"] == "UNAVAILABLE"
    assert bundle.production_authority_established is False
