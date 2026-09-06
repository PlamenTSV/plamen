"""Adversarial contracts for proposal-only asset-representation discovery.

These fixtures intentionally exercise the trust boundary separately from the
P1-C lifecycle fixtures.  Identifier/name evidence may create work, but it
must never certify that the work was applied.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import asset_representation_foundation as F
import security_obligation_authority as A


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest().upper()


def _run_binding() -> dict[str, str]:
    return {
        "run_id": str(uuid.uuid4()),
        "source_snapshot_digest": _sha("source"),
        "ecosystem": "evm",
        "mode": "thorough",
    }


def _write_checkpoint(root: Path, binding: dict[str, str]) -> None:
    (root / "_v2_checkpoint.json").write_text(
        json.dumps(
            {
                "run_id": binding["run_id"],
                "source_snapshot_digest": binding["source_snapshot_digest"],
                "ecosystem": binding["ecosystem"],
                "mode": binding["mode"],
                "config": {
                    "pipeline": "sc",
                    "language": binding["ecosystem"],
                    "mode": binding["mode"],
                },
                "audit_snapshot": {
                    "schema": "plamen.audit-input-snapshot.v1",
                    "snapshot_digest": binding["source_snapshot_digest"],
                    "components": {
                        "source_scope": {"digest": _sha("source scope")}
                    },
                },
            }
        ),
        encoding="utf-8",
    )


def _graph(functions: dict, *, source: str = "slither", **extra) -> dict:
    return {
        "schema_version": "plamen.mechanical_graph.v2",
        "source": source,
        "functions": functions,
        "var_refs": {},
        **extra,
    }


def _write_graph(root: Path, payload: dict) -> None:
    (root / "_mechanical_graph.json").write_text(
        json.dumps(payload), encoding="utf-8"
    )


def _derive(root: Path, binding: dict[str, str]):
    return A.derive_security_obligation_authority(
        root,
        mode=binding["mode"],
        ecosystem=binding["ecosystem"],
        run_id=binding["run_id"],
        source_snapshot_digest=binding["source_snapshot_digest"],
        stage=A.PRE_DEPTH_STAGE,
    )


def _obligation(payload: dict, rule_id: str):
    return next(
        (row for row in payload["obligations"] if row["rule_id"] == rule_id),
        None,
    )


def _relation(subject: str = "fn:Vault.nativeTransfer") -> dict[str, str]:
    return {
        "kind": "WRAPPED_ASSET_CLASSIFICATION",
        "object_id": "graph:var:vault.wasset",
        "symbol": "wasset",
    }


def _recon_fact(binding: dict[str, str], *, schema: str, provenance=None) -> dict:
    row = {
        "subject_id": "fn:Vault.nativeTransfer",
        "concept": "wrapped_asset",
        "polarity": "PRESENT",
        "evidence_identity": "recon:classification:wasset",
        "relation": _relation(),
    }
    if provenance is not None:
        row["provenance"] = provenance
    return {
        "schema_version": schema,
        "run_id": binding["run_id"],
        "source_snapshot_digest": binding["source_snapshot_digest"],
        "ecosystem": binding["ecosystem"],
        "facts": [row],
    }


def _write_operator_registry(
    root: Path,
    binding: dict[str, str],
    attestations: list[dict],
) -> None:
    path = root / F.OPERATOR_ATTESTATION_FILE
    path.write_text(
        json.dumps(
            F.build_operator_attestation_registry(
                attestations, run_binding=binding
            ),
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    checkpoint_path = root / "_v2_checkpoint.json"
    checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    checkpoint["operator_attestation_bindings"] = {
        F.OPERATOR_ATTESTATION_FILE: hashlib.sha256(path.read_bytes())
        .hexdigest()
        .upper()
    }
    checkpoint_path.write_text(json.dumps(checkpoint, sort_keys=True), encoding="utf-8")


def test_provider_capability_matrix_is_closed_and_current_providers_cannot_classify():
    for provider in (
        "slither",
        "scip-rust",
        "scip-go",
        "move",
        "rust-source",
        "typed-semantic-v3",
    ):
        capability = F.provider_capability(provider)
        assert capability["provider"] == provider
        assert capability["terminal_classification"] is False

    unknown = F.provider_capability("future-magic-provider")
    assert unknown["provider"] == "UNKNOWN"
    assert unknown["native_primitive"] == F.UNAVAILABLE
    assert unknown["terminal_classification"] is False
    matrix = F.provider_capability_matrix_payload()
    assert matrix["version"] == F.PROVIDER_CAPABILITY_MATRIX_VERSION
    assert len(matrix["sha256"]) == 64
    assert matrix["providers"] == F.provider_capability_matrix()


def test_foundation_module_is_runtime_packaged_and_git_visible():
    repo = Path(__file__).resolve().parents[1]
    rules = (repo / ".gitignore").read_text(encoding="utf-8")
    assert rules.count("!scripts/asset_representation_foundation.py") == 1
    result = subprocess.run(
        ["git", "check-ignore", "-q", "scripts/asset_representation_foundation.py"],
        cwd=repo,
        check=False,
    )
    assert result.returncode == 1


@pytest.mark.parametrize(
    "windows,posix",
    [
        (r"contracts\\Vault.sol", "contracts/Vault.sol"),
        (r".\\src\\bridge\\Gateway.sol", "src/bridge/Gateway.sol"),
    ],
)
def test_path_normalization_is_host_independent(windows: str, posix: str):
    assert F.normalize_bound_path(windows) == F.normalize_bound_path(posix)


def test_manifest_path_normalization_collapses_dot_but_preserves_case():
    assert F.normalize_bound_path("src/./Vault.sol") == "src/Vault.sol"
    assert F.normalize_bound_path("src/Vault.sol") != F.normalize_bound_path(
        "src/vault.sol"
    )


@pytest.mark.parametrize(
    "unsafe", ("C:src/A.sol", "C:/src/A.sol", "/src/A.sol", "src/../A.sol")
)
def test_semantic_edge_source_rejects_absolute_drive_relative_and_parent_paths(
    unsafe: str,
):
    graph = {
        "schema_version": F.MECHANICAL_GRAPH_SCHEMA_V3,
        "source": "typed-semantic-v3",
        "semantic_edges": [
            {
                "kind": "REPRESENTATION_TRANSITION",
                "subject_id": "fn:Vault.deposit",
                "object_id": "type:WrappedAsset",
                "occurrence_id": "occ:deposit:call:1",
                "source_path": unsafe,
                "source_line": 19,
                "source_column": 5,
                "source_sha256": _sha("source bytes"),
                "provider": "typed-semantic-v3",
            }
        ],
        "functions": {},
        "var_refs": {},
    }
    result = F.extract_semantic_edge_foundation(graph)
    assert result["semantic_edges"] == []
    assert len(result["repair_obligations"]) == 1


def test_candidate_enumeration_is_uncapped_and_proposal_only():
    functions = {
        f"Module.nativeTransfer{i}": {
            "bare": f"nativeTransfer{i}",
            "loc": f"src/Module.sol:L{i + 1}",
            "callees": [f"AssetAdapter.wrap{i}"],
        }
        for i in range(17)
    }
    payload = F.enumerate_asset_representation_candidates(_graph(functions))
    assert len(payload["candidates"]) == 17
    assert payload["candidate_count"] == 17
    assert all(row["provenance"] == F.MODEL_PROPOSAL for row in payload["candidates"])
    assert all(row["terminal_application_authority"] is False for row in payload["candidates"])
    assert all(row["obligation_class"] == "asset_representation_boundary" for row in payload["candidates"])


def test_candidate_identity_is_path_separator_stable():
    win = _graph(
        {
            "Module.nativeTransfer": {
                "bare": "nativeTransfer",
                "loc": r"src\\Module.sol:L9",
                "callees": ["Adapter.wrap"],
            }
        }
    )
    posix = _graph(
        {
            "Module.nativeTransfer": {
                "bare": "nativeTransfer",
                "loc": "src/Module.sol:L9",
                "callees": ["Adapter.wrap"],
            }
        }
    )
    assert (
        F.enumerate_asset_representation_candidates(win)["candidates"][0]["candidate_id"]
        == F.enumerate_asset_representation_candidates(posix)["candidates"][0]["candidate_id"]
    )


def test_v2_recon_present_is_migration_debt_and_cannot_suppress(tmp_path: Path):
    binding = _run_binding()
    _write_checkpoint(tmp_path, binding)
    _write_graph(
        tmp_path,
        _graph(
            {
                "Vault.nativeTransfer": {
                    "bare": "nativeTransfer",
                    "loc": "src/Vault.sol:L7",
                    "callees": ["Token.approve"],
                }
            },
            var_refs={
                "Vault.wAsset": {
                    "bare": "wAsset",
                    "refs": ["Vault.nativeTransfer(src/Vault.sol:7)"],
                }
            },
        ),
    )
    (tmp_path / A.RECON_FEATURE_FILE).write_text(
        json.dumps(_recon_fact(binding, schema=A.RECON_FEATURE_SCHEMA)),
        encoding="utf-8",
    )

    facts, obligations, _ = _derive(tmp_path, binding)
    debt = _obligation(obligations, "security.wrapped_asset_classification.v1")
    assert debt is not None
    assert debt["state"] == "UNACCOUNTED"
    assert facts["issues"] == []
    assert facts["recon_provenance_summary"]["legacy_model_proposal_count"] == 1
    assert all(
        row["rule_id"] != "security.feature_fact_coverage.v1"
        for row in obligations["obligations"]
    )
    wrapped_rows = [row for row in facts["facts"] if row["concept"] == "wrapped_asset"]
    assert wrapped_rows
    assert all(row["terminal_application_authority"] is False for row in wrapped_rows)


def test_valid_v2_proposal_without_trigger_is_not_global_phase_debt(tmp_path: Path):
    binding = _run_binding()
    _write_checkpoint(tmp_path, binding)
    _write_graph(tmp_path, _graph({}))
    payload = _recon_fact(binding, schema=A.RECON_FEATURE_SCHEMA)
    payload["facts"][0].update(
        {
            "concept": "native_asset",
            "evidence_identity": "recon:native-context",
        }
    )
    payload["facts"][0].pop("relation")
    (tmp_path / A.RECON_FEATURE_FILE).write_text(json.dumps(payload), encoding="utf-8")
    facts, obligations, _ = _derive(tmp_path, binding)
    assert facts["issues"] == []
    assert facts["recon_provenance_summary"]["legacy_model_proposal_count"] == 1
    assert obligations["status"] == "COMPLETE"


def test_model_proposal_cannot_self_upgrade_by_claiming_capability(tmp_path: Path):
    binding = _run_binding()
    _write_checkpoint(tmp_path, binding)
    _write_graph(
        tmp_path,
        _graph(
            {
                "Vault.nativeTransfer": {
                    "bare": "nativeTransfer",
                    "loc": "src/Vault.sol:L7",
                    "callees": ["Token.approve"],
                }
            },
            var_refs={
                "Vault.wAsset": {
                    "bare": "wAsset",
                    "refs": ["Vault.nativeTransfer(src/Vault.sol:7)"],
                }
            },
        ),
    )
    provenance = {
        "authority": F.MODEL_PROPOSAL,
        "provider": "typed-semantic-v3",
        "capability": F.EXACT_OCCURRENCE,
    }
    payload = _recon_fact(binding, schema=F.RECON_FEATURE_SCHEMA_V3, provenance=provenance)
    (tmp_path / A.RECON_FEATURE_FILE).write_text(json.dumps(payload), encoding="utf-8")
    _, obligations, _ = _derive(tmp_path, binding)
    assert _obligation(obligations, "security.wrapped_asset_classification.v1") is not None


def test_checkpoint_local_operator_attestation_is_reserved_proposal_only(tmp_path: Path):
    binding = _run_binding()
    _write_checkpoint(tmp_path, binding)
    _write_graph(
        tmp_path,
        _graph(
            {
                "Vault.nativeTransfer": {
                    "bare": "nativeTransfer",
                    "loc": "src/Vault.sol:L7",
                    "callees": ["Token.approve"],
                }
            },
            var_refs={
                "Vault.wAsset": {
                    "bare": "wAsset",
                    "refs": ["Vault.nativeTransfer(src/Vault.sol:7)"],
                }
            },
        ),
    )
    base = _recon_fact(binding, schema=F.RECON_FEATURE_SCHEMA_V3)
    row = base["facts"][0]
    attestation = F.make_operator_attestation(
        row,
        run_binding=binding,
        attestor_id="reviewer:asset-model-owner",
        evidence_sha256=_sha("signed review record"),
    )
    row["provenance"] = {
        "authority": F.OPERATOR_ATTESTED,
        "attestation_id": attestation["attestation_id"],
    }
    _write_operator_registry(tmp_path, binding, [attestation])
    (tmp_path / A.RECON_FEATURE_FILE).write_text(json.dumps(base), encoding="utf-8")

    facts, obligations, _ = _derive(tmp_path, binding)
    assert _obligation(obligations, "security.wrapped_asset_classification.v1") is not None
    assert _obligation(obligations, "security.asset_representation_boundary.v1") is not None
    row = next(row for row in facts["facts"] if row["concept"] == "wrapped_asset")
    assert row["terminal_application_authority"] is False
    assert F.OPERATOR_ATTESTED in row["authority_provenance"]
    assert facts["recon_provenance_summary"]["reserved_operator_count"] == 1
    assert F.OPERATOR_ATTESTATION_FILE in A.security_obligation_input_artifacts(
        tmp_path, stage=A.PRE_DEPTH_STAGE
    )


def test_model_writable_operator_string_and_unbound_sidecar_are_not_authority(
    tmp_path: Path,
):
    binding = _run_binding()
    _write_checkpoint(tmp_path, binding)
    _write_graph(
        tmp_path,
        _graph(
            {
                "Vault.nativeTransfer": {
                    "bare": "nativeTransfer",
                    "loc": "src/Vault.sol:L7",
                    "callees": ["Token.approve"],
                }
            },
            var_refs={
                "Vault.wAsset": {
                    "bare": "wAsset",
                    "refs": ["Vault.nativeTransfer(src/Vault.sol:7)"],
                }
            },
        ),
    )
    payload = _recon_fact(binding, schema=F.RECON_FEATURE_SCHEMA_V3)
    row = payload["facts"][0]
    attestation = F.make_operator_attestation(
        row,
        run_binding=binding,
        attestor_id="reviewer:asset-model-owner",
        evidence_sha256=_sha("signed review record"),
    )
    row["provenance"] = {
        "authority": F.OPERATOR_ATTESTED,
        "attestation_id": attestation["attestation_id"],
    }
    # Write a syntactically exact sidecar but deliberately do not bind its
    # bytes into the driver-owned checkpoint.
    (tmp_path / F.OPERATOR_ATTESTATION_FILE).write_text(
        json.dumps(
            F.build_operator_attestation_registry([attestation], run_binding=binding),
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (tmp_path / A.RECON_FEATURE_FILE).write_text(json.dumps(payload), encoding="utf-8")

    facts, obligations, _ = _derive(tmp_path, binding)
    assert _obligation(obligations, "security.wrapped_asset_classification.v1") is not None
    assert facts["recon_provenance_summary"]["invalid_claim_count"] == 1


@pytest.mark.parametrize(
    ("attestor_id", "evidence_sha256"),
    (
        ("unknown:principal", _sha("purported evidence that does not exist")),
        ("reviewer:claimed", "F" * 64),
    ),
)
def test_unknown_operator_and_nonexistent_evidence_are_proposal_only(
    tmp_path: Path, attestor_id: str, evidence_sha256: str
):
    binding = _run_binding()
    _write_checkpoint(tmp_path, binding)
    _write_graph(
        tmp_path,
        _graph(
            {
                "Vault.nativeTransfer": {
                    "bare": "nativeTransfer",
                    "loc": "src/Vault.sol:L7",
                    "callees": ["Token.approve"],
                }
            },
            var_refs={
                "Vault.wAsset": {
                    "bare": "wAsset",
                    "refs": ["Vault.nativeTransfer(src/Vault.sol:7)"],
                }
            },
        ),
    )
    payload = _recon_fact(binding, schema=F.RECON_FEATURE_SCHEMA_V3)
    row = payload["facts"][0]
    attestation = F.make_operator_attestation(
        row,
        run_binding=binding,
        attestor_id=attestor_id,
        evidence_sha256=evidence_sha256,
    )
    row["provenance"] = {
        "authority": F.OPERATOR_ATTESTED,
        "attestation_id": attestation["attestation_id"],
    }
    _write_operator_registry(tmp_path, binding, [attestation])
    (tmp_path / A.RECON_FEATURE_FILE).write_text(json.dumps(payload), encoding="utf-8")

    facts, obligations, _ = _derive(tmp_path, binding)
    assert _obligation(obligations, "security.wrapped_asset_classification.v1") is not None
    declared = next(
        item
        for item in facts["facts"]
        if item["evidence_identity"] == "recon:classification:wasset"
    )
    assert declared["terminal_application_authority"] is False
    assert facts["recon_provenance_summary"]["reserved_operator_count"] == 1


@pytest.mark.parametrize("mutator", ("run", "source", "binding", "evidence"))
def test_stale_or_malformed_operator_attestation_reopens_work(
    tmp_path: Path, mutator: str
):
    binding = _run_binding()
    _write_checkpoint(tmp_path, binding)
    _write_graph(
        tmp_path,
        _graph(
            {
                "Vault.nativeTransfer": {
                    "bare": "nativeTransfer",
                    "loc": "src/Vault.sol:L7",
                    "callees": ["Token.approve"],
                }
            },
            var_refs={
                "Vault.wAsset": {
                    "bare": "wAsset",
                    "refs": ["Vault.nativeTransfer(src/Vault.sol:7)"],
                }
            },
        ),
    )
    base = _recon_fact(binding, schema=F.RECON_FEATURE_SCHEMA_V3)
    row = base["facts"][0]
    attestation = F.make_operator_attestation(
        row,
        run_binding=binding,
        attestor_id="reviewer:asset-model-owner",
        evidence_sha256=_sha("signed review record"),
    )
    if mutator == "run":
        attestation["run_id"] = str(uuid.uuid4())
    elif mutator == "source":
        attestation["source_snapshot_digest"] = _sha("other source")
    elif mutator == "binding":
        attestation["fact_binding_sha256"] = _sha("another fact")
    else:
        attestation["evidence_sha256"] = "not-a-digest"
    # Recompute the content ID so the fixture reaches the field-level stale
    # check instead of failing only at registry identity validation.
    attestation["attestation_id"] = "ARO-" + F._sha256(
        {key: value for key, value in attestation.items() if key != "attestation_id"}
    )[:24]
    row["provenance"] = {
        "authority": F.OPERATOR_ATTESTED,
        "attestation_id": attestation["attestation_id"],
    }
    _write_operator_registry(tmp_path, binding, [attestation])
    (tmp_path / A.RECON_FEATURE_FILE).write_text(json.dumps(base), encoding="utf-8")

    facts, obligations, _ = _derive(tmp_path, binding)
    assert _obligation(obligations, "security.wrapped_asset_classification.v1") is not None
    assert facts["recon_provenance_summary"]["invalid_claim_count"] == 1


def test_current_graph_explicit_feature_is_not_a_universal_classifier(tmp_path: Path):
    binding = _run_binding()
    _write_checkpoint(tmp_path, binding)
    _write_graph(
        tmp_path,
        _graph(
            {
                "Vault.nativeTransfer": {
                    "bare": "nativeTransfer",
                    "loc": "src/Vault.sol:L7",
                    "callees": ["Token.approve"],
                }
            },
            var_refs={
                "Vault.wAsset": {
                    "bare": "wAsset",
                    "refs": ["Vault.nativeTransfer(src/Vault.sol:7)"],
                }
            },
            feature_facts=[
                {
                    "subject_id": "fn:Vault.nativeTransfer",
                    "concept": "wrapped_asset",
                    "polarity": "PRESENT",
                    "evidence_identity": "graph:classification:wasset",
                    "relation": _relation(),
                }
            ],
        ),
    )
    facts, obligations, _ = _derive(tmp_path, binding)
    assert _obligation(obligations, "security.wrapped_asset_classification.v1") is not None
    graph_row = next(
        row
        for row in facts["facts"]
        if row["evidence_identity"] == "graph:classification:wasset"
    )
    assert graph_row["terminal_application_authority"] is False


@pytest.mark.parametrize("edge_object", ("graph:var:vault.wasset", "type:unrelated"))
def test_graph_v3_edge_is_reserved_nonterminal_even_when_exactly_bound(
    tmp_path: Path, edge_object: str
):
    binding = _run_binding()
    _write_checkpoint(tmp_path, binding)
    edge = {
        "kind": "REPRESENTATION_TRANSITION",
        "subject_id": "fn:Vault.nativeTransfer",
        "object_id": edge_object,
        "occurrence_id": "occ:native-transfer:7",
        "source_path": "src/Vault.sol",
        "source_line": 7,
        "source_column": 3,
        "source_sha256": _sha("source bytes"),
        "provider": "typed-semantic-v3",
    }
    graph = {
        "schema_version": F.MECHANICAL_GRAPH_SCHEMA_V3,
        "source": "typed-semantic-v3",
        "functions": {
            "Vault.nativeTransfer": {
                "bare": "nativeTransfer",
                "loc": "src/Vault.sol:L7",
                "callees": ["Token.approve"],
            }
        },
        "var_refs": {
            "Vault.wAsset": {
                "bare": "wAsset",
                "refs": ["Vault.nativeTransfer(src/Vault.sol:7)"],
            }
        },
        "semantic_edges": [edge],
    }
    semantic = F.extract_semantic_edge_foundation(graph)
    edge_row = semantic["semantic_edges"][0]
    feature = {
        "subject_id": "fn:Vault.nativeTransfer",
        "concept": "wrapped_asset",
        "polarity": "PRESENT",
        "evidence_identity": "typed-edge:classification:wasset",
        "relation": _relation(),
    }
    feature["provenance"] = {
        "authority": F.MECHANICAL_PROVIDER,
        "provider": "typed-semantic-v3",
        "capability": F.EXACT_RELATION_CAPABILITY,
        "semantic_edge_id": edge_row["edge_id"],
        "occurrence_id": edge_row["occurrence_id"],
        "source_sha256": edge_row["source_sha256"],
        "fact_binding_sha256": F._sha256(F.feature_fact_binding(feature)),
    }
    graph["feature_facts"] = [feature]
    _write_graph(tmp_path, graph)

    facts, obligations, _ = _derive(tmp_path, binding)
    debt = _obligation(obligations, "security.wrapped_asset_classification.v1")
    assert debt is not None
    assert _obligation(obligations, "security.asset_representation_boundary.v1") is not None
    declared = next(
        row
        for row in facts["facts"]
        if row["evidence_identity"] == "typed-edge:classification:wasset"
    )
    assert declared["terminal_application_authority"] is False


def test_v3_semantic_edges_require_exact_occurrence_binding():
    edge = {
        "kind": "REPRESENTATION_TRANSITION",
        "subject_id": "fn:Vault.deposit",
        "object_id": "type:WrappedAsset",
        "occurrence_id": "occ:deposit:call:1",
        "source_path": r"src\\Vault.sol",
        "source_line": 19,
        "source_column": 5,
        "source_sha256": _sha("source bytes"),
        "provider": "typed-semantic-v3",
    }
    graph = {
        "schema_version": F.MECHANICAL_GRAPH_SCHEMA_V3,
        "source": "typed-semantic-v3",
        "semantic_edges": [edge],
        "functions": {},
        "var_refs": {},
    }
    result = F.extract_semantic_edge_foundation(graph)
    assert result["migration_state"] == "FOUNDATION_ONLY"
    assert len(result["semantic_edges"]) == 1
    assert result["semantic_edges"][0]["source_path"] == "src/Vault.sol"
    assert result["semantic_edges"][0]["terminal_application_authority"] is False
    assert result["repair_obligations"] == []

    graph["semantic_edges"][0]["source_sha256"] = "bad"
    stale = F.extract_semantic_edge_foundation(graph)
    assert stale["migration_state"] == "DEGRADED_LOCAL_REPAIR"
    assert stale["semantic_edges"] == []
    assert len(stale["repair_obligations"]) == 1


def test_v2_graph_exposes_explicit_migration_debt_without_halting():
    result = F.extract_semantic_edge_foundation(_graph({}))
    assert result["migration_state"] == "EXPECTED_ABSENCE"
    assert result["semantic_edges"] == []
    assert result["repair_obligations"] == []
    assert result["issues"] == []


@pytest.mark.parametrize(
    "self_claim",
    (
        {"source_sha256": "A" * 64, "provider_execution_receipt": "missing"},
        {"frozen_source_sha256": "B" * 64},
        {"run_id": str(uuid.uuid4()), "source_snapshot_digest": "C" * 64},
        {"provider_execution_receipt": None},
    ),
)
def test_self_asserted_graph_v3_source_run_and_receipt_fields_never_authorize(
    self_claim: dict,
):
    edge = {
        "kind": "REPRESENTATION_TRANSITION",
        "subject_id": "fn:Vault.deposit",
        "object_id": "type:WrappedAsset",
        "occurrence_id": "occ:deposit:call:1",
        "source_path": "src/Vault.sol",
        "source_line": 19,
        "source_column": 5,
        "source_sha256": _sha("source bytes"),
        "provider": "typed-semantic-v3",
        **self_claim,
    }
    graph = {
        "schema_version": F.MECHANICAL_GRAPH_SCHEMA_V3,
        "source": "typed-semantic-v3",
        "semantic_edges": [edge],
        "functions": {},
        "var_refs": {},
    }
    result = F.extract_semantic_edge_foundation(graph)
    assert all(
        row["terminal_application_authority"] is False
        for row in result["semantic_edges"]
    )
    assert result["provider_authority_state"] == "OUT_OF_TREE_RECEIPT_UNAVAILABLE"


@pytest.mark.parametrize("provider", ("slither", "scip", "scip-rust", "evm-source"))
def test_current_provider_cannot_overclaim_graph_v3_semantic_authority(provider: str):
    graph = {
        "schema_version": F.MECHANICAL_GRAPH_SCHEMA_V3,
        "source": provider,
        "semantic_edges": [
            {
                "kind": "REPRESENTATION_TRANSITION",
                "subject_id": "fn:Vault.deposit",
                "object_id": "type:WrappedAsset",
                "occurrence_id": "occ:deposit:call:1",
                "source_path": "src/Vault.sol",
                "source_line": 19,
                "source_column": 5,
                "source_sha256": _sha("source bytes"),
                "provider": provider,
            }
        ],
        "functions": {},
        "var_refs": {},
    }
    result = F.extract_semantic_edge_foundation(graph)
    assert result["semantic_edges"] == []
    assert len(result["repair_obligations"]) == 1
    assert F.provider_capability(provider)["terminal_classification"] is False


@pytest.mark.parametrize("conflicting", (False, True))
def test_duplicate_or_conflicting_occurrence_is_local_repair(conflicting: bool):
    base = {
        "kind": "REPRESENTATION_TRANSITION",
        "subject_id": "fn:Vault.deposit",
        "object_id": "type:WrappedAsset",
        "occurrence_id": "occ:deposit:call:1",
        "source_path": "src/Vault.sol",
        "source_line": 19,
        "source_column": 5,
        "source_sha256": _sha("source bytes"),
        "provider": "typed-semantic-v3",
    }
    sibling = dict(base)
    if conflicting:
        sibling["object_id"] = "type:OtherAsset"
    graph = {
        "schema_version": F.MECHANICAL_GRAPH_SCHEMA_V3,
        "source": "typed-semantic-v3",
        "semantic_edges": [base, sibling],
        "functions": {},
        "var_refs": {},
    }
    result = F.extract_semantic_edge_foundation(graph)
    assert result["semantic_edges"] == []
    assert len(result["repair_obligations"]) == 1
    assert result["repair_obligations"][0]["occurrence_id"] == base["occurrence_id"]


def test_mixed_valid_and_malformed_v3_edges_retain_valid_and_queue_only_bad(
    tmp_path: Path,
):
    binding = _run_binding()
    _write_checkpoint(tmp_path, binding)
    valid = {
        "kind": "REPRESENTATION_TRANSITION",
        "subject_id": "fn:Vault.nativeTransfer",
        "object_id": "type:WrappedAsset",
        "occurrence_id": "occ:native-transfer:1",
        "source_path": "src/Vault.sol",
        "source_line": 7,
        "source_column": 3,
        "source_sha256": _sha("source bytes"),
        "provider": "typed-semantic-v3",
    }
    malformed = {
        **valid,
        "occurrence_id": "occ:native-transfer:2",
        "source_path": "C:src/Vault.sol",
    }
    graph = {
        "schema_version": F.MECHANICAL_GRAPH_SCHEMA_V3,
        "source": "typed-semantic-v3",
        "functions": {
            "Vault.nativeTransfer": {
                "bare": "nativeTransfer",
                "loc": "src/Vault.sol:L7",
                "callees": ["Token.wrap"],
            }
        },
        "var_refs": {},
        "semantic_edges": [valid, malformed],
    }
    foundation = F.extract_semantic_edge_foundation(graph)
    assert [row["occurrence_id"] for row in foundation["semantic_edges"]] == [
        valid["occurrence_id"]
    ]
    assert [row["occurrence_id"] for row in foundation["repair_obligations"]] == [
        malformed["occurrence_id"]
    ]
    _write_graph(tmp_path, graph)
    facts, obligations, _ = _derive(tmp_path, binding)
    repair = _obligation(obligations, "security.asset_representation_edge_repair.v1")
    assert repair is not None
    assert len(repair["trigger_aliases"]) == 1
    assert repair["trigger_aliases"][0]["object_id"] == malformed["occurrence_id"]
    assert facts["asset_representation_foundation"]["semantic_edge_count"] == 1


def test_case_distinct_symbols_and_paths_produce_distinct_relations(tmp_path: Path):
    binding = _run_binding()
    _write_checkpoint(tmp_path, binding)
    functions = {
        "Vault.lower": {
            "bare": "nativeTransfer",
            "loc": "src/Vault.sol:L7",
            "callees": ["Token.approve"],
        },
        "Vault.upper": {
            "bare": "nativeTransfer",
            "loc": "src/vault.sol:L7",
            "callees": ["Token.approve"],
        },
    }
    var_refs = {
        "Vault.wCoin": {"bare": "wCoin", "refs": ["Vault.lower(src/Vault.sol:7)"]},
        "Vault.WCoin": {"bare": "WCoin", "refs": ["Vault.upper(src/vault.sol:7)"]},
    }
    _write_graph(tmp_path, _graph(functions, var_refs=var_refs))
    _, obligations, _ = _derive(tmp_path, binding)
    debt = _obligation(obligations, "security.wrapped_asset_classification.v1")
    assert debt is not None
    aliases = debt["trigger_aliases"]
    assert {row["symbol"] for row in aliases} == {"wCoin", "WCoin"}
    assert len({row["relation_id"] for row in aliases}) == 2
    assert {row["object_id"] for row in aliases} == {
        "graph:var:Vault.wCoin",
        "graph:var:Vault.WCoin",
    }


def test_case_distinct_qualified_function_refs_bind_only_the_exact_subject(
    tmp_path: Path,
):
    binding = _run_binding()
    _write_checkpoint(tmp_path, binding)
    functions = {
        "Vault.nativeRoute": {
            "bare": "nativeRoute",
            "loc": "src/Vault.sol:L7",
            "callees": ["Token.approve"],
        },
        "vault.nativeRoute": {
            "bare": "nativeRoute",
            "loc": "src/vault.sol:L9",
            "callees": ["Token.approve"],
        },
    }
    var_refs = {
        "Vault.wCoin": {
            "bare": "wCoin",
            "refs": ["Vault.nativeRoute(src/Vault.sol:7)"],
        },
        "vault.WCoin": {
            "bare": "WCoin",
            "refs": ["vault.nativeRoute(src/vault.sol:9)"],
        },
    }
    _write_graph(tmp_path, _graph(functions, var_refs=var_refs))

    _, obligations, _ = _derive(tmp_path, binding)
    debt = _obligation(obligations, "security.wrapped_asset_classification.v1")

    assert debt is not None
    bindings = {
        row["object_id"]: row["subject_id"] for row in debt["trigger_aliases"]
    }
    assert bindings == {
        "graph:var:Vault.wCoin": "fn:Vault.nativeRoute",
        "graph:var:vault.WCoin": "fn:vault.nativeRoute",
    }


def test_reported_structured_receipt_symbol_evidence_is_case_sensitive() -> None:
    lower = {
        "alias_id": "SOT-" + "A" * 24,
        "subject_id": "fn:Vault.route",
        "relation_id": "SWR-" + "1" * 24,
        "symbol": "wCoin",
        "object_id": "graph:var:Vault.wCoin",
    }
    upper = {
        "alias_id": "SOT-" + "B" * 24,
        "subject_id": "fn:Vault.route",
        "relation_id": "SWR-" + "2" * 24,
        "symbol": "WCoin",
        "object_id": "graph:var:Vault.WCoin",
    }
    receipt = {
        "referent_alias_bindings": [
            {
                "schema_version": (
                    "plamen.security-obligation-evidence-binding.v1"
                ),
                **lower,
            }
        ]
    }

    assert A._reported_receipt_matches_alias(receipt, lower) is True
    assert A._reported_receipt_matches_alias(receipt, upper) is False


def test_legacy_receipt_without_exact_symbols_cannot_bind_case_sibling() -> None:
    receipt = {
        "referent_identifiers": ["wcoin"],
        "referent_normalized": "vaultwcoin",
    }

    assert A._reported_receipt_matches_alias(
        receipt,
        {"symbol": "wCoin", "object_id": "graph:var:Vault.wCoin"},
    ) is False


def test_wrong_schema_or_conflicting_exact_binding_cannot_bind_alias() -> None:
    alias = {
        "alias_id": "SOT-" + "A" * 24,
        "subject_id": "fn:Vault.route",
        "relation_id": "SWR-" + "1" * 24,
        "object_id": "graph:var:Vault.wCoin",
        "symbol": "wCoin",
    }
    exact = {
        "schema_version": "plamen.security-obligation-evidence-binding.v1",
        **alias,
    }
    wrong_schema = {
        "referent_alias_bindings": [
            {**exact, "schema_version": "plamen.self-asserted.v99"}
        ]
    }
    conflict = {
        "referent_alias_bindings": [
            exact,
            {**exact, "object_id": "graph:var:Sibling.wCoin"},
        ]
    }
    duplicate = {"referent_alias_bindings": [exact, dict(exact)]}

    assert A._reported_receipt_matches_alias(wrong_schema, alias) is False
    assert A._reported_receipt_matches_alias(conflict, alias) is False
    assert A._reported_receipt_matches_alias(duplicate, alias) is True


def test_duplicate_json_identity_key_is_rejected_as_malformed_binding() -> None:
    issues: list[str] = []
    marker = (
        '<!-- PLAMEN_SECURITY_OBLIGATION_EVIDENCE: {'
        '"schema_version":"plamen.security-obligation-evidence-binding.v1",'
        '"alias_id":"SOT-AAAAAAAAAAAAAAAAAAAAAAAA",'
        '"alias_id":"SOT-BBBBBBBBBBBBBBBBBBBBBBBB",'
        '"subject_id":"fn:Vault.route",'
        '"relation_id":"","object_id":"","symbol":""} -->'
    )

    rows = A._finding_alias_evidence_bindings(
        marker, issues=issues, source_label="fixture:INV-001"
    )

    assert rows == []
    assert any("malformed structured obligation evidence JSON" in row for row in issues)


@pytest.mark.parametrize(
    ("first_id", "second_id"),
    (("INV-001", "INV-001"), ("INV-001", "inv-001")),
)
def test_duplicate_or_casefold_colliding_finding_id_invalidates_only_referent(
    first_id: str, second_id: str
) -> None:
    issues: list[str] = []
    text = (
        f"## Finding [{first_id}]\nfirst\n"
        f"## Finding [{second_id}]\nsecond\n"
        "## Finding [INV-002]\nindependent\n"
    )

    sections = A._finding_sections(
        text, issues=issues, source_label="depth.md"
    )

    assert set(sections) == {"inv-002"}
    assert "independent" in sections["inv-002"]
    assert any("duplicate finding referent" in issue for issue in issues)


@pytest.mark.parametrize(
    ("start", "boundary"),
    (
        ("### Finding [INV-001]", "## Next section"),
        ("### Finding [INV-001]", "### Peer section"),
        ("## Finding [INV-001]", "## Peer section"),
    ),
)
def test_finding_section_stops_at_equal_or_higher_heading(
    start: str, boundary: str
) -> None:
    sections = A._finding_sections(
        f"{start}\ninside\n{boundary}\noutside\n"
    )

    assert "inside" in sections["inv-001"]
    assert "outside" not in sections["inv-001"]


def test_finding_section_keeps_deeper_subsections() -> None:
    sections = A._finding_sections(
        "### Finding [INV-001]\ninside\n"
        "#### Evidence\nnested evidence\n"
        "### Peer\noutside\n"
    )

    assert "#### Evidence" in sections["inv-001"]
    assert "nested evidence" in sections["inv-001"]
    assert "outside" not in sections["inv-001"]


def test_evidence_marker_inside_backtick_or_tilde_fence_is_rejected() -> None:
    payload = {
        "schema_version": "plamen.security-obligation-evidence-binding.v1",
        "alias_id": "SOT-" + "A" * 24,
        "subject_id": "fn:Vault.route",
        "relation_id": "",
        "object_id": "",
        "symbol": "",
    }
    marker = (
        "<!-- PLAMEN_SECURITY_OBLIGATION_EVIDENCE: "
        + json.dumps(payload, sort_keys=True, separators=(",", ":"))
        + " -->"
    )
    for fence in ("```json", "~~~json"):
        issues: list[str] = []
        section = f"### Finding [INV-001]\n{fence}\n{marker}\n{fence[:3]}\n"

        rows = A._finding_alias_evidence_bindings(
            section, issues=issues, source_label="depth.md:INV-001"
        )

        assert rows == []
        assert any("fenced structured obligation evidence" in issue for issue in issues)


@pytest.mark.parametrize(
    "mutation",
    (
        ("missing", "schema_version"),
        ("missing", "alias_id"),
        ("missing", "subject_id"),
        ("missing", "relation_id"),
        ("missing", "object_id"),
        ("missing", "symbol"),
        ("extra", "unexpected"),
        ("value", None),
        ("value", True),
        ("value", 7),
        ("value", []),
        ("value", {}),
        ("schema", "plamen.self-asserted.v99"),
    ),
)
def test_evidence_marker_schema_is_closed_and_string_typed(
    mutation: tuple[str, object]
) -> None:
    payload: dict[str, object] = {
        "schema_version": "plamen.security-obligation-evidence-binding.v1",
        "alias_id": "SOT-" + "A" * 24,
        "subject_id": "fn:Vault.route",
        "relation_id": "",
        "object_id": "",
        "symbol": "",
    }
    operation, value = mutation
    if operation == "missing":
        payload.pop(str(value))
    elif operation == "extra":
        payload[str(value)] = "not allowed"
    elif operation == "value":
        payload["symbol"] = value
    else:
        payload["schema_version"] = value
    marker = (
        "<!-- PLAMEN_SECURITY_OBLIGATION_EVIDENCE: "
        + json.dumps(payload, sort_keys=True, separators=(",", ":"))
        + " -->"
    )
    issues: list[str] = []

    rows = A._finding_alias_evidence_bindings(
        marker, issues=issues, source_label="depth.md:INV-001"
    )

    assert rows == []
    assert any("structured obligation evidence" in issue for issue in issues)


def test_production_authority_has_no_test_only_terminal_fixture_reference() -> None:
    source = Path(A.__file__).read_text(encoding="utf-8")

    assert "TEST_ONLY_TERMINAL_FIXTURE" not in source
    assert "TEST_ONLY_TERMINAL" not in source


@pytest.mark.parametrize(
    "unsafe",
    (
        "C:src/Vault.sol",
        "C:/src/Vault.sol",
        "/src/Vault.sol",
        "src/../Vault.sol",
    ),
)
def test_unsafe_candidate_source_path_is_localized_not_trusted(
    tmp_path: Path, unsafe: str
) -> None:
    binding = _run_binding()
    _write_checkpoint(tmp_path, binding)
    graph = _graph(
        {
            "Vault.nativeToken": {
                "bare": "nativeToken",
                "loc": f"{unsafe}:L7",
                "callees": ["Token.approve"],
            }
        }
    )
    _write_graph(tmp_path, graph)

    _, authority, _ = _derive(tmp_path, binding)

    boundary = _obligation(authority, "security.asset_representation_boundary.v1")
    repair = _obligation(
        authority, "security.asset_representation_edge_repair.v1"
    )
    assert boundary is not None
    assert boundary["state"] == "UNACCOUNTED"
    assert repair is not None and len(repair["trigger_aliases"]) == 1
    assert repair["trigger_aliases"][0]["object_id"] == "function:Vault.nativeToken"
    assert authority["issues"] == []
    assert authority["status"] == "COMPLETE"


def test_unsafe_candidate_path_spelling_is_excluded_from_stable_identity(
    tmp_path: Path,
) -> None:
    observed: list[tuple[str, str]] = []
    for index, unsafe in enumerate(("C:src/Vault.sol", "/other/Vault.sol")):
        root = tmp_path / str(index)
        root.mkdir()
        binding = _run_binding()
        _write_checkpoint(root, binding)
        _write_graph(
            root,
            _graph(
                {
                    "Vault.nativeToken": {
                        "bare": "nativeToken",
                        "loc": f"{unsafe}:L7",
                        "callees": ["Token.approve"],
                    }
                }
            ),
        )

        _, authority, _ = _derive(root, binding)
        boundary = _obligation(
            authority, "security.asset_representation_boundary.v1"
        )
        assert boundary is not None
        alias = boundary["trigger_aliases"][0]
        observed.append((alias["alias_id"], alias["relation_id"]))

    assert observed[0] == observed[1]


def test_unsafe_candidate_path_repairs_only_bad_sibling(tmp_path: Path) -> None:
    binding = _run_binding()
    _write_checkpoint(tmp_path, binding)
    _write_graph(
        tmp_path,
        _graph(
            {
                "Vault.nativeTokenUnsafe": {
                    "bare": "nativeTokenUnsafe",
                    "loc": "C:src/Vault.sol:L7",
                    "callees": ["Token.approve"],
                },
                "Vault.nativeTokenValid": {
                    "bare": "nativeTokenValid",
                    "loc": "src/Vault.sol:L9",
                    "callees": ["Token.approve"],
                },
            }
        ),
    )

    _, authority, _ = _derive(tmp_path, binding)
    boundary = _obligation(authority, "security.asset_representation_boundary.v1")
    repair = _obligation(
        authority, "security.asset_representation_edge_repair.v1"
    )

    assert boundary is not None and len(boundary["trigger_aliases"]) == 2
    assert repair is not None and len(repair["trigger_aliases"]) == 1
    assert (
        repair["trigger_aliases"][0]["object_id"]
        == "function:Vault.nativeTokenUnsafe"
    )
    assert authority["issues"] == []


def test_claimed_terminal_wrapper_classification_cannot_remove_boundary_work(
    tmp_path: Path,
):
    binding = _run_binding()
    _write_checkpoint(tmp_path, binding)
    graph = _graph(
        {
            "Vault.nativeTransfer": {
                "bare": "nativeTransfer",
                "loc": "src/Vault.sol:L7",
                "callees": ["Token.wrap"],
            }
        }
    )
    graph["var_refs"] = {
        "Vault.wAsset": {
            "bare": "wAsset",
            "refs": ["Vault.nativeTransfer(src/Vault.sol:7)"],
        }
    }
    graph["feature_facts"] = [
        {
            "subject_id": "fn:Vault.nativeTransfer",
            "concept": "wrapped_asset",
            "polarity": "PRESENT",
            "evidence_identity": "spoofed:terminal",
            "relation": _relation(),
            "provenance": {
                "authority": F.MECHANICAL_PROVIDER,
                "provider": "typed-semantic-v3",
                "capability": F.EXACT_RELATION_CAPABILITY,
                "terminal_application_authority": True,
            },
        }
    ]
    _write_graph(tmp_path, graph)
    _, obligations, _ = _derive(tmp_path, binding)
    assert _obligation(obligations, "security.asset_representation_boundary.v1") is not None
    assert _obligation(obligations, "security.wrapped_asset_classification.v1") is not None


def test_asset_representation_boundary_obligation_is_additive(tmp_path: Path):
    binding = _run_binding()
    _write_checkpoint(tmp_path, binding)
    functions = {
        f"Module.nativeTransfer{i}": {
            "bare": f"nativeTransfer{i}",
            "loc": f"src/Module.sol:L{i + 1}",
            "callees": [f"AssetAdapter.wrap{i}"],
        }
        for i in range(14)
    }
    _write_graph(tmp_path, _graph(functions))
    _, obligations, _ = _derive(tmp_path, binding)
    boundary = _obligation(obligations, "security.asset_representation_boundary.v1")
    assert boundary is not None
    assert boundary["state"] == "UNACCOUNTED"
    assert len(boundary["trigger_aliases"]) == 14
    assert len({row["alias_id"] for row in boundary["trigger_aliases"]}) == 14
