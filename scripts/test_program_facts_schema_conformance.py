from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

from jsonschema import Draft202012Validator
import pytest


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = ROOT / "rules" / "schemas"
SCHEMA_FILES = {
    "facts": "mechanical_program_facts.v1.schema.json",
    "receipt": "mechanical_program_facts_receipt.v1.schema.json",
    "debt": "mechanical_program_facts_debt.v1.schema.json",
    "registry": "program_facts_provider_registry.v1.schema.json",
    "slice": "program_facts_slice.v1.schema.json",
    "disagreement": "program_facts_disagreement.v1.schema.json",
}
H0 = "0" * 64
H1 = "1" * 64


def _schemas() -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for key, name in SCHEMA_FILES.items():
        path = SCHEMA_ROOT / name
        assert path.is_file(), f"missing schema: {path}"
        payload = json.loads(path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(payload)
        result[key] = payload
    return result


def _minimal_documents() -> dict[str, dict[str, object]]:
    facts = {
        "schema_version": "plamen.mechanical_program_facts.v1",
        "canonicalization_version": "plamen.canonical_json.v1",
        "authority": {
            "semantic_authority": "ADDITIVE_PROPOSAL_ONLY",
            "terminal_negative_authority": False,
            "can_suppress": False,
            "can_demote": False,
            "can_refute": False,
            "can_mark_examined": False,
            "can_certify_clean": False,
        },
        "snapshot_ref": {
            "snapshot_digest": H0,
            "source_scope_digest": H0,
            "source_manifest_digest": H0,
        },
        "ecosystem": "daml",
        "build_variants": [],
        "source_files": [],
        "provider_capability_refs": [],
        "nodes": [],
        "occurrences": [],
        "facts": [],
        "coverage": [],
        "payload_sha256": H1,
    }
    debt = {
        "schema_version": "plamen.mechanical_program_facts_debt.v1",
        "snapshot_digest": H0,
        "source_manifest_digest": H0,
        "authority": "MANDATORY_REVIEW_NO_NEGATIVE_INFERENCE",
        "debts": [],
        "summary": {
            "by_reason": {},
            "affected_capabilities": [],
            "affected_source_file_ids": [],
            "has_blocking_reuse_debt": False,
        },
        "debt_sha256": H1,
    }
    receipt = {
        "schema_version": "plamen.mechanical_program_facts_receipt.v1",
        "run_id": "fixture-run",
        "status": "UNAVAILABLE",
            "audit_snapshot": {
            "snapshot_digest": H0,
            "source_scope_digest": H0,
            "audit_config_digest": H0,
            "methodology_digest": H0,
                "toolchain_digest": H0,
            },
            "source_authority_digest": H0,
            "source_manifest": {
            "policy_version": "plamen.program_facts_source_scope.v1",
            "eligible_files": [],
            "excluded_files": [],
            "file_count": 0,
            "byte_count": 0,
            "manifest_digest": H0,
        },
        "build_attempts": [],
        "provider_runs": [],
        "worker_transaction_refs": [],
        "phase_io": {
            "contract_digest": H0,
            "launch_digest": H0,
            "input_set_digest": H0,
            "work_unit_key": "recon/program_facts_bake/fixture",
            "ledger_binding_state": "PRECOMMIT",
            "ledger_record_digest": "",
        },
        "artifacts": {
            "facts": {
                "path": "mechanical_program_facts.v1.json",
                "document_sha256": H1,
                "file_sha256": H1,
                "size": 0,
            },
            "debt": {
                "path": "mechanical_program_facts_debt.v1.json",
                "document_sha256": H1,
                "file_sha256": H1,
                "size": 0,
            },
        },
        "reuse_key": H0,
        "receipt_sha256": H1,
    }
    registry = {
        "schema_version": "plamen.program_facts_provider_registry.v1",
        "release_state": "NO_PROVIDER_AUTHORITY",
        "providers": [],
    }
    slice_doc = {
        "schema_version": "plamen.program_facts_slice.v1",
        "bundle_ref": {
            "snapshot_digest": H0,
            "payload_sha256": H1,
            "receipt_sha256": H1,
            "debt_sha256": H1,
        },
        "request": {
            "obligation_ids": [],
            "selection_predicate": {
                "seed_node_ids": [],
                "relation_kinds": [],
                "direction": "BOTH",
                "max_graph_radius": 0,
            },
            "max_facts": 0,
            "max_bytes": 0,
            "max_excerpts": 0,
        },
        "selected": {"fact_ids": [], "node_ids": [], "occurrence_ids": []},
        "source_excerpts": [],
        "capability_evidence": [],
        "debt_banner": {
            "disagreement_ids": [],
            "coverage_ids": [],
            "debt_ids": [],
            "truncated": False,
            "additional_facts_omitted_obligation_id": "",
        },
        "authority_statement": (
            "Structural evidence only; absence is not safety; do not suppress, "
            "demote, refute, or mark examined."
        ),
    }
    disagreement = {
        "schema_version": "plamen.program_facts_disagreement.v1",
        "disagreement_id": "PFDG-" + "a" * 24,
        "canonical_obligation_id": "PFOB-" + "b" * 24,
        "providers": ["fixture.provider.a", "fixture.provider.b"],
        "fact_ids": ["PFF-" + "c" * 24, "PFF-" + "d" * 24],
        "conflict_kind": "TARGET",
        "required_action": "ADD_REVIEW_OBLIGATION",
        "resolution": "UNRESOLVED",
        "terminal_negative_authority": False,
    }
    return {
        "facts": facts,
        "receipt": receipt,
        "debt": debt,
        "registry": registry,
        "slice": slice_doc,
        "disagreement": disagreement,
    }


def test_all_six_draft_2020_12_schemas_accept_minimal_closed_documents() -> None:
    schemas = _schemas()
    for key, document in _minimal_documents().items():
        Draft202012Validator(schemas[key]).validate(document)


def test_provider_api_debt_vocabulary_matches_closed_mechanical_schema() -> None:
    import program_facts_provider_api as provider_api

    schema_reasons = set(
        _schemas()["debt"]["$defs"]["reason"]["enum"]
    )
    assert provider_api._MECHANICAL_DEBT_CODES == schema_reasons


@pytest.mark.parametrize("schema_key", sorted(SCHEMA_FILES))
def test_every_top_level_schema_rejects_unknown_fields(schema_key: str) -> None:
    schemas = _schemas()
    document = deepcopy(_minimal_documents()[schema_key])
    document["unexpected"] = True
    errors = list(Draft202012Validator(schemas[schema_key]).iter_errors(document))
    assert any(error.validator == "additionalProperties" for error in errors)


def test_payload_authority_is_closed_and_additive_only() -> None:
    schema = _schemas()["facts"]
    document = deepcopy(_minimal_documents()["facts"])
    document["authority"]["can_suppress"] = True
    assert list(Draft202012Validator(schema).iter_errors(document))
    document = deepcopy(_minimal_documents()["facts"])
    document["authority"]["unexpected"] = False
    assert list(Draft202012Validator(schema).iter_errors(document))


def test_receipt_rejects_postcommit_cycle_and_nonempty_ledger_digest() -> None:
    schema = _schemas()["receipt"]
    document = deepcopy(_minimal_documents()["receipt"])
    document["phase_io"]["ledger_binding_state"] = "POSTCOMMIT"
    document["phase_io"]["ledger_record_digest"] = H0
    assert list(Draft202012Validator(schema).iter_errors(document))


def test_disagreement_cannot_choose_a_winner_or_have_one_provider() -> None:
    schema = _schemas()["disagreement"]
    document = deepcopy(_minimal_documents()["disagreement"])
    document["providers"] = ["fixture.provider.a"]
    assert list(Draft202012Validator(schema).iter_errors(document))
    document = deepcopy(_minimal_documents()["disagreement"])
    document["resolution"] = "PROVIDER_A_WINS"
    assert list(Draft202012Validator(schema).iter_errors(document))
