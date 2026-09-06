"""Fixture-first contract tests for the universal MethodCard Catalog R1.

The fixtures are deliberately synthetic and Part-0 generic.  This slice proves
only a catalog/loader and receipt-validation substrate; it does not claim that
the driver, PhaseIO, prompts, or worker runtimes consume MethodCards yet.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from method_card_catalog import (
    APPLICATION_RECEIPT_SCHEMA,
    CATALOG_SCHEMA,
    UNIVERSAL_OPERATOR_IDS,
    MethodCardCatalogError,
    canonical_catalog_bytes,
    load_method_card_catalog,
    render_bound_prompt_fragment,
    validate_application_receipt,
)


REPO_ROOT = Path(__file__).resolve().parent.parent
CATALOG_PATH = REPO_ROOT / "methodology" / "method-cards-v1.yaml"
KERNEL_PATH = (
    REPO_ROOT / "prompts" / "shared" / "v2"
    / "breadth-semantic-operator-kernel.md"
)


def _default():
    return load_method_card_catalog(CATALOG_PATH, repo_root=REPO_ROOT)


def _write_catalog(tmp_path: Path, value: dict, *, canonical: bool = True) -> Path:
    target = tmp_path / "method-cards-v1.yaml"
    if canonical:
        target.write_bytes(canonical_catalog_bytes(value))
    else:
        target.write_text(
            json.dumps(value, ensure_ascii=False, indent=4) + "\n",
            encoding="utf-8",
        )
    return target


def _receipt_for(catalog, method_id: str | None = None) -> dict:
    card = catalog.card(method_id or UNIVERSAL_OPERATOR_IDS[0])
    return {
        "catalog_digest": catalog.digest,
        "evidence_locations": [
            {"line_end": 12, "line_start": 7, "path": "src/module.ext"}
        ],
        "method_id": card.method_id,
        "method_version": card.method_version,
        "not_applicable": None,
        "outcomes": [
            {
                "candidate_ids": [],
                "detail": "No safety-property deviation was established.",
                "kind": "NO_CANDIDATE",
            }
        ],
        "relation_coverage": [
            {
                "relation_ids": [],
                "selector": selector,
                "status": "EXAMINED",
            }
            for selector in card.relation_selectors
        ],
        "schema_version": APPLICATION_RECEIPT_SCHEMA,
        "status": "APPLIED",
        "steps_completed": [step.step_id for step in card.required_steps],
        "targets_examined": [
            {"node_kind": card.node_kinds[0], "target_id": "entity:1"}
        ],
        "unresolved_assumptions": [],
    }


def test_default_catalog_is_closed_canonical_and_exactly_twelve_universal_cards():
    catalog = _default()

    assert catalog.schema_version == CATALOG_SCHEMA
    assert catalog.catalog_version == "1.0.0"
    assert tuple(card.method_id for card in catalog.cards) == UNIVERSAL_OPERATOR_IDS
    assert len(catalog.cards) == 12
    assert all(card.method_version == "1.0.0" for card in catalog.cards)
    assert catalog.source_bytes == canonical_catalog_bytes(catalog.to_mapping())
    assert catalog.digest == _default().digest


def test_catalog_is_explicitly_substrate_only_and_records_integration_debt():
    catalog = _default()

    assert catalog.integration.runtime_authority is False
    assert catalog.integration.status == "SUBSTRATE_ONLY"
    assert set(catalog.integration.debt) == {
        "bind_catalog_digest_to_run_manifest_phaseio_and_workplan",
        "compile_graph_targets_and_relations_into_obligations",
        "render_or_reference_catalog_methods_from_consumer_prompts",
        "retire_duplicate_normative_method_content_after_parity",
    }


def test_bound_renderer_preserves_current_kernel_bytes_exactly():
    catalog = _default()

    assert render_bound_prompt_fragment(catalog) == KERNEL_PATH.read_bytes()


def test_catalog_semantics_cannot_drift_behind_an_unchanged_prompt_hash(tmp_path):
    raw = _default().to_mapping()
    raw["methods"][0]["operator_instruction"] = (
        "apply an unrelated generic analysis."
    )
    target = _write_catalog(tmp_path, raw)

    with pytest.raises(MethodCardCatalogError, match="byte-for-byte"):
        load_method_card_catalog(target, repo_root=REPO_ROOT)


def test_positive_application_receipt_is_complete_and_separates_judgment():
    catalog = _default()
    result = validate_application_receipt(catalog, _receipt_for(catalog))

    assert result["application_complete"] is True
    assert result["requires_human_review"] is False
    assert result["semantic_outcome"] == "NO_CANDIDATE"


def test_selector_consistent_not_applicable_receipt_is_valid():
    catalog = _default()
    receipt = _receipt_for(catalog)
    receipt.update(
        {
            "evidence_locations": [
                {"line_end": 4, "line_start": 1, "path": "src/module.ext"}
            ],
            "not_applicable": {
                "code": "NO_TARGET_MATCH",
                "detail": "The selector enumeration produced no matching entity.",
                "selector_evidence": ["src/module.ext:1-4"],
            },
            "outcomes": [
                {
                    "candidate_ids": [],
                    "detail": "No target matched the card selector.",
                    "kind": "NOT_APPLICABLE",
                }
            ],
            "relation_coverage": [],
            "status": "NOT_APPLICABLE",
            "steps_completed": [],
            "targets_examined": [],
        }
    )

    result = validate_application_receipt(catalog, receipt)

    assert result["application_complete"] is True
    assert result["semantic_outcome"] == "NOT_APPLICABLE"


def test_applied_receipt_cannot_claim_completion_without_a_target():
    catalog = _default()
    receipt = _receipt_for(catalog)
    receipt["targets_examined"] = []

    with pytest.raises(MethodCardCatalogError, match="targets_examined"):
        validate_application_receipt(catalog, receipt)


def test_applied_receipt_cannot_omit_a_required_relation_enumeration():
    catalog = _default()
    receipt = _receipt_for(catalog)
    assert receipt["relation_coverage"]
    receipt["relation_coverage"].pop()

    with pytest.raises(MethodCardCatalogError, match="relation_coverage"):
        validate_application_receipt(catalog, receipt)


def test_material_unresolved_work_is_typed_and_routes_to_human_review():
    catalog = _default()
    receipt = _receipt_for(catalog)
    receipt["status"] = "UNRESOLVED"
    receipt["steps_completed"] = receipt["steps_completed"][:-1]
    receipt["unresolved_assumptions"] = [
        "A required external behavior could not be established."
    ]
    receipt["outcomes"] = [
        {
            "candidate_ids": [],
            "detail": "Application remains materially unresolved.",
            "kind": "UNRESOLVED",
        }
    ]

    result = validate_application_receipt(catalog, receipt)

    assert result["application_complete"] is False
    assert result["requires_human_review"] is True
    assert result["semantic_outcome"] == "UNRESOLVED"


def test_duplicate_json_keys_are_rejected_before_schema_validation(tmp_path):
    raw = CATALOG_PATH.read_text(encoding="utf-8")
    duplicate = raw.replace(
        '{\n  "catalog_version"',
        '{\n  "catalog_version": "1.0.0",\n  "catalog_version"',
        1,
    )
    target = tmp_path / "duplicate.yaml"
    target.write_text(duplicate, encoding="utf-8")

    with pytest.raises(MethodCardCatalogError, match="duplicate JSON key"):
        load_method_card_catalog(target, repo_root=REPO_ROOT)


def test_casefold_duplicate_method_identity_is_rejected(tmp_path):
    raw = _default().to_mapping()
    raw["methods"][1]["method_id"] = raw["methods"][0]["method_id"].upper()
    target = _write_catalog(tmp_path, raw)

    with pytest.raises(MethodCardCatalogError, match="case-fold duplicate"):
        load_method_card_catalog(target, repo_root=REPO_ROOT)


def test_semantically_equivalent_but_noncanonical_source_is_rejected(tmp_path):
    raw = _default().to_mapping()
    target = _write_catalog(tmp_path, raw, canonical=False)

    with pytest.raises(MethodCardCatalogError, match="canonical JSON"):
        load_method_card_catalog(target, repo_root=REPO_ROOT)


@pytest.mark.parametrize(
    ("mutator", "pattern"),
    [
        (lambda raw: raw.update({"unexpected": True}), "unknown keys"),
        (
            lambda raw: raw["methods"][0].update({"unexpected": True}),
            "unknown keys",
        ),
        (
            lambda raw: raw["methods"][0]["applies_to"].update(
                {"unexpected": []}
            ),
            "unknown keys",
        ),
    ],
)
def test_unknown_keys_fail_closed(tmp_path, mutator, pattern):
    raw = _default().to_mapping()
    mutator(raw)
    target = _write_catalog(tmp_path, raw)

    with pytest.raises(MethodCardCatalogError, match=pattern):
        load_method_card_catalog(target, repo_root=REPO_ROOT)


@pytest.mark.parametrize(
    "unsafe_path",
    [
        "../outside.md",
        "C:/outside.md",
        "prompts//kernel.md",
        "prompts/kernel.md:stream",
        "prompts/NUL",
    ],
)
def test_prompt_fragment_path_escape_is_rejected(tmp_path, unsafe_path):
    raw = _default().to_mapping()
    raw["methods"][0]["prompt_fragment"]["path"] = unsafe_path
    target = _write_catalog(tmp_path, raw)

    with pytest.raises(MethodCardCatalogError, match="safe repo-relative"):
        load_method_card_catalog(target, repo_root=REPO_ROOT)


def test_prompt_fragment_hash_drift_is_rejected(tmp_path):
    raw = _default().to_mapping()
    raw["methods"][0]["prompt_fragment"]["sha256"] = "0" * 64
    target = _write_catalog(tmp_path, raw)

    with pytest.raises(MethodCardCatalogError, match="hash drift"):
        load_method_card_catalog(target, repo_root=REPO_ROOT)


@pytest.mark.parametrize(
    "marker",
    [
        "Expected H-01 finding",
        "Known target-specific vulnerability",
        "Inspect TokenVaultRouter for this answer",
        "Read C:/Users/example/private-target.sol",
    ],
)
def test_part0_lint_rejects_answer_or_target_markers(tmp_path, marker):
    raw = _default().to_mapping()
    raw["methods"][0]["required_steps"][0]["instruction"] = marker
    target = _write_catalog(tmp_path, raw)

    with pytest.raises(MethodCardCatalogError, match="Part-0"):
        load_method_card_catalog(target, repo_root=REPO_ROOT)


def test_unknown_capability_and_fidelity_fail_closed(tmp_path):
    raw = _default().to_mapping()
    raw["methods"][0]["applies_to"]["required_capabilities"].append(
        "omniscient_graph"
    )
    raw["methods"][0]["applies_to"]["required_capabilities"].sort()
    raw["methods"][0]["applies_to"]["accepted_fidelity"][
        "omniscient_graph"
    ] = ["perfect"]
    target = _write_catalog(tmp_path, raw)

    with pytest.raises(MethodCardCatalogError, match="capability"):
        load_method_card_catalog(target, repo_root=REPO_ROOT)


def test_required_and_optional_capabilities_must_be_disjoint(tmp_path):
    raw = _default().to_mapping()
    capability = raw["methods"][0]["applies_to"]["required_capabilities"][0]
    raw["methods"][0]["applies_to"]["optional_capabilities"].append(capability)
    raw["methods"][0]["applies_to"]["optional_capabilities"].sort()
    target = _write_catalog(tmp_path, raw)

    with pytest.raises(MethodCardCatalogError, match="disjoint"):
        load_method_card_catalog(target, repo_root=REPO_ROOT)


def test_every_declared_capability_requires_an_accepted_fidelity(tmp_path):
    raw = _default().to_mapping()
    capability = raw["methods"][0]["applies_to"]["required_capabilities"][0]
    del raw["methods"][0]["applies_to"]["accepted_fidelity"][capability]
    target = _write_catalog(tmp_path, raw)

    with pytest.raises(MethodCardCatalogError, match="accepted_fidelity"):
        load_method_card_catalog(target, repo_root=REPO_ROOT)


def test_unknown_target_or_relation_selector_fails_closed(tmp_path):
    raw = _default().to_mapping()
    raw["methods"][0]["relation_selectors"].append("guess_related_state")
    target = _write_catalog(tmp_path, raw)

    with pytest.raises(MethodCardCatalogError, match="relation selector"):
        load_method_card_catalog(target, repo_root=REPO_ROOT)


def test_method_id_major_and_semver_major_must_agree(tmp_path):
    raw = _default().to_mapping()
    raw["methods"][0]["method_version"] = "2.0.0"
    target = _write_catalog(tmp_path, raw)

    with pytest.raises(MethodCardCatalogError, match="major version"):
        load_method_card_catalog(target, repo_root=REPO_ROOT)


def test_receipt_rejects_wrong_catalog_or_method_version():
    catalog = _default()
    receipt = _receipt_for(catalog)
    receipt["catalog_digest"] = "0" * 64

    with pytest.raises(MethodCardCatalogError, match="catalog_digest"):
        validate_application_receipt(catalog, receipt)

    receipt = _receipt_for(catalog)
    receipt["method_version"] = "2.0.0"
    with pytest.raises(MethodCardCatalogError, match="method_version"):
        validate_application_receipt(catalog, receipt)


def test_receipt_rejects_unknown_keys_and_unsafe_evidence_paths():
    catalog = _default()
    receipt = _receipt_for(catalog)
    receipt["unexpected"] = True
    with pytest.raises(MethodCardCatalogError, match="unknown keys"):
        validate_application_receipt(catalog, receipt)

    receipt = _receipt_for(catalog)
    receipt["evidence_locations"][0]["path"] = "../outside.ext"
    with pytest.raises(MethodCardCatalogError, match="safe repo-relative"):
        validate_application_receipt(catalog, receipt)


def test_not_applicable_selector_evidence_must_bind_evidence_locations():
    catalog = _default()
    receipt = _receipt_for(catalog)
    receipt.update(
        {
            "not_applicable": {
                "code": "NO_TARGET_MATCH",
                "detail": "No selected entity was enumerated.",
                "selector_evidence": ["src/other.ext:1-4"],
            },
            "outcomes": [
                {
                    "candidate_ids": [],
                    "detail": "No target matched the selector.",
                    "kind": "NOT_APPLICABLE",
                }
            ],
            "relation_coverage": [],
            "status": "NOT_APPLICABLE",
            "steps_completed": [],
            "targets_examined": [],
        }
    )

    with pytest.raises(MethodCardCatalogError, match="selector_evidence"):
        validate_application_receipt(catalog, receipt)


def test_candidate_outcome_requires_a_candidate_identity():
    catalog = _default()
    receipt = _receipt_for(catalog)
    receipt["outcomes"][0]["kind"] = "CANDIDATE_PROPOSED"

    with pytest.raises(MethodCardCatalogError, match="candidate_ids"):
        validate_application_receipt(catalog, receipt)


def test_applied_receipt_cannot_hide_unresolved_assumptions():
    catalog = _default()
    receipt = _receipt_for(catalog)
    receipt["unresolved_assumptions"] = ["A material premise remains open."]

    with pytest.raises(MethodCardCatalogError, match="UNRESOLVED"):
        validate_application_receipt(catalog, receipt)


def test_catalog_copy_is_detached_from_frozen_loaded_state():
    catalog = _default()
    raw = catalog.to_mapping()
    raw["methods"][0]["title"] = "Mutated title"

    assert catalog.cards[0].title != "Mutated title"
