"""B0 RED fixtures for exact Program Facts CAS and PhaseIO lineage."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Callable, Mapping

from review_fixtures.program_facts_r2_1_b0_red_support import (
    require_accepts,
    require_callable,
)


EXECUTION_MODULE = "program_facts_evm_execution_set"
TERMINAL_ROLES = (
    "ATTEMPT_ARM",
    "ATTEMPT_COMPLETION",
    "ATTEMPT_DEBT",
    "RAW_CAS_MANIFEST",
)


def _terminal_artifact(
    variant_id: str,
    role: str,
    index: int,
) -> dict[str, Any]:
    output_id = f"{variant_id}-{role.casefold().replace('_', '-')}"
    return {
        "semantic_role": role,
        "producer_output_identity": output_id,
        "physical_path": (
            f"_worker_transactions/{variant_id}/{index:02d}-{role}.json"
        ),
        "size": 128 + index,
        "sha256": f"{index + 1:x}" * 64,
        "regular_single_file": True,
        "before_after_stable": True,
    }


def _execution_lineage_document() -> dict[str, Any]:
    variants = ("variant-a", "variant-b")
    expected_children = [
        {
            "selected_variant_id": variant,
            "producer_work_unit_id": f"recon/program-facts-wtx-{variant}",
            "producer_attempt_identity": f"attempt-{variant}",
        }
        for variant in variants
    ]
    terminal_rows = []
    for variant in variants:
        terminal_rows.append(
            {
                "selected_variant_id": variant,
                "producer_work_unit_id": (
                    f"recon/program-facts-wtx-{variant}"
                ),
                "producer_attempt_identity": f"attempt-{variant}",
                "terminal_artifacts": [
                    _terminal_artifact(variant, role, index)
                    for index, role in enumerate(TERMINAL_ROLES)
                ],
            }
        )
    raw_leaf = {
        "semantic_role": "RAW_CAS_LEAF",
        "producer_output_identity": "variant-a-raw-cas-leaf-0",
        "source_manifest_output_identity": (
            "variant-a-raw-cas-manifest"
        ),
        "physical_path": (
            "_program_facts_private_cas/variant-a-raw-cas-leaf-0.pfcas"
        ),
        "namespace": "program-facts-raw-cas-v1",
        "size": 64,
        "sha256": "a" * 64,
        "regular_single_file": True,
        "before_after_stable": True,
        "max_size": 128,
    }
    expanded = [
        deepcopy(artifact)
        for row in terminal_rows
        for artifact in row["terminal_artifacts"]
    ] + [deepcopy(raw_leaf)]
    expanded.sort(key=lambda row: row["producer_output_identity"])
    document: dict[str, Any] = {
        "schema": "plamen.program_facts_execution_lineage.v1",
        "run_id": "fixture-run",
        "run_generation": 7,
        "build_plan_digest": "1" * 64,
        "execution_authority_digest": "2" * 64,
        "expected_children": expected_children,
        "terminal_roster": terminal_rows,
        "terminal_roster_state": "ACTIVE",
        "raw_cas_manifests": {
            "variant-a-raw-cas-manifest": [deepcopy(raw_leaf)],
            "variant-b-raw-cas-manifest": [],
        },
        "expanded_phaseio_inputs": expanded,
        "capture_producer": {
            "work_unit_id": (
                "recon/program_facts_execution_set_capture_v1"
            ),
            "required_predecessors": [
                "recon/program_facts_build_plan_capture_v1",
                "recon/program_facts_terminal_wtx_roster_capture_v1",
            ],
        },
        "execution_rows": [
            {
                "selected_variant_id": "variant-a",
                "raw_cas_leaf_identity": (
                    "variant-a-raw-cas-leaf-0"
                ),
                "raw_cas_sha256": "a" * 64,
            }
        ],
        "bake": {
            "declared_input_identities": [
                "evm_execution_evidence.v1.pfcas",
                "evm_execution_set.v1.json",
            ],
            "observed_read_identities": [
                "evm_execution_evidence.v1.pfcas",
                "evm_execution_set.v1.json",
            ],
            "live_project_reads": [],
            "direct_raw_cas_reads": [],
        },
    }
    _assert_lineage_positive(document)
    return document


def _assert_lineage_positive(document: Mapping[str, Any]) -> None:
    expected = document["expected_children"]
    roster = document["terminal_roster"]
    assert [row["selected_variant_id"] for row in expected] == [
        "variant-a",
        "variant-b",
    ]
    assert [row["selected_variant_id"] for row in roster] == [
        "variant-a",
        "variant-b",
    ]
    assert document["terminal_roster_state"] == "ACTIVE"
    for row in roster:
        assert tuple(
            artifact["semantic_role"]
            for artifact in row["terminal_artifacts"]
        ) == TERMINAL_ROLES
    expanded = document["expanded_phaseio_inputs"]
    identities = [row["producer_output_identity"] for row in expanded]
    assert identities == sorted(identities)
    assert len(identities) == len(set(identities))
    raw_row = document["execution_rows"][0]
    raw_input = next(
        row
        for row in expanded
        if row["producer_output_identity"]
        == raw_row["raw_cas_leaf_identity"]
    )
    assert raw_input["sha256"] == raw_row["raw_cas_sha256"]
    bake = document["bake"]
    assert bake["observed_read_identities"] == bake[
        "declared_input_identities"
    ]
    assert bake["live_project_reads"] == []
    assert bake["direct_raw_cas_reads"] == []


def _validator(law: str) -> Callable[..., Any]:
    return require_callable(
        EXECUTION_MODULE,
        "validate_program_facts_execution_lineage_v1",
        law,
    )


def _accept_positive(
    validator: Callable[..., Any],
    law: str,
    document: Mapping[str, Any],
) -> None:
    _assert_lineage_positive(document)
    require_accepts(validator, law, document)


def _require_targeted_rejection(
    validator: Callable[..., Any],
    law: str,
    reason_code: str,
    document: Mapping[str, Any],
) -> None:
    try:
        result = validator(document)
    except Exception as exc:
        assert reason_code in str(exc), (
            f"R21_B0_RED[{law}]: wrong rejection cause: "
            f"{exc.__class__.__name__}: {exc}; expected {reason_code}"
        )
        return
    assert isinstance(result, Mapping), (
        f"R21_B0_RED[{law}]: rejection must carry {reason_code}"
    )
    assert result.get("accepted") is False
    assert result.get("reason_code") == reason_code


def test_a11_missing_swapped_aliased_linked_truncated_oversized_cas_rejected() -> None:
    law = "A11/raw-cas-exact-rooted-byte-authority"
    validator = _validator(law)
    mutation_classes = (
        "missing",
        "swapped",
        "aliased",
        "linked",
        "truncated",
        "oversized",
    )
    for mutation_class in mutation_classes:
        positive = _execution_lineage_document()
        _accept_positive(validator, law, positive)
        mutation = deepcopy(positive)
        raw_inputs = [
            row
            for row in mutation["expanded_phaseio_inputs"]
            if row["semantic_role"] == "RAW_CAS_LEAF"
        ]
        assert len(raw_inputs) == 1
        raw_input = raw_inputs[0]
        if mutation_class == "missing":
            mutation["expanded_phaseio_inputs"].remove(raw_input)
        elif mutation_class == "swapped":
            raw_input["sha256"] = "b" * 64
        elif mutation_class == "aliased":
            raw_input["physical_path"] = (
                "_worker_transactions/variant-a/00-ATTEMPT_ARM.json"
            )
        elif mutation_class == "linked":
            raw_input["regular_single_file"] = False
        elif mutation_class == "truncated":
            raw_input["size"] = 63
        else:
            raw_input["size"] = raw_input["max_size"] + 1
        _require_targeted_rejection(
            validator,
            law,
            "PF_A11_RAW_CAS_AUTHORITY_INVALID",
            mutation,
        )


def test_a11_execution_row_raw_digest_must_be_expanded_phaseio_input() -> None:
    law = "A11/execution-row-raw-digest-is-expanded-input"
    positive = _execution_lineage_document()
    validator = _validator(law)
    _accept_positive(validator, law, positive)
    mutation = deepcopy(positive)
    mutation["execution_rows"][0]["raw_cas_sha256"] = "f" * 64
    _require_targeted_rejection(
        validator,
        law,
        "PF_A11_EXECUTION_RAW_DIGEST_NOT_EXPANDED_INPUT",
        mutation,
    )


def test_a11_duplicate_terminal_wtx_row_rejected() -> None:
    law = "A11/one-terminal-row-per-planned-child"
    positive = _execution_lineage_document()
    validator = _validator(law)
    _accept_positive(validator, law, positive)
    mutation = deepcopy(positive)
    mutation["terminal_roster"].append(
        deepcopy(mutation["terminal_roster"][0])
    )
    _require_targeted_rejection(
        validator,
        law,
        "PF_A11_DUPLICATE_TERMINAL_WTX_ROW",
        mutation,
    )


def test_a11_n_minus_one_terminal_capture_denominator_rejected() -> None:
    law = "A11/terminal-capture-is-n-of-n"
    positive = _execution_lineage_document()
    validator = _validator(law)
    _accept_positive(validator, law, positive)
    mutation = deepcopy(positive)
    mutation["terminal_roster"] = mutation["terminal_roster"][:-1]
    _require_targeted_rejection(
        validator,
        law,
        "PF_A11_TERMINAL_CAPTURE_DENOMINATOR_INCOMPLETE",
        mutation,
    )


def test_a11_capture_producer_without_exact_predecessors_rejected() -> None:
    law = "A11/execution-capture-predecessor-set-is-exact"
    positive = _execution_lineage_document()
    validator = _validator(law)
    _accept_positive(validator, law, positive)
    mutation = deepcopy(positive)
    mutation["capture_producer"]["required_predecessors"].remove(
        "recon/program_facts_terminal_wtx_roster_capture_v1"
    )
    _require_targeted_rejection(
        validator,
        law,
        "PF_A11_CAPTURE_PREDECESSOR_SET_DIVERGED",
        mutation,
    )


def test_a11_bake_cannot_read_undeclared_raw_or_live_path() -> None:
    law = "A11/bake-reads-only-declared-evidence-pack"
    positive = _execution_lineage_document()
    validator = _validator(law)
    _accept_positive(validator, law, positive)
    mutation = deepcopy(positive)
    mutation["bake"]["direct_raw_cas_reads"] = [
        "_program_facts_private_cas/variant-a-raw-cas-leaf-0.pfcas"
    ]
    _require_targeted_rejection(
        validator,
        law,
        "PF_A11_BAKE_UNDECLARED_READ",
        mutation,
    )
