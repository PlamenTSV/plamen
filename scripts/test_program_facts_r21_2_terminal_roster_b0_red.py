from __future__ import annotations

from collections.abc import Iterator, Mapping
from copy import deepcopy
import ast
import hashlib
import importlib
import inspect
from pathlib import Path
from typing import Any

from review_fixtures.program_facts_r2_1_b0_red_support import (
    body_digest,
    build_plan_validation_kwargs,
    execution_input_material,
    expected_children_document,
    frozen_build_plan_document,
    ledger_rows_for,
    one_raw_cas_leaf,
    raw_cas_leaf,
    require_accepts,
    require_callable,
    require_rejects,
    assert_schema_accepts,
    terminal_roster_document,
)


EXECUTION_MODULE = "program_facts_evm_execution_set"


class _ObjectNewBuildPlan(Mapping[str, object]):
    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise RuntimeError("constructor is intentionally unavailable")

    def __getitem__(self, key: str) -> object:
        return self._payload[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._payload)

    def __len__(self) -> int:
        return len(self._payload)


def _expected_and_roster(
    law: str,
    *,
    variants: tuple[str, ...] = ("variant-a", "variant-b"),
    plan_document: Mapping[str, Any] | None = None,
    with_raw_leaf: bool = False,
    raw_leaf_groups: list[list[dict[str, object]]] | None = None,
):
    plan_document = dict(
        plan_document or frozen_build_plan_document(variants)
    )
    plan_kwargs = build_plan_validation_kwargs(plan_document)
    plan_validator = require_callable(
        EXECUTION_MODULE, "validate_frozen_build_plan_v1", law
    )
    build_plan = require_accepts(
        plan_validator,
        law,
        plan_document,
        **plan_kwargs,
    )
    expected_builder = require_callable(
        EXECUTION_MODULE, "build_expected_wtx_children_v1", law
    )
    expected = require_accepts(
        expected_builder,
        law,
        run_id=plan_document["run_id"],
        run_generation=plan_document["run_generation"],
        execution_authority_digest=plan_document[
            "execution_authority_digest"
        ],
        build_plan=build_plan,
        **plan_kwargs,
    )
    base_ledger = ledger_rows_for(expected)
    manifest_outputs = [
        artifact["producer_output_identity"]
        for child in expected["expected_wtx_children"]
        for artifact in child["terminal_artifacts"]
        if artifact["logical_role"] == "RAW_CAS_MANIFEST"
    ]
    if raw_leaf_groups is not None:
        assert len(raw_leaf_groups) <= len(manifest_outputs)
        leaves_by_manifest = {
            manifest_outputs[index]: leaves
            for index, leaves in enumerate(raw_leaf_groups)
        }
    else:
        leaves_by_manifest = (
            {manifest_outputs[0]: [one_raw_cas_leaf()]}
            if with_raw_leaf
            else {}
        )
    ledger, raw_manifests, expanded = execution_input_material(
        expected,
        base_ledger,
        leaves_by_manifest=leaves_by_manifest,
    )
    roster_builder = require_callable(
        EXECUTION_MODULE, "build_terminal_wtx_roster_v1", law
    )
    roster = require_accepts(
        roster_builder,
        law,
        expected_children=expected,
        ledger_rows=ledger,
        build_plan=build_plan,
        **plan_kwargs,
    )
    assert_schema_accepts("expected_children", expected)
    assert_schema_accepts("terminal_roster", roster)
    return expected, roster, ledger, build_plan, raw_manifests, expanded


def _require_valid_expected(validator, law, expected, build_plan):
    return require_accepts(
        validator,
        law,
        expected,
        build_plan=build_plan,
        **build_plan_validation_kwargs(build_plan),
    )


def _require_valid_roster(
    validator,
    law,
    expected,
    roster,
    ledger,
    build_plan,
):
    return require_accepts(
        validator,
        law,
        roster,
        expected_children=expected,
        ledger_rows=ledger,
        build_plan=build_plan,
        **build_plan_validation_kwargs(build_plan),
    )


def _require_valid_execution(
    law: str,
    *,
    with_raw_leaf: bool = False,
    raw_leaf_groups: list[list[dict[str, object]]] | None = None,
):
    expected, roster, ledger, build_plan, manifests, expanded = (
        _expected_and_roster(
            law,
            with_raw_leaf=with_raw_leaf,
            raw_leaf_groups=raw_leaf_groups,
        )
    )
    validator = require_callable(
        EXECUTION_MODULE, "validate_execution_set_capture_inputs_v1", law
    )
    result = require_accepts(
        validator,
        law,
        build_plan=build_plan,
        expected_children=expected,
        terminal_roster=roster,
        terminal_roster_ledger_state="ACTIVE",
        terminal_ledger_rows=ledger,
        raw_cas_manifests=manifests,
        expanded_inputs=expanded,
        **build_plan_validation_kwargs(build_plan),
    )
    assert result["terminal_artifact_count"] == len(ledger)
    expected_leaf_count = (
        sum(len(group) for group in raw_leaf_groups)
        if raw_leaf_groups is not None
        else (1 if with_raw_leaf else 0)
    )
    assert result["raw_cas_leaf_count"] == expected_leaf_count
    assert result["terminal_artifact_denominator_digest"]
    assert result["raw_cas_leaf_denominator_digest"]
    return (
        expected,
        roster,
        ledger,
        build_plan,
        manifests,
        expanded,
        validator,
    )


def _reject_raw_path_alias(
    law: str,
    raw_leaf_groups: list[list[dict[str, object]]],
) -> None:
    _require_valid_execution(
        law,
        raw_leaf_groups=[
            [
                raw_cas_leaf(
                    cas_leaf_id="distinct-leaf-a",
                    physical_path=(
                        "_program_facts_private_cas/distinct-a.pfcas"
                    ),
                ),
                raw_cas_leaf(
                    cas_leaf_id="distinct-leaf-b",
                    physical_path=(
                        "_program_facts_private_cas/distinct-b.pfcas"
                    ),
                ),
            ]
        ],
    )
    expected, roster, ledger, build_plan, manifests, expanded = (
        _expected_and_roster(
            law,
            raw_leaf_groups=raw_leaf_groups,
        )
    )
    validator = require_callable(
        EXECUTION_MODULE, "validate_execution_set_capture_inputs_v1", law
    )
    require_rejects(
        validator,
        law,
        build_plan=build_plan,
        expected_children=expected,
        terminal_roster=roster,
        terminal_roster_ledger_state="ACTIVE",
        terminal_ledger_rows=ledger,
        raw_cas_manifests=manifests,
        expanded_inputs=expanded,
        **build_plan_validation_kwargs(build_plan),
    )


def _legacy_plan_closure_mint():
    integrity_key = b"fixture-plan-key-is-not-authority"

    def mint(payload: Mapping[str, Any]) -> tuple[dict[str, Any], str]:
        tag = body_digest(
            {
                **dict(payload),
                "legacy_integrity_key_digest": hashlib.sha256(
                    integrity_key
                ).hexdigest(),
            },
            "build_plan_digest",
        )
        return dict(payload), tag

    return mint


def test_r21_2_terminal_roster_producer_is_registered_and_required() -> None:
    law = "R2.1-2/terminal-roster-producer-registration"
    contracts = require_callable(
        EXECUTION_MODULE, "program_facts_phase_io_contracts_v1", law
    )
    rows = require_accepts(contracts, law)
    assert "recon/program_facts_terminal_wtx_roster_capture_v1" in rows
    assert "recon/program_facts_execution_set_capture_v1" in rows
    execution = rows["recon/program_facts_execution_set_capture_v1"]
    assert (
        "recon/program_facts_terminal_wtx_roster_capture_v1"
        in execution["required_predecessors"]
    )


def test_r21_2_roster_cannot_define_its_own_producer_denominator() -> None:
    law = "R2.1-2/roster-cannot-self-authorize-denominator"
    expected, roster, ledger, build_plan, _manifests, _expanded = (
        _expected_and_roster(law)
    )
    validator = require_callable(
        EXECUTION_MODULE, "validate_terminal_wtx_roster_v1", law
    )
    _require_valid_roster(
        validator, law, expected, roster, ledger, build_plan
    )
    roster["rows"][0]["producer_work_unit_id"] = "unplanned-self-declared-work"
    roster["roster_body_sha256"] = body_digest(roster, "roster_body_sha256")
    require_rejects(
        validator,
        law,
        roster,
        expected_children=expected,
        ledger_rows=ledger,
        build_plan=build_plan,
        **build_plan_validation_kwargs(build_plan),
    )


def test_r21_2_build_plan_and_expected_child_ids_must_match() -> None:
    law = "R2.1-2/build-plan-child-id-cross-binding"
    expected, _roster, _ledger, build_plan, _manifests, _expanded = (
        _expected_and_roster(law)
    )
    assert_schema_accepts("expected_children", expected)
    validator = require_callable(
        EXECUTION_MODULE, "validate_expected_wtx_children_v1", law
    )
    _require_valid_expected(validator, law, expected, build_plan)
    foreign_document = frozen_build_plan_document(
        ("variant-a", "variant-c")
    )
    plan_validator = require_callable(
        EXECUTION_MODULE, "validate_frozen_build_plan_v1", law
    )
    foreign_plan = require_accepts(
        plan_validator,
        law,
        foreign_document,
        **build_plan_validation_kwargs(foreign_document),
    )
    require_rejects(
        validator,
        law,
        expected,
        build_plan=foreign_plan,
        **build_plan_validation_kwargs(foreign_plan),
    )


def test_r21_2_selected_variants_map_one_to_one_to_expected_children() -> None:
    law = "R2.1-2/selected-variant-child-bijection"
    positive, _roster, _ledger, build_plan, _manifests, _expanded = (
        _expected_and_roster(law)
    )
    validator = require_callable(
        EXECUTION_MODULE, "validate_expected_wtx_children_v1", law
    )
    _require_valid_expected(validator, law, positive, build_plan)
    expected = deepcopy(positive)
    expected["expected_wtx_children"][1]["selected_variant_id"] = "variant-a"
    expected["children_body_sha256"] = body_digest(
        expected, "children_body_sha256"
    )
    assert_schema_accepts("expected_children", expected)
    require_rejects(
        validator,
        law,
        expected,
        build_plan=build_plan,
        **build_plan_validation_kwargs(build_plan),
    )


def test_r21_2_n_minus_one_and_n_plus_one_terminal_producers_rejected() -> None:
    law = "R2.1-2/terminal-cardinality-totality"
    expected, roster, ledger, build_plan, _manifests, _expanded = (
        _expected_and_roster(law)
    )
    validator = require_callable(
        EXECUTION_MODULE, "validate_terminal_wtx_roster_v1", law
    )
    _require_valid_roster(
        validator, law, expected, roster, ledger, build_plan
    )
    for rows in (roster["rows"][:-1], roster["rows"] + [deepcopy(roster["rows"][0])]):
        mutated = deepcopy(roster)
        mutated["rows"] = rows
        mutated["terminal_child_count"] = len(rows)
        mutated["roster_body_sha256"] = body_digest(
            mutated, "roster_body_sha256"
        )
        assert_schema_accepts("terminal_roster", mutated)
        require_rejects(
            validator,
            law,
            mutated,
            expected_children=expected,
            ledger_rows=ledger,
            build_plan=build_plan,
            **build_plan_validation_kwargs(build_plan),
        )


def test_r21_2_terminal_path_size_hash_and_role_must_match_ledger() -> None:
    law = "R2.1-2/terminal-artifact-ledger-cross-binding"
    expected, roster, ledger, build_plan, _manifests, _expanded = (
        _expected_and_roster(law)
    )
    validator = require_callable(
        EXECUTION_MODULE, "validate_terminal_wtx_roster_v1", law
    )
    _require_valid_roster(
        validator, law, expected, roster, ledger, build_plan
    )
    mutations = {
        "physical_path": "foreign/path.json",
        "size": roster["rows"][0]["terminal_artifacts"][0]["size"] + 1,
        "sha256": "f" * 64,
        "semantic_role": "FOREIGN_ROLE",
    }
    for field, value in mutations.items():
        mutated = deepcopy(roster)
        mutated["rows"][0]["terminal_artifacts"][0][field] = value
        mutated["roster_body_sha256"] = body_digest(
            mutated, "roster_body_sha256"
        )
        assert_schema_accepts("terminal_roster", mutated)
        require_rejects(
            validator,
            law,
            mutated,
            expected_children=expected,
            ledger_rows=ledger,
            build_plan=build_plan,
            **build_plan_validation_kwargs(build_plan),
        )


def test_r21_2_roster_capture_rejects_foreign_run_generation_or_attempt() -> None:
    law = "R2.1-2/terminal-producer-run-generation-attempt-binding"
    expected, roster, ledger, build_plan, _manifests, _expanded = (
        _expected_and_roster(law)
    )
    validator = require_callable(
        EXECUTION_MODULE, "validate_terminal_wtx_roster_v1", law
    )
    _require_valid_roster(
        validator, law, expected, roster, ledger, build_plan
    )
    mutations = (
        ("run_id", "foreign-run"),
        ("run_generation", expected["run_generation"] + 1),
        ("producer_attempt_identity", "foreign-attempt"),
    )
    for field, value in mutations:
        mutated_ledger = deepcopy(ledger)
        if field == "producer_attempt_identity":
            mutated_ledger[0][field] = value
        else:
            mutated_ledger[0][field] = value
        require_rejects(
            validator,
            law,
            roster,
            expected_children=expected,
            ledger_rows=mutated_ledger,
            build_plan=build_plan,
            **build_plan_validation_kwargs(build_plan),
        )


def test_r21_2_execution_capture_waits_for_active_roster() -> None:
    law = "R2.1-2/execution-capture-requires-active-roster"
    expected, roster, ledger, build_plan, manifests, expanded = (
        _expected_and_roster(law)
    )
    validator = require_callable(
        EXECUTION_MODULE, "validate_execution_set_capture_inputs_v1", law
    )
    require_accepts(
        validator,
        law,
        build_plan=build_plan,
        expected_children=expected,
        terminal_roster=roster,
        terminal_roster_ledger_state="ACTIVE",
        terminal_ledger_rows=ledger,
        raw_cas_manifests=manifests,
        expanded_inputs=expanded,
        **build_plan_validation_kwargs(build_plan),
    )
    require_rejects(
        validator,
        law,
        build_plan=build_plan,
        expected_children=expected,
        terminal_roster=roster,
        terminal_roster_ledger_state="COMMITTED_NOT_ACTIVE",
        terminal_ledger_rows=ledger,
        raw_cas_manifests=manifests,
        expanded_inputs=expanded,
        **build_plan_validation_kwargs(build_plan),
    )


def test_r21_2_b4_cannot_start_without_b3_manifest_expansion() -> None:
    law = "R2.1-2/b3-manifest-expansion-precedes-b4"
    authorizer = require_callable(
        EXECUTION_MODULE, "authorize_b4_execution_capture_v1", law
    )
    require_accepts(
        authorizer,
        law,
        manifest_expansion_state="FROZEN_ACCEPTED",
        independent_b3_review_state="PASS",
    )
    require_rejects(
        authorizer,
        law,
        manifest_expansion_state="PROVISIONAL_OR_ABSENT",
        independent_b3_review_state="PASS",
    )


def test_r21_2_c2_cannot_redefine_manifest_expansion() -> None:
    law = "R2.1-2/c2-reuses-b3-manifest-expansion-semantics"
    validator = require_callable(
        EXECUTION_MODULE, "validate_manifest_expansion_reuse_v1", law
    )
    require_accepts(
        validator,
        law,
        accepted_b3_semantics_digest="1" * 64,
        c2_observed_semantics_digest="1" * 64,
    )
    require_rejects(
        validator,
        law,
        accepted_b3_semantics_digest="1" * 64,
        c2_observed_semantics_digest="2" * 64,
    )


def test_r21_2_manifest_expansion_change_invalidates_b4_evidence() -> None:
    law = "R2.1-2/manifest-expansion-drift-invalidates-b4"
    validator = require_callable(
        EXECUTION_MODULE, "validate_b4_evidence_authority_v1", law
    )
    require_accepts(
        validator,
        law,
        b4_evidence={"manifest_expansion_semantics_digest": "1" * 64},
        installed_manifest_expansion_semantics_digest="1" * 64,
    )
    require_rejects(
        validator,
        law,
        b4_evidence={"manifest_expansion_semantics_digest": "1" * 64},
        installed_manifest_expansion_semantics_digest="2" * 64,
    )


def test_r21_2_execution_set_cannot_read_unrostered_cas_or_terminal_output() -> None:
    law = "R2.1-2/execution-set-exact-expanded-input-denominator"
    expected, roster, ledger, build_plan, manifests, expanded = (
        _expected_and_roster(law)
    )
    unmanifested = deepcopy(expanded)
    expanded.append(
        {
            "run_id": expected["run_id"],
            "run_generation": expected["run_generation"],
            "producer_work_unit_id": "unrostered-work",
            "producer_attempt_identity": "unrostered-attempt",
            "producer_output_identity": "unrostered-cas-leaf",
            "source_manifest_output_identity": "unrostered-manifest",
            "semantic_role": "RAW_CAS_LEAF",
            "namespace": "program-facts-raw-cas-v1",
            "cas_leaf_id": "unrostered-cas-leaf",
            "physical_path": "foreign/unrostered.pfcas",
            "size": 1,
            "sha256": "f" * 64,
            "terminal": False,
        }
    )
    validator = require_callable(
        EXECUTION_MODULE, "validate_execution_set_capture_inputs_v1", law
    )
    require_accepts(
        validator,
        law,
        build_plan=build_plan,
        expected_children=expected,
        terminal_roster=roster,
        terminal_roster_ledger_state="ACTIVE",
        terminal_ledger_rows=ledger,
        raw_cas_manifests=manifests,
        expanded_inputs=unmanifested,
        **build_plan_validation_kwargs(build_plan),
    )
    require_rejects(
        validator,
        law,
        build_plan=build_plan,
        expected_children=expected,
        terminal_roster=roster,
        terminal_roster_ledger_state="ACTIVE",
        terminal_ledger_rows=ledger,
        raw_cas_manifests=manifests,
        expanded_inputs=expanded,
        **build_plan_validation_kwargs(build_plan),
    )


def test_core2_one_child_identity_family_substitution_rejected_after_resign() -> None:
    law = "PF-CORE-2/one-family-rederived-identity"
    expected, _roster, _ledger, build_plan, _manifests, _expanded = (
        _expected_and_roster(law)
    )
    validator = require_callable(
        EXECUTION_MODULE, "validate_expected_wtx_children_v1", law
    )
    _require_valid_expected(validator, law, expected, build_plan)
    forged = deepcopy(expected)
    child = forged["expected_wtx_children"][0]
    child["expected_work_unit_id"] = "program-facts-wtx-forged-family"
    child["expected_attempt_identity"] = "attempt-forged-family"
    for index, artifact in enumerate(child["terminal_artifacts"]):
        artifact["producer_output_identity"] = f"output-forged-{index}"
        artifact["expected_relative_path"] = (
            f"_worker_transactions/attempt-forged-family/forged-{index}.json"
        )
    forged["children_body_sha256"] = body_digest(
        forged, "children_body_sha256"
    )
    require_rejects(
        validator,
        law,
        forged,
        build_plan=build_plan,
        **build_plan_validation_kwargs(build_plan),
    )


def test_core2_all_child_identity_families_substitution_rejected_after_resign() -> None:
    law = "PF-CORE-2/all-families-rederived-identity"
    expected, _roster, _ledger, build_plan, _manifests, _expanded = (
        _expected_and_roster(law)
    )
    validator = require_callable(
        EXECUTION_MODULE, "validate_expected_wtx_children_v1", law
    )
    _require_valid_expected(validator, law, expected, build_plan)
    forged = deepcopy(expected)
    for family, child in enumerate(forged["expected_wtx_children"]):
        child["expected_work_unit_id"] = (
            f"program-facts-wtx-forged-family-{family}"
        )
        child["expected_attempt_identity"] = (
            f"attempt-forged-family-{family}"
        )
        for index, artifact in enumerate(child["terminal_artifacts"]):
            artifact["producer_output_identity"] = (
                f"output-forged-{family}-{index}"
            )
            artifact["expected_relative_path"] = (
                "_worker_transactions/"
                f"attempt-forged-family-{family}/forged-{index}.json"
            )
    forged["children_body_sha256"] = body_digest(
        forged, "children_body_sha256"
    )
    require_rejects(
        validator,
        law,
        forged,
        build_plan=build_plan,
        **build_plan_validation_kwargs(build_plan),
    )


def test_core2_variant_and_claimed_plan_digest_substitution_rejected() -> None:
    law = "PF-CORE-2/variant-and-plan-digest-substitution"
    expected, _roster, _ledger, build_plan, _manifests, _expanded = (
        _expected_and_roster(law)
    )
    validator = require_callable(
        EXECUTION_MODULE, "validate_expected_wtx_children_v1", law
    )
    _require_valid_expected(validator, law, expected, build_plan)
    plan_validator = require_callable(
        EXECUTION_MODULE, "validate_frozen_build_plan_v1", law
    )
    foreign_plan_document = frozen_build_plan_document(
        ("variant-a", "variant-c")
    )
    foreign_plan = require_accepts(
        plan_validator,
        law,
        foreign_plan_document,
        **build_plan_validation_kwargs(foreign_plan_document),
    )
    forged = deepcopy(expected)
    forged["build_plan_digest"] = foreign_plan_document[
        "build_plan_digest"
    ]
    forged["expected_wtx_children"][1][
        "selected_variant_id"
    ] = "variant-c"
    forged["children_body_sha256"] = body_digest(
        forged, "children_body_sha256"
    )
    require_rejects(
        validator,
        law,
        forged,
        build_plan=foreign_plan,
        **build_plan_validation_kwargs(foreign_plan),
    )


def test_core2_changed_build_plan_body_with_claimed_digest_rejected() -> None:
    law = "PF-CORE-2/build-plan-body-self-digest"
    validator = require_callable(
        EXECUTION_MODULE, "validate_frozen_build_plan_v1", law
    )
    positive = frozen_build_plan_document()
    positive_kwargs = build_plan_validation_kwargs(positive)
    require_accepts(validator, law, positive, **positive_kwargs)
    forged = deepcopy(positive)
    forged["selected_variant_ids"][1] = "variant-c"
    require_rejects(validator, law, forged, **positive_kwargs)


def test_core_r6_raw_build_plan_exact_mapping_replay_accepts() -> None:
    law = "PF-R6-1/raw-build-plan-exact-mapping"
    validator = require_callable(
        EXECUTION_MODULE, "validate_frozen_build_plan_v1", law
    )
    document = frozen_build_plan_document()
    result = require_accepts(
        validator,
        law,
        document,
        **build_plan_validation_kwargs(document),
    )
    assert type(result) is dict
    assert result == document


def test_core_r6_recovered_plan_key_and_object_new_gain_no_authority() -> None:
    law = "PF-R6-1/plan-key-and-object-new-are-nonauthoritative"
    document = frozen_build_plan_document()
    mint = _legacy_plan_closure_mint()
    recovered_by_name = inspect.getclosurevars(mint).nonlocals[
        "integrity_key"
    ]
    recovered_by_cell = next(
        cell.cell_contents
        for name, cell in zip(
            mint.__code__.co_freevars,
            mint.__closure__ or (),
        )
        if name == "integrity_key"
    )
    assert recovered_by_name == recovered_by_cell
    payload, legacy_tag = mint(document)
    forged = object.__new__(_ObjectNewBuildPlan)
    object.__setattr__(forged, "_payload", payload)
    object.__setattr__(forged, "_legacy_integrity_mac", legacy_tag)
    validator = require_callable(
        EXECUTION_MODULE, "validate_frozen_build_plan_v1", law
    )
    kwargs = build_plan_validation_kwargs(document)
    require_accepts(validator, law, forged, **kwargs)
    kwargs["expected_build_plan_digest"] = "f" * 64
    require_rejects(validator, law, forged, **kwargs)


def test_core_r6_build_plan_replay_has_no_process_local_secret_dependency() -> None:
    module = importlib.import_module(EXECUTION_MODULE)
    source_path = Path(module.__file__).resolve()
    tree = ast.parse(
        source_path.read_text(encoding="utf-8"),
        filename=str(source_path),
    )
    forbidden: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            forbidden.update(
                alias.name
                for alias in node.names
                if alias.name in {"hmac", "secrets"}
            )
        elif isinstance(node, ast.ImportFrom) and node.module in {
            "hmac",
            "secrets",
        }:
            forbidden.add(node.module)
        elif isinstance(node, (ast.ClassDef, ast.Name)) and getattr(
            node,
            "name",
            getattr(node, "id", ""),
        ) in {
            "FrozenBuildPlanAuthority",
            "integrity_key",
            "_integrity_mac",
        }:
            forbidden.add(
                getattr(node, "name", getattr(node, "id", ""))
            )
    assert not forbidden
    validator = getattr(module, "validate_frozen_build_plan_v1")
    assert not inspect.getclosurevars(validator).nonlocals


def test_core_r6_expected_build_plan_digest_substitution_rejected() -> None:
    law = "PF-R6-1/expected-build-plan-digest"
    validator = require_callable(
        EXECUTION_MODULE, "validate_frozen_build_plan_v1", law
    )
    document = frozen_build_plan_document()
    kwargs = build_plan_validation_kwargs(document)
    require_accepts(validator, law, document, **kwargs)
    kwargs["expected_build_plan_digest"] = "f" * 64
    require_rejects(validator, law, document, **kwargs)


def test_core_r6_each_build_plan_ledger_binding_field_replayed() -> None:
    law = "PF-R6-1/build-plan-ledger-binding-fields"
    validator = require_callable(
        EXECUTION_MODULE, "validate_frozen_build_plan_v1", law
    )
    document = frozen_build_plan_document()
    positive = build_plan_validation_kwargs(document)
    require_accepts(validator, law, document, **positive)
    binding = positive["build_plan_ledger_binding"]
    substitutions = {
        "ledger_state": "COMMITTED_NOT_ACTIVE",
        "path": "_program_facts_inputs/alias-plan.json",
        "size": binding["size"] + 1,
        "sha256": "f" * 64,
    }
    for field, value in substitutions.items():
        negative = deepcopy(positive)
        negative["build_plan_ledger_binding"][field] = value
        require_rejects(validator, law, document, **negative)


def test_core_r6_build_plan_ledger_binding_exact_shape_required() -> None:
    law = "PF-R6-1/build-plan-ledger-binding-exact-shape"
    validator = require_callable(
        EXECUTION_MODULE, "validate_frozen_build_plan_v1", law
    )
    document = frozen_build_plan_document()
    positive = build_plan_validation_kwargs(document)
    require_accepts(validator, law, document, **positive)
    extra = deepcopy(positive)
    extra["build_plan_ledger_binding"]["unbound_extra"] = True
    require_rejects(validator, law, document, **extra)
    for field in ("ledger_state", "path", "size", "sha256"):
        missing = deepcopy(positive)
        missing["build_plan_ledger_binding"].pop(field)
        require_rejects(validator, law, document, **missing)


def test_core3_zero_raw_cas_leaf_denominator_is_valid() -> None:
    _require_valid_execution(
        "PF-CORE-3/zero-raw-cas-leaf-positive",
        with_raw_leaf=False,
    )


def test_core3_manifested_raw_cas_leaf_is_included_in_exact_denominator() -> None:
    _require_valid_execution(
        "PF-CORE-3/manifested-raw-cas-leaf-positive",
        with_raw_leaf=True,
    )


def test_core3_missing_manifested_raw_cas_leaf_rejected() -> None:
    law = "PF-CORE-3/missing-manifested-raw-cas-leaf"
    (
        expected,
        roster,
        ledger,
        build_plan,
        manifests,
        expanded,
        validator,
    ) = _require_valid_execution(law, with_raw_leaf=True)
    missing = [
        row
        for row in expanded
        if row.get("semantic_role") != "RAW_CAS_LEAF"
    ]
    require_rejects(
        validator,
        law,
        build_plan=build_plan,
        expected_children=expected,
        terminal_roster=roster,
        terminal_roster_ledger_state="ACTIVE",
        terminal_ledger_rows=ledger,
        raw_cas_manifests=manifests,
        expanded_inputs=missing,
        **build_plan_validation_kwargs(build_plan),
    )


def test_core3_swapped_raw_cas_leaf_manifest_binding_rejected() -> None:
    law = "PF-CORE-3/swapped-raw-cas-manifest-binding"
    (
        expected,
        roster,
        ledger,
        build_plan,
        manifests,
        expanded,
        validator,
    ) = _require_valid_execution(law, with_raw_leaf=True)
    swapped = deepcopy(expanded)
    leaf = next(
        row for row in swapped if row["semantic_role"] == "RAW_CAS_LEAF"
    )
    leaf["source_manifest_output_identity"] = next(
        output
        for output in manifests
        if output != leaf["source_manifest_output_identity"]
    )
    require_rejects(
        validator,
        law,
        build_plan=build_plan,
        expected_children=expected,
        terminal_roster=roster,
        terminal_roster_ledger_state="ACTIVE",
        terminal_ledger_rows=ledger,
        raw_cas_manifests=manifests,
        expanded_inputs=swapped,
        **build_plan_validation_kwargs(build_plan),
    )


def test_core3_foreign_raw_cas_leaf_authority_rejected() -> None:
    law = "PF-CORE-3/foreign-raw-cas-leaf-authority"
    (
        expected,
        roster,
        ledger,
        build_plan,
        manifests,
        expanded,
        validator,
    ) = _require_valid_execution(law, with_raw_leaf=True)
    foreign = deepcopy(expanded)
    leaf = next(
        row for row in foreign if row["semantic_role"] == "RAW_CAS_LEAF"
    )
    leaf["run_id"] = "foreign-run"
    require_rejects(
        validator,
        law,
        build_plan=build_plan,
        expected_children=expected,
        terminal_roster=roster,
        terminal_roster_ledger_state="ACTIVE",
        terminal_ledger_rows=ledger,
        raw_cas_manifests=manifests,
        expanded_inputs=foreign,
        **build_plan_validation_kwargs(build_plan),
    )


def test_core_r3_2_distinct_raw_cas_physical_paths_remain_valid() -> None:
    _require_valid_execution(
        "PF-R3-2/distinct-raw-cas-physical-paths",
        raw_leaf_groups=[
            [
                raw_cas_leaf(
                    cas_leaf_id="distinct-leaf-a",
                    physical_path=(
                        "_program_facts_private_cas/distinct-a.pfcas"
                    ),
                ),
                raw_cas_leaf(
                    cas_leaf_id="distinct-leaf-b",
                    physical_path=(
                        "_program_facts_private_cas/distinct-b.pfcas"
                    ),
                ),
            ]
        ],
    )


def test_core_r3_2_exact_duplicate_raw_cas_physical_path_rejected() -> None:
    shared = "_program_facts_private_cas/shared.pfcas"
    _reject_raw_path_alias(
        "PF-R3-2/exact-raw-cas-physical-path-alias",
        raw_leaf_groups=[
            [
                raw_cas_leaf(
                    cas_leaf_id="exact-alias-a",
                    physical_path=shared,
                ),
                raw_cas_leaf(
                    cas_leaf_id="exact-alias-b",
                    physical_path=shared,
                ),
            ]
        ],
    )


def test_core_r3_2_casefold_raw_cas_physical_path_alias_rejected() -> None:
    _reject_raw_path_alias(
        "PF-R3-2/casefold-raw-cas-physical-path-alias",
        raw_leaf_groups=[
            [
                raw_cas_leaf(
                    cas_leaf_id="case-alias-a",
                    physical_path=(
                        "_program_facts_private_cas/shared.pfcas"
                    ),
                ),
                raw_cas_leaf(
                    cas_leaf_id="case-alias-b",
                    physical_path=(
                        "_program_facts_private_cas/SHARED.pfcas"
                    ),
                ),
            ]
        ],
    )


def test_core_r3_2_cross_namespace_raw_cas_path_collision_rejected() -> None:
    shared = "_program_facts_private_cas/shared.pfcas"
    _reject_raw_path_alias(
        "PF-R3-2/cross-namespace-raw-cas-physical-path-alias",
        raw_leaf_groups=[
            [
                raw_cas_leaf(
                    cas_leaf_id="namespace-a-leaf",
                    physical_path=shared,
                    namespace="program-facts-raw-cas-a",
                )
            ],
            [
                raw_cas_leaf(
                    cas_leaf_id="namespace-b-leaf",
                    physical_path=shared,
                    namespace="program-facts-raw-cas-b",
                )
            ],
        ],
    )
