from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path

from review_fixtures.program_facts_r2_1_b0_red_support import (
    body_digest,
    canonical_bytes,
    logical_output_bytes,
    publication_arm_document,
    publication_selection_document,
    public_generation_document,
    require_accepts,
    require_callable,
    require_rejects,
    assert_schema_accepts,
)


PUBLICATION_MODULE = "program_facts_publication"


def _evidence():
    outputs = logical_output_bytes()
    arm = publication_arm_document(outputs)
    generation = public_generation_document(outputs)
    selection = publication_selection_document(arm, generation, outputs)
    assert_schema_accepts("publication_arm", arm)
    assert_schema_accepts("public_generation", generation)
    return arm, generation, outputs, selection


def _validated_evidence(law):
    arm, generation, outputs, selection = _evidence()
    validator = require_callable(
        PUBLICATION_MODULE, "validate_generation_selection_evidence_v1", law
    )
    require_accepts(
        validator,
        law,
        arm=arm,
        generation_manifest=generation,
        logical_outputs=outputs,
        selection_record=selection,
    )
    return arm, generation, outputs, selection, validator


def _rebuilt_selection(arm, generation, outputs):
    arm["arm_body_sha256"] = body_digest(arm, "arm_body_sha256")
    generation["manifest_body_sha256"] = body_digest(
        generation, "manifest_body_sha256"
    )
    return publication_selection_document(arm, generation, outputs)


def _reject_consistent_identity_substitution(
    law: str,
    *,
    generation_id: str | None = None,
    transaction_id: str | None = None,
) -> None:
    arm, generation, outputs, _selection, validator = _validated_evidence(law)
    if generation_id is not None:
        arm["generation_id"] = generation_id
        generation["generation_id"] = generation_id
    if transaction_id is not None:
        arm["transaction_id"] = transaction_id
        generation["transaction_id"] = transaction_id
    forged_selection = _rebuilt_selection(arm, generation, outputs)
    require_rejects(
        validator,
        law,
        arm=arm,
        generation_manifest=generation,
        logical_outputs=outputs,
        selection_record=forged_selection,
    )


def test_r21_4_generation_manifest_mutation_rejected_with_outputs_unchanged() -> None:
    law = "R2.1-4/generation-manifest-full-file-binding"
    arm, generation, outputs, selection, validator = _validated_evidence(law)
    generation["composition_authority_digest"] = "f" * 64
    generation["manifest_body_sha256"] = body_digest(
        generation, "manifest_body_sha256"
    )
    assert_schema_accepts("public_generation", generation)
    require_rejects(
        validator,
        law,
        arm=arm,
        generation_manifest=generation,
        logical_outputs=outputs,
        selection_record=selection,
    )


def test_r21_4_arm_body_or_full_file_digest_substitution_rejected() -> None:
    law = "R2.1-4/arm-body-and-file-binding"
    arm, generation, outputs, selection, validator = _validated_evidence(law)
    for field in ("arm_body_sha256", "arm_full_file_sha256"):
        mutated = deepcopy(selection)
        mutated["publication_transaction"][field] = "f" * 64
        require_rejects(
            validator,
            law,
            arm=arm,
            generation_manifest=generation,
            logical_outputs=outputs,
            selection_record=mutated,
        )


def test_r21_4_expected_path_but_unbound_arm_has_no_authority() -> None:
    law = "R2.1-4/expected-path-is-not-authority"
    arm, generation, outputs, selection, validator = _validated_evidence(law)
    selection["publication_transaction"]["arm_full_file_sha256"] = "f" * 64
    require_rejects(
        validator,
        law,
        arm=arm,
        generation_manifest=generation,
        logical_outputs=outputs,
        selection_record=selection,
    )


def test_r21_4_selection_missing_manifest_or_arm_field_rejected() -> None:
    law = "R2.1-4/selection-requires-complete-private-evidence"
    arm, generation, outputs, selection, validator = _validated_evidence(law)
    for section, field in (
        ("generation_manifest", "full_file_sha256"),
        ("publication_transaction", "arm_body_sha256"),
        ("publication_transaction", "arm_full_file_sha256"),
    ):
        mutated = deepcopy(selection)
        del mutated[section][field]
        require_rejects(
            validator,
            law,
            arm=arm,
            generation_manifest=generation,
            logical_outputs=outputs,
            selection_record=mutated,
        )


def test_r21_4_loader_never_searches_generation_or_transaction_directories(
    tmp_path: Path,
) -> None:
    law = "R2.1-4/loader-no-directory-discovery"
    _arm, _generation, _outputs, selection, _validator = _validated_evidence(law)
    stray_generation = (
        tmp_path
        / ".program_facts_public_generations"
        / "newest-looking-generation"
    )
    stray_generation.mkdir(parents=True)
    (stray_generation / "generation_manifest.v1.json").write_bytes(b"{}\n")
    stray_transaction = (
        tmp_path
        / ".program_facts_publication_transactions"
        / "newest-looking-transaction"
    )
    stray_transaction.mkdir(parents=True)
    (stray_transaction / "publication_arm.v1.json").write_bytes(b"{}\n")
    loader = require_callable(
        PUBLICATION_MODULE, "load_program_facts_v2_from_active_selection", law
    )
    require_accepts(
        loader,
        law,
        scratchpad=tmp_path,
        active_selection=selection,
    )
    require_rejects(
        loader,
        law,
        scratchpad=tmp_path,
        active_selection=None,
    )


def test_r21_4_same_generation_id_divergent_manifest_rejected() -> None:
    law = "R2.1-4/same-generation-divergence-blocks"
    _arm, generation, _outputs, selection, _validator = _validated_evidence(law)
    divergent = deepcopy(generation)
    divergent["logical_outputs"][0]["full_file_sha256"] = "f" * 64
    divergent["manifest_body_sha256"] = body_digest(
        divergent, "manifest_body_sha256"
    )
    assert divergent["generation_id"] == generation["generation_id"]
    validator = require_callable(
        PUBLICATION_MODULE, "validate_same_generation_idempotence_v1", law
    )
    require_accepts(
        validator,
        law,
        existing_generation=generation,
        candidate_generation=deepcopy(generation),
        selection_record=selection,
    )
    require_rejects(
        validator,
        law,
        existing_generation=generation,
        candidate_generation=divergent,
        selection_record=selection,
    )


def test_r21_4_private_transaction_evidence_cannot_be_public_sidecar() -> None:
    law = "R2.1-4/private-evidence-not-logical-output"
    arm, generation, outputs, selection, validator = _validated_evidence(law)
    selection["logical_outputs"].append(
        {
            "logical_identity": "generation_manifest.v1.json",
            "physical_path": "generation_manifest.v1.json",
            "size": 2,
            "full_file_sha256": hashlib.sha256(b"{}").hexdigest(),
        }
    )
    require_rejects(
        validator,
        law,
        arm=arm,
        generation_manifest=generation,
        logical_outputs=outputs,
        selection_record=selection,
    )


def test_r21_4_unselected_complete_generation_is_quarantined_not_adopted(
    tmp_path: Path,
) -> None:
    law = "R2.1-4/unselected-generation-is-not-adoptable"
    arm, generation, outputs, _selection, _validator = _validated_evidence(law)
    loader = require_callable(
        PUBLICATION_MODULE, "recover_program_facts_publication_v1", law
    )
    result = require_accepts(
        loader,
        law,
        scratchpad=tmp_path,
        active_selection=None,
        unselected_arm=arm,
        unselected_generation=generation,
        logical_outputs=outputs,
    )
    assert result["state"] == "QUARANTINED_RECOMPOSE_REQUIRED"
    assert result.get("selected") is not True
    assert result.get("adopted") is not True


def test_r21_4_atomic_api_replays_all_five_files_before_selection(
    tmp_path: Path,
) -> None:
    law = "R2.1-4/atomic-selection-replays-arm-manifest-and-three-outputs"
    arm, generation, outputs, selection, _validator = _validated_evidence(law)
    arm_path = tmp_path / "publication_arm.v1.json"
    manifest_path = tmp_path / "generation_manifest.v1.json"
    arm_path.write_bytes(canonical_bytes(arm) + b"\n")
    manifest_path.write_bytes(canonical_bytes(generation) + b"\n")
    output_paths = {}
    for identity, content in outputs.items():
        path = tmp_path / identity
        path.write_bytes(content)
        output_paths[identity] = path
    committer = require_callable(
        "artifact_ledger", "commit_immutable_generation_selection", law
    )
    five_paths = [arm_path, manifest_path, *output_paths.values()]
    for index, target in enumerate(five_paths):
        original = target.read_bytes()
        target.write_bytes(original + b"tampered")
        require_rejects(
            committer,
            law,
            selection_record=selection,
            arm_path=arm_path,
            generation_manifest_path=manifest_path,
            logical_output_paths=output_paths,
        )
        target.write_bytes(original)


def test_r21_4_receipt_manifest_arm_and_ledger_digest_graph_is_acyclic() -> None:
    law = "R2.1-4/acyclic-publication-digest-graph"
    arm, generation, outputs, selection, _validator = _validated_evidence(law)
    validator = require_callable(
        PUBLICATION_MODULE, "validate_publication_digest_graph_v1", law
    )
    require_accepts(
        validator,
        law,
        arm=arm,
        generation_manifest=generation,
        logical_outputs=outputs,
        selection_record=selection,
        receipt_precommit_identity={
            "transaction_id": arm["transaction_id"],
            "generation_id": arm["generation_id"],
        },
    )


def test_core4_selection_missing_prior_active_prestate_rejected() -> None:
    law = "PF-CORE-4/missing-prior-active-prestate"
    arm, generation, outputs, selection, validator = _validated_evidence(law)
    del selection["prior_active"]
    require_rejects(
        validator,
        law,
        arm=arm,
        generation_manifest=generation,
        logical_outputs=outputs,
        selection_record=selection,
    )


def test_core4_selection_divergent_prior_active_prestate_rejected() -> None:
    law = "PF-CORE-4/divergent-prior-active-prestate"
    arm, generation, outputs, selection, validator = _validated_evidence(law)
    selection["prior_active"] = {
        "state": "ACTIVE",
        "generation_id": "pfg-" + ("f" * 32),
        "selection_digest": "f" * 64,
    }
    require_rejects(
        validator,
        law,
        arm=arm,
        generation_manifest=generation,
        logical_outputs=outputs,
        selection_record=selection,
    )


def test_core4_arbitrary_generation_id_substitution_rejected() -> None:
    _reject_consistent_identity_substitution(
        "PF-CORE-4/underived-generation-id",
        generation_id="pfg-" + ("f" * 32),
    )


def test_core4_arbitrary_transaction_id_substitution_rejected() -> None:
    _reject_consistent_identity_substitution(
        "PF-CORE-4/underived-transaction-id",
        transaction_id="pftx-" + ("f" * 32),
    )


def test_core4_dot_segment_generation_id_rejected() -> None:
    _reject_consistent_identity_substitution(
        "PF-CORE-4/dot-segment-id",
        generation_id="..",
    )


def test_core4_slash_generation_id_rejected() -> None:
    _reject_consistent_identity_substitution(
        "PF-CORE-4/slash-id",
        generation_id="pfg/escape",
    )


def test_core4_backslash_transaction_id_rejected() -> None:
    _reject_consistent_identity_substitution(
        "PF-CORE-4/backslash-id",
        transaction_id=r"pftx\escape",
    )


def test_core4_colon_ads_transaction_id_rejected() -> None:
    _reject_consistent_identity_substitution(
        "PF-CORE-4/colon-ads-id",
        transaction_id="pftx:alternate-stream",
    )


def test_core4_case_alias_generation_id_rejected() -> None:
    arm, _generation, _outputs, _selection, _validator = _validated_evidence(
        "PF-CORE-4/case-alias-id"
    )
    _reject_consistent_identity_substitution(
        "PF-CORE-4/case-alias-id",
        generation_id=arm["generation_id"].upper(),
    )


def test_core4_long_path_identity_rejected() -> None:
    _reject_consistent_identity_substitution(
        "PF-CORE-4/long-path-id",
        generation_id="pfg-" + ("a" * 300),
    )


def test_core4_preimage_field_change_invalidates_old_derived_ids() -> None:
    law = "PF-CORE-4/preimage-change-invalidates-derived-ids"
    arm, generation, outputs, _selection, validator = _validated_evidence(law)
    arm["launch_digest"] = "f" * 64
    forged_selection = _rebuilt_selection(arm, generation, outputs)
    require_rejects(
        validator,
        law,
        arm=arm,
        generation_manifest=generation,
        logical_outputs=outputs,
        selection_record=forged_selection,
    )
