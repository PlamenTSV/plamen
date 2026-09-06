from __future__ import annotations

from copy import deepcopy
import hashlib
import hmac
import json

from review_fixtures.program_facts_r2_1_b0_red_support import (
    body_digest,
    compatibility_delta_positive_vector,
    require_accepts,
    require_callable,
    require_rejects,
    assert_schema_accepts,
)


COMPATIBILITY_MODULE = "program_facts_compatibility_delta"


def _validated_vector(
    law: str,
    *,
    state: str = "COMPONENT_LOCAL_PROVISIONAL_C4",
    changed_path: str = "rules/schemas/new_program_facts_v2.json",
    semantic_class: str = "NEW_PRIVATE_OR_V2_ARTIFACT",
):
    vector = compatibility_delta_positive_vector(
        state=state,
        changed_path=changed_path,
        semantic_class=semantic_class,
    )
    document = vector["document"]
    assert_schema_accepts("compatibility_delta", document)
    validator = require_callable(
        COMPATIBILITY_MODULE, "validate_compatibility_delta_v1", law
    )
    require_accepts(
        validator,
        law,
        document,
        **vector["validation_kwargs"],
    )
    return vector, validator


def _rehash(document):
    document["receipt_body_sha256"] = body_digest(
        document, "receipt_body_sha256"
    )
    return document


def _binding_for(path: str, content: bytes) -> dict[str, object]:
    return {
        "path": path,
        "size": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def _replace_bound_bytes(
    kwargs,
    *,
    bytes_key: str,
    binding_key: str,
    content: bytes,
):
    replaced = deepcopy(kwargs)
    path = replaced[binding_key]["path"]
    replaced[bytes_key] = content
    replaced[binding_key] = _binding_for(path, content)
    return replaced


def _reseal_authority_bytes(
    content: bytes,
    trusted_review_keys,
    mutator,
    *,
    key_override: bytes | None = None,
) -> bytes:
    document = json.loads(content.decode("ascii"))
    mutator(document)
    key_id = document["authority_key_id"]
    key = key_override or trusted_review_keys[key_id]
    preimage = deepcopy(document)
    preimage.pop("authority_hmac_sha256", None)
    document["authority_hmac_sha256"] = hmac.new(
        key,
        json.dumps(
            preimage,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    return (
        json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        + b"\n"
    )


def _runtime_manifest_bytes(document) -> bytes:
    updated = deepcopy(document)
    updated["manifest_body_sha256"] = body_digest(
        updated, "manifest_body_sha256"
    )
    return (
        json.dumps(
            updated,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        + b"\n"
    )


def _require_producer_rejects(law: str, vector, kwargs) -> None:
    producer = require_callable(
        COMPATIBILITY_MODULE, "produce_compatibility_delta_v1", law
    )
    require_rejects(
        producer,
        law,
        state=vector["document"]["state"],
        **kwargs,
    )


def _reclassified_path_kwargs(
    vector,
    *,
    portable_path: str,
    semantic_class: str,
):
    kwargs = deepcopy(vector["validation_kwargs"])
    post_document = json.loads(
        kwargs["post_runtime_manifest_bytes"].decode("ascii")
    )
    changed = next(
        row
        for row in post_document["paths"]
        if row["portable_path"] == vector["changed_path"]
    )
    changed["portable_path"] = portable_path
    changed_post_bytes = _runtime_manifest_bytes(post_document)
    kwargs = _replace_bound_bytes(
        kwargs,
        bytes_key="post_runtime_manifest_bytes",
        binding_key="post_r2_runtime_manifest",
        content=changed_post_bytes,
    )
    roster_bytes = _reseal_authority_bytes(
        kwargs["allowed_change_roster_bytes"],
        kwargs["trusted_review_keys"],
        lambda authority: authority["rows"][0].update(
            {
                "portable_path": portable_path,
                "semantic_class": semantic_class,
                "reviewed_reason": "fixture adversarial reclassification",
            }
        ),
    )
    kwargs = _replace_bound_bytes(
        kwargs,
        bytes_key="allowed_change_roster_bytes",
        binding_key="allowed_change_roster_binding",
        content=roster_bytes,
    )
    semantic_bytes = _reseal_authority_bytes(
        kwargs["semantic_review_bytes"],
        kwargs["trusted_review_keys"],
        lambda authority: authority["rows"][0].update(
            {
                "portable_path": portable_path,
                "semantic_class": semantic_class,
            }
        ),
    )
    return _replace_bound_bytes(
        kwargs,
        bytes_key="semantic_review_bytes",
        binding_key="semantic_review_binding",
        content=semantic_bytes,
    )


def test_r21_5_wildcard_glob_and_directory_only_allowance_rejected() -> None:
    law = "R2.1-5/no-wildcard-glob-or-directory-allowance"
    vector, validator = _validated_vector(law)
    for path in ("rules/*.json", "rules/**", "rules/schemas"):
        document = deepcopy(vector["document"])
        document["allowed_change_roster"][0]["portable_path"] = path
        document["actual_deltas"][0]["portable_path"] = path
        _rehash(document)
        require_rejects(
            validator,
            law,
            document,
            **vector["validation_kwargs"],
        )


def test_r21_5_omitted_duplicate_and_stale_changed_path_rejected() -> None:
    law = "R2.1-5/exact-bijection-between-deltas-and-allowances"
    vector, validator = _validated_vector(law)
    baseline = vector["document"]
    variants = []
    omitted = deepcopy(baseline)
    omitted["actual_deltas"] = []
    omitted["changed_path_count"] = 0
    variants.append(omitted)
    duplicate = deepcopy(baseline)
    duplicate["actual_deltas"].append(deepcopy(duplicate["actual_deltas"][0]))
    duplicate["changed_path_count"] = 2
    variants.append(duplicate)
    stale = deepcopy(baseline)
    stale["allowed_change_roster"].append(
        {
            "portable_path": "rules/schemas/stale_allowance.json",
            "semantic_class": "NEW_PRIVATE_OR_V2_ARTIFACT",
            "reviewed_reason": "stale row",
        }
    )
    variants.append(stale)
    for document in variants:
        _rehash(document)
        require_rejects(
            validator,
            law,
            document,
            **vector["validation_kwargs"],
        )


def test_r21_5_unexplained_legacy_public_delta_rejected() -> None:
    law = "R2.1-5/no-unexplained-legacy-public-delta"
    vector, validator = _validated_vector(law)
    document = deepcopy(vector["document"])
    path = "scratchpad/mechanical_program_facts.v1.json"
    document["allowed_change_roster"][0].update(
        {
            "portable_path": path,
            "semantic_class": "TOOLCHAIN_COMPONENT",
            "reviewed_reason": "disguised legacy delta",
        }
    )
    document["actual_deltas"][0].update(
        {
            "portable_path": path,
            "semantic_class": "TOOLCHAIN_COMPONENT",
        }
    )
    _rehash(document)
    require_rejects(
        validator,
        law,
        document,
        **vector["validation_kwargs"],
    )


def test_r21_5_disabled_and_shadow_same_postimage_mismatch_rejected() -> None:
    law = "R2.1-5/same-postimage-disabled-shadow-byte-parity"
    vector, validator = _validated_vector(law)
    for branch in ("disabled", "shadow_raw"):
        document = deepcopy(vector["document"])
        document["public_comparisons"][branch]["right_files"][0]["sha256"] = (
            "f" * 64
        )
        _rehash(document)
        assert_schema_accepts("compatibility_delta", document)
        require_rejects(
            validator,
            law,
            document,
            **vector["validation_kwargs"],
        )


def test_r21_5_wrong_pre_r2_boundary_manifest_rejected() -> None:
    law = "R2.1-5/exact-pre-r2-boundary-authority"
    vector, validator = _validated_vector(law)
    document = vector["document"]
    kwargs = deepcopy(vector["validation_kwargs"])
    kwargs["pre_r2_boundary_manifest"]["sha256"] = "f" * 64
    require_rejects(
        validator,
        law,
        document,
        **kwargs,
    )


def test_r21_5_manifest_path_size_or_digest_mismatch_rejected() -> None:
    law = "R2.1-5/manifest-row-path-size-digest-replay"
    vector, validator = _validated_vector(law)
    document = vector["document"]
    variants = []
    wrong_path = deepcopy(vector["validation_kwargs"])
    wrong_path["post_r2_runtime_manifest"]["path"] = "foreign/path.json"
    variants.append(wrong_path)
    wrong_size = deepcopy(vector["validation_kwargs"])
    wrong_size["post_r2_runtime_manifest"]["size"] += 1
    variants.append(wrong_size)
    wrong_digest = deepcopy(vector["validation_kwargs"])
    wrong_digest["post_r2_runtime_manifest"]["sha256"] = "f" * 64
    variants.append(wrong_digest)
    for kwargs in variants:
        require_rejects(
            validator,
            law,
            document,
            **kwargs,
        )


def test_r21_5_semantic_delta_cannot_hide_as_methodology_churn() -> None:
    law = "R2.1-5/no-semantic-disguise-as-methodology-churn"
    vector, validator = _validated_vector(law)
    document = deepcopy(vector["document"])
    path = "rules/finding-output-format.md"
    document["allowed_change_roster"][0].update(
        {
            "portable_path": path,
            "semantic_class": "METHODOLOGY_COMPONENT",
            "reviewed_reason": "claimed methodology churn",
        }
    )
    document["actual_deltas"][0].update(
        {
            "portable_path": path,
            "semantic_class": "METHODOLOGY_COMPONENT",
        }
    )
    _rehash(document)
    require_rejects(
        validator,
        law,
        document,
        **vector["validation_kwargs"],
    )


def test_r21_5_provisional_receipt_cannot_claim_final_quiescence() -> None:
    law = "R2.1-5/provisional-cannot-claim-final"
    vector, validator = _validated_vector(law)
    document = deepcopy(vector["document"])
    document["state"] = "FINAL_RUNTIME_QUIESCENT"
    _rehash(document)
    kwargs = deepcopy(vector["validation_kwargs"])
    kwargs["runtime_closure_state"] = (
        "COMPONENT_LOCAL_PROVISIONAL_NOT_FINAL_RUNTIME_CLOSURE"
    )
    require_rejects(
        validator,
        law,
        document,
        **kwargs,
    )


def test_r21_5_receipt_excluded_from_authorities_and_compared_manifest() -> None:
    law = "R2.1-5/compatibility-receipt-out-of-band-no-cycle"
    vector, validator = _validated_vector(law)
    document = vector["document"]
    receipt_path = (
        "review_fixtures/"
        "program_facts_compatibility_delta_final_release.v1.json"
    )
    kwargs = vector["validation_kwargs"]
    mutated_bytes = _reseal_authority_bytes(
        kwargs["exclusion_authority_bytes"],
        kwargs["trusted_review_keys"],
        lambda authority: (
            authority["execution_authority_paths"].append(receipt_path),
            authority["compared_runtime_manifest_paths"].append(receipt_path),
        ),
    )
    negative_kwargs = _replace_bound_bytes(
        kwargs,
        bytes_key="exclusion_authority_bytes",
        binding_key="exclusion_authority_binding",
        content=mutated_bytes,
    )
    require_rejects(
        validator,
        law,
        document,
        **negative_kwargs,
    )


def test_r21_5_final_receipt_invalidated_by_later_runtime_change() -> None:
    law = "R2.1-5/later-runtime-change-invalidates-final-receipt"
    vector, validator = _validated_vector(
        law,
        state="FINAL_RUNTIME_QUIESCENT",
    )
    document = vector["document"]
    kwargs = deepcopy(vector["validation_kwargs"])
    kwargs["bound_post_runtime_manifest_digest"] = document[
        "post_r2_runtime_manifest"
    ]["sha256"]
    kwargs["observed_post_runtime_manifest_digest"] = "f" * 64
    require_rejects(
        validator,
        law,
        document,
        **kwargs,
    )


def test_core5_reduced_manifest_bytes_under_original_binding_rejected() -> None:
    law = "PF-CORE-5/reduced-bound-manifest"
    vector, _validator = _validated_vector(law)
    kwargs = deepcopy(vector["validation_kwargs"])
    pre_document = json.loads(
        kwargs["pre_runtime_manifest_bytes"].decode("ascii")
    )
    post_document = json.loads(
        kwargs["post_runtime_manifest_bytes"].decode("ascii")
    )
    pre_document["paths"] = []
    post_document["paths"] = [
        row
        for row in post_document["paths"]
        if row["portable_path"] != vector["unchanged_path"]
    ]
    kwargs["pre_runtime_manifest_bytes"] = _runtime_manifest_bytes(
        pre_document
    )
    kwargs["post_runtime_manifest_bytes"] = _runtime_manifest_bytes(
        post_document
    )
    _require_producer_rejects(law, vector, kwargs)


def test_core5_forged_equal_comparator_claim_rejected_against_output_bytes() -> None:
    law = "PF-CORE-5/forged-comparator-equality"
    vector, _validator = _validated_vector(law)
    kwargs = deepcopy(vector["validation_kwargs"])
    right_path = next(
        path
        for path in kwargs["compared_output_bytes"]
        if path.endswith("/right.json")
    )
    kwargs["compared_output_bytes"][right_path] += b"tampered"
    _require_producer_rejects(law, vector, kwargs)


def test_core5_omitted_semantic_review_authority_rejected() -> None:
    law = "PF-CORE-5/semantic-review-mandatory"
    vector, _validator = _validated_vector(law)
    kwargs = deepcopy(vector["validation_kwargs"])
    kwargs["semantic_review_bytes"] = b""
    kwargs["semantic_review_binding"] = _binding_for(
        kwargs["semantic_review_binding"]["path"],
        b"",
    )
    _require_producer_rejects(law, vector, kwargs)


def test_core5_arbitrary_rule_mislabeled_as_methodology_rejected() -> None:
    law = "PF-CORE-5/arbitrary-rule-mislabeled-methodology"
    vector, _validator = _validated_vector(law)
    kwargs = _reclassified_path_kwargs(
        vector,
        portable_path="rules/mechanical-gate-registry.json",
        semantic_class="METHODOLOGY_COMPONENT",
    )
    _require_producer_rejects(law, vector, kwargs)


def test_core5_arbitrary_script_mislabeled_as_toolchain_rejected() -> None:
    law = "PF-CORE-5/arbitrary-script-mislabeled-toolchain"
    vector, _validator = _validated_vector(law)
    kwargs = _reclassified_path_kwargs(
        vector,
        portable_path="scripts/plamen_driver.py",
        semantic_class="TOOLCHAIN_COMPONENT",
    )
    _require_producer_rejects(law, vector, kwargs)


def test_core5_missing_execution_exclusion_denominator_rejected() -> None:
    law = "PF-CORE-5/execution-exclusion-denominator-mandatory"
    vector, _validator = _validated_vector(law)
    kwargs = vector["validation_kwargs"]
    content = _reseal_authority_bytes(
        kwargs["exclusion_authority_bytes"],
        kwargs["trusted_review_keys"],
        lambda authority: authority.pop("execution_authority_paths"),
    )
    negative = _replace_bound_bytes(
        kwargs,
        bytes_key="exclusion_authority_bytes",
        binding_key="exclusion_authority_binding",
        content=content,
    )
    _require_producer_rejects(law, vector, negative)


def test_core5_missing_composition_exclusion_denominator_rejected() -> None:
    law = "PF-CORE-5/composition-exclusion-denominator-mandatory"
    vector, _validator = _validated_vector(law)
    kwargs = vector["validation_kwargs"]
    content = _reseal_authority_bytes(
        kwargs["exclusion_authority_bytes"],
        kwargs["trusted_review_keys"],
        lambda authority: authority.pop("composition_authority_paths"),
    )
    negative = _replace_bound_bytes(
        kwargs,
        bytes_key="exclusion_authority_bytes",
        binding_key="exclusion_authority_binding",
        content=content,
    )
    _require_producer_rejects(law, vector, negative)


def test_core5_missing_runtime_exclusion_denominator_rejected() -> None:
    law = "PF-CORE-5/runtime-exclusion-denominator-mandatory"
    vector, _validator = _validated_vector(law)
    kwargs = vector["validation_kwargs"]
    content = _reseal_authority_bytes(
        kwargs["exclusion_authority_bytes"],
        kwargs["trusted_review_keys"],
        lambda authority: authority.pop(
            "compared_runtime_manifest_paths"
        ),
    )
    negative = _replace_bound_bytes(
        kwargs,
        bytes_key="exclusion_authority_bytes",
        binding_key="exclusion_authority_binding",
        content=content,
    )
    _require_producer_rejects(law, vector, negative)


def test_core5_missing_trusted_review_key_rejected() -> None:
    law = "PF-CORE-5/missing-trusted-review-key"
    vector, _validator = _validated_vector(law)
    kwargs = deepcopy(vector["validation_kwargs"])
    kwargs["trusted_review_keys"] = {}
    _require_producer_rejects(law, vector, kwargs)


def test_core5_wrong_trusted_review_key_rejected() -> None:
    law = "PF-CORE-5/wrong-trusted-review-key"
    vector, _validator = _validated_vector(law)
    kwargs = deepcopy(vector["validation_kwargs"])
    key_id = vector["trusted_review_key_id"]
    kwargs["trusted_review_keys"][key_id] = b"wrong-review-key"
    _require_producer_rejects(law, vector, kwargs)


def test_core_r3_3_exact_phase_io_shared_path_is_registry_admissible() -> None:
    vector, _validator = _validated_vector(
        "PF-R3-3/exact-phase-io-shared-path",
        changed_path="scripts/phase_io_contracts.py",
        semantic_class="TOOLCHAIN_COMPONENT",
    )
    assert vector["document"]["actual_deltas"][0][
        "portable_path"
    ] == "scripts/phase_io_contracts.py"


def test_core_r3_3_exact_artifact_ledger_shared_path_is_registry_admissible() -> None:
    vector, _validator = _validated_vector(
        "PF-R3-3/exact-artifact-ledger-shared-path",
        changed_path="scripts/artifact_ledger.py",
        semantic_class="TOOLCHAIN_COMPONENT",
    )
    assert vector["document"]["actual_deltas"][0][
        "portable_path"
    ] == "scripts/artifact_ledger.py"


def test_core_r3_3_phase_io_substring_lookalike_not_in_registry_rejected() -> None:
    law = "PF-R3-3/phase-io-substring-lookalike"
    vector, _validator = _validated_vector(law)
    kwargs = _reclassified_path_kwargs(
        vector,
        portable_path="scripts/program_facts_phase_io_contracts_copy.py",
        semantic_class="TOOLCHAIN_COMPONENT",
    )
    _require_producer_rejects(law, vector, kwargs)


def test_core_r3_3_artifact_ledger_substring_lookalike_not_in_registry_rejected() -> None:
    law = "PF-R3-3/artifact-ledger-substring-lookalike"
    vector, _validator = _validated_vector(law)
    kwargs = _reclassified_path_kwargs(
        vector,
        portable_path="scripts/program_facts_artifact_ledger_copy.py",
        semantic_class="TOOLCHAIN_COMPONENT",
    )
    _require_producer_rejects(law, vector, kwargs)


def test_core_r3_3_case_alias_of_registered_shared_path_rejected() -> None:
    law = "PF-R3-3/registered-path-case-alias"
    vector, _validator = _validated_vector(law)
    kwargs = _reclassified_path_kwargs(
        vector,
        portable_path="scripts/Phase_IO_Contracts.py",
        semantic_class="TOOLCHAIN_COMPONENT",
    )
    _require_producer_rejects(law, vector, kwargs)
