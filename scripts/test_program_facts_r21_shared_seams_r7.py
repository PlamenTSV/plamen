from __future__ import annotations

from collections.abc import Iterator, Mapping
from copy import deepcopy
import hashlib
import os
from pathlib import Path
from typing import Any, Callable

import pytest

import artifact_ledger
import program_facts_publication
from artifact_ledger import (
    ArtifactLedgerError,
    LEDGER_NAME,
    read_artifact_ledger,
    write_artifact_ledger,
)
from program_facts_v2_contracts import ProgramFactsTypeError
from review_fixtures.program_facts_r2_1_b0_red_support import (
    PUBLIC_IDENTITIES,
    canonical_bytes,
    logical_output_bytes,
    publication_arm_document,
    publication_selection_document,
    public_generation_document,
    require_accepts,
    require_callable,
)
from test_program_facts_r21_3_test_composer_b0_red import (
    _ObjectNewMapping,
    _StatefulVariantMapping,
    _authority_vector,
    _candidate_mapping,
    _candidate_validation_kwargs,
    _production_candidate_vector,
    _sealed_inputs,
)


PHASEIO_CALLABLE = "validate_program_facts_v2_private_commit_candidate"
LEDGER_CALLABLE = "commit_immutable_generation_selection"


class _FlippingNestedMapping(Mapping[str, object]):
    def __init__(self, first: str, later: str) -> None:
        self._first = first
        self._later = later
        self.reads = 0

    def __getitem__(self, key: str) -> object:
        if key != "tag":
            raise KeyError(key)
        self.reads += 1
        return self._first if self.reads == 1 else self._later

    def __iter__(self) -> Iterator[str]:
        return iter(("tag",))

    def __len__(self) -> int:
        return 1


def _phaseio_vector(law: str):
    (
        candidate,
        inputs,
        document,
        _environment,
        authority_kwargs,
        core_validator,
    ) = _production_candidate_vector(law)
    kwargs = _candidate_validation_kwargs(
        inputs,
        document,
        authority_kwargs,
    )
    baseline = require_accepts(
        core_validator,
        law,
        candidate,
        **kwargs,
    )
    return (
        _candidate_mapping(baseline),
        inputs,
        document,
        authority_kwargs,
        kwargs,
    )


def _phaseio_validator(law: str) -> Callable[..., Any]:
    return require_callable("phase_io_contracts", PHASEIO_CALLABLE, law)


def _tree_bytes(root: Path) -> dict[str, bytes]:
    if not root.exists():
        return {}
    rows: dict[str, bytes] = {}
    for path in sorted(
        (candidate for candidate in root.rglob("*") if candidate.is_file()),
        key=lambda value: value.relative_to(root).as_posix(),
    ):
        rows[path.relative_to(root).as_posix()] = path.read_bytes()
    return rows


def _ledger_bytes(root: Path) -> bytes | None:
    path = root / LEDGER_NAME
    return path.read_bytes() if path.is_file() else None


def _selection_digest(selection: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(selection)).hexdigest()


def _active_prestate(result: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "state": "PRESENT",
        "generation_id": result["generation_id"],
        "selection_digest": result["selection_digest"],
    }


def _assert_selection_store(
    root: Path,
    *,
    selection: Mapping[str, Any],
    expected_history_count: int,
) -> dict[str, Any]:
    ledger = read_artifact_ledger(root)
    history = ledger["program_facts_v2_generation_selections"]
    active = ledger["program_facts_v2_active_selection"]
    digest = _selection_digest(selection)
    assert len(history) == expected_history_count
    assert history[selection["generation_id"]] == {
        "selection_digest": digest,
        "selection_record": selection,
    }
    assert active == {
        "state": "PRESENT",
        "generation_id": selection["generation_id"],
        "selection_digest": digest,
    }
    return ledger


def _publication_vector(
    root: Path,
    law: str,
    *,
    prior_active: Mapping[str, Any] | None = None,
    outputs: Mapping[str, bytes] | None = None,
    transaction_nonce: str | None = None,
) -> dict[str, Any]:
    output_bytes = dict(outputs or logical_output_bytes())
    arm = publication_arm_document(
        output_bytes,
        prior_active=prior_active,
    )
    if transaction_nonce is not None:
        arm["transaction_nonce"] = transaction_nonce
        preimage_keys = (
            "run_id",
            "run_generation",
            "transaction_nonce",
            "phase",
            "work_unit_id",
            "contract_digest",
            "launch_digest",
            "expanded_input_set_digest",
            "composition_authority_digest",
            "prior_active",
        )
        identities = (
            program_facts_publication
            .derive_program_facts_publication_identities_v1(
                {
                    key: deepcopy(arm[key])
                    for key in preimage_keys
                }
            )
        )
        arm["transaction_id"] = identities["transaction_id"]
        arm["generation_id"] = identities["generation_id"]
        arm["arm_body_sha256"] = hashlib.sha256(
            canonical_bytes(
                {
                    key: value
                    for key, value in arm.items()
                    if key != "arm_body_sha256"
                }
            )
        ).hexdigest()
    generation = public_generation_document(
        output_bytes,
        arm=arm,
    )
    selection = publication_selection_document(
        arm,
        generation,
        output_bytes,
    )
    arm_path = root / selection["publication_transaction"][
        "arm_physical_path"
    ]
    manifest_path = root / selection["generation_manifest"]["physical_path"]
    arm_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    arm_path.write_bytes(canonical_bytes(arm) + b"\n")
    manifest_path.write_bytes(canonical_bytes(generation) + b"\n")
    output_paths: dict[str, Path] = {}
    for identity in PUBLIC_IDENTITIES:
        path = root / next(
            row["physical_path"]
            for row in selection["logical_outputs"]
            if row["logical_identity"] == identity
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(output_bytes[identity])
        output_paths[identity] = path
    validator = require_callable(
        "program_facts_publication",
        "validate_generation_selection_evidence_v1",
        law,
    )
    require_accepts(
        validator,
        law,
        arm=arm,
        generation_manifest=generation,
        logical_outputs=output_bytes,
        selection_record=selection,
    )
    return {
        "root": root,
        "arm": arm,
        "generation": generation,
        "outputs": output_bytes,
        "selection": selection,
        "arm_path": arm_path,
        "manifest_path": manifest_path,
        "output_paths": output_paths,
    }


def _commit_kwargs(vector: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "selection_record": vector["selection"],
        "arm_path": vector["arm_path"],
        "generation_manifest_path": vector["manifest_path"],
        "logical_output_paths": vector["output_paths"],
    }


def _committer(law: str) -> Callable[..., Any]:
    return require_callable("artifact_ledger", LEDGER_CALLABLE, law)


def _require_artifact_rejection_without_mutation(
    committer: Callable[..., Any],
    root: Path,
    law: str,
    **kwargs: Any,
) -> None:
    before_tree = _tree_bytes(root)
    before_ledger = _ledger_bytes(root)
    with pytest.raises(ArtifactLedgerError):
        committer(**kwargs)
    assert _ledger_bytes(root) == before_ledger, law
    assert _tree_bytes(root) == before_tree, law


def test_shared_phaseio_exact_positive_replays_all_mandatory_authorities(
    tmp_path: Path,
) -> None:
    law = "PF-SHARED-R7/phaseio-exact-positive"
    candidate, _inputs, _document, _authority, kwargs = _phaseio_vector(law)
    before = _tree_bytes(tmp_path)
    observed = require_accepts(
        _phaseio_validator(law),
        law,
        candidate,
        **kwargs,
    )
    assert _candidate_mapping(observed) == candidate
    assert _tree_bytes(tmp_path) == before


def test_shared_phaseio_fake_test_carrier_rejects_with_full_valid_kwargs() -> None:
    law = "PF-SHARED-R7/phaseio-full-kwargs-fake-reject"
    _candidate, _inputs, _document, _authority, kwargs = _phaseio_vector(law)
    fake = {
        "authority_class": "TEST_ONLY_NONAUTHORITATIVE",
        "candidate_bytes": b"{}",
    }
    with pytest.raises(ProgramFactsTypeError):
        _phaseio_validator(law)(fake, **kwargs)


@pytest.mark.parametrize(
    "carrier_kind",
    (
        "bare_bytes",
        "extra_prose_key",
        "object_new_mutation",
        "test_wrapper",
    ),
)
def test_shared_phaseio_untrusted_carrier_shape_never_bypasses_replay(
    carrier_kind: str,
) -> None:
    law = f"PF-SHARED-R7/phaseio-carrier-{carrier_kind}"
    candidate, _inputs, _document, _authority, kwargs = _phaseio_vector(law)
    if carrier_kind == "bare_bytes":
        carrier: object = b"{}"
    elif carrier_kind == "extra_prose_key":
        mutated = deepcopy(candidate)
        mutated["validation_reason"] = "already checked"
        carrier = mutated
    elif carrier_kind == "test_wrapper":
        carrier = {
            "authority_class": "TEST_ONLY_NONAUTHORITATIVE",
            "candidate": candidate,
        }
    else:
        forged = object.__new__(_ObjectNewMapping)
        mutated = deepcopy(candidate)
        mutated["candidate_digest"] = "f" * 64
        forged._payload = mutated
        carrier = forged
    with pytest.raises(ProgramFactsTypeError):
        _phaseio_validator(law)(carrier, **kwargs)


def test_shared_phaseio_unknown_trust_keyword_is_not_an_authority() -> None:
    law = "PF-SHARED-R7/phaseio-unknown-trust-keyword"
    candidate, _inputs, _document, _authority, kwargs = _phaseio_vector(law)
    with pytest.raises(TypeError):
        _phaseio_validator(law)(
            candidate,
            **kwargs,
            validated=True,
        )


def test_shared_phaseio_outer_sealed_mapping_is_snapshotted_once() -> None:
    law = "PF-SHARED-R7/phaseio-outer-single-snapshot"
    candidate, inputs, document, authority, _kwargs = _phaseio_vector(law)
    stateful = _StatefulVariantMapping(
        inputs,
        stable_variant_reads=1,
        later_variants=["variant-b"],
    )
    observed = require_accepts(
        _phaseio_validator(law),
        law,
        candidate,
        **_candidate_validation_kwargs(
            stateful,
            document,
            authority,
        ),
    )
    assert _candidate_mapping(observed) == candidate
    assert stateful._variant_reads == 1


def test_shared_phaseio_nested_sealed_mapping_is_snapshotted_once() -> None:
    law = "PF-SHARED-R7/phaseio-nested-single-snapshot"
    composer = require_callable(
        "program_facts_positive_composer",
        "compose_program_facts_v2_production",
        law,
    )
    inputs = _sealed_inputs()
    inputs["facts"] = [{"tag": "first"}]
    _environment, document, authority = _authority_vector()
    candidate = require_accepts(
        composer,
        law,
        inputs,
        document,
        **authority,
    )
    core_validator = require_callable(
        "program_facts_positive_composer",
        "validate_production_composition_candidate",
        law,
    )
    require_accepts(
        core_validator,
        law,
        candidate,
        **_candidate_validation_kwargs(
            inputs,
            document,
            authority,
        ),
    )
    nested = _FlippingNestedMapping("first", "second")
    stateful_inputs = deepcopy(inputs)
    stateful_inputs["facts"] = [nested]
    observed = require_accepts(
        _phaseio_validator(law),
        law,
        candidate,
        **_candidate_validation_kwargs(
            stateful_inputs,
            document,
            authority,
        ),
    )
    assert _candidate_mapping(observed) == _candidate_mapping(candidate)
    assert nested.reads == 1


_EXPECTED_AUTHORITY_FIELDS = (
    "expected_run_id",
    "expected_run_generation",
    "expected_execution_authority_digest",
    "expected_composition_authority_digest",
    "expected_methodology_package_digest",
    "expected_provider_environment_digest",
    "expected_provider_package_digest",
    "expected_native_host_receipt_digest",
    "expected_independent_review_receipts",
    "expected_issuer_policy_digest",
    "expected_issuer_id",
    "expected_release_id",
    "expected_activation_decision_digest",
    "provider_environment",
)


def _substitute_authority(field: str, value: Any) -> Any:
    if field == "expected_run_generation":
        return int(value) + 1
    if field == "expected_independent_review_receipts":
        mutated = dict(value)
        first = sorted(mutated)[0]
        mutated[first] = "f" * 64
        return mutated
    if field == "provider_environment":
        mutated = deepcopy(value)
        mutated["environment_digest"] = "f" * 64
        return mutated
    if field.endswith("_id") or field == "expected_run_id":
        return f"{value}-foreign"
    return "f" * 64


@pytest.mark.parametrize("authority_field", _EXPECTED_AUTHORITY_FIELDS)
def test_shared_phaseio_each_external_authority_is_independently_replayed(
    authority_field: str,
) -> None:
    law = f"PF-SHARED-R7/phaseio-authority-{authority_field}"
    candidate, _inputs, _document, _authority, kwargs = _phaseio_vector(law)
    mutated = deepcopy(kwargs)
    mutated[authority_field] = _substitute_authority(
        authority_field,
        mutated[authority_field],
    )
    with pytest.raises(ProgramFactsTypeError):
        _phaseio_validator(law)(candidate, **mutated)


_CANDIDATE_MUTATIONS = (
    "artifact_bytes",
    "artifact_order",
    "artifact_identity",
    "permit_digest",
    "sealed_input_digest",
    "candidate_digest",
)


def _mutated_candidate(
    candidate: Mapping[str, Any],
    mutation: str,
) -> dict[str, Any]:
    value = deepcopy(dict(candidate))
    if mutation == "artifact_bytes":
        rows = list(value["artifacts"])
        identity, content = rows[0]
        rows[0] = (identity, bytes(content) + b" ")
        value["artifacts"] = rows
    elif mutation == "artifact_order":
        value["artifacts"] = list(reversed(value["artifacts"]))
    elif mutation == "artifact_identity":
        rows = list(value["artifacts"])
        _identity, content = rows[0]
        rows[0] = ("forged.json", content)
        value["artifacts"] = rows
    else:
        value[mutation] = "f" * 64
    return value


@pytest.mark.parametrize("mutation", _CANDIDATE_MUTATIONS)
def test_shared_phaseio_candidate_fields_are_fully_recomputed(
    mutation: str,
) -> None:
    law = f"PF-SHARED-R7/phaseio-candidate-{mutation}"
    candidate, _inputs, _document, _authority, kwargs = _phaseio_vector(law)
    with pytest.raises(ProgramFactsTypeError):
        _phaseio_validator(law)(
            _mutated_candidate(candidate, mutation),
            **kwargs,
        )


def test_shared_phaseio_positive_and_rejection_have_zero_side_effects(
    tmp_path: Path,
) -> None:
    law = "PF-SHARED-R7/phaseio-zero-side-effects"
    candidate, _inputs, _document, _authority, kwargs = _phaseio_vector(law)
    sentinel = tmp_path / "sentinel"
    sentinel.write_bytes(b"unchanged")
    before = _tree_bytes(tmp_path)
    validator = _phaseio_validator(law)
    require_accepts(validator, law, candidate, **kwargs)
    with pytest.raises(ProgramFactsTypeError):
        validator(
            _mutated_candidate(candidate, "candidate_digest"),
            **kwargs,
        )
    assert _tree_bytes(tmp_path) == before


def test_shared_ledger_clean_five_file_commit_creates_exact_active_row(
    tmp_path: Path,
) -> None:
    law = "PF-SHARED-R7/ledger-clean-positive"
    root = tmp_path / ".scratchpad"
    vector = _publication_vector(root, law)
    result = require_accepts(
        _committer(law),
        law,
        **_commit_kwargs(vector),
    )
    expected_digest = _selection_digest(vector["selection"])
    assert result == {
        "state": "ACTIVE",
        "generation_id": vector["selection"]["generation_id"],
        "selection_digest": expected_digest,
        "selection_record": vector["selection"],
        "idempotent_replay": False,
    }
    _assert_selection_store(
        root,
        selection=vector["selection"],
        expected_history_count=1,
    )


@pytest.mark.parametrize(
    "target_name",
    ("arm", "manifest", *PUBLIC_IDENTITIES),
)
def test_shared_ledger_reopens_and_rejects_each_tampered_file(
    tmp_path: Path,
    target_name: str,
) -> None:
    law = f"PF-SHARED-R7/ledger-reopen-{target_name}"
    root = tmp_path / ".scratchpad"
    vector = _publication_vector(root, law)
    if target_name == "arm":
        target = vector["arm_path"]
    elif target_name == "manifest":
        target = vector["manifest_path"]
    else:
        target = vector["output_paths"][target_name]
    target.write_bytes(target.read_bytes() + b"tampered")
    _require_artifact_rejection_without_mutation(
        _committer(law),
        root,
        law,
        **_commit_kwargs(vector),
    )


def test_shared_ledger_parse_only_selection_is_not_commit_authority(
    tmp_path: Path,
) -> None:
    law = "PF-SHARED-R7/ledger-parse-only-reject"
    root = tmp_path / ".scratchpad"
    vector = _publication_vector(root, law)
    substituted = deepcopy(vector["selection"])
    substituted["contract_digest"] = "f" * 64
    parser = require_callable(
        "program_facts_publication",
        "parse_immutable_generation_selection_v1",
        law,
    )
    require_accepts(parser, law, substituted)
    kwargs = _commit_kwargs(vector)
    kwargs["selection_record"] = substituted
    _require_artifact_rejection_without_mutation(
        _committer(law),
        root,
        law,
        **kwargs,
    )


@pytest.mark.parametrize(
    "path_attack",
    (
        "missing_output",
        "extra_output",
        "reordered_outputs",
        "duplicate_physical_path",
        "wrong_bound_suffix",
        "case_alias",
    ),
)
def test_shared_ledger_path_denominator_and_bindings_are_exact(
    tmp_path: Path,
    path_attack: str,
) -> None:
    law = f"PF-SHARED-R7/ledger-path-{path_attack}"
    root = tmp_path / ".scratchpad"
    vector = _publication_vector(root, law)
    paths = dict(vector["output_paths"])
    if path_attack == "missing_output":
        paths.pop(PUBLIC_IDENTITIES[-1])
    elif path_attack == "extra_output":
        paths["extra.json"] = vector["output_paths"][PUBLIC_IDENTITIES[0]]
    elif path_attack == "reordered_outputs":
        paths = dict(reversed(tuple(paths.items())))
    elif path_attack == "duplicate_physical_path":
        paths[PUBLIC_IDENTITIES[1]] = paths[PUBLIC_IDENTITIES[0]]
    else:
        identity = PUBLIC_IDENTITIES[0]
        original = paths[identity]
        alias = (
            original.with_name(original.name.upper())
            if path_attack == "case_alias"
            else root / "unbound" / original.name
        )
        alias.parent.mkdir(parents=True, exist_ok=True)
        if not alias.exists():
            alias.write_bytes(original.read_bytes())
        paths[identity] = alias
    kwargs = _commit_kwargs(vector)
    kwargs["logical_output_paths"] = paths
    _require_artifact_rejection_without_mutation(
        _committer(law),
        root,
        law,
        **kwargs,
    )


def test_shared_ledger_hardlinked_evidence_is_rejected(
    tmp_path: Path,
) -> None:
    law = "PF-SHARED-R7/ledger-hardlink-reject"
    root = tmp_path / ".scratchpad"
    vector = _publication_vector(root, law)
    target = vector["output_paths"][PUBLIC_IDENTITIES[0]]
    hardlink = target.with_name(f"{target.name}.hardlink")
    try:
        os.link(target, hardlink)
    except OSError as exc:
        pytest.skip(f"hard links unavailable: {exc}")
    _require_artifact_rejection_without_mutation(
        _committer(law),
        root,
        law,
        **_commit_kwargs(vector),
    )


def test_shared_ledger_symlink_or_reparse_evidence_is_rejected(
    tmp_path: Path,
) -> None:
    law = "PF-SHARED-R7/ledger-symlink-reject"
    root = tmp_path / ".scratchpad"
    vector = _publication_vector(root, law)
    identity = PUBLIC_IDENTITIES[0]
    target = vector["output_paths"][identity]
    backing = root / "symlink-backing-output"
    target.replace(backing)
    try:
        target.symlink_to(backing)
    except OSError as exc:
        if backing.exists() and not target.exists():
            backing.replace(target)
        pytest.skip(f"symlinks unavailable: {exc}")
    _require_artifact_rejection_without_mutation(
        _committer(law),
        root,
        law,
        **_commit_kwargs(vector),
    )


def test_shared_ledger_post_validation_replacement_is_detected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    law = "PF-SHARED-R7/ledger-post-validation-toctou"
    root = tmp_path / ".scratchpad"
    vector = _publication_vector(root, law)
    target = vector["output_paths"][PUBLIC_IDENTITIES[0]]
    original_validator = (
        program_facts_publication.validate_generation_selection_evidence_v1
    )
    calls = 0

    def validate_then_replace(**kwargs: Any):
        nonlocal calls
        calls += 1
        result = original_validator(**kwargs)
        target.write_bytes(target.read_bytes() + b"raced")
        return result

    monkeypatch.setattr(
        program_facts_publication,
        "validate_generation_selection_evidence_v1",
        validate_then_replace,
    )
    before_ledger = _ledger_bytes(root)
    with pytest.raises(ArtifactLedgerError):
        _committer(law)(**_commit_kwargs(vector))
    assert calls == 1
    assert _ledger_bytes(root) == before_ledger


@pytest.mark.parametrize(
    "prior_attack",
    (
        "first_present",
        "successor_absent",
        "successor_wrong_generation",
        "successor_wrong_digest",
    ),
)
def test_shared_ledger_prior_active_is_an_exact_compare_and_swap(
    tmp_path: Path,
    prior_attack: str,
) -> None:
    law = f"PF-SHARED-R7/ledger-prior-cas-{prior_attack}"
    root = tmp_path / ".scratchpad"
    if prior_attack == "first_present":
        forged_prior = {
            "state": "PRESENT",
            "generation_id": "pfg-" + ("f" * 32),
            "selection_digest": "f" * 64,
        }
        vector = _publication_vector(
            root,
            law,
            prior_active=forged_prior,
        )
        committer = _committer(law)
        _require_artifact_rejection_without_mutation(
            committer,
            root,
            law,
            **_commit_kwargs(vector),
        )
        return

    first = _publication_vector(root, law)
    committer = _committer(law)
    first_result = require_accepts(
        committer,
        law,
        **_commit_kwargs(first),
    )
    if prior_attack == "successor_absent":
        prior: Mapping[str, Any] | None = None
    else:
        prior = _active_prestate(first_result)
        prior = dict(prior)
        if prior_attack == "successor_wrong_generation":
            prior["generation_id"] = "pfg-" + ("f" * 32)
        else:
            prior["selection_digest"] = "f" * 64
    successor = _publication_vector(
        root,
        law,
        prior_active=prior,
        transaction_nonce=(
            "nonce-fixture-successor-absent"
            if prior_attack == "successor_absent"
            else None
        ),
    )
    if prior_attack == "successor_absent":
        assert successor["selection"]["prior_active"] == {
            "state": "ABSENT"
        }
        assert (
            successor["selection"]["generation_id"]
            != first["selection"]["generation_id"]
        )
        assert (
            successor["selection"]["publication_transaction"][
                "transaction_id"
            ]
            != first["selection"]["publication_transaction"][
                "transaction_id"
            ]
        )
    _require_artifact_rejection_without_mutation(
        committer,
        root,
        law,
        **_commit_kwargs(successor),
    )
    _assert_selection_store(
        root,
        selection=first["selection"],
        expected_history_count=1,
    )


def test_shared_ledger_exact_replay_is_idempotent_after_five_file_reopen(
    tmp_path: Path,
) -> None:
    law = "PF-SHARED-R7/ledger-idempotent-replay"
    root = tmp_path / ".scratchpad"
    vector = _publication_vector(root, law)
    committer = _committer(law)
    first = require_accepts(
        committer,
        law,
        **_commit_kwargs(vector),
    )
    before = _ledger_bytes(root)
    replay = require_accepts(
        committer,
        law,
        **_commit_kwargs(vector),
    )
    assert replay == {**first, "idempotent_replay": True}
    assert _ledger_bytes(root) == before
    _assert_selection_store(
        root,
        selection=vector["selection"],
        expected_history_count=1,
    )


def test_shared_ledger_idempotent_replay_still_reopens_all_five_files(
    tmp_path: Path,
) -> None:
    law = "PF-SHARED-R7/ledger-idempotent-reopen"
    root = tmp_path / ".scratchpad"
    vector = _publication_vector(root, law)
    committer = _committer(law)
    require_accepts(committer, law, **_commit_kwargs(vector))
    target = vector["output_paths"][PUBLIC_IDENTITIES[-1]]
    target.write_bytes(target.read_bytes() + b"tampered")
    before = _ledger_bytes(root)
    with pytest.raises(ArtifactLedgerError):
        committer(**_commit_kwargs(vector))
    assert _ledger_bytes(root) == before


def test_shared_ledger_successor_cas_and_older_rollback_rejection(
    tmp_path: Path,
) -> None:
    law = "PF-SHARED-R7/ledger-successor-and-rollback"
    root = tmp_path / ".scratchpad"
    first = _publication_vector(root, law)
    committer = _committer(law)
    first_result = require_accepts(
        committer,
        law,
        **_commit_kwargs(first),
    )
    successor = _publication_vector(
        root,
        law,
        prior_active=_active_prestate(first_result),
    )
    require_accepts(
        committer,
        law,
        **_commit_kwargs(successor),
    )
    _assert_selection_store(
        root,
        selection=successor["selection"],
        expected_history_count=2,
    )
    before = _ledger_bytes(root)
    with pytest.raises(ArtifactLedgerError):
        committer(**_commit_kwargs(first))
    assert _ledger_bytes(root) == before


def test_shared_ledger_same_generation_divergent_selection_rejects(
    tmp_path: Path,
) -> None:
    law = "PF-SHARED-R7/ledger-same-generation-divergence"
    root = tmp_path / ".scratchpad"
    first = _publication_vector(root, law)
    committer = _committer(law)
    require_accepts(committer, law, **_commit_kwargs(first))
    before_ledger = _ledger_bytes(root)
    divergent_outputs = logical_output_bytes()
    divergent_outputs[PUBLIC_IDENTITIES[0]] += b" "
    divergent = _publication_vector(
        root,
        law,
        outputs=divergent_outputs,
    )
    assert (
        divergent["selection"]["generation_id"]
        == first["selection"]["generation_id"]
    )
    assert (
        _selection_digest(divergent["selection"])
        != _selection_digest(first["selection"])
    )
    with pytest.raises(ArtifactLedgerError):
        committer(**_commit_kwargs(divergent))
    assert _ledger_bytes(root) == before_ledger


@pytest.mark.parametrize(
    "malformed_state",
    (
        "pointer_only",
        "history_only",
        "pointer_row_mismatch",
        "malformed_digest",
    ),
)
def test_shared_ledger_malformed_selection_tables_fail_without_normalization(
    tmp_path: Path,
    malformed_state: str,
) -> None:
    law = f"PF-SHARED-R7/ledger-malformed-{malformed_state}"
    root = tmp_path / ".scratchpad"
    vector = _publication_vector(root, law)
    selection = vector["selection"]
    digest = _selection_digest(selection)
    history = {
        selection["generation_id"]: {
            "selection_digest": digest,
            "selection_record": selection,
        }
    }
    pointer = {
        "state": "PRESENT",
        "generation_id": selection["generation_id"],
        "selection_digest": digest,
    }
    ledger = read_artifact_ledger(root)
    if malformed_state != "pointer_only":
        ledger["program_facts_v2_generation_selections"] = history
    if malformed_state != "history_only":
        ledger["program_facts_v2_active_selection"] = pointer
    if malformed_state == "pointer_row_mismatch":
        ledger["program_facts_v2_active_selection"] = {
            **pointer,
            "selection_digest": "f" * 64,
        }
    if malformed_state == "malformed_digest":
        ledger["program_facts_v2_generation_selections"][
            selection["generation_id"]
        ]["selection_digest"] = "not-a-digest"
    write_artifact_ledger(root, ledger)
    _require_artifact_rejection_without_mutation(
        _committer(law),
        root,
        law,
        **_commit_kwargs(vector),
    )


def test_shared_ledger_pre_replace_failure_preserves_prior_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    law = "PF-SHARED-R7/ledger-pre-replace-failure"
    root = tmp_path / ".scratchpad"
    vector = _publication_vector(root, law)
    before_tree = _tree_bytes(root)
    before_ledger = _ledger_bytes(root)

    def fail_before_write(_root: Path, _ledger: dict[str, Any]) -> None:
        raise ArtifactLedgerError("injected pre-replace failure")

    monkeypatch.setattr(
        artifact_ledger,
        "write_artifact_ledger",
        fail_before_write,
    )
    with pytest.raises(ArtifactLedgerError):
        _committer(law)(**_commit_kwargs(vector))
    assert _ledger_bytes(root) == before_ledger
    assert _tree_bytes(root) == before_tree


def test_shared_ledger_post_replace_failure_leaves_one_complete_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    law = "PF-SHARED-R7/ledger-post-replace-complete-state"
    root = tmp_path / ".scratchpad"
    vector = _publication_vector(root, law)
    original_write = artifact_ledger.write_artifact_ledger

    def write_then_fail(
        target_root: Path,
        ledger: dict[str, Any],
    ) -> None:
        original_write(target_root, ledger)
        raise ArtifactLedgerError("injected post-replace failure")

    monkeypatch.setattr(
        artifact_ledger,
        "write_artifact_ledger",
        write_then_fail,
    )
    try:
        _committer(law)(**_commit_kwargs(vector))
    except ArtifactLedgerError:
        pass
    _assert_selection_store(
        root,
        selection=vector["selection"],
        expected_history_count=1,
    )


def test_shared_ledger_commit_never_mutates_five_input_files(
    tmp_path: Path,
) -> None:
    law = "PF-SHARED-R7/ledger-five-inputs-immutable"
    root = tmp_path / ".scratchpad"
    vector = _publication_vector(root, law)
    five = (
        vector["arm_path"],
        vector["manifest_path"],
        *tuple(vector["output_paths"].values()),
    )
    before = {path: path.read_bytes() for path in five}
    require_accepts(
        _committer(law),
        law,
        **_commit_kwargs(vector),
    )
    assert {path: path.read_bytes() for path in five} == before
