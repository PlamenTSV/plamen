from __future__ import annotations

from collections.abc import Iterator, Mapping
from copy import deepcopy
import ast
import hashlib
import importlib
import importlib.util
import inspect
import json
from pathlib import Path
from typing import Any

from review_fixtures.program_facts_r2_1_b0_red_support import (
    H2,
    H3,
    H4,
    HE,
    PUBLIC_IDENTITIES,
    ROOT,
    assert_schema_accepts,
    body_digest,
    build_plan_validation_kwargs,
    compatibility_delta_positive_vector,
    frozen_build_plan_document,
    linux_environment_document,
    linux_permit_document,
    permit_validation_kwargs,
    require_accepts,
    require_callable,
    require_rejects,
)
from test_program_facts_r21_2_terminal_roster_b0_red import (
    _expected_and_roster,
)


COMPOSER_MODULE = "program_facts_positive_composer"
ENVIRONMENT_MODULE = "program_facts_evm_environment_authority"
TEST_COMPOSER_MODULE = (
    "review_fixtures.program_facts_test_support.nonpublishing_composer_v1"
)
CANDIDATE_SCHEMA = (
    "plamen.program_facts_production_composition_candidate.v1"
)
CANDIDATE_KEYS = (
    "schema_version",
    "authority_class",
    "run_id",
    "run_generation",
    "permit_digest",
    "permit_binding_digest",
    "sealed_input_digest",
    "artifacts",
    "candidate_digest",
)
AGGREGATE_RESULT_KEYS = (
    "accepted",
    "build_plan_digest",
    "expected_wtx_children_digest",
    "terminal_wtx_roster_digest",
    "expanded_input_count",
    "raw_cas_leaf_denominator_digest",
    "compatibility_receipt_body_sha256",
    "candidate_digest",
)


class _ShapeCompatibleFakeTestCapability:
    authority_class = "TEST_ONLY_NONAUTHORITATIVE"


class _ObjectNewMapping(Mapping[str, object]):
    """A deliberately forgeable carrier with an unusable constructor."""

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise RuntimeError("constructor is intentionally unavailable")

    def __getitem__(self, key: str) -> object:
        return self._payload[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._payload)

    def __len__(self) -> int:
        return len(self._payload)


class _StatefulVariantMapping(Mapping[str, object]):
    """Return one variant set, then a different caller-controlled set."""

    def __init__(
        self,
        payload: Mapping[str, object],
        *,
        stable_variant_reads: int,
        later_variants: list[str],
    ) -> None:
        self._payload = deepcopy(dict(payload))
        self._stable_variant_reads = stable_variant_reads
        self._later_variants = list(later_variants)
        self._variant_reads = 0

    def __getitem__(self, key: str) -> object:
        if key == "selected_variant_ids":
            self._variant_reads += 1
            if self._variant_reads > self._stable_variant_reads:
                return list(self._later_variants)
        return deepcopy(self._payload[key])

    def __iter__(self) -> Iterator[str]:
        return iter(self._payload)

    def __len__(self) -> int:
        return len(self._payload)


def _sealed_inputs(run_id: str = "fixture-run") -> dict[str, object]:
    return {
        "run_id": run_id,
        "run_generation": 7,
        "execution_authority_digest": H2,
        "composition_authority_digest": H3,
        "methodology_package_digest": H4,
        "selected_variant_ids": ["variant-a"],
        "selected_capability_ids": ["capability-a"],
        "facts": [],
        "debt": [],
    }


def _authority_vector(
    run_id: str = "fixture-run",
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    environment = linux_environment_document()
    document = linux_permit_document(run_id=run_id)
    kwargs = permit_validation_kwargs(
        document,
        provider_environment=environment,
    )
    return environment, document, kwargs


def _candidate_validation_kwargs(
    inputs: Mapping[str, Any],
    document: Mapping[str, Any],
    authority_kwargs: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "sealed_composition_inputs": inputs,
        "activation_permit_document": document,
        **dict(authority_kwargs),
    }


def _candidate_mapping(candidate: object) -> dict[str, Any]:
    assert isinstance(candidate, Mapping)
    value = deepcopy(dict(candidate))
    assert set(value) == set(CANDIDATE_KEYS)
    assert value["schema_version"] == CANDIDATE_SCHEMA
    assert tuple(identity for identity, _content in value["artifacts"]) == (
        PUBLIC_IDENTITIES
    )
    return value


def _candidate_payload(candidate: object) -> dict[str, Any]:
    mapping = _candidate_mapping(candidate)
    _identity, payload_bytes = mapping["artifacts"][0]
    return json.loads(bytes(payload_bytes).decode("ascii"))


def _production_candidate_vector(
    law: str,
    *,
    run_id: str = "fixture-run",
):
    composer = require_callable(
        COMPOSER_MODULE, "compose_program_facts_v2_production", law
    )
    validator = require_callable(
        COMPOSER_MODULE, "validate_production_composition_candidate", law
    )
    inputs = _sealed_inputs(run_id)
    environment, document, authority_kwargs = _authority_vector(run_id)
    candidate = require_accepts(
        composer,
        law,
        inputs,
        document,
        **authority_kwargs,
    )
    validated = require_accepts(
        validator,
        law,
        candidate,
        **_candidate_validation_kwargs(
            inputs,
            document,
            authority_kwargs,
        ),
    )
    _candidate_mapping(validated)
    return (
        validated,
        inputs,
        document,
        environment,
        authority_kwargs,
        validator,
    )


def _require_valid_production_candidate(
    law: str,
    *,
    run_id: str = "fixture-run",
):
    return _production_candidate_vector(law, run_id=run_id)[0]


def _reject_expected_substitution(
    law: str,
    expected_field: str,
    substituted_value: object,
) -> None:
    (
        candidate,
        inputs,
        document,
        _environment,
        authority_kwargs,
        validator,
    ) = _production_candidate_vector(law)
    negative_kwargs = deepcopy(authority_kwargs)
    negative_kwargs[expected_field] = substituted_value
    require_rejects(
        validator,
        law,
        candidate,
        **_candidate_validation_kwargs(
            inputs,
            document,
            negative_kwargs,
        ),
    )


def _reject_candidate_mutation(
    law: str,
    mutator,
) -> None:
    (
        candidate,
        inputs,
        document,
        _environment,
        authority_kwargs,
        validator,
    ) = _production_candidate_vector(law)
    mutated = _candidate_mapping(candidate)
    mutator(mutated)
    require_rejects(
        validator,
        law,
        mutated,
        **_candidate_validation_kwargs(
            inputs,
            document,
            authority_kwargs,
        ),
    )


def _replace_candidate_field(field: str, value: object):
    def mutate(candidate: dict[str, Any]) -> None:
        candidate[field] = value

    return mutate


def _mutate_artifact(
    index: int,
    *,
    identity: str | None = None,
    suffix: bytes = b"",
):
    def mutate(candidate: dict[str, Any]) -> None:
        artifacts = list(candidate["artifacts"])
        old_identity, old_content = artifacts[index]
        artifacts[index] = (
            identity if identity is not None else old_identity,
            bytes(old_content) + suffix,
        )
        candidate["artifacts"] = artifacts

    return mutate


def _legacy_closure_mint():
    integrity_key = b"fixture-process-local-key-is-not-authority"

    def mint(payload: Mapping[str, object]) -> tuple[dict[str, object], str]:
        tag_preimage = dict(payload)
        tag_preimage["artifacts"] = [
            {
                "logical_identity": identity,
                "size": len(content),
                "sha256": hashlib.sha256(bytes(content)).hexdigest(),
            }
            for identity, content in payload["artifacts"]
        ]
        body = json.dumps(
            tag_preimage,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        return dict(payload), hashlib.sha256(integrity_key + body).hexdigest()

    return mint


def _assert_module_has_no_secret_authority(
    module_name: str,
    public_names: tuple[str, ...],
) -> None:
    module = importlib.import_module(module_name)
    source_path = Path(module.__file__).resolve()
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(source_path))
    forbidden_imports: set[str] = set()
    forbidden_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            forbidden_imports.update(
                alias.name
                for alias in node.names
                if alias.name in {"hmac", "secrets"}
            )
        elif isinstance(node, ast.ImportFrom) and node.module in {
            "hmac",
            "secrets",
        }:
            forbidden_imports.add(node.module)
        elif isinstance(node, ast.Name) and node.id in {
            "integrity_key",
            "integrity_mac",
            "_integrity_key",
            "_integrity_mac",
        }:
            forbidden_names.add(node.id)
    assert not forbidden_imports, (
        f"process-local secret imports remain in {module_name}: "
        f"{sorted(forbidden_imports)!r}"
    )
    assert not forbidden_names, (
        f"opaque carrier secret fields remain in {module_name}: "
        f"{sorted(forbidden_names)!r}"
    )
    for name in public_names:
        function = getattr(module, name)
        closure = inspect.getclosurevars(function)
        assert not closure.nonlocals, (
            f"{module_name}.{name} retains closure authority: "
            f"{sorted(closure.nonlocals)!r}"
        )


def _aggregate_vector(law: str):
    (
        candidate,
        inputs,
        document,
        environment,
        authority_kwargs,
        _validator,
    ) = _production_candidate_vector(law)
    (
        expected,
        roster,
        ledger,
        build_plan,
        raw_manifests,
        expanded_inputs,
    ) = _expected_and_roster(law, variants=("variant-a",))
    compatibility = compatibility_delta_positive_vector()
    aggregate = require_callable(
        "program_facts_bake",
        "validate_program_facts_v2_authority_graph_v1",
        law,
    )
    aggregate_kwargs = {
        "candidate": candidate,
        "sealed_composition_inputs": inputs,
        "activation_permit_document": document,
        "provider_environment": environment,
        **{
            key: value
            for key, value in authority_kwargs.items()
            if key != "provider_environment"
        },
        "build_plan": build_plan,
        **build_plan_validation_kwargs(build_plan),
        "expected_children": expected,
        "terminal_roster": roster,
        "terminal_roster_ledger_state": "ACTIVE",
        "terminal_ledger_rows": ledger,
        "raw_cas_manifests": raw_manifests,
        "expanded_inputs": expanded_inputs,
        "compatibility_document": compatibility["document"],
        "compatibility_validation_inputs": compatibility[
            "validation_kwargs"
        ],
    }
    return aggregate, aggregate_kwargs


def _replace_complete_execution_branch(
    law: str,
    aggregate_kwargs: dict[str, Any],
    plan_document: Mapping[str, Any],
) -> None:
    (
        expected,
        roster,
        ledger,
        build_plan,
        raw_manifests,
        expanded_inputs,
    ) = _expected_and_roster(law, plan_document=plan_document)
    aggregate_kwargs.update(
        {
            "build_plan": build_plan,
            "expected_children": expected,
            "terminal_roster": roster,
            "terminal_ledger_rows": ledger,
            "raw_cas_manifests": raw_manifests,
            "expanded_inputs": expanded_inputs,
            **build_plan_validation_kwargs(build_plan),
        }
    )


def test_r21_3_test_capability_rejected_by_production_composer() -> None:
    law = "R2.1-3/production-rejects-test-capability"
    composer = require_callable(
        COMPOSER_MODULE, "compose_program_facts_v2_production", law
    )
    _require_valid_production_candidate(law)
    _environment, document, authority_kwargs = _authority_vector()
    require_rejects(
        composer,
        law,
        _sealed_inputs(),
        _ShapeCompatibleFakeTestCapability(),
        **authority_kwargs,
    )


def test_r21_3_test_capability_rejected_by_bake_phaseio_and_publication() -> None:
    law = "R2.1-3/test-authority-rejected-at-all-production-boundaries"
    (
        _candidate,
        inputs,
        document,
        _environment,
        authority_kwargs,
        _validator,
    ) = _production_candidate_vector(law)
    validation_kwargs = _candidate_validation_kwargs(
        inputs,
        document,
        authority_kwargs,
    )
    fake = {
        "authority_class": "TEST_ONLY_NONAUTHORITATIVE",
        "candidate_bytes": b"{}",
    }
    targets = (
        (
            "program_facts_bake",
            "accept_program_facts_v2_production_candidate",
        ),
        (
            "phase_io_contracts",
            "validate_program_facts_v2_private_commit_candidate",
        ),
        (
            "program_facts_publication",
            "publish_program_facts_v2_candidate",
        ),
    )
    for module_name, callable_name in targets:
        validator = require_callable(module_name, callable_name, law)
        require_rejects(
            validator,
            law,
            fake,
            **validation_kwargs,
        )


def test_r21_3_denied_envelope_emits_zero_positive_rows_only() -> None:
    law = "R2.1-3/denied-envelope-zero-positive-only"
    composer = require_callable(
        COMPOSER_MODULE, "compose_program_facts_v2_production", law
    )
    result = require_accepts(
        composer,
        law,
        _sealed_inputs(),
        {
            "state": "ABSENT_DENIED",
            "reason": "ACTIVATION_PERMIT_DENIED",
        },
    )
    assert result["status"] == "UNAVAILABLE"
    assert result["positive_fact_count"] == 0
    assert result["positive_node_count"] == 0
    assert result["debt"]


def test_r21_3_test_composer_returns_only_test_only_nonauthoritative_wrappers() -> None:
    law = "R2.1-3/test-composer-return-type-boundary"
    composer = require_callable(
        TEST_COMPOSER_MODULE, "compose_program_facts_v2_test_only", law
    )
    mint = require_callable(TEST_COMPOSER_MODULE, "mint_test_capability", law)
    result = require_accepts(composer, law, _sealed_inputs(), mint())
    assert result.authority_class == "TEST_ONLY_NONAUTHORITATIVE"
    assert result.__class__.__name__ == "TestOnlyNonAuthoritativeComposition"
    assert result.artifacts
    for artifact in result.artifacts:
        assert artifact.authority_class == "TEST_ONLY_NONAUTHORITATIVE"
        assert artifact.candidate_sha256


def test_r21_3_test_composer_has_no_filesystem_ledger_or_generation_effect(
    tmp_path: Path,
    monkeypatch,
) -> None:
    law = "R2.1-3/test-composer-nonpublishing-side-effect-law"
    composer = require_callable(
        TEST_COMPOSER_MODULE, "compose_program_facts_v2_test_only", law
    )
    mint = require_callable(TEST_COMPOSER_MODULE, "mint_test_capability", law)
    monkeypatch.chdir(tmp_path)
    before = sorted(path.relative_to(tmp_path).as_posix() for path in tmp_path.rglob("*"))
    result = require_accepts(composer, law, _sealed_inputs(), mint())
    after = sorted(path.relative_to(tmp_path).as_posix() for path in tmp_path.rglob("*"))
    assert result.authority_class == "TEST_ONLY_NONAUTHORITATIVE"
    assert after == before


def test_r21_3_test_result_and_bare_bytes_cannot_become_production_carrier() -> None:
    law = "R2.1-3/no-test-to-production-adoption"
    (
        _candidate,
        inputs,
        document,
        _environment,
        authority_kwargs,
        validator,
    ) = _production_candidate_vector(law)
    for value in (
        b'{"authority_class":"TEST_ONLY_NONAUTHORITATIVE"}',
        {
            "authority_class": "TEST_ONLY_NONAUTHORITATIVE",
            "candidate_bytes": b"{}",
        },
        _ShapeCompatibleFakeTestCapability(),
    ):
        require_rejects(
            validator,
            law,
            value,
            **_candidate_validation_kwargs(
                inputs,
                document,
                authority_kwargs,
            ),
        )


def test_r21_3_test_support_is_absent_from_installed_runtime_and_entry_points() -> None:
    law = "R2.1-3/test-support-not-installed"
    support_path = (
        ROOT
        / "review_fixtures"
        / "program_facts_test_support"
        / "nonpublishing_composer_v1.py"
    )
    assert support_path.is_file()
    validator = require_callable(
        COMPOSER_MODULE, "validate_test_support_packaging_exclusion_v1", law
    )
    require_accepts(
        validator,
        law,
        test_support_path=support_path,
        runtime_manifest_path=(
            ROOT / "verification_policy" / "toolchain_runtime_closure.v1.json"
        ),
        entry_point_files=[ROOT / "plamen.py", ROOT / "pyproject.toml"],
    )


def test_r21_3_test_support_import_closure_excludes_mutating_modules() -> None:
    law = "R2.1-3/test-support-static-import-closure"
    support_path = (
        ROOT
        / "review_fixtures"
        / "program_facts_test_support"
        / "nonpublishing_composer_v1.py"
    )
    assert support_path.is_file()
    validator = require_callable(
        COMPOSER_MODULE, "validate_test_support_import_closure_v1", law
    )
    require_accepts(
        validator,
        law,
        support_path,
        forbidden_modules={
            "artifact_ledger",
            "phase_io_contracts",
            "program_facts_publication",
            "plamen_driver",
            "owned_process_runner",
            "program_facts_evm_provider",
            "program_facts_evm_environment_installer",
            "plamen",
        },
    )


def test_r21_3_checkpoint_d_recomposes_under_real_permit_and_fresh_run() -> None:
    law = "R2.1-3/checkpoint-d-fresh-authoritative-recomposition"
    result = _require_valid_production_candidate(
        law,
        run_id="fresh-checkpoint-d-run",
    )
    mapping = _candidate_mapping(result)
    assert mapping["authority_class"] == "PRODUCTION_PERMIT_BOUND"
    assert mapping["run_id"] == "fresh-checkpoint-d-run"


def test_core_r5_exact_recomputed_untrusted_mapping_accepts() -> None:
    law = "PF-R5-1/exact-recomputed-untrusted-mapping"
    (
        candidate,
        inputs,
        document,
        _environment,
        authority_kwargs,
        validator,
    ) = _production_candidate_vector(law)
    ordinary_mapping = _candidate_mapping(candidate)
    ordinary_mapping["artifacts"] = list(ordinary_mapping["artifacts"])
    require_accepts(
        validator,
        law,
        ordinary_mapping,
        **_candidate_validation_kwargs(
            inputs,
            document,
            authority_kwargs,
        ),
    )


def test_core_r5_recovered_closure_key_and_object_new_forgery_gain_no_authority() -> None:
    law = "PF-R5-1/closure-key-and-object-new-are-nonauthoritative"
    (
        candidate,
        inputs,
        document,
        _environment,
        authority_kwargs,
        validator,
    ) = _production_candidate_vector(law)
    legacy_mint = _legacy_closure_mint()
    recovered_by_name = inspect.getclosurevars(legacy_mint).nonlocals[
        "integrity_key"
    ]
    recovered_by_cell = next(
        cell.cell_contents
        for name, cell in zip(
            legacy_mint.__code__.co_freevars,
            legacy_mint.__closure__ or (),
        )
        if name == "integrity_key"
    )
    assert recovered_by_name == recovered_by_cell
    payload, legacy_mac = legacy_mint(_candidate_mapping(candidate))
    forged = object.__new__(_ObjectNewMapping)
    object.__setattr__(forged, "_payload", payload)
    object.__setattr__(forged, "_legacy_integrity_mac", legacy_mac)
    require_accepts(
        validator,
        law,
        forged,
        **_candidate_validation_kwargs(
            inputs,
            document,
            authority_kwargs,
        ),
    )
    negative_kwargs = deepcopy(authority_kwargs)
    negative_kwargs["expected_release_id"] = "valid-but-different-release"
    require_rejects(
        validator,
        law,
        forged,
        **_candidate_validation_kwargs(
            inputs,
            document,
            negative_kwargs,
        ),
    )


def test_core_r5_permit_validator_has_no_process_local_secret_dependency() -> None:
    _assert_module_has_no_secret_authority(
        ENVIRONMENT_MODULE,
        ("validate_activation_permit_v1",),
    )


def test_core_r5_candidate_replay_has_no_process_local_secret_dependency() -> None:
    _assert_module_has_no_secret_authority(
        COMPOSER_MODULE,
        (
            "compose_program_facts_v2_production",
            "validate_production_composition_candidate",
        ),
    )


def test_core1_permit_rejects_expected_run_id_substitution() -> None:
    _reject_expected_substitution(
        "PF-CORE-1/permit-expected-run-id",
        "expected_run_id",
        "foreign-run",
    )


def test_core1_permit_rejects_expected_run_generation_substitution() -> None:
    _reject_expected_substitution(
        "PF-CORE-1/permit-expected-run-generation",
        "expected_run_generation",
        8,
    )


def test_core1_permit_rejects_execution_authority_substitution() -> None:
    _reject_expected_substitution(
        "PF-CORE-1/permit-execution-authority",
        "expected_execution_authority_digest",
        "f" * 64,
    )


def test_core1_permit_rejects_composition_authority_substitution() -> None:
    _reject_expected_substitution(
        "PF-CORE-1/permit-composition-authority",
        "expected_composition_authority_digest",
        "f" * 64,
    )


def test_core1_permit_rejects_methodology_authority_substitution() -> None:
    _reject_expected_substitution(
        "PF-CORE-1/permit-methodology-authority",
        "expected_methodology_package_digest",
        "f" * 64,
    )


def test_core1_permit_rejects_environment_authority_substitution() -> None:
    _reject_expected_substitution(
        "PF-CORE-1/permit-environment-authority",
        "expected_provider_environment_digest",
        "f" * 64,
    )


def test_core1_permit_rejects_package_authority_substitution() -> None:
    _reject_expected_substitution(
        "PF-CORE-1/permit-package-authority",
        "expected_provider_package_digest",
        "f" * 64,
    )


def test_core1_permit_rejects_native_host_authority_substitution() -> None:
    _reject_expected_substitution(
        "PF-CORE-1/permit-native-host-authority",
        "expected_native_host_receipt_digest",
        "f" * 64,
    )


def test_core1_permit_rejects_independent_review_substitution() -> None:
    reviews = permit_validation_kwargs()[
        "expected_independent_review_receipts"
    ]
    substituted = dict(reviews)
    substituted["B"] = "f" * 64
    _reject_expected_substitution(
        "PF-CORE-1/permit-independent-reviews",
        "expected_independent_review_receipts",
        substituted,
    )


def test_core1_permit_rejects_issuer_policy_substitution() -> None:
    _reject_expected_substitution(
        "PF-CORE-1/permit-issuer-policy",
        "expected_issuer_policy_digest",
        "f" * 64,
    )


def test_core1_permit_rejects_issuer_identity_substitution() -> None:
    _reject_expected_substitution(
        "PF-CORE-1/permit-issuer-identity",
        "expected_issuer_id",
        "foreign-issuer",
    )


def test_core1_permit_rejects_release_identity_substitution() -> None:
    _reject_expected_substitution(
        "PF-CORE-1/permit-release-identity",
        "expected_release_id",
        "foreign-release",
    )


def test_core1_permit_rejects_activation_decision_substitution() -> None:
    _reject_expected_substitution(
        "PF-CORE-1/permit-activation-decision",
        "expected_activation_decision_digest",
        "f" * 64,
    )


def test_core_r5_valid_but_different_raw_authority_set_rejected() -> None:
    law = "PF-R5-1/valid-but-different-raw-authority-set"
    (
        candidate,
        inputs,
        _document,
        _environment,
        _authority_kwargs,
        validator,
    ) = _production_candidate_vector(law)
    alternate_environment = linux_environment_document()
    alternate_environment["environment_digest"] = HE
    assert_schema_accepts("provider_environment", alternate_environment)
    alternate_document = linux_permit_document()
    alternate_document["provider_environment_digest"] = HE
    alternate_document["permit_digest"] = body_digest(
        alternate_document,
        "permit_digest",
    )
    assert_schema_accepts("activation_permit", alternate_document)
    permit_validator = require_callable(
        ENVIRONMENT_MODULE,
        "validate_activation_permit_v1",
        law,
    )
    alternate_kwargs = permit_validation_kwargs(
        alternate_document,
        provider_environment=alternate_environment,
    )
    require_accepts(
        permit_validator,
        law,
        alternate_document,
        **alternate_kwargs,
    )
    require_rejects(
        validator,
        law,
        candidate,
        **_candidate_validation_kwargs(
            inputs,
            alternate_document,
            alternate_kwargs,
        ),
    )


def test_core1_candidate_private_slot_mutation_rejected() -> None:
    _reject_candidate_mutation(
        "PF-CORE-1/candidate-private-slot-integrity",
        _replace_candidate_field("run_id", "mutated-run"),
    )


def test_core_r5_candidate_schema_version_mutation_rejected() -> None:
    _reject_candidate_mutation(
        "PF-R5-1/candidate-schema-version",
        _replace_candidate_field("schema_version", "foreign.schema.v1"),
    )


def test_core_r5_candidate_authority_class_mutation_rejected() -> None:
    _reject_candidate_mutation(
        "PF-R5-1/candidate-authority-class",
        _replace_candidate_field(
            "authority_class",
            "TEST_ONLY_NONAUTHORITATIVE",
        ),
    )


def test_core_r5_candidate_run_generation_mutation_rejected() -> None:
    _reject_candidate_mutation(
        "PF-R5-1/candidate-run-generation",
        _replace_candidate_field("run_generation", 8),
    )


def test_core_r5_candidate_permit_digest_mutation_rejected() -> None:
    _reject_candidate_mutation(
        "PF-R5-1/candidate-permit-digest",
        _replace_candidate_field("permit_digest", "f" * 64),
    )


def test_core_r5_candidate_permit_binding_digest_mutation_rejected() -> None:
    _reject_candidate_mutation(
        "PF-R5-1/candidate-permit-binding-digest",
        _replace_candidate_field("permit_binding_digest", "f" * 64),
    )


def test_core_r5_candidate_sealed_input_digest_mutation_rejected() -> None:
    _reject_candidate_mutation(
        "PF-R5-1/candidate-sealed-input-digest",
        _replace_candidate_field("sealed_input_digest", "f" * 64),
    )


def test_core1_candidate_artifact_byte_mutation_rejected() -> None:
    _reject_candidate_mutation(
        "PF-CORE-1/candidate-artifact-byte-integrity",
        _mutate_artifact(0, suffix=b"tampered"),
    )


def test_core_r5_candidate_receipt_artifact_byte_mutation_rejected() -> None:
    _reject_candidate_mutation(
        "PF-R5-1/candidate-receipt-artifact-byte",
        _mutate_artifact(1, suffix=b"tampered"),
    )


def test_core_r5_candidate_debt_artifact_byte_mutation_rejected() -> None:
    _reject_candidate_mutation(
        "PF-R5-1/candidate-debt-artifact-byte",
        _mutate_artifact(2, suffix=b"tampered"),
    )


def test_core_r5_candidate_artifact_identity_mutation_rejected() -> None:
    _reject_candidate_mutation(
        "PF-R5-1/candidate-artifact-identity",
        _mutate_artifact(0, identity="foreign-output.json"),
    )


def test_core_r5_candidate_artifact_order_mutation_rejected() -> None:
    def mutate(candidate: dict[str, Any]) -> None:
        artifacts = list(candidate["artifacts"])
        artifacts[0], artifacts[1] = artifacts[1], artifacts[0]
        candidate["artifacts"] = artifacts

    _reject_candidate_mutation(
        "PF-R5-1/candidate-artifact-order",
        mutate,
    )


def test_core_r5_candidate_duplicate_artifact_identity_rejected() -> None:
    def mutate(candidate: dict[str, Any]) -> None:
        artifacts = list(candidate["artifacts"])
        artifacts[1] = (artifacts[0][0], artifacts[1][1])
        candidate["artifacts"] = artifacts

    _reject_candidate_mutation(
        "PF-R5-1/candidate-duplicate-artifact-identity",
        mutate,
    )


def test_core1_candidate_digest_slot_mutation_rejected() -> None:
    _reject_candidate_mutation(
        "PF-CORE-1/candidate-digest-integrity",
        _replace_candidate_field("candidate_digest", "f" * 64),
    )


def test_core_r5_candidate_extra_top_level_key_rejected() -> None:
    def mutate(candidate: dict[str, Any]) -> None:
        candidate["unbound_extra"] = "must reject"

    _reject_candidate_mutation(
        "PF-R5-1/candidate-extra-top-level-key",
        mutate,
    )


def test_core_r5_candidate_each_missing_top_level_key_rejected() -> None:
    law = "PF-R5-1/candidate-each-missing-top-level-key"
    (
        candidate,
        inputs,
        document,
        _environment,
        authority_kwargs,
        validator,
    ) = _production_candidate_vector(law)
    complete = _candidate_mapping(candidate)
    for key in CANDIDATE_KEYS:
        missing = deepcopy(complete)
        missing.pop(key)
        require_rejects(
            validator,
            law,
            missing,
            **_candidate_validation_kwargs(
                inputs,
                document,
                authority_kwargs,
            ),
        )


def test_core_r5_aggregate_authority_graph_exact_replay_accepts() -> None:
    law = "PF-R5-1/aggregate-authority-graph-exact-replay"
    aggregate, kwargs = _aggregate_vector(law)
    result = require_accepts(aggregate, law, **kwargs)
    assert set(result) == set(AGGREGATE_RESULT_KEYS)
    assert result["accepted"] is True
    assert result["candidate_digest"] == kwargs["candidate"][
        "candidate_digest"
    ]


def test_core_r5_aggregate_authority_graph_candidate_mutation_rejected() -> None:
    law = "PF-R5-1/aggregate-authority-graph-candidate-mutation"
    aggregate, kwargs = _aggregate_vector(law)
    mutated = _candidate_mapping(kwargs["candidate"])
    mutated["run_generation"] = 8
    kwargs["candidate"] = mutated
    require_rejects(aggregate, law, **kwargs)


def test_core_r6_aggregate_whole_valid_different_execution_branch_rejected() -> None:
    law = "PF-R6-2/aggregate-whole-valid-different-execution-branch"
    aggregate, kwargs = _aggregate_vector(law)
    alternate = frozen_build_plan_document(
        ("variant-c",),
        run_id="valid-different-run",
        run_generation=9,
        execution_authority_digest="f" * 64,
    )
    _replace_complete_execution_branch(law, kwargs, alternate)
    require_rejects(aggregate, law, **kwargs)


def test_core_r6_aggregate_plan_run_id_cross_edge_rejected() -> None:
    law = "PF-R6-2/aggregate-plan-run-id-cross-edge"
    aggregate, kwargs = _aggregate_vector(law)
    alternate = frozen_build_plan_document(
        ("variant-a",),
        run_id="valid-different-run",
    )
    _replace_complete_execution_branch(law, kwargs, alternate)
    require_rejects(aggregate, law, **kwargs)


def test_core_r6_aggregate_plan_generation_cross_edge_rejected() -> None:
    law = "PF-R6-2/aggregate-plan-generation-cross-edge"
    aggregate, kwargs = _aggregate_vector(law)
    alternate = frozen_build_plan_document(
        ("variant-a",),
        run_generation=9,
    )
    _replace_complete_execution_branch(law, kwargs, alternate)
    require_rejects(aggregate, law, **kwargs)


def test_core_r6_aggregate_plan_execution_authority_cross_edge_rejected() -> None:
    law = "PF-R6-2/aggregate-plan-execution-authority-cross-edge"
    aggregate, kwargs = _aggregate_vector(law)
    alternate = frozen_build_plan_document(
        ("variant-a",),
        execution_authority_digest="f" * 64,
    )
    _replace_complete_execution_branch(law, kwargs, alternate)
    require_rejects(aggregate, law, **kwargs)


def test_core_r6_aggregate_candidate_plan_variant_denominator_mismatch_rejected() -> None:
    law = "PF-R6-2/aggregate-candidate-plan-variant-denominator"
    aggregate, kwargs = _aggregate_vector(law)
    alternate = frozen_build_plan_document(
        ("variant-a", "variant-b"),
    )
    _replace_complete_execution_branch(law, kwargs, alternate)
    require_rejects(aggregate, law, **kwargs)


def test_core_r6_aggregate_expected_build_plan_digest_edge_rejected() -> None:
    law = "PF-R6-2/aggregate-expected-build-plan-digest-edge"
    aggregate, kwargs = _aggregate_vector(law)
    kwargs["expected_build_plan_digest"] = "f" * 64
    require_rejects(aggregate, law, **kwargs)


def test_core_r6_aggregate_build_plan_ledger_binding_edge_rejected() -> None:
    law = "PF-R6-2/aggregate-build-plan-ledger-binding-edge"
    aggregate, kwargs = _aggregate_vector(law)
    kwargs["build_plan_ledger_binding"] = deepcopy(
        kwargs["build_plan_ledger_binding"]
    )
    kwargs["build_plan_ledger_binding"]["sha256"] = "f" * 64
    require_rejects(aggregate, law, **kwargs)


def test_core_r6_aggregate_expected_children_must_derive_from_same_plan() -> None:
    law = "PF-R6-2/aggregate-expected-children-same-plan"
    aggregate, kwargs = _aggregate_vector(law)
    alternate = frozen_build_plan_document(("variant-c",))
    expected, _roster, _ledger, _plan, _manifests, _expanded = (
        _expected_and_roster(law, plan_document=alternate)
    )
    kwargs["expected_children"] = expected
    require_rejects(aggregate, law, **kwargs)


def test_core_r6_aggregate_roster_must_derive_from_same_plan() -> None:
    law = "PF-R6-2/aggregate-roster-same-plan"
    aggregate, kwargs = _aggregate_vector(law)
    alternate = frozen_build_plan_document(("variant-c",))
    _expected, roster, _ledger, _plan, _manifests, _expanded = (
        _expected_and_roster(law, plan_document=alternate)
    )
    kwargs["terminal_roster"] = roster
    require_rejects(aggregate, law, **kwargs)


def test_core_r6_aggregate_manifests_must_derive_from_same_plan() -> None:
    law = "PF-R6-2/aggregate-manifests-same-plan"
    aggregate, kwargs = _aggregate_vector(law)
    alternate = frozen_build_plan_document(("variant-c",))
    _expected, _roster, _ledger, _plan, manifests, _expanded = (
        _expected_and_roster(law, plan_document=alternate)
    )
    kwargs["raw_cas_manifests"] = manifests
    require_rejects(aggregate, law, **kwargs)


def test_core_r6_aggregate_expanded_union_must_derive_from_same_plan() -> None:
    law = "PF-R6-2/aggregate-expanded-union-same-plan"
    aggregate, kwargs = _aggregate_vector(law)
    alternate = frozen_build_plan_document(("variant-c",))
    _expected, _roster, _ledger, _plan, _manifests, expanded = (
        _expected_and_roster(law, plan_document=alternate)
    )
    kwargs["expanded_inputs"] = expanded
    require_rejects(aggregate, law, **kwargs)


def test_core_r6_stateful_sealed_mapping_is_snapshotted_before_validation() -> None:
    law = "PF-R6-3/stateful-sealed-input-single-snapshot"
    composer = require_callable(
        COMPOSER_MODULE,
        "compose_program_facts_v2_production",
        law,
    )
    validator = require_callable(
        COMPOSER_MODULE,
        "validate_production_composition_candidate",
        law,
    )
    inputs = _sealed_inputs()
    _environment, document, authority_kwargs = _authority_vector()
    stateful_for_composer = _StatefulVariantMapping(
        inputs,
        stable_variant_reads=1,
        later_variants=["variant-b", "variant-a"],
    )
    candidate = require_accepts(
        composer,
        law,
        stateful_for_composer,
        document,
        **authority_kwargs,
    )
    assert _candidate_payload(candidate)["selected_variant_ids"] == [
        "variant-a"
    ]
    stateful_for_validator = _StatefulVariantMapping(
        inputs,
        stable_variant_reads=1,
        later_variants=["variant-b", "variant-a"],
    )
    validated = require_accepts(
        validator,
        law,
        candidate,
        **_candidate_validation_kwargs(
            stateful_for_validator,
            document,
            authority_kwargs,
        ),
    )
    assert _candidate_payload(validated)["selected_variant_ids"] == [
        "variant-a"
    ]


def test_core_r6_aggregate_reuses_one_sealed_snapshot_for_variant_edge() -> None:
    law = "PF-R6-3/aggregate-reuses-sealed-input-snapshot"
    aggregate, kwargs = _aggregate_vector(law)
    alternate = frozen_build_plan_document(("variant-b",))
    _replace_complete_execution_branch(law, kwargs, alternate)
    kwargs["sealed_composition_inputs"] = _StatefulVariantMapping(
        _sealed_inputs(),
        stable_variant_reads=2,
        later_variants=["variant-b"],
    )
    require_rejects(aggregate, law, **kwargs)
