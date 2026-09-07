"""Public, synthetic support for Program Facts contract tests.

This module contains only test data builders and assertion helpers.  It has no
implementation fallback or customer/target fixture data, and it is excluded
from the installed runtime authority.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import hmac
import importlib
import json
from pathlib import Path
import sys
from types import ModuleType
from typing import Any, Callable, Mapping

from jsonschema import Draft202012Validator
import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_ROOT = ROOT / "scripts"
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))
SCHEMA_ROOT = ROOT / "rules" / "schemas"
H0 = "0" * 64
H1 = "1" * 64
H2 = "2" * 64
H3 = "3" * 64
H4 = "4" * 64
H5 = "5" * 64
H6 = "6" * 64
H7 = "7" * 64
H8 = "8" * 64
H9 = "9" * 64
HA = "a" * 64
HB = "b" * 64
HC = "c" * 64
HD = "d" * 64
HE = "e" * 64
HF = "f" * 64

LINUX_PROVIDED_CAPABILITIES = [
    "PINNED_HELPER_RUNTIME_TOOL_EXECUTION_IDENTITY",
    "IMMUTABLE_ENUMERATED_FILESYSTEM_READ_ROOTS",
    "BOUNDED_ENUMERATED_WRITABLE_ROOTS",
    "SECRET_FREE_CLOSED_CHILD_ENVIRONMENT",
    "CLOSED_INHERITED_FILE_DESCRIPTOR_SET",
    "NO_NETWORK_NAMESPACE_ACCESS",
    "CGROUP_PROCESS_TREE_AND_RESOURCE_OWNERSHIP",
    "TERMINAL_CGROUP_POPULATION_ZERO_EVIDENCE",
]
LINUX_LIMITATIONS = [
    "SAME_UID_HOST_CONFIDENTIALITY_NOT_PROVIDED",
    "GENERAL_HOSTILE_HOST_ISOLATION_NOT_PROVIDED",
]
TERMINAL_ROLES = (
    "ATTEMPT_ARM",
    "ATTEMPT_COMPLETION",
    "ATTEMPT_DEBT",
    "RAW_CAS_MANIFEST",
)
PUBLIC_IDENTITIES = (
    "mechanical_program_facts.v2.json",
    "mechanical_program_facts_receipt.v2.json",
    "mechanical_program_facts_debt.v2.json",
)

SCHEMA_FILES = {
    "provider_environment": "program_facts_evm_provider_environment.v1.schema.json",
    "activation_permit": "program_facts_evm_activation_permit.v1.schema.json",
    "expected_children": "program_facts_evm_expected_wtx_children.v1.schema.json",
    "terminal_roster": "program_facts_evm_terminal_wtx_roster.v1.schema.json",
    "publication_arm": "program_facts_publication_arm.v1.schema.json",
    "public_generation": "program_facts_public_generation.v1.schema.json",
    "compatibility_delta": "program_facts_compatibility_delta.v1.schema.json",
}

_EXPECTED_REJECTION_SUBSTRINGS = {
    "R2.1-1/no-same-uid-confidentiality-claim": ("schema violation",),
    "R2.1-1/permit-cannot-upgrade-linux-limitation": ("schema violation",),
    "R2.1-1/policy-requiring-unprovided-capability-denies": (
        "explicitly not provided",
    ),
    "R2.1-1/limitation-does-not-waive-containment": (
        "mandatory Linux containment capability failed",
    ),
    "R2.1-2/roster-cannot-self-authorize-denominator": (
        "roster work unit was not predeclared",
    ),
    "R2.1-2/build-plan-child-id-cross-binding": (
        "selected variants and expected children are not a bijection",
    ),
    "R2.1-2/selected-variant-child-bijection": (
        "contains duplicate identities",
    ),
    "R2.1-2/terminal-cardinality-totality": (
        "terminal roster is not N-of-N",
    ),
    "R2.1-2/terminal-artifact-ledger-cross-binding": (
        "terminal ledger field",
        "roster terminal roles are not exact",
    ),
    "R2.1-2/terminal-producer-run-generation-attempt-binding": (
        "foreign-run terminal producer",
        "foreign-generation terminal producer",
        "terminal attempt identity diverges",
    ),
    "R2.1-2/execution-capture-requires-active-roster": (
        "terminal roster is not ACTIVE",
    ),
    "R2.1-2/b3-manifest-expansion-precedes-b4": (
        "B3 manifest expansion is not accepted",
    ),
    "R2.1-2/c2-reuses-b3-manifest-expansion-semantics": (
        "C2 redefined B3 manifest-expansion semantics",
    ),
    "R2.1-2/manifest-expansion-drift-invalidates-b4": (
        "stale after semantics drift",
    ),
    "R2.1-2/execution-set-exact-expanded-input-denominator": (
        "ledger denominator contains unplanned outputs",
    ),
    "R2.1-3/production-rejects-test-capability": (
        "activation permit must be a mapping",
        "activation permit schema violation",
    ),
    "R2.1-3/test-authority-rejected-at-all-production-boundaries": (
        "candidate keys mismatch",
        "candidate authority_class diverges",
        "TEST_ONLY_NONAUTHORITATIVE",
    ),
    "R2.1-3/no-test-to-production-adoption": (
        "candidate must be a mapping",
        "candidate keys mismatch",
    ),
    "R2.1-4/generation-manifest-full-file-binding": (
        "root field 'composition_authority_digest' diverges",
    ),
    "R2.1-4/arm-body-and-file-binding": (
        "selection arm body digest diverges",
        "publication arm digest binding mismatch",
    ),
    "R2.1-4/expected-path-is-not-authority": (
        "publication arm digest binding mismatch",
    ),
    "R2.1-4/selection-requires-complete-private-evidence": (
        "keys mismatch",
    ),
    "R2.1-4/loader-no-directory-discovery": (
        "ACTIVE selection is required",
    ),
    "R2.1-4/same-generation-divergence-blocks": (
        "same generation ID has divergent manifest bytes",
    ),
    "R2.1-4/private-evidence-not-logical-output": (
        "exactly three outputs",
    ),
    "R2.1-4/atomic-selection-replays-arm-manifest-and-three-outputs": (
        "digest",
        "size",
        "binding",
        "tamper",
    ),
    "R2.1-5/no-wildcard-glob-or-directory-allowance": (
        "schema violation",
        "glob syntax",
        "file, not a directory",
    ),
    "R2.1-5/exact-bijection-between-deltas-and-allowances": (
        "denominators are not a bijection",
        "duplicated or aliased",
    ),
    "R2.1-5/no-unexplained-legacy-public-delta": (
        "legacy public Program Facts bytes cannot change",
    ),
    "R2.1-5/same-postimage-disabled-shadow-byte-parity": (
        "same-postimage bytes differ",
    ),
    "R2.1-5/exact-pre-r2-boundary-authority": (
        "wrong pre-R2 boundary manifest",
    ),
    "R2.1-5/manifest-row-path-size-digest-replay": (
        "receipt deltas do not equal the full manifest path union",
        "delta path/size/digest does not replay",
    ),
    "R2.1-5/no-semantic-disguise-as-methodology-churn": (
        "finding/report semantics cannot hide",
    ),
    "R2.1-5/provisional-cannot-claim-final": (
        "provisional runtime closure cannot support a final receipt",
    ),
    "R2.1-5/compatibility-receipt-out-of-band-no-cycle": (
        "entered the authority it compares",
    ),
    "R2.1-5/later-runtime-change-invalidates-final-receipt": (
        "later runtime change invalidates",
    ),
    "PF-CORE-1/exact-shape-forged-permit-mapping": (
        "ValidatedProductionPermit",
        "typed validated permit",
    ),
    "PF-CORE-1/permit-expected-run-id": ("permit run_id diverges",),
    "PF-CORE-1/permit-expected-run-generation": (
        "permit run_generation diverges",
    ),
    "PF-CORE-1/permit-execution-authority": (
        "permit execution authority diverges",
    ),
    "PF-CORE-1/permit-composition-authority": (
        "permit composition authority diverges",
    ),
    "PF-CORE-1/permit-methodology-authority": (
        "permit methodology package diverges",
    ),
    "PF-CORE-1/permit-environment-authority": (
        "permit provider environment diverges",
    ),
    "PF-CORE-1/permit-package-authority": (
        "permit provider package diverges",
    ),
    "PF-CORE-1/permit-native-host-authority": (
        "permit native host receipt diverges",
    ),
    "PF-CORE-1/permit-independent-reviews": (
        "permit independent review receipts diverge",
    ),
    "PF-CORE-1/permit-issuer-policy": (
        "permit issuer policy diverges",
    ),
    "PF-CORE-1/permit-issuer-identity": ("permit issuer_id diverges",),
    "PF-CORE-1/permit-release-identity": ("permit release_id diverges",),
    "PF-CORE-1/permit-activation-decision": (
        "permit activation decision diverges",
    ),
    "PF-CORE-1/candidate-private-slot-integrity": (
        "candidate run_id diverges",
    ),
    "PF-CORE-1/candidate-artifact-byte-integrity": (
        "candidate artifacts diverge",
    ),
    "PF-CORE-1/candidate-digest-integrity": (
        "candidate candidate_digest diverges",
    ),
    "PF-CORE-1/direct-constructor-arbitrary-token": (
        "constructor",
        "private",
    ),
    "PF-CORE-1/constructor-token-not-module-recoverable": (
        "candidate integrity",
        "constructor",
    ),
    "PF-R5-1/closure-key-and-object-new-are-nonauthoritative": (
        "permit release_id diverges",
    ),
    "PF-R5-1/valid-but-different-raw-authority-set": (
        "candidate permit binding digest diverges",
        "candidate permit digest diverges",
    ),
    "PF-R5-1/candidate-schema-version": (
        "candidate schema_version diverges",
        "candidate keys mismatch",
    ),
    "PF-R5-1/candidate-authority-class": (
        "candidate authority_class diverges",
    ),
    "PF-R5-1/candidate-run-generation": (
        "candidate run_generation diverges",
    ),
    "PF-R5-1/candidate-permit-digest": (
        "candidate permit_digest diverges",
    ),
    "PF-R5-1/candidate-permit-binding-digest": (
        "candidate permit_binding_digest diverges",
    ),
    "PF-R5-1/candidate-sealed-input-digest": (
        "candidate sealed_input_digest diverges",
    ),
    "PF-R5-1/candidate-receipt-artifact-byte": (
        "candidate artifacts diverge",
    ),
    "PF-R5-1/candidate-debt-artifact-byte": (
        "candidate artifacts diverge",
    ),
    "PF-R5-1/candidate-artifact-identity": (
        "candidate artifacts diverge",
    ),
    "PF-R5-1/candidate-artifact-order": (
        "candidate artifacts diverge",
    ),
    "PF-R5-1/candidate-duplicate-artifact-identity": (
        "candidate artifacts diverge",
    ),
    "PF-R5-1/candidate-extra-top-level-key": (
        "candidate keys mismatch",
    ),
    "PF-R5-1/candidate-each-missing-top-level-key": (
        "candidate keys mismatch",
    ),
    "PF-R5-1/aggregate-authority-graph-candidate-mutation": (
        "candidate run_generation diverges",
    ),
    "PF-R6-1/plan-key-and-object-new-are-nonauthoritative": (
        "build-plan digest diverges from expected authority",
    ),
    "PF-R6-1/expected-build-plan-digest": (
        "build-plan digest diverges from expected authority",
    ),
    "PF-R6-1/build-plan-ledger-binding-fields": (
        "build-plan ledger binding",
    ),
    "PF-R6-1/build-plan-ledger-binding-exact-shape": (
        "build-plan ledger binding keys mismatch",
    ),
    "PF-R6-2/aggregate-whole-valid-different-execution-branch": (
        "execution plan run_id diverges",
        "execution plan generation diverges",
        "execution plan authority diverges",
    ),
    "PF-R6-2/aggregate-plan-run-id-cross-edge": (
        "execution plan run_id diverges",
    ),
    "PF-R6-2/aggregate-plan-generation-cross-edge": (
        "execution plan generation diverges",
    ),
    "PF-R6-2/aggregate-plan-execution-authority-cross-edge": (
        "execution plan authority diverges",
    ),
    "PF-R6-2/aggregate-candidate-plan-variant-denominator": (
        "execution and candidate variant denominators diverge",
    ),
    "PF-R6-2/aggregate-expected-build-plan-digest-edge": (
        "build-plan digest diverges from expected authority",
    ),
    "PF-R6-2/aggregate-build-plan-ledger-binding-edge": (
        "build-plan ledger binding",
    ),
    "PF-R6-2/aggregate-expected-children-same-plan": (
        "selected variants and expected children are not a bijection",
    ),
    "PF-R6-2/aggregate-roster-same-plan": (
        "terminal roster",
        "roster",
    ),
    "PF-R6-2/aggregate-manifests-same-plan": (
        "raw CAS manifest",
        "manifest",
    ),
    "PF-R6-2/aggregate-expanded-union-same-plan": (
        "ledger denominator",
        "expanded",
    ),
    "PF-R6-3/aggregate-reuses-sealed-input-snapshot": (
        "execution and candidate variant denominators diverge",
    ),
    "PF-CORE-2/one-family-rederived-identity": (
        "expected-child derivation diverges",
    ),
    "PF-CORE-2/all-families-rederived-identity": (
        "expected-child derivation diverges",
    ),
    "PF-CORE-2/variant-and-plan-digest-substitution": (
        "expected-child derivation diverges",
    ),
    "PF-CORE-2/build-plan-body-self-digest": (
        "build plan digest does not replay",
    ),
    "PF-CORE-3/missing-manifested-raw-cas-leaf": (
        "raw CAS leaf denominator",
    ),
    "PF-CORE-3/swapped-raw-cas-manifest-binding": (
        "source manifest",
        "raw CAS leaf denominator",
    ),
    "PF-CORE-3/foreign-raw-cas-leaf-authority": (
        "foreign-run raw CAS leaf",
        "raw CAS leaf denominator",
    ),
    "PF-CORE-4/missing-prior-active-prestate": ("prior_active",),
    "PF-CORE-4/divergent-prior-active-prestate": (
        "prior ACTIVE prestate diverges",
    ),
    "PF-CORE-4/underived-generation-id": (
        "derived generation_id diverges",
    ),
    "PF-CORE-4/underived-transaction-id": (
        "derived transaction_id diverges",
    ),
    "PF-CORE-4/dot-segment-id": (
        "schema violation",
        "portable publication identifier",
    ),
    "PF-CORE-4/slash-id": (
        "schema violation",
        "portable publication identifier",
    ),
    "PF-CORE-4/backslash-id": (
        "schema violation",
        "portable publication identifier",
    ),
    "PF-CORE-4/colon-ads-id": (
        "schema violation",
        "portable publication identifier",
    ),
    "PF-CORE-4/case-alias-id": (
        "derived generation_id diverges",
        "portable publication identifier",
    ),
    "PF-CORE-4/long-path-id": (
        "schema violation",
        "portable publication identifier",
    ),
    "PF-CORE-4/preimage-change-invalidates-derived-ids": (
        "derived generation_id diverges",
    ),
    "PF-CORE-5/reduced-bound-manifest": (
        "manifest binding",
        "manifest bytes",
    ),
    "PF-CORE-5/forged-comparator-equality": (
        "comparator",
        "compared output",
    ),
    "PF-CORE-5/semantic-review-mandatory": ("semantic review",),
    "PF-CORE-5/arbitrary-rule-mislabeled-methodology": (
        "semantic disguise",
        "protected runtime path",
        "component registry",
    ),
    "PF-CORE-5/arbitrary-script-mislabeled-toolchain": (
        "semantic disguise",
        "protected runtime path",
        "component registry",
    ),
    "PF-CORE-5/execution-exclusion-denominator-mandatory": (
        "execution_authority_paths",
        "exclusion authority",
    ),
    "PF-CORE-5/composition-exclusion-denominator-mandatory": (
        "composition_authority_paths",
        "exclusion authority",
    ),
    "PF-CORE-5/runtime-exclusion-denominator-mandatory": (
        "compared_runtime_manifest_paths",
        "exclusion authority",
    ),
    "PF-CORE-5/missing-trusted-review-key": ("trusted review key",),
    "PF-CORE-5/wrong-trusted-review-key": (
        "authority HMAC",
        "trusted review key",
    ),
    "PF-R3-1/recovered-permit-mint-bypass": (
        "raw mint capability",
        "typed validated permit",
        "ValidatedProductionPermit",
    ),
    "PF-R3-1/recovered-candidate-mint-bypass": (
        "raw mint capability",
        "production candidate",
        "candidate integrity",
    ),
    "PF-R3-2/exact-raw-cas-physical-path-alias": (
        "raw CAS physical path alias",
    ),
    "PF-R3-2/casefold-raw-cas-physical-path-alias": (
        "raw CAS physical path alias",
    ),
    "PF-R3-2/cross-namespace-raw-cas-physical-path-alias": (
        "raw CAS physical path alias",
    ),
    "PF-R3-3/phase-io-substring-lookalike": (
        "component registry",
    ),
    "PF-R3-3/artifact-ledger-substring-lookalike": (
        "component registry",
    ),
    "PF-R3-3/registered-path-case-alias": (
        "component registry",
        "case-fold",
    ),
}


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def body_digest(value: Mapping[str, Any], digest_field: str) -> str:
    payload = dict(value)
    payload.pop(digest_field, None)
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


def load_schema(name: str) -> dict[str, Any]:
    path = SCHEMA_ROOT / SCHEMA_FILES[name]
    assert path.is_file(), f"B0 schema fixture missing: {path}"
    value = json.loads(path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(value)
    return value


def schema_errors(name: str, document: Mapping[str, Any]) -> list[Any]:
    return list(Draft202012Validator(load_schema(name)).iter_errors(document))


def assert_schema_accepts(name: str, document: Mapping[str, Any]) -> None:
    errors = schema_errors(name, document)
    assert not errors, f"{name} fixture is not schema-valid: {errors}"


def assert_schema_rejects(name: str, document: Mapping[str, Any]) -> None:
    errors = schema_errors(name, document)
    assert errors, f"{name} schema accepted the intended invalid mutation"


def require_module(module_name: str, law_id: str) -> ModuleType:
    try:
        return importlib.import_module(module_name)
    except (ImportError, ModuleNotFoundError) as exc:
        pytest.fail(
            f"R21_B0_RED[{law_id}]: planned production module "
            f"{module_name!r} is absent ({exc.__class__.__name__})",
            pytrace=False,
        )


def require_callable(module_name: str, callable_name: str, law_id: str) -> Callable[..., Any]:
    module = require_module(module_name, law_id)
    candidate = getattr(module, callable_name, None)
    if not callable(candidate):
        pytest.fail(
            f"R21_B0_RED[{law_id}]: planned production callable "
            f"{module_name}.{callable_name} is absent",
            pytrace=False,
        )
    return candidate


def require_rejects(
    callable_: Callable[..., Any],
    law_id: str,
    *args: Any,
    **kwargs: Any,
) -> None:
    try:
        result = callable_(*args, **kwargs)
    except Exception as exc:
        require_expected_rejection_exception(law_id, exc)
        return
    rejected = result is False
    if isinstance(result, Mapping):
        rejected = rejected or result.get("accepted") is False
        rejected = rejected or result.get("state") in {"DENIED", "REJECTED", "INVALID"}
    assert rejected, f"R21_B0_RED[{law_id}]: invalid authority was accepted"


def require_expected_rejection_exception(
    law_id: str,
    exc: Exception,
) -> None:
    expected = _EXPECTED_REJECTION_SUBSTRINGS.get(law_id)
    if expected and not any(fragment in str(exc) for fragment in expected):
        pytest.fail(
            f"R21_B0_RED[{law_id}]: rejected for the wrong reason: "
            f"{exc.__class__.__name__}: {exc}; expected one of {expected!r}",
            pytrace=False,
        )


def require_accepts(
    callable_: Callable[..., Any],
    law_id: str,
    *args: Any,
    **kwargs: Any,
) -> Any:
    try:
        result = callable_(*args, **kwargs)
    except Exception as exc:
        pytest.fail(
            f"R21_B0_RED[{law_id}]: valid authority was rejected: "
            f"{exc.__class__.__name__}: {exc}",
            pytrace=False,
        )
    if result is False:
        pytest.fail(
            f"R21_B0_RED[{law_id}]: valid authority returned rejection",
            pytrace=False,
        )
    if isinstance(result, Mapping):
        assert result.get("accepted", True) is not False
        assert result.get("state") not in {"DENIED", "REJECTED", "INVALID"}
    return result


def linux_environment_document() -> dict[str, Any]:
    return {
        "schema_version": "plamen.program_facts_evm_provider_environment.v1",
        "environment_digest": H0,
        "sandbox_receipt_digest": H1,
        "platform": "LINUX",
        "linux_boundary": {
            "boundary_profile": "LINUX_PROVIDER_BOUNDARY_V1",
            "provided_capabilities": list(LINUX_PROVIDED_CAPABILITIES),
            "limitations": list(LINUX_LIMITATIONS),
            "same_uid_host_confidentiality_claim": False,
        },
    }


def linux_permit_document(
    *,
    run_id: str = "fixture-run",
    run_generation: int = 7,
    required_capabilities: list[str] | None = None,
) -> dict[str, Any]:
    document = {
        "schema_version": "plamen.program_facts_evm_activation_permit.v1",
        "release_id": "fixture-release",
        "issuer_id": "fixture-release-authority",
        "run_id": run_id,
        "run_generation": run_generation,
        "execution_authority_digest": H2,
        "composition_authority_digest": H3,
        "methodology_package_digest": H4,
        "provider_environment_digest": H0,
        "provider_package_digest": H6,
        "native_host_receipt_digest": H7,
        "independent_review_receipts": [
            {"role": "B", "sha256": H8},
            {"role": "C", "sha256": H9},
            {"role": "NATIVE_HOST", "sha256": HA},
            {"role": "PACKAGE", "sha256": HB},
        ],
        "issuer_policy_digest": HC,
        "activation_decision_digest": HD,
        "platform_capability": {
            "os": "LINUX",
            "architecture": "AMD64",
            "filesystem_class": "fixture-fs",
            "sandbox_environment_receipt_digest": H1,
            "boundary_profile": "LINUX_PROVIDER_BOUNDARY_V1",
            "provided_capabilities": list(LINUX_PROVIDED_CAPABILITIES),
            "limitations": list(LINUX_LIMITATIONS),
            "same_uid_host_confidentiality_claim": False,
            "required_capabilities": list(
                required_capabilities
                if required_capabilities is not None
                else LINUX_PROVIDED_CAPABILITIES
            ),
        },
        "permit_digest": H5,
    }
    document["permit_digest"] = body_digest(document, "permit_digest")
    return document


def permit_validation_kwargs(
    document: Mapping[str, Any] | None = None,
    *,
    provider_environment: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    permit = dict(document or linux_permit_document())
    environment = dict(provider_environment or linux_environment_document())
    return {
        "expected_run_id": permit["run_id"],
        "expected_run_generation": permit["run_generation"],
        "expected_execution_authority_digest": permit[
            "execution_authority_digest"
        ],
        "expected_composition_authority_digest": permit[
            "composition_authority_digest"
        ],
        "expected_methodology_package_digest": permit[
            "methodology_package_digest"
        ],
        "expected_provider_environment_digest": permit[
            "provider_environment_digest"
        ],
        "expected_provider_package_digest": permit[
            "provider_package_digest"
        ],
        "expected_native_host_receipt_digest": permit[
            "native_host_receipt_digest"
        ],
        "expected_independent_review_receipts": {
            row["role"]: row["sha256"]
            for row in permit["independent_review_receipts"]
        },
        "expected_issuer_policy_digest": permit["issuer_policy_digest"],
        "expected_issuer_id": permit["issuer_id"],
        "expected_release_id": permit["release_id"],
        "expected_activation_decision_digest": permit[
            "activation_decision_digest"
        ],
        "provider_environment": environment,
    }


def frozen_build_plan_document(
    variants: tuple[str, ...] = ("variant-a", "variant-b"),
    *,
    run_id: str = "fixture-run",
    run_generation: int = 7,
    execution_authority_digest: str = H2,
) -> dict[str, Any]:
    document = {
        "schema_version": "plamen.program_facts_evm_frozen_build_plan.v1",
        "run_id": run_id,
        "run_generation": run_generation,
        "execution_authority_digest": execution_authority_digest,
        "selected_variant_ids": sorted(variants),
        "build_plan_digest": H0,
    }
    document["build_plan_digest"] = body_digest(document, "build_plan_digest")
    return document


def build_plan_ledger_binding(
    document: Mapping[str, Any],
) -> dict[str, Any]:
    raw = canonical_bytes(document) + b"\n"
    return {
        "ledger_state": "ACTIVE",
        "path": "_program_facts_inputs/evm_frozen_build_plan.v1.json",
        "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def build_plan_validation_kwargs(
    document: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "expected_build_plan_digest": document["build_plan_digest"],
        "build_plan_ledger_binding": build_plan_ledger_binding(document),
    }


def _fixture_tagged_identity(tag: str, binding: Mapping[str, Any]) -> str:
    digest = hashlib.sha256(
        canonical_bytes({"tag": tag, **dict(binding)})
    ).hexdigest()
    return f"{tag}-{digest[:24]}"


def expected_children_document(
    variants: tuple[str, ...] = ("variant-a", "variant-b"),
    *,
    build_plan: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    plan = dict(build_plan or frozen_build_plan_document(variants))
    rows: list[dict[str, Any]] = []
    for variant in plan["selected_variant_ids"]:
        common = {
            "run_id": plan["run_id"],
            "run_generation": plan["run_generation"],
            "execution_authority_digest": plan[
                "execution_authority_digest"
            ],
            "build_plan_digest": plan["build_plan_digest"],
            "selected_variant_id": variant,
        }
        work_unit = _fixture_tagged_identity("program-facts-wtx", common)
        attempt = _fixture_tagged_identity(
            "attempt",
            {**common, "work_unit_id": work_unit},
        )
        rows.append(
            {
                "selected_variant_id": variant,
                "expected_work_unit_id": work_unit,
                "expected_attempt_identity": attempt,
                "terminal_artifacts": [
                    {
                        "logical_role": role,
                        "producer_output_identity": _fixture_tagged_identity(
                            "output",
                            {
                                **common,
                                "work_unit_id": work_unit,
                                "attempt_identity": attempt,
                                "logical_role": role,
                            },
                        ),
                        "expected_relative_path": (
                            f"_worker_transactions/{attempt}/{role.lower()}.json"
                        ),
                    }
                    for role in TERMINAL_ROLES
                ],
            }
        )
    document = {
        "schema_version": "plamen.program_facts_evm_expected_wtx_children.v1",
        "run_id": plan["run_id"],
        "run_generation": plan["run_generation"],
        "execution_authority_digest": plan["execution_authority_digest"],
        "build_plan_digest": plan["build_plan_digest"],
        "expected_child_count": len(rows),
        "expected_wtx_children": rows,
        "children_body_sha256": H0,
    }
    document["children_body_sha256"] = body_digest(document, "children_body_sha256")
    return document


def ledger_rows_for(expected: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for child in expected["expected_wtx_children"]:
        for artifact in child["terminal_artifacts"]:
            content = canonical_bytes(
                {
                    "run_id": expected["run_id"],
                    "run_generation": expected["run_generation"],
                    "work_unit_id": child["expected_work_unit_id"],
                    "attempt_identity": child["expected_attempt_identity"],
                    "semantic_role": artifact["logical_role"],
                }
            )
            rows.append(
                {
                    "run_id": expected["run_id"],
                    "run_generation": expected["run_generation"],
                    "producer_work_unit_id": child["expected_work_unit_id"],
                    "producer_attempt_identity": child["expected_attempt_identity"],
                    "producer_output_identity": artifact["producer_output_identity"],
                    "semantic_role": artifact["logical_role"],
                    "physical_path": artifact["expected_relative_path"],
                    "size": len(content),
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "ledger_output_row_digest": hashlib.sha256(
                        b"ledger:" + content
                    ).hexdigest(),
                    "terminal": True,
                }
            )
    return rows


def raw_cas_manifest_document(
    *,
    expected: Mapping[str, Any],
    child: Mapping[str, Any],
    manifest_output_identity: str,
    leaves: list[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    rows = sorted(
        [dict(row) for row in (leaves or [])],
        key=lambda row: (
            str(row["namespace"]).casefold(),
            str(row["cas_leaf_id"]).casefold(),
        ),
    )
    namespace = (
        str(rows[0]["namespace"])
        if rows
        else "program-facts-raw-cas-v1"
    )
    document = {
        "schema_version": "plamen.program_facts_evm_raw_cas_manifest.v1",
        "run_id": expected["run_id"],
        "run_generation": expected["run_generation"],
        "producer_work_unit_id": child["expected_work_unit_id"],
        "producer_attempt_identity": child["expected_attempt_identity"],
        "producer_output_identity": manifest_output_identity,
        "namespace": namespace,
        "leaves": rows,
        "manifest_body_sha256": H0,
    }
    document["manifest_body_sha256"] = body_digest(
        document, "manifest_body_sha256"
    )
    return document


def execution_input_material(
    expected: Mapping[str, Any],
    ledger_rows: list[dict[str, Any]],
    *,
    leaves_by_manifest: Mapping[str, list[Mapping[str, Any]]] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, bytes], list[dict[str, Any]]]:
    """Return terminal rows, authenticated manifest bytes, and exact union."""

    terminal_rows = deepcopy(ledger_rows)
    configured = dict(leaves_by_manifest or {})
    raw_manifests: dict[str, bytes] = {}
    raw_leaf_rows: list[dict[str, Any]] = []
    child_by_output: dict[str, Mapping[str, Any]] = {}
    for child in expected["expected_wtx_children"]:
        for artifact in child["terminal_artifacts"]:
            if artifact["logical_role"] == "RAW_CAS_MANIFEST":
                child_by_output[artifact["producer_output_identity"]] = child
    for manifest_output, child in child_by_output.items():
        leaves = configured.get(manifest_output, [])
        document = raw_cas_manifest_document(
            expected=expected,
            child=child,
            manifest_output_identity=manifest_output,
            leaves=leaves,
        )
        content = canonical_bytes(document) + b"\n"
        raw_manifests[manifest_output] = content
        terminal_row = next(
            row
            for row in terminal_rows
            if row["producer_output_identity"] == manifest_output
        )
        terminal_row["size"] = len(content)
        terminal_row["sha256"] = hashlib.sha256(content).hexdigest()
        terminal_row["ledger_output_row_digest"] = hashlib.sha256(
            b"ledger:" + content
        ).hexdigest()
        for leaf in document["leaves"]:
            raw_leaf_rows.append(
                {
                    "run_id": expected["run_id"],
                    "run_generation": expected["run_generation"],
                    "producer_work_unit_id": child["expected_work_unit_id"],
                    "producer_attempt_identity": child[
                        "expected_attempt_identity"
                    ],
                    "producer_output_identity": leaf["cas_leaf_id"],
                    "source_manifest_output_identity": manifest_output,
                    "semantic_role": "RAW_CAS_LEAF",
                    "namespace": leaf["namespace"],
                    "cas_leaf_id": leaf["cas_leaf_id"],
                    "physical_path": leaf["physical_path"],
                    "size": leaf["size"],
                    "sha256": leaf["sha256"],
                    "terminal": False,
                }
            )
    raw_leaf_rows.sort(
        key=lambda row: (
            row["namespace"].casefold(),
            row["cas_leaf_id"].casefold(),
        )
    )
    return terminal_rows, raw_manifests, [*terminal_rows, *raw_leaf_rows]


def raw_cas_leaf(
    *,
    cas_leaf_id: str,
    physical_path: str,
    namespace: str = "program-facts-raw-cas-v1",
    size: int = 17,
    sha256: str = HE,
) -> dict[str, Any]:
    return {
        "namespace": namespace,
        "cas_leaf_id": cas_leaf_id,
        "physical_path": physical_path,
        "size": size,
        "sha256": sha256,
    }


def one_raw_cas_leaf() -> dict[str, Any]:
    return raw_cas_leaf(
        cas_leaf_id="cas-leaf-fixture-a",
        physical_path=(
            "_program_facts_private_cas/cas-leaf-fixture-a.pfcas"
        ),
    )


def terminal_roster_document(
    expected: Mapping[str, Any] | None = None,
    ledger_rows: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    expected = deepcopy(expected or expected_children_document())
    ledger_rows = deepcopy(ledger_rows or ledger_rows_for(expected))
    ledger_by_output = {
        row["producer_output_identity"]: row for row in ledger_rows
    }
    rows = []
    for child in expected["expected_wtx_children"]:
        artifacts = []
        for planned in child["terminal_artifacts"]:
            observed = ledger_by_output[planned["producer_output_identity"]]
            artifacts.append(
                {
                    "semantic_role": observed["semantic_role"],
                    "producer_output_identity": observed["producer_output_identity"],
                    "physical_path": observed["physical_path"],
                    "size": observed["size"],
                    "sha256": observed["sha256"],
                    "ledger_output_row_digest": observed[
                        "ledger_output_row_digest"
                    ],
                }
            )
        rows.append(
            {
                "selected_variant_id": child["selected_variant_id"],
                "producer_work_unit_id": child["expected_work_unit_id"],
                "producer_attempt_identity": child["expected_attempt_identity"],
                "terminal_artifacts": artifacts,
            }
        )
    document = {
        "schema_version": "plamen.program_facts_evm_terminal_wtx_roster.v1",
        "run_id": expected["run_id"],
        "run_generation": expected["run_generation"],
        "execution_authority_digest": expected["execution_authority_digest"],
        "build_plan_digest": expected["build_plan_digest"],
        "expected_wtx_children_digest": expected["children_body_sha256"],
        "expected_child_count": expected["expected_child_count"],
        "terminal_child_count": len(rows),
        "rows": rows,
        "roster_body_sha256": H0,
    }
    document["roster_body_sha256"] = body_digest(document, "roster_body_sha256")
    return document


def logical_output_bytes() -> dict[str, bytes]:
    return {
        PUBLIC_IDENTITIES[0]: b'{"schema_version":"plamen.mechanical_program_facts.v2"}\n',
        PUBLIC_IDENTITIES[1]: (
            b'{"schema_version":"plamen.mechanical_program_facts_receipt.v2"}\n'
        ),
        PUBLIC_IDENTITIES[2]: (
            b'{"schema_version":"plamen.mechanical_program_facts_debt.v2"}\n'
        ),
    }


def publication_identity_preimage(
    *,
    prior_active: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "run_id": "fixture-run",
        "run_generation": 7,
        "transaction_nonce": "nonce-fixture",
        "phase": "recon",
        "work_unit_id": "program_facts_bake_v2",
        "contract_digest": H1,
        "launch_digest": H2,
        "expanded_input_set_digest": H3,
        "composition_authority_digest": H4,
        "prior_active": deepcopy(prior_active or {"state": "ABSENT"}),
    }


def publication_arm_document(
    outputs: Mapping[str, bytes] | None = None,
    *,
    prior_active: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    from program_facts_publication import (
        derive_program_facts_publication_identities_v1,
    )

    outputs = outputs or logical_output_bytes()
    preimage = publication_identity_preimage(prior_active=prior_active)
    identities = derive_program_facts_publication_identities_v1(preimage)
    rows = []
    for identity in PUBLIC_IDENTITIES:
        content = outputs[identity]
        rows.append(
            {
                "logical_identity": identity,
                "candidate_relative_path": identity,
                "expected_size": len(content),
                "expected_sha256": hashlib.sha256(content).hexdigest(),
            }
        )
    document = {
        "schema_version": "plamen.program_facts_publication_arm.v1",
        **preimage,
        "transaction_id": identities["transaction_id"],
        "generation_id": identities["generation_id"],
        "logical_outputs": rows,
        "durability_requirement": "PROCESS_CRASH_ATOMIC",
        "lock_order": [
            "GLOBAL_RUN",
            "PROGRAM_FACTS_PUBLICATION",
            "ARTIFACT_LEDGER",
        ],
        "arm_body_sha256": H0,
    }
    document["arm_body_sha256"] = body_digest(document, "arm_body_sha256")
    return document


def public_generation_document(
    outputs: Mapping[str, bytes] | None = None,
    *,
    arm: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    outputs = outputs or logical_output_bytes()
    arm = arm or publication_arm_document(outputs)
    rows = []
    for identity in PUBLIC_IDENTITIES:
        content = outputs[identity]
        rows.append(
            {
                "logical_identity": identity,
                "physical_relative_path": identity,
                "size": len(content),
                "full_file_sha256": hashlib.sha256(content).hexdigest(),
            }
        )
    document = {
        "schema_version": "plamen.program_facts_public_generation.v1",
        "run_id": arm["run_id"],
        "run_generation": arm["run_generation"],
        "generation_id": arm["generation_id"],
        "transaction_id": arm["transaction_id"],
        "composition_authority_digest": arm["composition_authority_digest"],
        "logical_outputs": rows,
        "manifest_body_sha256": H0,
    }
    document["manifest_body_sha256"] = body_digest(
        document, "manifest_body_sha256"
    )
    return document


def publication_selection_document(
    arm: Mapping[str, Any] | None = None,
    generation: Mapping[str, Any] | None = None,
    outputs: Mapping[str, bytes] | None = None,
) -> dict[str, Any]:
    arm = deepcopy(arm or publication_arm_document(outputs))
    generation = deepcopy(
        generation or public_generation_document(outputs, arm=arm)
    )
    outputs = outputs or logical_output_bytes()
    arm_bytes = canonical_bytes(arm) + b"\n"
    generation_bytes = canonical_bytes(generation) + b"\n"
    return {
        "run_id": arm["run_id"],
        "run_generation": arm["run_generation"],
        "phase": arm["phase"],
        "work_unit_id": arm["work_unit_id"],
        "contract_digest": arm["contract_digest"],
        "launch_digest": arm["launch_digest"],
        "expanded_input_set_digest": arm["expanded_input_set_digest"],
        "composition_authority_digest": arm["composition_authority_digest"],
        "generation_id": arm["generation_id"],
        "prior_active": deepcopy(arm["prior_active"]),
        "generation_manifest": {
            "physical_path": (
                f".program_facts_public_generations/{arm['generation_id']}/"
                "generation_manifest.v1.json"
            ),
            "size": len(generation_bytes),
            "full_file_sha256": hashlib.sha256(generation_bytes).hexdigest(),
        },
        "publication_transaction": {
            "transaction_id": arm["transaction_id"],
            "arm_physical_path": (
                f".program_facts_publication_transactions/{arm['transaction_id']}/"
                "publication_arm.v1.json"
            ),
            "arm_body_sha256": arm["arm_body_sha256"],
            "arm_file_size": len(arm_bytes),
            "arm_full_file_sha256": hashlib.sha256(arm_bytes).hexdigest(),
        },
        "logical_outputs": [
            {
                "logical_identity": identity,
                "physical_path": (
                    f".program_facts_public_generations/{arm['generation_id']}/"
                    f"{identity}"
                ),
                "size": len(outputs[identity]),
                "full_file_sha256": hashlib.sha256(outputs[identity]).hexdigest(),
            }
            for identity in PUBLIC_IDENTITIES
        ],
    }


def compatibility_delta_positive_vector(
    *,
    state: str = "COMPONENT_LOCAL_PROVISIONAL_C4",
    changed_path: str = "rules/schemas/new_program_facts_v2.json",
    semantic_class: str = "NEW_PRIVATE_OR_V2_ARTIFACT",
) -> dict[str, Any]:
    """Build/replay a compatibility receipt from sealed bound input bytes."""

    from program_facts_compatibility_delta import (
        produce_compatibility_delta_v1,
        validate_compatibility_delta_v1,
    )

    key_id = "fixture-independent-review-key"
    trusted_review_keys = {
        key_id: b"program-facts-r2.1-fixture-review-key-v1"
    }
    authority_key = trusted_review_keys[key_id]

    def binding(path: str, content: bytes) -> dict[str, Any]:
        return {
            "path": path,
            "size": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        }

    def manifest_bytes(
        *,
        manifest_class: str,
        paths: list[dict[str, Any]],
    ) -> bytes:
        document = {
            "schema_version": (
                "plamen.program_facts_runtime_path_manifest.v1"
            ),
            "manifest_class": manifest_class,
            "paths": sorted(
                deepcopy(paths),
                key=lambda row: row["portable_path"].casefold(),
            ),
            "manifest_body_sha256": H0,
        }
        document["manifest_body_sha256"] = body_digest(
            document, "manifest_body_sha256"
        )
        return canonical_bytes(document) + b"\n"

    def sealed_authority_bytes(document: Mapping[str, Any]) -> bytes:
        sealed = {
            **deepcopy(dict(document)),
            "authority_key_id": key_id,
            "authority_hmac_sha256": H0,
        }
        preimage = dict(sealed)
        preimage.pop("authority_hmac_sha256")
        sealed["authority_hmac_sha256"] = hmac.new(
            authority_key,
            canonical_bytes(preimage),
            hashlib.sha256,
        ).hexdigest()
        return canonical_bytes(sealed) + b"\n"

    unchanged_path = "rules/unchanged_program_facts_control.json"
    old_paths = [
        {"portable_path": unchanged_path, "size": 11, "sha256": H9}
    ]
    new_paths = [
        *deepcopy(old_paths),
        {"portable_path": changed_path, "size": 42, "sha256": H7},
    ]
    pre_runtime_manifest_bytes = manifest_bytes(
        manifest_class="PRE_R2_BOUNDARY",
        paths=old_paths,
    )
    post_runtime_manifest_bytes = manifest_bytes(
        manifest_class="POST_R2_RUNTIME",
        paths=new_paths,
    )
    pre_r2_boundary_manifest = {
        "path": "review_fixtures/pre_r2_runtime_manifest.json",
        "size": len(pre_runtime_manifest_bytes),
        "sha256": hashlib.sha256(pre_runtime_manifest_bytes).hexdigest(),
    }
    post_r2_runtime_manifest = {
        "path": "review_fixtures/post_r2_runtime_manifest.json",
        "size": len(post_runtime_manifest_bytes),
        "sha256": hashlib.sha256(post_runtime_manifest_bytes).hexdigest(),
    }

    compared_output_bytes: dict[str, bytes] = {}
    public_comparisons: dict[str, dict[str, Any]] = {}
    for branch in ("legacy_v1", "disabled", "shadow_raw"):
        content = canonical_bytes({"branch": branch, "value": "stable"}) + b"\n"
        left_path = f"review_fixtures/comparator/{branch}/left.json"
        right_path = f"review_fixtures/comparator/{branch}/right.json"
        compared_output_bytes[left_path] = content
        compared_output_bytes[right_path] = content
        row = {
            "size": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        }
        public_comparisons[branch] = {
            "left_files": [{"path": left_path, **row}],
            "right_files": [{"path": right_path, **row}],
            "exact_equal": True,
        }
    comparator_receipt_bytes = sealed_authority_bytes(
        {
            "schema_version": (
                "plamen.program_facts_same_postimage_comparator_receipt.v1"
            ),
            "public_comparisons": public_comparisons,
        }
    )
    registry_id = "program-facts-r2.1-r4-component-registry"
    registry_rows_by_path = {
        "rules/schemas/new_program_facts_v2.json": (
            "NEW_PRIVATE_OR_V2_ARTIFACT"
        ),
        "scripts/artifact_ledger.py": "TOOLCHAIN_COMPONENT",
        "scripts/phase_io_contracts.py": "TOOLCHAIN_COMPONENT",
        changed_path: semantic_class,
    }
    component_registry_bytes = sealed_authority_bytes(
        {
            "schema_version": (
                "plamen.program_facts_compatibility_component_registry.v1"
            ),
            "registry_id": registry_id,
            "rows": [
                {
                    "portable_path": path,
                    "semantic_class": registry_rows_by_path[path],
                }
                for path in sorted(
                    registry_rows_by_path,
                    key=str.casefold,
                )
            ],
        }
    )
    component_registry_sha256 = hashlib.sha256(
        component_registry_bytes
    ).hexdigest()
    allowed_change_roster_bytes = sealed_authority_bytes(
        {
            "schema_version": (
                "plamen.program_facts_allowed_change_roster.v1"
            ),
            "component_registry_id": registry_id,
            "component_registry_sha256": component_registry_sha256,
            "rows": [
                {
                    "portable_path": changed_path,
                    "semantic_class": semantic_class,
                    "reviewed_reason": "R2.1 governed component delta",
                }
            ],
        }
    )
    semantic_review_bytes = sealed_authority_bytes(
        {
            "schema_version": (
                "plamen.program_facts_compatibility_semantic_review.v1"
            ),
            "component_registry_id": registry_id,
            "component_registry_sha256": component_registry_sha256,
            "rows": [
                {
                    "portable_path": changed_path,
                    "semantic_class": semantic_class,
                    "review_disposition": "ALLOWED_RELEASE_DELTA",
                }
            ],
        }
    )
    compatibility_receipt_paths = [
        (
            "review_fixtures/"
            "program_facts_compatibility_delta_c4_provisional.v1.json"
        ),
        (
            "review_fixtures/"
            "program_facts_compatibility_delta_final_release.v1.json"
        ),
    ]
    exclusion_authority_bytes = sealed_authority_bytes(
        {
            "schema_version": (
                "plamen.program_facts_compatibility_exclusion_authority.v1"
            ),
            "compatibility_receipt_paths": compatibility_receipt_paths,
            "execution_authority_paths": [
                "scripts/program_facts_evm_execution_set.py"
            ],
            "composition_authority_paths": [
                "scripts/program_facts_positive_composer.py"
            ],
            "compared_runtime_manifest_paths": [
                row["portable_path"] for row in new_paths
            ],
        }
    )
    producer_bytes = (
        ROOT / "scripts" / "program_facts_compatibility_delta.py"
    ).read_bytes()
    runtime_closure_state = (
        "FINAL_RUNTIME_QUIESCENT"
        if state == "FINAL_RUNTIME_QUIESCENT"
        else "COMPONENT_LOCAL_PROVISIONAL_NOT_FINAL_RUNTIME_CLOSURE"
    )
    shared_kwargs = {
        "producer_bytes": producer_bytes,
        "pre_runtime_manifest_bytes": pre_runtime_manifest_bytes,
        "pre_r2_boundary_manifest": pre_r2_boundary_manifest,
        "post_runtime_manifest_bytes": post_runtime_manifest_bytes,
        "post_r2_runtime_manifest": post_r2_runtime_manifest,
        "comparator_receipt_bytes": comparator_receipt_bytes,
        "comparator_receipt_binding": binding(
            "review_fixtures/comparator_receipt.v1.json",
            comparator_receipt_bytes,
        ),
        "compared_output_bytes": compared_output_bytes,
        "component_registry_bytes": component_registry_bytes,
        "component_registry_binding": binding(
            "review_fixtures/compatibility_component_registry.v1.json",
            component_registry_bytes,
        ),
        "allowed_change_roster_bytes": allowed_change_roster_bytes,
        "allowed_change_roster_binding": binding(
            "review_fixtures/allowed_change_roster.v1.json",
            allowed_change_roster_bytes,
        ),
        "semantic_review_bytes": semantic_review_bytes,
        "semantic_review_binding": binding(
            "review_fixtures/compatibility_semantic_review.v1.json",
            semantic_review_bytes,
        ),
        "exclusion_authority_bytes": exclusion_authority_bytes,
        "exclusion_authority_binding": binding(
            "review_fixtures/compatibility_exclusion_authority.v1.json",
            exclusion_authority_bytes,
        ),
        "trusted_review_keys": trusted_review_keys,
        "runtime_closure_state": runtime_closure_state,
    }
    document = produce_compatibility_delta_v1(state=state, **shared_kwargs)
    validated = validate_compatibility_delta_v1(document, **shared_kwargs)
    assert validated == document
    return {
        "document": document,
        "validation_kwargs": shared_kwargs,
        "changed_path": changed_path,
        "unchanged_path": unchanged_path,
        "trusted_review_key_id": key_id,
        "component_registry_id": registry_id,
        "compatibility_receipt_paths": compatibility_receipt_paths,
    }


def compatibility_delta_document() -> dict[str, Any]:
    return clone(compatibility_delta_positive_vector()["document"])


def clone(value: Any) -> Any:
    return deepcopy(value)
