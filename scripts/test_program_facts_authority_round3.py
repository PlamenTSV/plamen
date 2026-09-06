"""PF-AUTH-01 regression fixtures.

These tests exercise malformed and reflection-constructed values at the
orchestrator data boundary.  Underscore names are not data authority:
readiness must remain derived from replayed parents, not raw issuer callables
or seals.  The provider/worker itself is outside the orchestrator process;
arbitrary execution that rewrites loaded TCB code or closure cells is excluded
by process/code integrity rather than by Python naming conventions.
"""

from __future__ import annotations

import concurrent.futures
import copy

import pytest

import program_facts_provider_api as provider_api
import program_facts_provider_registry as registry_api
from test_program_facts_registry_api_authority_blockers import (
    _structural_plan,
    _structural_registry,
)


def test_no_importable_raw_production_issuer_or_seal_surface() -> None:
    for module, names in (
        (
            registry_api,
            (
                "_PRODUCTION_REGISTRY_SEAL",
                "_issue_loaded_registry",
                "_issue_registry_decision",
            ),
        ),
        (
            provider_api,
            (
                "_PRODUCTION_PLAN_SEAL",
                "_issue_plan",
                "_issue_plan_decision",
            ),
        ),
    ):
        for name in names:
            assert not hasattr(module, name), (
                f"{module.__name__}.{name} exposes raw production issuance"
            )


def test_structural_registry_row_cannot_be_reissued_ready() -> None:
    registry = _structural_registry()
    selection = registry.provider("fixture.compiler.primary")
    assert selection.ready is False

    raw_factory = getattr(
        registry_api, "_new_provider_registry_decision", None
    )
    assert raw_factory is None, (
        "caller-controlled registry-decision factory remains importable"
    )


def test_structural_plan_cannot_be_resealed_or_redecided_ready() -> None:
    _registry, _context, _observed, plan = _structural_plan()
    assert provider_api._plan_authority_state(plan) == "STRUCTURAL_TEST_ONLY"

    raw_factory = getattr(provider_api, "_new_plan_decision", None)
    assert raw_factory is None, (
        "caller-controlled plan-decision factory remains importable"
    )
    assert not hasattr(provider_api, "_PRODUCTION_PLAN_SEAL")
    assert not hasattr(provider_api, "_issue_plan")


def test_structural_authority_is_stable_under_copy_and_concurrency() -> None:
    registry, _context, _observed, plan = _structural_plan()
    copied = copy.copy(plan)
    assert provider_api._plan_authority_state(copied) is None

    def attempt_reseal() -> str:
        try:
            provider_api._record_compiled_plan(
                plan,
                registry=registry,
                structural_test_only=False,
            )
        except Exception as exc:  # exact disposition asserted below
            return f"{type(exc).__name__}:{exc}"
        return "UNEXPECTED_SUCCESS"

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        dispositions = tuple(pool.map(lambda _: attempt_reseal(), range(128)))
    assert all(
        item.startswith("TypeError:provider plan issuance is internal")
        for item in dispositions
    )
    assert provider_api._plan_authority_state(plan) == "STRUCTURAL_TEST_ONLY"


def test_structural_decision_has_no_production_sink_shortcut() -> None:
    registry, context, observed, plan = _structural_plan()
    replayed = provider_api.validate_provider_plan(
        plan,
        registry=registry,
        context=context,
        observed_identity=observed,
        allowed_license_classifications=("MIT",),
        source_manifest_authority=None,
    )
    assert replayed.ready is False
    assert replayed.structurally_valid is True
    assert replayed.plan is not None
    assert (
        provider_api._plan_authority_state(replayed.plan)
        == "STRUCTURAL_TEST_ONLY"
    )


def test_common_registry_parser_cannot_mint_production_authority() -> None:
    registry = _structural_registry()
    issued = registry_api._loaded_registry_issuance_preimage(registry)
    assert issued is not None
    with pytest.raises(
        TypeError,
        match="registry issuance is internal",
    ):
        registry_api._record_loaded_registry(registry, issued)
    with pytest.raises(
        registry_api.ProgramFactsProviderRegistryError,
        match="internal to its authority loader",
    ):
        registry_api._load_registry_bytes(
            registry.canonical_bytes,
            expected_registry_digest=None,
            max_bytes=registry_api.DEFAULT_MAX_REGISTRY_BYTES,
            source_identity="forged-production-registry.json",
            authority_state=registry_api.INSTALLED_PRODUCTION_AUTHORITY,
            snapshot_digest="0" * 64,
            source_scope_digest="1" * 64,
            audit_run_id="forged-run",
            methodology_capture_digest="2" * 64,
            phase_io_input_bytes={},
        )
