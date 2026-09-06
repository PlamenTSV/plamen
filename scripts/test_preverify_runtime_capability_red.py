"""Adversarial RED contracts for preverify runtime capabilities.

This suite pins the corrected architecture at the trust boundary:

* offline introspection is not a production runtime data source;
* runtime resolution is bound to the exact run and typed routing consumer;
* naming a consumer is not itself proof of a current committed capability;
* an invalid successor can never be translated into an innocent empty
  finding denominator by recall-sensitive consumers.

The tests deliberately do *not* require each helper to call the resolver.
A clean implementation may resolve one authenticated capability at a typed
boundary and pass that immutable capability through pure helpers.

No audit, model, network request, or production artifact is launched.
"""
from __future__ import annotations

import ast
from copy import deepcopy
import json
from pathlib import Path
from typing import Any, Mapping

import pytest

from artifact_ledger import read_artifact_ledger, write_artifact_ledger
import plamen_mechanical as MECHANICAL
import plamen_validators as VALIDATORS
from preverify_projection_authority import (
    PreverifyProjectionAuthorityError,
    resolve_current_preverify_projection,
)
import test_preverify_capture_pair_contract as AUTHORITY_FIXTURE


_SCRIPTS = Path(__file__).resolve().parent
_AUTHORITY_MODULE = "preverify_projection_authority.py"
_INSPECTION_SYMBOL = "inspect_current_preverify_projection"
_RUNTIME_CONSUMER = "sc/thorough/evm/claude/sc_verify_queue/routing"

# Diagnostics must be consciously enumerated here.  Tests are excluded by
# name below and the authority module owns the offline API definition.
_DIAGNOSTIC_ALLOWLIST: frozenset[str] = frozenset()


def _offline_introspection_uses(path: Path) -> list[str]:
    """Return import/call evidence for the offline-only inspection API."""

    tree = ast.parse(path.read_text(encoding="utf-8", errors="strict"))
    direct_names = {_INSPECTION_SYMBOL}
    module_names: set[str] = set()
    evidence: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module == "preverify_projection_authority":
                for alias in node.names:
                    if alias.name != _INSPECTION_SYMBOL:
                        continue
                    direct_names.add(alias.asname or alias.name)
                    evidence.append(
                        f"line {node.lineno}: imports {_INSPECTION_SYMBOL}"
                    )
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "preverify_projection_authority":
                    module_names.add(alias.asname or alias.name)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        function = node.func
        if (
            isinstance(function, ast.Name)
            and function.id in direct_names
        ):
            evidence.append(
                f"line {node.lineno}: calls {function.id}"
            )
        elif (
            isinstance(function, ast.Attribute)
            and function.attr == _INSPECTION_SYMBOL
            and isinstance(function.value, ast.Name)
            and function.value.id in module_names
        ):
            evidence.append(
                f"line {node.lineno}: calls "
                f"{function.value.id}.{_INSPECTION_SYMBOL}"
            )
    return evidence


def test_offline_projection_introspection_is_absent_from_production() -> None:
    """Only explicit diagnostics may import or call offline introspection."""

    violations: list[str] = []
    for path in sorted(_SCRIPTS.rglob("*.py")):
        relative = path.relative_to(_SCRIPTS).as_posix()
        if (
            path.name.startswith("test_")
            or relative == _AUTHORITY_MODULE
            or relative in _DIAGNOSTIC_ALLOWLIST
        ):
            continue
        for evidence in _offline_introspection_uses(path):
            violations.append(f"{relative}: {evidence}")

    assert violations == [], (
        "offline preverify introspection crossed the production runtime "
        "trust boundary:\n" + "\n".join(violations)
    )


@pytest.mark.parametrize(
    ("expected_run_id", "consumer_key", "error_pattern"),
    (
        (
            "foreign-run",
            _RUNTIME_CONSUMER,
            "run.*current|current.*run",
        ),
        (
            "",
            _RUNTIME_CONSUMER,
            "partial|run.*consumer|consumer.*run",
        ),
        (
            "USE_FIXTURE_RUN",
            "sc/thorough/evm/codex/sc_verify_queue/routing",
            "authorize|consumer|owner|backend",
        ),
        (
            "USE_FIXTURE_RUN",
            "sc/thorough/soroban/claude/sc_verify_queue/routing",
            "authorize|consumer|owner|ecosystem",
        ),
        (
            "USE_FIXTURE_RUN",
            "sc/thorough/evm/claude/verify_queue/routing",
            "authorize|consumer|owner|phase",
        ),
        (
            "USE_FIXTURE_RUN",
            "sc/thorough/evm/claude/sc_verify_queue/not-routing",
            "malformed|routing|consumer",
        ),
    ),
    ids=(
        "run",
        "partial-binding",
        "backend",
        "ecosystem",
        "phase",
        "work-unit-key",
    ),
)
def test_runtime_resolution_rejects_every_context_mismatch(
    tmp_path: Path,
    expected_run_id: str,
    consumer_key: str,
    error_pattern: str,
) -> None:
    root, _config, run_id, _frozen, _ledger, _bindings = (
        AUTHORITY_FIXTURE._live_authority_fixture(tmp_path)
    )
    selected_run = (
        run_id if expected_run_id == "USE_FIXTURE_RUN" else expected_run_id
    )

    with pytest.raises(
        PreverifyProjectionAuthorityError,
        match=error_pattern,
    ):
        resolve_current_preverify_projection(
            root,
            expected_run_id=selected_run,
            expected_consumer_work_unit_key=consumer_key,
        )


def _install_unauthorized_routing_claim(
    root: Path,
    *,
    run_id: str,
    state: str,
) -> None:
    """Install a status-shaped claim without valid commit authority."""

    ledger = read_artifact_ledger(root)
    assert _RUNTIME_CONSUMER not in ledger["work_units"]
    claimed_run = "foreign-run" if state == "foreign" else run_id
    execution_state = (
        "OUTPUT_COMMITTED" if state == "foreign" else "PREPARED"
    )
    ledger["work_units"][_RUNTIME_CONSUMER] = {
        "schema": "plamen.artifact-work-unit.v2",
        "work_unit_key": _RUNTIME_CONSUMER,
        "run_id": claimed_run,
        "execution_state": execution_state,
        "semantic_status": "ACTIVE",
        "contract_manifest": {
            "key": _RUNTIME_CONSUMER,
            "outputs": [],
        },
        "artifacts": {},
        "input_bindings": {},
        # Deliberately no active commit receipt.  A self-reported state or
        # foreign run must not become a capability.
    }
    write_artifact_ledger(root, ledger)


@pytest.mark.parametrize(
    "capability_state",
    ("absent", "prepared", "foreign"),
    ids=(
        "no-consumer-capability",
        "uncommitted-consumer-capability",
        "non-current-consumer-capability",
    ),
)
def test_runtime_resolution_requires_current_committed_routing_capability(
    tmp_path: Path,
    capability_state: str,
) -> None:
    """A canonical consumer string is a name, not an authority capability."""

    root, _config, run_id, _frozen, ledger, _bindings = (
        AUTHORITY_FIXTURE._live_authority_fixture(tmp_path)
    )
    assert _RUNTIME_CONSUMER in ledger["work_units"]
    del ledger["work_units"][_RUNTIME_CONSUMER]
    write_artifact_ledger(root, ledger)
    if capability_state != "absent":
        _install_unauthorized_routing_claim(
            root,
            run_id=run_id,
            state=capability_state,
        )

    with pytest.raises(
        PreverifyProjectionAuthorityError,
        match="capability|consumer|routing|commit|current",
    ):
        resolve_current_preverify_projection(
            root,
            expected_run_id=run_id,
            expected_consumer_work_unit_key=_RUNTIME_CONSUMER,
        )


def _poisoned_successor(
    tmp_path: Path,
    state: str,
) -> Path:
    if state == "partial":
        root = tmp_path / "project" / ".scratchpad"
        root.mkdir(parents=True)
        (root / "preverify_inventory_successor.json").write_text(
            "{}\n",
            encoding="utf-8",
            newline="\n",
        )
        return root

    root, _config, _run_id, _frozen, _ledger, _bindings = (
        AUTHORITY_FIXTURE._live_authority_fixture(tmp_path)
    )
    target = root / "preverify_inventory_successor.json"
    payload = json.loads(
        target.read_text(encoding="utf-8", errors="strict")
    )
    payload["run_id"] = "stale-foreign-run"
    target.write_text(
        json.dumps(
            payload,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return root


def _contains_explicit_authority_debt(value: Any) -> bool:
    """Recognize structured debt without prescribing one future API shape."""

    if isinstance(value, str):
        lowered = value.lower()
        return any(
            token in lowered
            for token in (
                "authority",
                "capability",
                "preverify successor",
                "projection",
                "repair debt",
            )
        )
    if isinstance(value, Mapping):
        return any(
            _contains_explicit_authority_debt(key)
            or _contains_explicit_authority_debt(item)
            for key, item in value.items()
        )
    if isinstance(value, (tuple, list, set, frozenset)):
        return any(_contains_explicit_authority_debt(item) for item in value)
    return False


def _consume_recall_sensitive_projection(
    consumer: str,
    root: Path,
) -> Any:
    if consumer == "mechanical-record-maps":
        return MECHANICAL._load_finding_record_maps(root)
    if consumer == "unrouted-inventory-ids":
        return VALIDATORS._compute_unrouted_inventory_ids(root)
    raise AssertionError(f"unknown fixture consumer: {consumer}")


@pytest.mark.parametrize(
    "consumer",
    ("mechanical-record-maps", "unrouted-inventory-ids"),
)
@pytest.mark.parametrize("successor_state", ("partial", "stale"))
def test_invalid_successor_never_becomes_a_silent_empty_denominator(
    tmp_path: Path,
    consumer: str,
    successor_state: str,
) -> None:
    """Authority failure must propagate or become explicit structured debt."""

    root = _poisoned_successor(tmp_path, successor_state)
    try:
        result = _consume_recall_sensitive_projection(consumer, root)
    except PreverifyProjectionAuthorityError:
        return

    assert _contains_explicit_authority_debt(result), (
        f"{consumer} translated a {successor_state} successor into an "
        f"unauthenticated clean/empty result: {result!r}"
    )
