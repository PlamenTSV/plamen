"""Independent RED contracts for preverify runtime and source replay.

These tests are intentionally test-only.  They pin four authority properties:

* production consumers must request run- and consumer-bound authority;
* frozen bytes must be replayed from authenticated source bytes;
* harmless provider source changes must not invalidate historical receipts;
* semantic-mutation authority rows must be replayed from the mutation ledger.

No audit, model, network request, or production artifact is launched.
"""
from __future__ import annotations

import ast
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from artifact_ledger import read_artifact_ledger
from preverify_chain_pair_projection import (
    prepare_preverify_chain_pair_projection,
)
from preverify_frozen_projection import (
    derive_preverify_finding_records_bytes,
    prepare_preverify_frozen_projection,
)
from preverify_projection_authority import (
    PreverifyProjectionAuthorityError,
    validate_frozen_projection_receipt,
)
import plamen_driver as DRIVER
import test_chain_post_model_driver_order_integration as CHAIN
import test_live_verify_queue_driver_adapter_cutover as ADAPTER
import test_preverify_frozen_projection as FROZEN
import test_preverify_projection_authority_red as AUTHORITY_RED


_SCRIPTS = Path(__file__).resolve().parent


def _call_name(node: ast.Call) -> str:
    function = node.func
    if isinstance(function, ast.Name):
        return function.id
    if isinstance(function, ast.Attribute):
        return function.attr
    return ""


def _function(path: str, name: str) -> ast.FunctionDef | ast.AsyncFunctionDef:
    tree = ast.parse((_SCRIPTS / path).read_text(encoding="utf-8"))
    matches = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == name
    ]
    assert len(matches) == 1, (
        f"{path}:{name} must remain an independently reviewable runtime "
        "consumer"
    )
    return matches[0]


_RUNTIME_CALLERS = (
    ("chain_grouping_assurance.py", "_inventory_records"),
    ("mandatory_reverification.py", "_load_current_delivery_receipt"),
    ("mandatory_reverification.py", "compile_primary_reopen_denominator"),
    ("mandatory_reverification.py", "compile_report_reopen_denominator"),
    ("plamen_mechanical.py", "_load_finding_record_maps"),
    ("plamen_validators.py", "_authoritative_postcutover_inventory"),
    ("plamen_driver.py", "_chain_grouping_assurance_input_paths"),
)


@pytest.mark.parametrize(
    ("relative", "function_name"),
    _RUNTIME_CALLERS,
    ids=[f"{Path(path).stem}.{name}" for path, name in _RUNTIME_CALLERS],
)
def test_production_projection_consumer_is_exactly_runtime_bound(
    relative: str,
    function_name: str,
) -> None:
    """A runtime caller may never consume offline/introspection authority."""

    function = _function(relative, function_name)
    calls = [
        node for node in ast.walk(function) if isinstance(node, ast.Call)
    ]
    introspection = [
        call
        for call in calls
        if _call_name(call) == "inspect_current_preverify_projection"
    ]
    assert introspection == [], (
        f"{relative}:{function_name} still consumes unbound introspection "
        "authority"
    )

    direct_runtime = [
        call
        for call in calls
        if _call_name(call) == "resolve_current_preverify_projection"
    ]
    active_capability = [
        call
        for call in calls
        if _call_name(call) == "resolve_active_preverify_projection"
    ]
    assert direct_runtime or active_capability, (
        f"{relative}:{function_name} must consume either an exact explicit "
        "runtime projection or the singular validated active routing "
        "capability"
    )
    for call in direct_runtime:
        keywords = {
            str(keyword.arg): keyword.value
            for keyword in call.keywords
            if keyword.arg is not None
        }
        assert {
            "expected_run_id",
            "expected_consumer_work_unit_key",
        } <= set(keywords), (
            f"{relative}:{function_name} must bind both run_id and the "
            "canonical consumer work-unit key"
        )
        for keyword in (
            "expected_run_id",
            "expected_consumer_work_unit_key",
        ):
            value = keywords[keyword]
            assert not (
                isinstance(value, ast.Constant)
                and value.value in {"", None}
            ), f"{relative}:{function_name} passes an empty {keyword}"


def _binding(raw: bytes) -> dict[str, int | str]:
    return {
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
    }


def _validate_context(
    context: dict[str, Any],
    *,
    receipt: dict[str, Any] | None = None,
    authority: dict[str, Any] | None = None,
    inventory_raw: bytes | None = None,
    records_raw: bytes | None = None,
) -> None:
    validate_frozen_projection_receipt(
        context["receipt"] if receipt is None else receipt,
        authority=(
            context["authority"] if authority is None else authority
        ),
        run_id=str(context["run_id"]),
        evidence_source=str(context["evidence_source"]),
        inventory_raw=(
            context["inventory_raw"]
            if inventory_raw is None
            else inventory_raw
        ),
        records_raw=(
            context["records_raw"]
            if records_raw is None
            else records_raw
        ),
        advisory_evidence_raw=context["evidence_raw"],
        scratchpad=Path(context["root"]),
        project_root=Path(context["root"]).parent,
    )


def _forge_output_bytes(
    context: dict[str, Any],
    forged_inventory: bytes,
) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    forged_records = derive_preverify_finding_records_bytes(
        forged_inventory
    )
    receipt = deepcopy(context["receipt"])
    receipt["inventory"] = _binding(forged_inventory)
    receipt["records"] = _binding(forged_records)
    authority = AUTHORITY_RED._readdress_receipt(
        receipt,
        context["authority"],
    )
    return receipt, authority, forged_records


def test_no_delta_inventory_bytes_are_exact_replay_of_authorized_source(
    tmp_path: Path,
) -> None:
    context = AUTHORITY_RED._receipt_context(tmp_path)
    original = context["inventory_raw"]
    forged = original.replace(
        b"exact mechanism remains candidate-bearing",
        b"reauthored mechanism changes the candidate semantics",
    )
    assert forged != original
    receipt, authority, records = _forge_output_bytes(context, forged)

    with pytest.raises(
        PreverifyProjectionAuthorityError,
        match="source|replay|inventory|bytes",
    ):
        _validate_context(
            context,
            receipt=receipt,
            authority=authority,
            inventory_raw=forged,
            records_raw=records,
        )


def _authority_from_frozen(
    root: Path,
    frozen: dict[str, Any],
) -> dict[str, Any]:
    ledger = read_artifact_ledger(root)
    producer_key = str(frozen["work_unit_key"])
    producer = ledger["work_units"][producer_key]
    physical = frozen["logical_to_physical"]
    inventory_path = str(physical["findings_inventory.md"])
    frozen_root = str(Path(inventory_path).parent).replace("\\", "/")
    return {
        "frozen_generation": str(frozen["generation_digest"]),
        "frozen_root": frozen_root,
        "producer_key": producer_key,
        "producer_contract_digest": str(producer["contract_digest"]),
        "provider_input_bindings": deepcopy(
            producer["input_bindings"]
        ),
        "source_preimage_rows": {
            identity.rsplit("/_sources/", 1)[1]: {
                "path": identity.removeprefix("scratchpad:"),
                "identity": identity,
                "binding": deepcopy(binding),
            }
            for identity, binding in producer["artifacts"].items()
            if "/_sources/" in identity
        },
        "inventory_path": inventory_path,
        "records_path": str(physical["finding_records.json"]),
        "evidence_path": str(frozen["advisory_evidence_path"]),
        "receipt_path": str(frozen["receipt_path"]),
    }


def _context_from_frozen(
    root: Path,
    frozen: dict[str, Any],
) -> dict[str, Any]:
    authority = _authority_from_frozen(root, frozen)
    receipt = json.loads(
        (root / authority["receipt_path"]).read_text(
            encoding="utf-8",
            errors="strict",
        )
    )
    evidence_source = (
        str(receipt["evidence_source"])
        if receipt["evidence_semantic_use"] is True
        else ""
    )
    return {
        "root": root,
        "run_id": receipt["run_id"],
        "authority": authority,
        "receipt": receipt,
        "inventory_raw": (root / authority["inventory_path"]).read_bytes(),
        "records_raw": (root / authority["records_path"]).read_bytes(),
        "evidence_source": evidence_source,
        "evidence_raw": (root / authority["evidence_path"]).read_bytes(),
    }


def _chain_delta_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> dict[str, Any]:
    project, root, config, _checkpoint = CHAIN._accepted_chain_model(
        tmp_path,
        include_enabler=True,
    )
    monkeypatch.setattr(
        DRIVER,
        "_derive_auto_map_unmapped_depth_findings",
        CHAIN._additive_pair_deriver(),
    )
    mapped, issues = (
        DRIVER._auto_map_unmapped_depth_findings_with_semantic_authority(
            root,
            config,
            owner_phase="chain",
            gate_issues=("unmapped DA-2",),
        )
    )
    assert mapped == ["DA-2"]
    assert issues == []
    pair = prepare_preverify_chain_pair_projection(
        scratchpad=root,
        project_root=project,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase_name="sc_verify_queue",
        run_id=CHAIN.CHAIN_FIXTURE.RUN_ID,
    )
    frozen = prepare_preverify_frozen_projection(
        scratchpad=root,
        project_root=project,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase_name="sc_verify_queue",
        run_id=CHAIN.CHAIN_FIXTURE.RUN_ID,
        chain_pair_projection=pair,
    )
    return _context_from_frozen(root, frozen)


def test_delta_inventory_is_exact_deterministic_base_candidate_union(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _chain_delta_context(tmp_path, monkeypatch)
    original = context["inventory_raw"]
    forged = original.replace(
        b"A generic chain-discovered precondition path.",
        b"A reauthored chain candidate with materially different semantics.",
    )
    assert forged != original
    receipt, authority, records = _forge_output_bytes(context, forged)

    with pytest.raises(
        PreverifyProjectionAuthorityError,
        match="delta|source|replay|union|bytes",
    ):
        _validate_context(
            context,
            receipt=receipt,
            authority=authority,
            inventory_raw=forged,
            records_raw=records,
        )


@pytest.mark.parametrize("harmless_change", ("comment", "crlf"))
def test_historical_receipt_survives_nonsemantic_provider_source_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    harmless_change: str,
) -> None:
    context = AUTHORITY_RED._receipt_context(tmp_path)
    import preverify_frozen_projection as provider

    original = Path(str(provider.__file__)).read_bytes()
    if harmless_change == "comment":
        changed = original + b"\n# fixture-only nonsemantic comment\n"
    else:
        changed = original.replace(b"\r\n", b"\n").replace(
            b"\n",
            b"\r\n",
        )
    assert changed != original
    alternate = tmp_path / f"provider-{harmless_change}.py"
    alternate.write_bytes(changed)
    monkeypatch.setattr(provider, "__file__", str(alternate))

    _validate_context(context)


def test_unknown_receipt_algorithm_schema_is_rejected(
    tmp_path: Path,
) -> None:
    """Stable version dispatch must not turn into accept-any-version replay."""

    context = AUTHORITY_RED._receipt_context(tmp_path)
    receipt = deepcopy(context["receipt"])
    receipt["schema_version"] = (
        "plamen.preverify_frozen_projection_receipt.v999"
    )
    authority = AUTHORITY_RED._readdress_receipt(
        receipt,
        context["authority"],
    )

    with pytest.raises(
        PreverifyProjectionAuthorityError,
        match="schema|version|algorithm|receipt",
    ):
        _validate_context(
            context,
            receipt=receipt,
            authority=authority,
        )


def _semantic_mutation_context(tmp_path: Path) -> dict[str, Any]:
    root, config, run_id = ADAPTER._seed(
        tmp_path,
        pipeline="sc",
        backend="claude",
    )
    FROZEN._split_source_owners(root, tmp_path, config, run_id)
    inventory_raw = (
        root / FROZEN.INVENTORY_LOGICAL
    ).read_bytes() + b"\n"
    FROZEN._mutate(
        root,
        tmp_path,
        run_id,
        FROZEN.INVENTORY_LOGICAL,
        inventory_raw,
        "FINDING_PROMOTION",
    )
    frozen = FROZEN._prepare(root, tmp_path, config, run_id)
    return _context_from_frozen(root, frozen)


def test_semantic_mutation_source_row_replays_exact_ledger_authority(
    tmp_path: Path,
) -> None:
    context = _semantic_mutation_context(tmp_path)
    receipt = deepcopy(context["receipt"])
    row = receipt["source_authorities"]["inventory"]
    assert row["authority_kind"] == "CONTIGUOUS_SEMANTIC_MUTATION_CHAIN"
    row["mutation_event_ids"] = ["SMUT-FORGED-EVENT"]
    row["mutation_authority_digests"] = ["0" * 64]
    authority = AUTHORITY_RED._readdress_receipt(
        receipt,
        context["authority"],
    )

    with pytest.raises(
        PreverifyProjectionAuthorityError,
        match="semantic|mutation|source|authority|ledger",
    ):
        _validate_context(
            context,
            receipt=receipt,
            authority=authority,
        )
