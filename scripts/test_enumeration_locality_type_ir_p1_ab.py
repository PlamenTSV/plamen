"""P1-A/P1-B generic acceptance fixtures.

These fixtures deliberately contain no protocol, contest, or benchmark names.
They lock two generator-only contracts:

* co-reference work starts from finding-local exact symbol anchors, never every
  symbol touched somewhere in the enclosing function; and
* boundary work is parameter-specific and derived from normalized type facts.

All emitted candidates remain low-confidence verification inputs.
"""
from __future__ import annotations

import hashlib
import importlib
import json
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def _eg():
    return importlib.import_module("enumeration_gate")


def _anchor_provider():
    return importlib.import_module("enumeration_anchor_facts")


def _type_provider():
    return importlib.import_module("enumeration_type_ir")


def _scratch(tmp_path: Path) -> Path:
    scratchpad = tmp_path / "project" / ".scratchpad"
    scratchpad.mkdir(parents=True)
    return scratchpad


def _finding(
    finding_id: str,
    location: str,
    body: str,
    *,
    verdict: str = "CONFIRMED",
) -> str:
    return (
        f"### Finding [{finding_id}]: Local transition inconsistency\n"
        "**Severity**: Medium\n"
        f"**Location**: `{location}`\n"
        f"**Verdict**: {verdict}\n"
        "**Source IDs**: SRC-1\n"
        f"**Description**: {body}\n"
        "**Impact**: A reachable transition may diverge.\n"
    )


def _write_inventory(scratchpad: Path, *blocks: str) -> None:
    (scratchpad / "findings_inventory.md").write_text(
        "# Finding Inventory\n\n" + "\n\n".join(blocks) + "\n",
        encoding="utf-8",
    )


def _write_graph(scratchpad: Path, graph: dict) -> None:
    (scratchpad / "_mechanical_graph.json").write_text(
        json.dumps(graph, sort_keys=True), encoding="utf-8"
    )


def _exact_graph(*, fanout: int = 2) -> dict:
    functions = {
        "Module.apply": {"bare": "apply", "loc": "src/Module.sol:L10", "callers": []},
        "Module.adjust": {"bare": "adjust", "loc": "src/Module.sol:L40", "callers": []},
    }
    refs = ["src/Module.sol:L12", "adjust (src/Module.sol:L40)"]
    for index in range(2, fanout):
        name = f"peer{index:02d}"
        line = 50 + index
        functions[f"Module.{name}"] = {
            "bare": name,
            "loc": f"src/Module.sol:L{line}",
            "callers": [],
        }
        refs.append(f"{name} (src/Module.sol:L{line})")
    return {
        "schema_version": "plamen.mechanical_graph.v2",
        "source": "slither",
        "functions": functions,
        "var_refs": {
            "Module.balance": {
                "bare": "balance",
                "refs": refs,
                "read_sites": ["src/Module.sol:L12", "src/Module.sol:L40"],
                "write_sites": [],
                "confidence": "AST_REFERENCE_SITE",
            },
            "Module.nonce": {
                "bare": "nonce",
                "refs": [
                    "src/Module.sol:L18",
                    "adjust (src/Module.sol:L40)",
                ],
                "read_sites": ["src/Module.sol:L18", "src/Module.sol:L40"],
                "write_sites": [],
                "confidence": "AST_REFERENCE_SITE",
            },
        },
    }


def test_p1a_statement_location_anchors_only_local_symbol(tmp_path: Path):
    eg = _eg()
    scratchpad = _scratch(tmp_path)
    _write_graph(scratchpad, _exact_graph())
    _write_inventory(
        scratchpad,
        _finding("INV-001", "src/Module.sol:L12", "The cited statement diverges."),
    )

    assert eg.compute_enumeration_obligations(scratchpad) == 1
    payload = json.loads(
        (scratchpad / "_enumeration_obligations.json").read_text(encoding="utf-8")
    )
    assert {row["symbol_identity"] for row in payload["anchors"]} == {
        "Module.balance"
    }
    assert {row["symbol"] for row in payload["obligations"]} == {"balance"}
    assert "nonce" not in json.dumps(payload)
    assert payload["anchors"][0]["anchor_kind"] == "STATEMENT_REFERENCE"
    assert payload["anchors"][0]["fidelity"] == "EXACT"


def test_p1a_exact_finding_symbol_excludes_unrelated_same_function_symbol(
    tmp_path: Path,
):
    eg = _eg()
    scratchpad = _scratch(tmp_path)
    graph = _exact_graph()
    # Cite the declaration, where no statement-level reference exists. The
    # exact normalized symbol named in the finding is the only legal anchor.
    _write_graph(scratchpad, graph)
    _write_inventory(
        scratchpad,
        _finding(
            "INV-001",
            "src/Module.sol:L10",
            "The `balance` transition diverges; the cited mechanism is local.",
        ),
    )

    eg.compute_enumeration_obligations(scratchpad)
    payload = json.loads(
        (scratchpad / "_enumeration_obligations.json").read_text(encoding="utf-8")
    )
    assert [row["symbol_identity"] for row in payload["anchors"]] == [
        "Module.balance"
    ]
    assert payload["anchors"][0]["anchor_kind"] == "FINDING_SYMBOL_IDENTITY"


def test_p1a_approximate_macro_provider_becomes_one_unknown_not_cartesian(
    tmp_path: Path,
):
    eg = _eg()
    scratchpad = _scratch(tmp_path)
    graph = _exact_graph(fanout=8)
    graph["source"] = "move-source"
    for value in graph["var_refs"].values():
        value.pop("read_sites", None)
        value.pop("write_sites", None)
        value["confidence"] = "FUNCTION_SCOPE_APPROXIMATE"
    _write_graph(scratchpad, graph)
    _write_inventory(
        scratchpad,
        _finding("INV-001", "src/Module.sol:L10", "A macro-generated branch diverges."),
    )

    assert eg.compute_enumeration_obligations(scratchpad) == 0
    payload = json.loads(
        (scratchpad / "_enumeration_obligations.json").read_text(encoding="utf-8")
    )
    assert payload["anchors"] == []
    assert len(payload["unresolved_anchor_obligations"]) == 1
    unknown = payload["unresolved_anchor_obligations"][0]
    assert unknown["status"] == "UNKNOWN"
    assert unknown["reason"] == "NO_EXACT_FINDING_LOCAL_ANCHOR"
    assert unknown["candidate_count"] == 0


def test_p1a_hub_tail_preserves_every_identity_and_digest(tmp_path: Path):
    eg = _eg()
    scratchpad = _scratch(tmp_path)
    graph = _exact_graph(fanout=31)
    _write_graph(scratchpad, graph)
    _write_inventory(
        scratchpad,
        _finding("INV-001", "src/Module.sol:L12", "The cited statement diverges."),
    )

    assert eg.compute_enumeration_obligations(scratchpad) == 1
    payload = json.loads(
        (scratchpad / "_enumeration_obligations.json").read_text(encoding="utf-8")
    )
    family = payload["family_cards"][0]
    assert family["member_count"] == 30
    assert len(family["scheduled_members"]) == eg._MAX_COREFS_PER_VAR
    assert len(family["tail_members"]) == 30 - eg._MAX_COREFS_PER_VAR
    assert set(family["all_members"]) == set(family["scheduled_members"]) | set(
        family["tail_members"]
    )
    expected = hashlib.sha256(
        json.dumps(
            family["tail_members"], separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    ).hexdigest()
    assert family["tail_digest"] == expected
    assert family["continuation_required"] is True
    assert family["schema"] == "plamen.enumeration_coreference_family.v1"
    assert all(
        row["function_identity"] and row["location"] and row["descriptor"]
        for row in family["member_facts"]
    )
    obligation = payload["obligations"][0]
    assert obligation["schema"] == "plamen.enumeration_coreference_obligation.v1"
    assert obligation["confidence"] == "LOW_CONFIDENCE"


def test_p1a_source_drift_refuses_stale_obligation_consumption(tmp_path: Path):
    eg = _eg()
    scratchpad = _scratch(tmp_path)
    graph = _exact_graph()
    _write_graph(scratchpad, graph)
    _write_inventory(
        scratchpad,
        _finding("INV-001", "src/Module.sol:L12", "The cited statement diverges."),
    )
    eg.compute_enumeration_obligations(scratchpad)

    graph["functions"]["Module.newPeer"] = {
        "bare": "newPeer",
        "loc": "src/Module.sol:L90",
        "callers": [],
    }
    _write_graph(scratchpad, graph)
    assert eg.compute_coverage_gaps(scratchpad) == []
    shortfalls = json.loads(
        (scratchpad / "_coverage_shortfalls.json").read_text(encoding="utf-8")
    )["shortfalls"]
    assert any(row["kind"] == "SOURCE_DRIFT" for row in shortfalls)


def test_p1a_obligation_projection_is_resume_idempotent(tmp_path: Path):
    eg = _eg()
    scratchpad = _scratch(tmp_path)
    _write_graph(scratchpad, _exact_graph(fanout=12))
    _write_inventory(
        scratchpad,
        _finding("INV-001", "src/Module.sol:L12", "The cited statement diverges."),
    )
    eg.compute_enumeration_obligations(scratchpad)
    before_json = (scratchpad / "_enumeration_obligations.json").read_bytes()
    before_md = (scratchpad / "enumeration_obligations.md").read_bytes()
    eg.compute_enumeration_obligations(scratchpad)
    assert (scratchpad / "_enumeration_obligations.json").read_bytes() == before_json
    assert (scratchpad / "enumeration_obligations.md").read_bytes() == before_md


def test_p1a_constructor_or_hub_without_exact_local_anchor_is_one_unknown(
    tmp_path: Path,
):
    eg = _eg()
    scratchpad = _scratch(tmp_path)
    graph = _exact_graph(fanout=31)
    graph["functions"]["Module.constructor"] = {
        "bare": "constructor",
        "loc": "src/Module.sol:L5",
        "callers": [],
    }
    for value in graph["var_refs"].values():
        value["refs"].append("constructor (src/Module.sol:L5)")
    _write_graph(scratchpad, graph)
    _write_inventory(
        scratchpad,
        _finding(
            "INV-001", "src/Module.sol:L5", "Initialization is broadly connected."
        ),
    )

    assert eg.compute_enumeration_obligations(scratchpad) == 0
    payload = json.loads(
        (scratchpad / "_enumeration_obligations.json").read_text(encoding="utf-8")
    )
    assert payload["anchors"] == []
    assert payload["anchor_tail"] == []
    assert len(payload["unresolved_anchor_obligations"]) == 1
    assert payload["unresolved_anchor_obligations"][0]["status"] == "UNKNOWN"


@pytest.mark.parametrize(
    ("ecosystem", "params", "families"),
    [
        (
            "sol",
            "address recipient, uint128 amount, bool enabled, bytes payload",
            ["address_identity", "unsigned_integer", "boolean", "dynamic_bytes"],
        ),
        (
            "rust",
            "recipient: Pubkey, delta: i64, enabled: bool, payload: Bytes",
            ["address_identity", "signed_integer", "boolean", "dynamic_bytes"],
        ),
        (
            "move",
            "recipient: address, amount: u64, enabled: bool, payload: vector<u8>",
            ["address_identity", "unsigned_integer", "boolean", "vector"],
        ),
        (
            "go",
            "recipient common.Address, amount uint64, enabled bool, payload []byte",
            ["address_identity", "unsigned_integer", "boolean", "dynamic_bytes"],
        ),
    ],
)
def test_p1b_ecosystem_parameter_type_ir(
    ecosystem: str,
    params: str,
    families: list[str],
):
    provider = _type_provider()
    facts = provider.normalize_parameter_ir(ecosystem, params)
    assert [fact["family"] for fact in facts] == families
    assert [fact["index"] for fact in facts] == list(range(len(facts)))
    assert all(fact["fidelity"] == "EXACT_DECLARATION" for fact in facts)


def test_p1b_alias_option_result_resource_and_domain_id_families():
    provider = _type_provider()
    aliases = {
        "Amount": {"target": "uint128", "kind": "alias"},
        "NestedAmount": {"target": "Amount", "kind": "alias"},
        "Mode": {"target": "", "kind": "enum", "members": ["A", "B"]},
        "NestedMode": {"target": "Mode", "kind": "alias"},
        "Store": {"target": "", "kind": "resource"},
    }
    sol = provider.normalize_parameter_ir(
        "sol", "NestedAmount amount, NestedMode mode", type_facts=aliases
    )
    assert [fact["family"] for fact in sol] == ["unsigned_integer", "enum"]
    move = provider.normalize_parameter_ir(
        "move",
        "maybe: option::Option<u64>, outcome: Result<u64, u8>, store: &mut Store, domain_id: DomainId",
        type_facts=aliases,
    )
    assert [fact["family"] for fact in move] == [
        "option",
        "result",
        "resource",
        "domain_id",
    ]


def test_p1b_soroban_address_and_bytes_are_not_numeric():
    provider = _type_provider()
    facts = provider.normalize_parameter_ir(
        "rust", "account: Address, key: BytesN<32>, payload: Bytes"
    )
    assert [fact["family"] for fact in facts] == [
        "address_identity",
        "fixed_bytes",
        "dynamic_bytes",
    ]
    assert "zero" not in {
        row["boundary"]
        for fact in facts[:1]
        for row in provider.boundary_specs_for_parameter(fact)
    }


def test_p1b_references_solidity_arrays_and_go_fixed_bytes_are_normalized():
    provider = _type_provider()
    move = provider.normalize_parameter_ir("move", "authority: &signer")
    solidity = provider.normalize_parameter_ir(
        "sol", "uint256[] amounts, address[2] recipients"
    )
    go = provider.normalize_parameter_ir("go", "digest [32]byte")
    assert [row["family"] for row in move] == ["address_identity"]
    assert [row["family"] for row in solidity] == ["list", "list"]
    assert [row["family"] for row in go] == ["fixed_bytes"]


def test_p1b_threshold_adjacent_only_when_expression_exists():
    provider = _type_provider()
    amount = provider.normalize_parameter_ir("rust", "amount: u64")[0]
    plain = provider.boundary_specs_for_parameter(amount, source_body="store(amount);")
    compared = provider.boundary_specs_for_parameter(
        amount, source_body="if amount >= 100 { return Err(()); }"
    )
    assert not any(row["boundary"].startswith("threshold_") for row in plain)
    threshold_rows = [
        row for row in compared if row["boundary"].startswith("threshold_")
    ]
    assert [row["boundary"] for row in threshold_rows] == [
        "threshold_below",
        "threshold_at",
        "threshold_above",
    ]
    assert all(row["evidence"] == "amount >= 100" for row in threshold_rows)


def test_p1b_addressed_boundary_requires_parameter_local_clause():
    provider = _type_provider()
    assert provider.boundary_is_addressed(
        "The amount was checked at zero.", "amount", "zero"
    )
    assert not provider.boundary_is_addressed(
        "The recipient uses the zero address; amount remains unchecked.",
        "amount",
        "zero",
    )


def test_p1b_unsupported_type_is_one_unknown_obligation():
    provider = _type_provider()
    fact = provider.normalize_parameter_ir("rust", "value: OpaqueHandle")[0]
    assert fact["family"] == "unknown"
    rows = provider.boundary_specs_for_parameter(fact)
    assert rows == [
        {
            "boundary": "unsupported_type",
            "class": "UNKNOWN",
            "status": "UNKNOWN",
            "evidence": "OpaqueHandle",
        }
    ]


def test_p1b_unparseable_parameter_is_unknown_not_silently_dropped():
    provider = _type_provider()
    facts = provider.normalize_parameter_ir("go", "first, second uint64")
    assert len(facts) == 2
    assert facts[0]["family"] == "unknown"
    assert facts[0]["fidelity"] == "UNPARSED_DECLARATION"
    assert facts[1]["family"] == "unsigned_integer"


def test_p1b_mixed_parameters_never_share_function_wide_boundaries(tmp_path: Path):
    eg = _eg()
    scratchpad = _scratch(tmp_path)
    source = scratchpad.parent / "src" / "Module.sol"
    source.parent.mkdir(parents=True)
    source.write_text(
        "pragma solidity ^0.8.20;\n"
        "contract Module {\n"
        "  function apply(address recipient, uint128 amount, bool enabled, bytes calldata payload) external {\n"
        "    if (amount >= 100) { return; }\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    _write_graph(
        scratchpad,
        {
            "source": "slither",
            "functions": {
                "Module.apply": {
                    "bare": "apply",
                    "loc": "src/Module.sol:L3",
                    "callers": [],
                }
            },
            "var_refs": {},
        },
    )
    _write_inventory(
        scratchpad,
        _finding(
            "INV-001",
            "src/Module.sol:L3",
            "The `recipient` self/local case and `amount` zero case were checked.",
        ),
    )

    inventory_before = (scratchpad / "findings_inventory.md").read_bytes()
    candidates = eg.compute_boundary_input_candidates(scratchpad)
    assert (scratchpad / "findings_inventory.md").read_bytes() == inventory_before
    by_parameter: dict[str, set[str]] = {}
    for candidate in candidates:
        by_parameter.setdefault(candidate["parameter"], set()).add(
            candidate["boundary"]
        )
    assert "self_or_local" not in by_parameter["recipient"]
    assert "empty" not in by_parameter["recipient"]
    assert "zero" not in by_parameter["amount"]
    assert {"false", "true"} <= by_parameter["enabled"]
    assert {"empty", "singleton"} <= by_parameter["payload"]
    assert not ({"false", "true"} & by_parameter["amount"])
    assert all(candidate["confidence"] == "LOW_CONFIDENCE" for candidate in candidates)
    obligations = json.loads(
        (scratchpad / "_boundary_input_obligations.json").read_text(encoding="utf-8")
    )["obligations"]
    assert all(
        row["schema"] == "plamen.boundary_input_obligation.v1"
        for row in obligations
    )


@pytest.mark.parametrize(
    ("relative_path", "source_text", "graph_source", "location", "families"),
    [
        (
            "src/module.rs",
            "pub fn apply(account: Address, key: BytesN<32>, amount: i64, maybe: Option<u64>) {}\n",
            "scip",
            "src/module.rs:L1",
            {"address_identity", "fixed_bytes", "signed_integer", "option"},
        ),
        (
            "sources/module.move",
            "module 0x1::module {\n"
            "  public fun apply(account: address, amount: u64, maybe: option::Option<u64>) {}\n"
            "}\n",
            "move",
            "sources/module.move:L2",
            {"address_identity", "unsigned_integer", "option"},
        ),
    ],
)
def test_p1b_runtime_provider_preserves_rust_soroban_and_move_families(
    tmp_path: Path,
    relative_path: str,
    source_text: str,
    graph_source: str,
    location: str,
    families: set[str],
):
    eg = _eg()
    scratchpad = _scratch(tmp_path)
    source = scratchpad.parent / relative_path
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(source_text, encoding="utf-8")
    _write_graph(
        scratchpad,
        {
            "source": graph_source,
            "functions": {
                "Module.apply": {
                    "bare": "apply",
                    "loc": location,
                    "callers": [],
                }
            },
            "var_refs": {},
        },
    )
    _write_inventory(
        scratchpad,
        _finding("INV-001", location, "No parameter boundary is discussed."),
    )

    candidates = eg.compute_boundary_input_candidates(scratchpad)
    assert families <= {row["type_family"] for row in candidates}
    assert all(row["confidence"] == "LOW_CONFIDENCE" for row in candidates)


def test_p1b_boundary_obligation_projection_is_idempotent(tmp_path: Path):
    eg = _eg()
    scratchpad = _scratch(tmp_path)
    source = scratchpad.parent / "Module.go"
    source.write_text(
        "package module\nfunc Apply(amount uint64, enabled bool) {}\n",
        encoding="utf-8",
    )
    _write_graph(
        scratchpad,
        {
            "source": "scip",
            "functions": {
                "Apply": {"bare": "Apply", "loc": "Module.go:L2", "callers": []}
            },
            "var_refs": {},
        },
    )
    _write_inventory(
        scratchpad,
        _finding("INV-001", "Module.go:L2", "No boundary class is discussed."),
    )
    first = eg.compute_boundary_input_candidates(scratchpad)
    receipt_before = (scratchpad / "_boundary_input_obligations.json").read_bytes()
    second = eg.compute_boundary_input_candidates(scratchpad)
    assert first == second
    assert (scratchpad / "_boundary_input_obligations.json").read_bytes() == receipt_before
