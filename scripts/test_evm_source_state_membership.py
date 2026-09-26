"""Source-only EVM state membership and identity regressions.

These fixtures exercise the lexical fallback only.  They must never imply
compiler/AST authority or add permissive alias merging to semantic authority.
"""

from __future__ import annotations

import json
from pathlib import Path

import enumeration_gate as E
import recon_prepass as R
import semantic_invariant_authority as S
from state_symbol_authority import parse_legacy_state_symbols


def test_lexical_state_extractor_covers_solidity_member_shapes_only() -> None:
    source = """
    pragma solidity ^0.8.20;
    contract First {
        struct Meta { uint256 value; address[] owners; }
        enum Phase { One, Two }
        uint256 public count;
        Widget public gateway;
        uint256[] internal values;
        mapping(address => uint256) private balances;
        function(address) external returns (bool) callback;
        string constant LABEL = "uint256 fake;";
        Meta public meta = Meta({value: 1, owners: new address[](0)});
        uint256 private unreferenced;

        function touch() external {
            uint256 localOnly = count;
            Meta memory temporary = meta;
        }
    }
    contract Second {
        uint256 public count;
    }
    library Limits {
        uint256 internal constant LIMIT = 7;
    }
    interface Ignored {
        function read() external view returns (uint256);
    }
    """

    rows = R._sol_state_declarations(source, source_path="contracts/States.sol")
    identities = {row["qualified_name"] for row in rows}

    assert identities == {
        "contracts/States.sol::First.LABEL",
        "contracts/States.sol::First.balances",
        "contracts/States.sol::First.callback",
        "contracts/States.sol::First.count",
        "contracts/States.sol::First.gateway",
        "contracts/States.sol::First.meta",
        "contracts/States.sol::First.unreferenced",
        "contracts/States.sol::First.values",
        "contracts/States.sol::Limits.LIMIT",
        "contracts/States.sol::Second.count",
    }
    assert not any("localOnly" in identity for identity in identities)
    assert not any("temporary" in identity for identity in identities)
    assert not any("owners" in identity for identity in identities)
    assert not any("Meta.value" in identity for identity in identities)
    assert all(row["declaration_locus"].startswith("contracts/States.sol:L") for row in rows)
    assert {row["confidence"] for row in rows} == {
        "LEXICAL_CONTRACT_MEMBER_APPROXIMATE"
    }
    assert all("SOURCE_ONLY_NO_TYPE_RESOLUTION" in row["uncertainty"] for row in rows)


def test_source_graph_uses_file_contract_member_identity_and_exact_inventory_join(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "One.sol").write_text(
        """
        contract C {
            uint256 x;
            uint256 reserve;
            function touch() external { uint256 localOnly = x; }
        }
        contract D {
            uint256 x;
            function touch() external { x = 1; }
        }
        """,
        encoding="utf-8",
    )
    (project / "Two.sol").write_text(
        """
        contract C {
            uint256 x;
            function touch() external { x = 2; }
        }
        """,
        encoding="utf-8",
    )
    scratch = tmp_path / "scratch"
    scratch.mkdir()

    assert R._bake_evm_source_graph(scratch, project) == "WRITTEN"
    assert R._write_table_artifact(scratch, project, "evm", "state") == "WRITTEN"
    graph = json.loads((scratch / "_mechanical_graph.json").read_text(encoding="utf-8"))
    expected = {
        "One.sol::C.reserve",
        "One.sol::C.x",
        "One.sol::D.x",
        "Two.sol::C.x",
    }

    assert set(graph["var_refs"]) == expected
    assert {row["qualified_name"] for row in graph["state_symbols"]} == expected
    assert "localOnly" not in json.dumps(graph["state_symbols"], sort_keys=True)
    reserve = graph["var_refs"]["One.sol::C.reserve"]
    assert reserve["refs"] == []
    assert reserve["declaration_locus"].startswith("One.sol:L")
    assert all(row["read_sites"] == [] for row in graph["state_symbols"])
    assert all(row["write_sites"] == [] for row in graph["state_symbols"])
    assert {row["graph_confidence"] for row in graph["state_symbols"]} == {
        "LEXICAL_CONTRACT_MEMBER_APPROXIMATE"
    }

    graph_rows, healthy, issues = S._load_graph_rows(scratch)
    legacy_rows, counts = parse_legacy_state_symbols(scratch)
    states, conflicts, compatibility_added = S._merge_state_sources(
        graph_rows, legacy_rows
    )
    assert healthy is True
    assert issues == []
    assert counts["recon_state_inventory"] == 4
    assert {row["qualified_name"] for row in states} == expected
    assert conflicts == []
    assert compatibility_added == 0


def test_state_only_contract_still_produces_approximate_graph(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "StateOnly.sol").write_text(
        "contract StateOnly { ExternalType public dependency; uint256[] values; }\n",
        encoding="utf-8",
    )
    scratch = tmp_path / "scratch"
    scratch.mkdir()

    assert R._bake_evm_source_graph(scratch, project) == "WRITTEN"
    graph = json.loads((scratch / "_mechanical_graph.json").read_text(encoding="utf-8"))
    assert set(graph["var_refs"]) == {
        "StateOnly.sol::StateOnly.dependency",
        "StateOnly.sol::StateOnly.values",
    }
    assert graph["functions"] == {}


def test_legacy_unnamed_fallback_body_cannot_pollute_state_membership() -> None:
    source = """
    pragma solidity ^0.5.17;
    contract Legacy {
        uint256 beforeState;
        function() external payable { uint256 localOnly = beforeState; }
        address payable afterState;
    }
    """

    rows = R._sol_state_declarations(source, source_path="Legacy.sol")
    assert [(row["qualified_name"], row["type_text"]) for row in rows] == [
        ("Legacy.sol::Legacy.afterState", "address payable"),
        ("Legacy.sol::Legacy.beforeState", "uint256"),
    ]
    assert "localOnly" not in json.dumps(rows, sort_keys=True)
    after = next(row for row in rows if row["bare"] == "afterState")
    assert after["declaration_locus"].endswith(":L6")


def test_function_universe_keeps_stateless_derived_free_and_overloaded_functions(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "Universe.sol").write_text(
        """function freeHelper(uint256 x) pure returns (uint256) { return x; }
contract Base {
    uint256 internal baseValue;
}
contract Derived is Base {
    function inheritedRead() external view returns (uint256) { return baseValue; }
}
contract Utility {
    function helper(uint256 x) internal pure returns (uint256) { return x; } function helper(address x) internal pure returns (address) { return x; }
    function usesOverload() external pure returns (uint256) { return helper(1); }
}
""",
        encoding="utf-8",
    )
    scratch = tmp_path / "scratch"
    scratch.mkdir()

    assert R._bake_evm_source_graph(scratch, project) == "WRITTEN"
    graph = json.loads((scratch / "_mechanical_graph.json").read_text(encoding="utf-8"))
    functions = graph["functions"]
    assert any("::<file>.freeHelper@" in key for key in functions)
    assert any("::Derived.inheritedRead@" in key for key in functions)
    assert any("::Utility.usesOverload@" in key for key in functions)
    overloads = [key for key in functions if "::Utility.helper@" in key]
    assert len(overloads) == 2
    assert len(set(overloads)) == 2
    assert all(":C" in key for key in overloads)
    loaded = E._load_graph(scratch)
    assert loaded is not None
    for key in overloads:
        descriptor = f"helper ({functions[key]['declaration_locus']})"
        assert E._descriptor_function_key(loaded, descriptor) is None
    uses = next(
        row for key, row in functions.items() if "::Utility.usesOverload@" in key
    )
    assert "SOURCE_ONLY_OVERLOAD_CALL_UNRESOLVED:helper" in uses["uncertainty"]
    assert uses["callees"] == []

    # The inherited read remains visible as a function without inventing a
    # Derived.baseValue declaration or a source-only inherited-state edge.
    assert set(graph["var_refs"]) == {"Universe.sol::Base.baseValue"}
    assert graph["var_refs"]["Universe.sol::Base.baseValue"]["refs"] == []
    inherited = next(
        row for key, row in functions.items() if "::Derived.inheritedRead@" in key
    )
    assert "SOURCE_ONLY_INHERITED_STATE_RESOLUTION_UNAVAILABLE" in inherited[
        "uncertainty"
    ]


def test_malformed_unclosed_contract_is_not_complete_state_authority(
    tmp_path: Path,
) -> None:
    malformed = "contract Broken { uint256 value; function f() external { value = 1; }"
    rows = R._sol_state_declarations(
        malformed,
        source_path="Broken.sol",
    )
    assert rows == []
    project = tmp_path / "project"
    project.mkdir()
    (project / "Broken.sol").write_text(malformed, encoding="utf-8")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    assert R._bake_evm_source_graph(scratch, project) == (
        "FAILED:evm source parse (MALFORMED_CONTRACT_SCOPE)"
    )
    assert not (scratch / "_mechanical_graph.json").exists()
