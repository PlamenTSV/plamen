"""Focused contracts for the contained Slither CLI evidence projection."""

from __future__ import annotations

import pytest

import recon_prepass as recon


def _printer(description: str) -> dict[str, object]:
    return {
        "success": True,
        "error": None,
        "results": {"printers": [{"description": description}]},
    }


def test_function_summary_description_projects_exact_graph_fields() -> None:
    description = """Contract Vault
Contract vars: ['owner', 'balance']
+----------+------------+-----------+-------------+-------------+----------------+----------------+-----------------------+
| Function | Visibility | Modifiers | Read        | Write       | Internal Calls | External Calls | Cyclomatic Complexity |
+----------+------------+-----------+-------------+-------------+----------------+----------------+-----------------------+
| deposit()| public     | ['live']  | ['owner']   | ['balance'] | ['_account()'] | []             | 2                     |
+----------+------------+-----------+-------------+-------------+----------------+----------------+-----------------------+
"""
    assert recon._slither_cli_function_rows(_printer(description)) == [{
        "contract": "Vault",
        "name": "deposit()",
        "bare": "deposit",
        "visibility": "public",
        "modifiers": ("live",),
        "reads": ("owner",),
        "writes": ("balance",),
        "internal_calls": ("_account()",),
        "external_calls": (),
        "cyclomatic_complexity": 2,
    }]


def test_function_summary_rejects_ambiguous_or_noncanonical_rows() -> None:
    description = """Contract Vault
Contract vars: []
| Function | Visibility | Modifiers | Read | Write | Internal Calls | External Calls | Cyclomatic Complexity |
| f() | public | [] | [] | [] | [] | [] | not-an-int |
+---+
"""
    with pytest.raises(ValueError, match="complexity"):
        recon._slither_cli_function_rows(_printer(description))

    ambiguous = _printer(description)
    ambiguous["results"]["printers"].append({"description": description})
    with pytest.raises(ValueError, match="ambiguous"):
        recon._slither_cli_function_rows(ambiguous)


def test_slither_compiler_signature_binds_overloaded_source_declaration(
    tmp_path,
) -> None:
    source = tmp_path / "contracts" / "GatewaySend.sol"
    source.parent.mkdir()
    source.write_text(
        """contract GatewaySend {
    function depositAndCall(
        address fromToken,
        uint256 amount,
        bytes calldata payload
    ) public payable {}

    function depositAndCall(
        address targetContract,
        uint256 amount
    ) public payable {}
}
""",
        encoding="utf-8",
    )
    first = "contracts/GatewaySend.sol::GatewaySend.depositAndCall@L2:C5"
    second = "contracts/GatewaySend.sol::GatewaySend.depositAndCall@L8:C5"
    functions = {
        first: {"bare": "depositAndCall", "loc": "contracts/GatewaySend.sol:L2"},
        second: {"bare": "depositAndCall", "loc": "contracts/GatewaySend.sol:L8"},
    }
    keys = {("GatewaySend", "depositAndCall"): [first, second]}

    assert recon._resolve_slither_source_function(
        tmp_path,
        functions,
        keys,
        contract="GatewaySend",
        raw_signature="depositAndCall(address,uint256,bytes)",
    ) == first
    assert recon._resolve_slither_source_function(
        tmp_path,
        functions,
        keys,
        contract="GatewaySend",
        raw_signature="GatewaySend.depositAndCall(address,uint256)",
    ) == second
    assert recon._resolve_slither_source_function(
        tmp_path,
        functions,
        keys,
        contract="GatewaySend",
        raw_signature="depositAndCall(bytes32)",
    ) is None


def test_inherited_printer_row_is_not_confused_with_local_override(
    tmp_path,
) -> None:
    source = tmp_path / "contracts" / "Gateway.sol"
    source.parent.mkdir()
    source.write_text(
        """contract Gateway {
    modifier onlyGateway() { _; }
    function _authorizeUpgrade(address next) internal override onlyOwner {}
    function onCall(bytes calldata message) external onlyGateway {}
}
""",
        encoding="utf-8",
    )
    authorize = "contracts/Gateway.sol::Gateway._authorizeUpgrade@L3:C5"
    on_call = "contracts/Gateway.sol::Gateway.onCall@L4:C5"
    functions = {
        authorize: {
            "bare": "_authorizeUpgrade",
            "loc": "contracts/Gateway.sol:L3",
        },
        on_call: {"bare": "onCall", "loc": "contracts/Gateway.sol:L4"},
    }
    inherited_authorize = {
        "visibility": "internal",
        "modifiers": (),
    }
    local_authorize = {
        "visibility": "internal",
        "modifiers": ("onlyOwner",),
    }
    inherited_on_call = {
        "visibility": "external",
        "modifiers": (),
    }
    local_on_call = {
        "visibility": "external",
        "modifiers": ("onlyGateway",),
    }

    assert recon._select_slither_source_row(
        tmp_path,
        functions,
        authorize,
        [inherited_authorize, local_authorize],
    ) is local_authorize
    assert recon._select_slither_source_row(
        tmp_path,
        functions,
        on_call,
        [inherited_on_call, local_on_call],
    ) is local_on_call


def test_ambiguous_slither_rows_do_not_gain_source_authority(tmp_path) -> None:
    source = tmp_path / "contracts" / "C.sol"
    source.parent.mkdir()
    source.write_text(
        "contract C { function f() external {} }\n",
        encoding="utf-8",
    )
    identity = "contracts/C.sol::C.f@L1:C14"
    functions = {
        identity: {"bare": "f", "loc": "contracts/C.sol:L1"},
    }
    first = {"visibility": "external", "modifiers": (), "reads": ("x",)}
    second = {"visibility": "external", "modifiers": (), "reads": ("y",)}

    assert recon._select_slither_source_row(
        tmp_path,
        functions,
        identity,
        [first, second],
    ) is None
    assert recon._select_slither_source_row(
        tmp_path,
        functions,
        identity,
        [dict(first), dict(first)],
    ) == first


def test_foundry_graph_skip_preserves_profile_and_excludes_only_project_scope(
    tmp_path,
) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "contracts" / "mocks").mkdir(parents=True)
    (tmp_path / "test").mkdir()
    (tmp_path / "lib" / "dependency" / "mocks").mkdir(parents=True)
    (tmp_path / "src" / "Live.sol").write_text(
        "contract Live {}\n", encoding="utf-8"
    )
    (tmp_path / "contracts" / "mocks" / "GatewayMock.sol").write_text(
        "contract GatewayMock {}\n", encoding="utf-8"
    )
    (tmp_path / "test" / "Live.t.sol").write_text(
        "contract LiveTest {}\n", encoding="utf-8"
    )
    (tmp_path / "lib" / "dependency" / "mocks" / "DependencyMock.sol").write_text(
        "contract DependencyMock {}\n", encoding="utf-8"
    )
    (tmp_path / "foundry.toml").write_text(
        '[profile.default]\nlibs = ["lib"]\nskip = ["legacy/generated"]\n',
        encoding="utf-8",
    )

    assert recon._foundry_graph_skip_paths(tmp_path, profile=None) == (
        "contracts/mocks/GatewayMock.sol",
        "legacy/generated",
        "test/Live.t.sol",
    )


def test_empty_contract_table_stops_before_following_printer_table() -> None:
    description = """Contract Empty
Contract vars: []
+----------+------------+-----------+------+-------+----------------+----------------+-----------------------+
| Function | Visibility | Modifiers | Read | Write | Internal Calls | External Calls | Cyclomatic Complexity |
+----------+------------+-----------+------+-------+----------------+----------------+-----------------------+
+----------+------------+-----------+------+-------+----------------+----------------+-----------------------+
| Modifiers | Visibility | Read | Write | Internal Calls | External Calls | Cyclomatic Complexity |
Contract Vault
Contract vars: []
+----------+------------+-----------+------+-------+----------------+----------------+-----------------------+
| Function | Visibility | Modifiers | Read | Write | Internal Calls | External Calls | Cyclomatic Complexity |
+----------+------------+-----------+------+-------+----------------+----------------+-----------------------+
| f() | public | [] | [] | [] | [] | [] | 1 |
+----------+------------+-----------+------+-------+----------------+----------------+-----------------------+
"""
    rows = recon._slither_cli_function_rows(_printer(description))
    assert [row["contract"] for row in rows] == ["Vault"]
