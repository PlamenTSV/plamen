"""Qualified-scope regressions for the L-04 critical-asset mover deriver."""

from __future__ import annotations

import importlib
import json
import os
import sys
from pathlib import Path


def _gate():
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    return importlib.import_module("enumeration_gate")


def _project(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "project"
    scratch = root / ".scratchpad"
    scratch.mkdir(parents=True)
    (scratch / "findings_inventory.md").write_text("# Inventory\n", encoding="utf-8")
    return root, scratch


def _source(root: Path, relative: str, text: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _graph(scratch: Path, rows: dict) -> None:
    (scratch / "_mechanical_graph.json").write_text(
        json.dumps({"source": "evm-source", "var_refs": rows, "functions": {}}),
        encoding="utf-8",
    )


def test_same_file_contracts_with_same_bare_state_do_not_cross_pair(
    tmp_path: Path,
) -> None:
    gate = _gate()
    root, scratch = _project(tmp_path)
    _source(
        root,
        "Vaults.sol",
        """
        contract Alpha {
            uint256 positionId;
            function withdrawAlpha(address token, uint256 tokenId, address to) external {
                require(tokenId != positionId);
                IERC721(token).safeTransferFrom(address(this), to, tokenId);
            }
        }
        contract Beta {
            uint256 positionId;
            function withdrawBeta(address token, uint256 tokenId, address to) external {
                IERC721(token).safeTransferFrom(address(this), to, tokenId);
            }
        }
        """,
    )
    _graph(scratch, {
        "Vaults.sol::Alpha.positionId": {
            "bare": "positionId",
            "declaration_locus": "Vaults.sol:L3",
            "refs": ["alphaOne (Vaults.sol:L4)", "alphaTwo (Vaults.sol:L5)"],
        },
        "Vaults.sol::Beta.positionId": {
            "bare": "positionId",
            "declaration_locus": "Vaults.sol:L10",
            "refs": ["betaOne (Vaults.sol:L11)", "betaTwo (Vaults.sol:L12)"],
        },
    })

    rows = gate.compute_critical_asset_mover_candidates(scratch)

    assert len(rows) == 1
    assert "Vaults.sol::Beta.withdrawBeta" in rows[0]["key"]
    assert rows[0]["key"].endswith("Vaults.sol::Beta.positionId")
    assert "Alpha.positionId" not in rows[0]["key"]


def test_cross_file_duplicate_members_keep_distinct_candidate_identity(
    tmp_path: Path,
) -> None:
    gate = _gate()
    root, scratch = _project(tmp_path)
    for relative, contract in (("A.sol", "A"), ("B.sol", "B")):
        _source(
            root,
            relative,
            f"""
            contract {contract} {{
                uint256 tokenId;
                function withdraw(address token, uint256 movedTokenId, address to) external {{
                    IERC721(token).safeTransferFrom(address(this), to, movedTokenId);
                }}
            }}
            """,
        )
    _graph(scratch, {
        "A.sol::A.tokenId": {
            "bare": "tokenId",
            "declaration_locus": "A.sol:L3",
            "refs": ["aOne (A.sol:L8)", "aTwo (A.sol:L9)"],
        },
        "B.sol::B.tokenId": {
            "bare": "tokenId",
            "declaration_locus": "B.sol:L3",
            "refs": ["bOne (B.sol:L8)", "bTwo (B.sol:L9)"],
        },
    })

    rows = gate.compute_critical_asset_mover_candidates(scratch)

    keys = {row["key"] for row in rows}
    assert len(keys) == 2
    assert any(key.endswith("A.sol::A.tokenId") for key in keys)
    assert any(key.endswith("B.sol::B.tokenId") for key in keys)


def test_same_line_overload_reference_does_not_suppress_distinct_mover(
    tmp_path: Path,
) -> None:
    gate = _gate()
    root, scratch = _project(tmp_path)
    _source(
        root,
        "Overloads.sol",
        """contract Vault { uint256 positionId;
function withdraw(address token, uint256 tokenId, address to) external { require(tokenId != positionId); IERC721(token).safeTransferFrom(address(this), to, tokenId); } function withdraw(uint256 tokenId, address token, address to) external { IERC721(token).safeTransferFrom(address(this), to, tokenId); }
}
""",
    )
    _graph(scratch, {
        "Overloads.sol::Vault.positionId": {
            "bare": "positionId",
            "declaration_locus": "Overloads.sol:L1",
            # The source-tier descriptor cannot distinguish the two overloads
            # because both declarations occupy L2. It must not suppress both.
            "refs": [
                "withdraw (Overloads.sol:L2)",
                "dependent (Overloads.sol:L2)",
            ],
        },
    })

    rows = gate.compute_critical_asset_mover_candidates(scratch)

    assert len(rows) == 1
    key = rows[0]["key"]
    assert "Overloads.sol::Vault.withdraw@L2:C" in key
    assert key.endswith("Overloads.sol::Vault.positionId")


def test_lexical_occurrence_is_not_declaration_authority(tmp_path: Path) -> None:
    gate = _gate()
    root, scratch = _project(tmp_path)
    _source(
        root,
        "Mover.sol",
        """
        contract Mover {
            function withdraw(address token, uint256 tokenId, address to) external {
                IERC721(token).safeTransferFrom(address(this), to, tokenId);
            }
        }
        """,
    )
    _graph(scratch, {
        "Missing.sol::Missing.positionId": {
            "bare": "positionId",
            "declaration_locus": "Missing.sol:L7",
            "refs": ["one (Missing.sol:L9)", "two (Missing.sol:L10)"],
        },
    })

    assert gate.compute_critical_asset_mover_candidates(scratch) == []
    receipt = json.loads(
        (scratch / "_coverage_shortfalls.json").read_text(encoding="utf-8")
    )
    assert any(
        row["kind"] == "DECLARATION_SCOPE_UNKNOWN"
        and "Missing.sol::Missing.positionId" in row["samples"]
        for row in receipt["shortfalls"]
    )


def test_inherited_state_relation_is_unknown_not_cross_contract_guess(
    tmp_path: Path,
) -> None:
    gate = _gate()
    root, scratch = _project(tmp_path)
    _source(
        root,
        "Inherited.sol",
        """
        contract Base {
            uint256 positionId;
        }
        contract Derived is Base {
            function withdraw(address token, uint256 tokenId, address to) external {
                IERC721(token).safeTransferFrom(address(this), to, tokenId);
            }
        }
        """,
    )
    _graph(scratch, {
        "Inherited.sol::Base.positionId": {
            "bare": "positionId",
            "declaration_locus": "Inherited.sol:L3",
            "refs": ["one (Inherited.sol:L8)", "two (Inherited.sol:L9)"],
        },
    })

    assert gate.compute_critical_asset_mover_candidates(scratch) == []
    receipt = json.loads(
        (scratch / "_coverage_shortfalls.json").read_text(encoding="utf-8")
    )
    assert any(
        row["kind"] == "INHERITED_STATE_SCOPE_UNRESOLVED"
        and any("Derived.withdraw" in sample for sample in row["samples"])
        for row in receipt["shortfalls"]
    )


def test_non_evm_bare_identity_behavior_is_unchanged(tmp_path: Path) -> None:
    gate = _gate()
    root, scratch = _project(tmp_path)
    _source(
        root,
        "lib.rs",
        """
        pub fn position_id() -> u64 { 0 }
        pub fn withdraw_nft(token: TokenClient, to: Address, id: u64) {
            token.transfer(&to, &id);
        }
        """,
    )
    (scratch / "_mechanical_graph.json").write_text(
        json.dumps({
            "source": "rust-source",
            "var_refs": {
                "position_id": {
                    "bare": "position_id",
                    "refs": ["one (lib.rs:L1)", "two (lib.rs:L2)"],
                },
            },
            "functions": {},
        }),
        encoding="utf-8",
    )

    rows = gate.compute_critical_asset_mover_candidates(scratch)

    assert [row["key"] for row in rows] == [
        "ASSETMOVE:lib.rs:withdraw_nft:position_id"
    ]


def test_qualified_non_evm_graph_key_keeps_legacy_bare_candidate_id(
    tmp_path: Path,
) -> None:
    gate = _gate()
    root, scratch = _project(tmp_path)
    _source(
        root,
        "lib.rs",
        """
        pub fn position_id() -> u64 { 0 }
        pub fn withdraw_nft(token: TokenClient, to: Address, id: u64) {
            token.transfer(&to, &id);
        }
        """,
    )
    (scratch / "_mechanical_graph.json").write_text(
        json.dumps({
            "source": "scip-rust",
            "var_refs": {
                "crate::Vault.position_id": {
                    "bare": "position_id",
                    "refs": ["one (lib.rs:L1)", "two (lib.rs:L2)"],
                },
            },
            "functions": {},
        }),
        encoding="utf-8",
    )

    rows = gate.compute_critical_asset_mover_candidates(scratch)

    assert [row["key"] for row in rows] == [
        "ASSETMOVE:lib.rs:withdraw_nft:position_id"
    ]
