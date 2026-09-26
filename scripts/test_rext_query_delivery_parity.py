"""The Claude R-EXT worker must receive the queries its gate will admit.

Every Claude run to date reported `dependency parity: researched=0
unresolved=25`, against Codex's `researched=24 unresolved=1`. That was an
UNWINNABLE CONTRACT, not worker failure:

  * the bounded-web gate admits a WebSearch ONLY when its query matches a
    pre-registered canonical query byte-for-byte, else `WEB_QUERY_UNREGISTERED`;
  * `_recon_worker_prompt` branched on backend -- the CODEX branch is handed
    "every obligation row and exact query group" before spawn, while the CLAUDE
    branch was told only to read `external_dependency_obligations.json`;
  * that file carries NO query field (run34's 25 obligations have keys
    {declaration_evidence, dependency, kind, obligation_id, research_question,
    source_location});
  * both branches then say "for each listed query group, issue exactly its one
    authorized WebSearch" -- so on Claude the worker was told to use a list it
    was never given, invented free-form queries, and had every one denied.

The derivation was already cross-provider; only DELIVERY was Codex-only. This
pins that the Claude prompt now carries the same canonical groups, and -- the
property that actually matters -- that every delivered query is one the gate
will accept. A delivered query the gate would reject is worse than none.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import claude_phase_tool_policy as P  # noqa: E402
import plamen_driver as D  # noqa: E402
from dependency_obligations import _stable_id  # noqa: E402


def _row(dependency: str, kind: str, question: str, locus: str, evidence: str):
    """Build a row with a PRODUCT-DERIVED id (it is a digest of the row)."""
    return {
        "obligation_id": _stable_id(kind, dependency, locus),
        "dependency": dependency,
        "kind": kind,
        "research_question": question,
        "source_location": locus,
        "declaration_evidence": evidence,
    }


# The compiler requires canonically ordered rows, so sort by obligation_id.
_OBLIGATION_ROWS = sorted(
    (
    _row("@openzeppelin/contracts", "source-import",
         "Determine the externally defined semantics.",
         "contracts/A.sol:L1", 'import "@openzeppelin/contracts/x.sol";'),
    _row("@openzeppelin/contracts", "source-import",
         "Determine the externally defined semantics.",
         "contracts/B.sol:L1", 'import "@openzeppelin/contracts/y.sol";'),
    _row("@uniswap/v2-core", "source-import",
         "Determine swap invariants.",
         "contracts/C.sol:L2", 'import "@uniswap/v2-core/z.sol";'),
    ),
    key=lambda row: row["obligation_id"],
)

# Envelope shape copied from a real run (run34's
# `external_dependency_obligations.json`); the compiler validates the exact
# denominator, so a hand-rolled shape is rejected.
_OBLIGATIONS = {
    "schema": "plamen.external-dependency-obligations.v1",
    "provider": "deterministic-direct-nonlocal-referenced-v1",
    "obligations": _OBLIGATION_ROWS,
    "observed_count": len(_OBLIGATION_ROWS),
    "retained_count": len(_OBLIGATION_ROWS),
    "overflow_ids": [],
    "truncated": False,
}


def _seed(tmp_path: Path) -> Path:
    (tmp_path / "external_dependency_obligations.json").write_text(
        json.dumps(_OBLIGATIONS), encoding="utf-8",
    )
    return tmp_path


def _delivered(block: str) -> list[str]:
    return [
        line.split("query: ", 1)[1]
        for line in block.splitlines()
        if line.strip().startswith("query: ")
    ]


def test_block_is_emitted_for_the_rext_role(tmp_path: Path) -> None:
    block = D._recon_dependency_query_projection(
        _seed(tmp_path), "external_dependency_research"
    )
    assert "Authorized web query groups" in block
    assert _delivered(block), "no queries were delivered to the worker"


@pytest.mark.parametrize(
    "role", ["inventory_surface", "templates_patterns", "build_static"],
)
def test_other_roles_receive_nothing(tmp_path: Path, role: str) -> None:
    assert D._recon_dependency_query_projection(_seed(tmp_path), role) == ""


def test_every_delivered_query_is_gate_admissible(tmp_path: Path) -> None:
    """THE property: a delivered query the gate rejects is worse than none."""
    block = D._recon_dependency_query_projection(
        _seed(tmp_path), "external_dependency_research"
    )
    authority = P.build_dependency_research_network_authority(_OBLIGATIONS)
    admitted = {str(row["query"]) for row in authority["obligations"]}
    rejected = [q for q in _delivered(block) if q not in admitted]
    assert rejected == [], (
        f"these delivered queries would be denied WEB_QUERY_UNREGISTERED: "
        f"{rejected}"
    )


def test_grouping_matches_the_shared_compiler(tmp_path: Path) -> None:
    """No second derivation: grouping must equal the cross-provider compiler."""
    block = D._recon_dependency_query_projection(
        _seed(tmp_path), "external_dependency_research"
    )
    _rows, groups = P.dependency_research_projection_rows_and_groups(_OBLIGATIONS)
    assert len(_delivered(block)) == len(groups)
    # The two same-dependency obligations must share one query group.
    assert len(groups) == 2, groups
    oz = sorted(
        r["obligation_id"] for r in _OBLIGATION_ROWS
        if r["dependency"] == "@openzeppelin/contracts"
    )
    assert ", ".join(oz) in block, (
        f"same-dependency obligations must share one query group: {oz}"
    )


def test_missing_or_malformed_obligations_do_not_block_assembly(
    tmp_path: Path,
) -> None:
    """Prompt assembly must never fail on projection trouble."""
    assert D._recon_dependency_query_projection(
        tmp_path, "external_dependency_research"
    ) == ""
    (tmp_path / "external_dependency_obligations.json").write_text(
        "{not json", encoding="utf-8",
    )
    assert D._recon_dependency_query_projection(
        tmp_path, "external_dependency_research"
    ) == ""
