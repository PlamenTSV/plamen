"""R10.1 fixtures for narrow external-premise un-demotion behavior.

The cases are intentionally generic.  They lock three rules:
* REFUTED can be reopened only from a positive depth anchor and an uncited,
  decisive external premise;
* lexical stability is not external provenance by itself;
* until premise-to-execution attestation exists, any executed PoC keeps the
  conservative G3 no-fire behavior.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import plamen_validators as V


def _scratch(tmp_path: Path) -> Path:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    (scratchpad / "config.json").write_text(json.dumps({}), encoding="utf-8")
    return scratchpad


def _queue(scratchpad: Path, fid: str, severity: str = "Low") -> None:
    (scratchpad / "verification_queue.md").write_text(
        "| Queue # | Finding ID | Severity | Title | PoC Class |\n"
        "|---------|------------|----------|-------|-----------|\n"
        f"| 1 | {fid} | {severity} | generic external-boundary finding | unit |\n",
        encoding="utf-8",
    )


def _inventory(
    scratchpad: Path,
    fid: str,
    *,
    verdict: str,
    external_provenance: bool,
) -> None:
    description = "A state transition uses a locally computed value."
    if external_provenance:
        description = (
            "A state transition consumes a value returned by a non-vendored "
            "dependency. [EXTERNAL-ASSUMPTION: returned rate may change "
            "between calls] NEEDS_DEPENDENCY_RESEARCH: dependency rate "
            "stability across calls."
        )
    (scratchpad / "findings_inventory.md").write_text(
        f"### Finding [{fid}] Generic finding\n\n"
        "**Severity**: Low\n\n"
        f"**Verdict**: {verdict}\n\n"
        "**Location**: `src/adapter.rs:L42`\n\n"
        f"**Description**: {description}\n",
        encoding="utf-8",
    )


def _mapping(scratchpad: Path, inventory_id: str, hypothesis_id: str) -> None:
    (scratchpad / "finding_mapping.md").write_text(
        "# Finding Mapping\n\n## INV Finding -> Hypothesis\n\n"
        "| Finding ID | Hypothesis ID | Mapping Status |\n"
        "|------------|---------------|----------------|\n"
        f"| {inventory_id} | {hypothesis_id} | PRIMARY |\n",
        encoding="utf-8",
    )
    (scratchpad / "hypotheses.md").write_text("# Hypotheses\n", encoding="utf-8")


def _verify(
    scratchpad: Path,
    fid: str,
    *,
    verdict: str,
    reasoning: str,
    attempted: str = "NO",
    result: str = "NOT_EXECUTED",
    ext_cited: bool = False,
) -> None:
    citation = ""
    if ext_cited:
        citation = (
            "[EXT-CITED: external dependency, source=https://docs.example/spec, "
            "fetched=2026-07-15]\n\n"
        )
    (scratchpad / f"verify_{fid}.md").write_text(
        "**Severity**: Low\n\n"
        f"**Verdict**: {verdict}\n\n"
        "**Location**: `src/adapter.rs:L42`\n\n"
        "**Evidence Tag**: [CODE-TRACE]\n\n"
        f"{reasoning}\n\n{citation}"
        "### PoC Attempt\n"
        "- PoC Required: YES\n"
        f"- Attempted: {attempted}\n"
        "- PoC Not Attempted Because: "
        f"{'N/A' if attempted == 'YES' else 'EXTERNAL_DEPENDENCY_NO_FORK_OR_ADDRESS'}\n\n"
        "### Execution Result\n"
        f"- Result: {result}\n",
        encoding="utf-8",
    )


def _research(scratchpad: Path, *, with_surface: bool = False) -> None:
    row = "| external dependency | src/adapter.rs:L42 |\n" if with_surface else ""
    (scratchpad / "external_dependency_research.md").write_text(
        "# External Dependency Research\n\n"
        "| Dependency | Integration Surface |\n"
        "|------------|---------------------|\n"
        f"{row}",
        encoding="utf-8",
    )


_DECISIVE_EXTERNAL = (
    "The local mechanism exists, but the finding is REFUTED because the "
    "external dependency's returned rate is stable within a block; as long "
    "as that favorable condition holds, no harm can materialize. "
    "[EXTERNAL-ASSUMPTION: external returned rate is stable within a block]"
)


def test_refuted_on_uncited_decisive_external_premise_fires(tmp_path: Path) -> None:
    scratchpad = _scratch(tmp_path)
    _queue(scratchpad, "H-801")
    _inventory(
        scratchpad, "INV-801", verdict="CONFIRMED", external_provenance=True
    )
    _mapping(scratchpad, "INV-801", "H-801")
    _verify(
        scratchpad,
        "H-801",
        verdict="REFUTED",
        reasoning=_DECISIVE_EXTERNAL,
    )
    _research(scratchpad)

    fired = V._apply_external_assumption_undemotions(scratchpad, "core")

    assert {row["finding_id"] for row in fired} == {"H-801"}
    assert fired[0]["depth_verdict"] == "CONFIRMED"
    assert "[UNPROVEN-EXTERNAL]" in (
        scratchpad / "verify_H-801.md"
    ).read_text(encoding="utf-8")


def test_refuted_with_background_external_mention_but_internal_basis_no_fire(
    tmp_path: Path,
) -> None:
    scratchpad = _scratch(tmp_path)
    _queue(scratchpad, "INV-808")
    _inventory(
        scratchpad, "INV-808", verdict="CONFIRMED", external_provenance=True
    )
    _verify(
        scratchpad,
        "INV-808",
        verdict="REFUTED",
        reasoning=(
            "An external dependency exists. [EXTERNAL-ASSUMPTION: its returned "
            "rate may vary]. The finding is REFUTED because an in-scope bound "
            "rejects every unsafe value, so no harm can occur."
        ),
    )
    _research(scratchpad)

    assert V._apply_external_assumption_undemotions(scratchpad, "core") == []


def test_refuted_with_all_depth_constituents_refuted_does_not_fire(
    tmp_path: Path,
) -> None:
    scratchpad = _scratch(tmp_path)
    _queue(scratchpad, "INV-802")
    _inventory(
        scratchpad, "INV-802", verdict="REFUTED", external_provenance=True
    )
    _verify(
        scratchpad,
        "INV-802",
        verdict="REFUTED",
        reasoning=_DECISIVE_EXTERNAL,
    )
    _research(scratchpad)

    assert V._apply_external_assumption_undemotions(scratchpad, "core") == []


def test_refuted_with_matching_external_citation_does_not_fire(
    tmp_path: Path,
) -> None:
    scratchpad = _scratch(tmp_path)
    _queue(scratchpad, "INV-803")
    _inventory(
        scratchpad, "INV-803", verdict="CONFIRMED", external_provenance=True
    )
    _verify(
        scratchpad,
        "INV-803",
        verdict="REFUTED",
        reasoning=_DECISIVE_EXTERNAL,
        ext_cited=True,
    )
    _research(scratchpad, with_surface=True)

    assert V._apply_external_assumption_undemotions(scratchpad, "core") == []


@pytest.mark.parametrize("verdict", ["FALSE_POSITIVE", "DUPLICATE"])
def test_nonfinding_dispositions_never_reopen(
    tmp_path: Path,
    verdict: str,
) -> None:
    scratchpad = _scratch(tmp_path)
    _queue(scratchpad, "INV-804")
    _inventory(
        scratchpad, "INV-804", verdict="CONFIRMED", external_provenance=True
    )
    _verify(
        scratchpad,
        "INV-804",
        verdict=verdict,
        reasoning=_DECISIVE_EXTERNAL,
    )
    _research(scratchpad)

    assert V._apply_external_assumption_undemotions(scratchpad, "core") == []


def test_internal_stability_language_without_external_provenance_does_not_fire(
    tmp_path: Path,
) -> None:
    scratchpad = _scratch(tmp_path)
    _queue(scratchpad, "INV-805")
    _inventory(
        scratchpad, "INV-805", verdict="CONFIRMED", external_provenance=False
    )
    _verify(
        scratchpad,
        "INV-805",
        verdict="CONTESTED",
        reasoning=(
            "The internal accumulator is stable within a block, so "
            "the in-scope arithmetic remains safe."
        ),
    )
    _research(scratchpad)

    assert V._apply_external_assumption_undemotions(scratchpad, "core") == []


def test_mapped_constituent_external_provenance_enables_stability_route(
    tmp_path: Path,
) -> None:
    scratchpad = _scratch(tmp_path)
    _queue(scratchpad, "H-806")
    _inventory(
        scratchpad, "INV-806", verdict="CONFIRMED", external_provenance=True
    )
    _mapping(scratchpad, "INV-806", "H-806")
    _verify(
        scratchpad,
        "H-806",
        verdict="CONTESTED",
        reasoning=(
            "The mismatch is harmless because the returned rate is stable "
            "within a ledger and a fresh read cannot differ."
        ),
    )
    _research(scratchpad)

    fired = V._apply_external_assumption_undemotions(scratchpad, "core")
    assert {row["finding_id"] for row in fired} == {"H-806"}
    assert fired[0]["depth_verdict"] == "CONFIRMED"


@pytest.mark.parametrize(
    ("scope_line", "result"),
    [
        ("- PoC Assertion Scope: LOCAL_MECHANISM", "PASS"),
        ("- PoC Assertion Scope: EXTERNAL_PREMISE", "FAIL"),
        ("", "PASS"),
    ],
)
def test_executed_poc_scope_is_conservatively_deferred_without_attestation(
    tmp_path: Path,
    scope_line: str,
    result: str,
) -> None:
    """An agent-authored scope label is not premise-resolving attestation.

    R10.1 therefore preserves G3 for local-only, external-labelled, and
    ambiguous executions until the general premise/disposition model binds the
    tested assertion to mechanically observed evidence.
    """
    scratchpad = _scratch(tmp_path)
    _queue(scratchpad, "INV-807")
    _inventory(
        scratchpad, "INV-807", verdict="CONFIRMED", external_provenance=True
    )
    reasoning = _DECISIVE_EXTERNAL
    if scope_line:
        reasoning += f"\n{scope_line}"
    _verify(
        scratchpad,
        "INV-807",
        verdict="REFUTED",
        reasoning=reasoning,
        attempted="YES",
        result=result,
    )
    _research(scratchpad)

    assert V._apply_external_assumption_undemotions(scratchpad, "core") == []
