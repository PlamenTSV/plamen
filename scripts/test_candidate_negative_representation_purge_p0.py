"""Metamorphic + adversarial controls for candidate_negative_authority.py.

Every gate this file covers was PROVEN representation-bound: a presentation-only
mutation of a real worker artifact flipped the verdict from accepted to
discarded.  The contract asserted here is Principle 4 (metamorphic testing):

    semantically equivalent inputs MUST produce equivalent verdicts

paired, for every gate, with an ADVERSARIAL CONTROL proving a mutation that
really does change meaning is STILL rejected.  A fix that accepts everything is
a worse bug than the one being fixed.

The Markdown bodies below are copied from the real DODO run46/run47/run48
worker outputs named in the audit inventory.  They are pasted, never read from
disk at runtime.
"""
from __future__ import annotations

from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import artifact_surface as AS  # noqa: E402
import candidate_negative_authority as CN  # noqa: E402


METHODOLOGY = b"# finding-output-format\n\nProducer dispositions are proposals.\n"


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


def _ledger(body: str, *, phase: str = "depth"):
    artifact = CN.ArtifactInput(
        relative_path="analysis_probe.md",
        content=body.encode("utf-8"),
        producer_identity="worker",
        producer_invocation_id="i" * 32,
    )
    return CN._build_candidate_negative_ledger_from_bytes(
        phase=phase,
        artifacts=(artifact,),
        methodology_bytes=METHODOLOGY,
        methodology_identity=CN._STAGED_METHODOLOGY_IDENTITY,
    )


def _staged(body: str, *, phase: str = "depth"):
    """-> (accepted, reasons) through the REAL staged validator."""
    identity = "scratchpad:analysis_probe.md"
    context = CN.compile_candidate_negative_staged_context(
        METHODOLOGY, identity, "worker", phase=phase, invocation_id="i" * 32
    )
    return CN.evaluate_staged_candidate_negative_receipt(
        {identity: body.encode("utf-8")}, context
    )


def _codes(body: str, *, phase: str = "depth") -> set[str]:
    return {str(issue.get("code")) for issue in _ledger(body, phase=phase)["issues"]}


def _identities(body: str, *, phase: str = "depth") -> list[str]:
    return [event["source_item_id"] for event in _ledger(body, phase=phase)["events"]]


def _states(body: str, *, phase: str = "depth") -> list[str]:
    return [event["identity_state"] for event in _ledger(body, phase=phase)["events"]]


# ---------------------------------------------------------------------------
# Real worker bytes
# ---------------------------------------------------------------------------

# DODO run48, worker.depth-state-trace.attempt-0002, 126,589 bytes, receipt
# subtype=success.  Deleting the two bracket characters from this ONE heading
# discarded the whole analysis, which carried DS-6/DS-7/DS-8.
RUN48_DS6 = '''## Finding [DS-6]: Mechanical "writes state with no access gate" on the inbound handlers — refutation proposal

**Verdict**: REFUTATION_PROPOSAL
**Preferred Tag**: CODE-TRACE
**Severity**: Informational
**Location**: contracts/GatewayCrossChain.sol:517
**Description**: every declaration carries the `onlyGateway` modifier on the declaration line itself.
**Reason**: the modifier reverts with `Unauthorized()` before the function body runs.
**Invariant Commitment**: CI:CI-6

committed-invariant [CI-6]
Locus: contracts/GatewayCrossChain.sol:L517
Shape: NO_REVERT_AT_BOUNDARY
Assertion: a non-gateway caller never reaches an SSTORE in onRevert
Falsify Class: boundary
Provenance: DS-6
'''

# DODO run46, breadth methodology_repair.model, 70,540 bytes.  Rejected solely
# because the worker wrote the CORRECT nonterminal enum with a sentence-ending
# period attached.
RUN46_ENUM = """## 5. Emission / rebase gate

Outcome: **NOT_APPLICABLE_PROPOSAL**. §5 is gated on "IF emission/rebase detected".

| Finding ID | Disposition | Notes |
|---|---|---|
| — | NOT_APPLICABLE_PROPOSAL | no emission primitive exists |
"""

# DODO run46, rescan worker.pc5, 10,220 bytes.  Its whole body is a
# zero-candidate attestation written as FIELDS rather than as a table row.
RUN46_FIELD_ATTESTATION = """## No Findings

**Disposition**: `NOT_APPLICABLE_PROPOSAL`
**Finding ID**: — (no new candidate for this shard)
"""

# DODO run48: an obligation receipt the worker wrapped in backticks so it
# renders as code.  Four of these produced "malformed obligation receipt-like
# line rejected".
RUN48_RECEIPTS = """## Obligation Dispositions

[OBLIG:security_obligations.md:SO-004] STATUS: D KEY: no reachable sink for the tainted length
"""


# ===========================================================================
# GATE 1 -- _normalize_legacy  (property: disposition.producer_enum)
# ===========================================================================


@pytest.mark.parametrize(
    "spelling",
    [
        "NOT_APPLICABLE_PROPOSAL",
        "NOT_APPLICABLE_PROPOSAL.",
        "NOT_APPLICABLE_PROPOSAL: no emission",
        "NOT_APPLICABLE_PROPOSAL (no emission)",
        "NOT_APPLICABLE_PROPOSAL - no emission",
        "**NOT_APPLICABLE_PROPOSAL**.",
        "`NOT_APPLICABLE_PROPOSAL`",
        "not_applicable_proposal",
        "NOT-APPLICABLE-PROPOSAL",
    ],
)
def test_metamorphic_nonterminal_enum_survives_punctuation(spelling: str) -> None:
    """The one-period, 70,540-byte discard, fixed at the root."""
    assert CN._normalize_legacy(spelling) == "NOT_APPLICABLE_PROPOSAL"


@pytest.mark.parametrize(
    "spelling", ["REFUTATION_PROPOSAL", "REFUTATION_PROPOSAL.", "**REFUTATION_PROPOSAL**"]
)
def test_metamorphic_refutation_enum_survives_punctuation(spelling: str) -> None:
    """Converse recall hole: `REFUTATION_PROPOSAL.` used to return None, so the
    negative left the denominator silently while the artifact was accepted."""
    assert CN._normalize_legacy(spelling) == "REFUTATION_PROPOSAL"


def test_adversarial_legacy_terminal_stays_distinct_from_the_proposal_enum() -> None:
    """ADVERSARIAL: the nonterminal enum must not swallow the legacy terminal.

    If `NOT_APPLICABLE` silently became `NOT_APPLICABLE_PROPOSAL`, a producer
    could close a real candidate with a bare `N/A` and the debt would vanish.
    """
    assert CN._normalize_legacy("NOT_APPLICABLE") == "NOT_APPLICABLE"
    assert CN._normalize_legacy("N/A") == "NOT_APPLICABLE"
    body = "### Candidate [ST-9]: live path\n\n**Verdict**: N/A\n"
    assert "EVENT_NOT_APPLICABLE_WITH_NONZERO_DENOMINATOR" in _codes(body)


def test_adversarial_prose_is_not_a_disposition() -> None:
    """ADVERSARIAL: ordinary prose that merely contains negative vocabulary is
    not authority and must still parse to None."""
    for prose in (
        "Safety of the guard was checked against the withdraw path",
        "Rounding loss on withdraw",
        "Clearly the accounting holds",
        "",
    ):
        assert CN._normalize_legacy(prose) is None


# ===========================================================================
# GATE 2/3 -- heading identity + the retired second table regex
#            (property: identity.candidate_id)
# ===========================================================================


@pytest.mark.parametrize(
    "heading",
    [
        "## Finding [DS-6]: refutation proposal",
        "## Finding DS-6: refutation proposal",
        "## **Finding [DS-6]**: refutation proposal",
        "## Finding `DS-6`: refutation proposal",
        "#### Finding [DS-6]: refutation proposal",
        "## Candidate [DS-6]: refutation proposal",
        "## Issue DS-6: refutation proposal",
        "## DS-6: refutation proposal",
    ],
)
def test_metamorphic_one_identity_many_spellings(heading: str) -> None:
    """Deleting `[` and `]` from ONE heading used to discard 126,589 bytes."""
    body = heading + "\n\n**Verdict**: REFUTATION_PROPOSAL\n**Evidence**: src/A.sol:L2\n"
    assert _identities(body) == ["DS-6"]
    assert _states(body) == ["EXACT"]
    assert "DERIVED_SOURCE_ITEM_ID" not in _codes(body)


def test_metamorphic_real_run48_artifact_survives_bracket_deletion() -> None:
    """REAL BYTES, the exact mutation from the inventory row."""
    original = _staged(RUN48_DS6)
    mutated = _staged(RUN48_DS6.replace("Finding [DS-6]", "Finding DS-6", 1))
    backticked = _staged(RUN48_DS6.replace("Finding [DS-6]", "Finding `DS-6`", 1))
    deeper = _staged(RUN48_DS6.replace("## Finding [DS-6]", "#### Finding [DS-6]", 1))
    assert original[0] is True, original
    assert mutated == original
    assert backticked == original
    assert deeper == original


def test_metamorphic_one_resolver_for_headings_and_table_cells() -> None:
    """The identical identity string used to be EXACT in a table cell and
    DERIVED in a heading: two regexes, one property."""
    for spelling in ("Finding DEPTH-TF-3", "DEPTH-TF-3", "Candidate DEPTH-TF-3"):
        heading = f"## {spelling}: rounding loss\n\n**Verdict**: REFUTATION_PROPOSAL\n"
        table = (
            "| Finding ID | Verdict |\n|---|---|\n"
            f"| {spelling} | REFUTATION_PROPOSAL |\n"
        )
        assert _identities(heading) == ["DEPTH-TF-3"], spelling
        assert _identities(table) == ["DEPTH-TF-3"], spelling


def test_adversarial_two_different_identities_never_merge() -> None:
    """ADVERSARIAL (STEP 7): the closed check must not be widened.

    Two genuinely different candidates must stay two families, two events and
    two separately re-addressable identities.  A permissive identity answer
    here would silently merge two bugs into one -- the exact failure the
    FAIL_CLOSED identity family exists to prevent.
    """
    body = (
        "## Finding DS-6: first mechanism\n\n**Verdict**: REFUTATION_PROPOSAL\n"
        "**Evidence**: src/A.sol:L2\n\n"
        "## Finding DS-7: different mechanism\n\n**Verdict**: REFUTATION_PROPOSAL\n"
        "**Evidence**: src/B.sol:L8\n"
    )
    ledger = _ledger(body)
    assert sorted(_identities(body)) == ["DS-6", "DS-7"]
    assert len({family["family_id"] for family in ledger["families"]}) == 2
    assert "DUPLICATE_SOURCE_ITEM_ID" not in _codes(body)


def test_adversarial_an_ordinary_heading_never_mints_an_identity() -> None:
    """ADVERSARIAL: a bare hyphenated English heading is a title, not an ID.

    A fabricated identity is as dangerous as a lost one: it would let an
    unrelated negative claim a candidate's join key.
    """
    for heading in ("## Cross-chain replay", "## Finding summary", "## Rounding loss"):
        body = heading + "\n\n**Verdict**: REFUTATION_PROPOSAL\n"
        assert _states(body) == ["DERIVED"], heading
        assert "DERIVED_SOURCE_ITEM_ID" in _codes(body), heading


def test_adversarial_derived_identity_is_never_promoted_or_closure_capable() -> None:
    """ADVERSARIAL / STEP 7: the FAIL_CLOSED identity property is intact.

    `DERIVED` is a transport identity.  It stays DERIVED on the event, the
    ledger stays INPUT_DEBT, and the event can never carry proof scope or
    bypass independent review -- so the candidate cannot be closed.  What
    changed is only that the artifact is no longer destroyed along with every
    OTHER candidate it carried.
    """
    body = "## An unnamed refutation\n\n**Verdict**: REFUTATION_PROPOSAL\n"
    ledger = _ledger(body)
    event = ledger["events"][0]
    assert event["identity_state"] == "DERIVED"
    assert event["source_item_id"].startswith("ENTITY-")
    assert event["proof_scope"] == "NONE"
    assert event["requires_independent_consumer"] is True
    assert ledger["status"] == "INPUT_DEBT"
    assert "DERIVED_SOURCE_ITEM_ID" in _codes(body)


def test_adversarial_a_terminal_disposition_is_still_refused() -> None:
    """ADVERSARIAL: the FAIL_CLOSED disposition gate still blocks.

    A producer event may never carry terminal authority, whatever the ledger
    is edited to say.
    """
    ledger = _ledger(RUN48_DS6)
    event = dict(ledger["events"][0])
    event["proposed_disposition"] = "SAFE"
    with pytest.raises(CN.CandidateNegativeAuthorityError):
        CN._validate_event_inner(event)
    event = dict(ledger["events"][0])
    event["proof_scope"] = "HARM"
    with pytest.raises(CN.CandidateNegativeAuthorityError):
        CN._validate_event_inner(event)


# ===========================================================================
# GATE 4 -- table identity column  (property: identity.candidate_id)
# ===========================================================================


@pytest.mark.parametrize(
    "header",
    ["Finding ID", "Candidate ID", "Issue ID", "**Finding ID**", "Finding&nbsp;ID"],
)
def test_metamorphic_identity_header_spellings(header: str) -> None:
    body = f"| {header} | Verdict |\n|---|---|\n| DE-1 | REFUTATION_PROPOSAL |\n"
    assert _identities(body) == ["DE-1"], header
    assert _states(body) == ["EXACT"], header


def test_metamorphic_an_extra_column_does_not_void_identity() -> None:
    """Adding a correct, MORE informative column used to make the gate
    strictly worse: `len(identity_indexes) != 1` dropped identity for EVERY
    row, so the artifact was discarded."""
    one = "| Finding ID | Verdict |\n|---|---|\n| DE-1 | REFUTATION_PROPOSAL |\n"
    two = (
        "| ID | Finding ID | Verdict |\n|---|---|---|\n"
        "| 1 | DE-1 | REFUTATION_PROPOSAL |\n"
    )
    assert _states(one) == ["EXACT"]
    assert _states(two) == ["EXACT"]
    assert _identities(two) == ["DE-1"]


def test_metamorphic_gfm_table_without_outer_pipes_is_still_harvested() -> None:
    """`line.strip().startswith("|")` made a legal GFM table invisible, and the
    producer's negative silently left the denominator."""
    piped = "| Finding ID | Verdict |\n|---|---|\n| DE-1 | REFUTATION_PROPOSAL |\n"
    bare = "Finding ID | Verdict\n---|---\nDE-1 | REFUTATION_PROPOSAL\n"
    assert _identities(bare) == _identities(piped) == ["DE-1"]


@pytest.mark.parametrize("header", ["Determination", "Finding Status", "Proposal", "Outcome"])
def test_metamorphic_disposition_header_synonyms(header: str) -> None:
    body = f"| Finding ID | {header} |\n|---|---|\n| DE-1 | REFUTATION_PROPOSAL |\n"
    assert _identities(body) == ["DE-1"], header


def test_adversarial_severity_column_never_disposes_a_candidate() -> None:
    """ADVERSARIAL: the ONE exclusion the measured gate got right.

    A tier column says nothing about a candidate's disposition and must never
    mint or dispose of one.
    """
    body = "| Finding ID | Severity |\n|---|---|\n| DS-6 | N/A |\n"
    assert _ledger(body)["event_count"] == 0


def test_adversarial_ambiguous_identity_cell_stays_derived() -> None:
    """ADVERSARIAL: a cell naming two candidates, or an ID plus prose, is
    genuinely ambiguous identity.  Guessing would bind a negative to the wrong
    candidate."""
    for cell in ("[A]/[B]", "DE-1 see ST-9", "DE-1 candidate"):
        body = f"| Finding ID | Verdict |\n|---|---|\n| {cell} | REFUTATION_PROPOSAL |\n"
        assert _states(body) == ["DERIVED"], cell


# ===========================================================================
# GATE 5/6 -- zero-candidate attestation  (property: identity.zero_denominator)
# ===========================================================================


@pytest.mark.parametrize(
    "placeholder",
    ["—", "–", "-", "N/A", "none", "(none)", "None new", "no new candidates", "−"],
)
def test_metamorphic_zero_candidate_placeholders(placeholder: str) -> None:
    """One codepoint used to decide between 'no candidate here' and a phantom
    candidate whose derived identity discarded the artifact."""
    body = (
        "| Finding ID | Disposition |\n|---|---|\n"
        f"| {placeholder} | NOT_APPLICABLE_PROPOSAL |\n"
    )
    assert _ledger(body)["event_count"] == 0, placeholder
    assert _ledger(body)["status"] == "CLEAN", placeholder


def test_metamorphic_zero_attestation_in_either_representation() -> None:
    """REAL BYTES (run46 rescan pc5): the identical two facts written as fields
    were invisible to a predicate that only scanned lines starting with `|`."""
    as_fields = _staged(RUN46_FIELD_ATTESTATION, phase="rescan")
    as_table = _staged(
        "## No Findings\n\n"
        "| Finding ID | Disposition |\n|---|---|\n"
        "| — | NOT_APPLICABLE_PROPOSAL |\n",
        phase="rescan",
    )
    assert as_fields[0] is True, as_fields
    assert as_fields == as_table


def test_metamorphic_zero_subject_is_column_position_free() -> None:
    """Reordering two non-status columns used to flip the verdict."""
    first = (
        "| Subject | Note | Disposition |\n|---|---|---|\n"
        "| — | shard empty | NOT_APPLICABLE_PROPOSAL |\n"
    )
    swapped = (
        "| Note | Subject | Disposition |\n|---|---|---|\n"
        "| shard empty | — | NOT_APPLICABLE_PROPOSAL |\n"
    )
    assert _ledger(first)["event_count"] == _ledger(swapped)["event_count"] == 0


def test_adversarial_a_real_candidate_is_never_read_as_a_zero_attestation() -> None:
    """ADVERSARIAL: the zero-denominator exemption must not swallow a real
    candidate.  Losing one here would delete a bug from human attention."""
    body = (
        "## Finding [B6-9]: emission backing\n\n"
        "**Verdict**: NOT_APPLICABLE_PROPOSAL\n"
        "| Finding ID | Disposition |\n|---|---|\n"
        "| — | NOT_APPLICABLE_PROPOSAL |\n"
    )
    assert _identities(body) == ["B6-9"]
    body_table = (
        "| Finding ID | Disposition |\n|---|---|\n"
        "| ST-9 | NOT_APPLICABLE_PROPOSAL |\n"
    )
    assert _identities(body_table) == ["ST-9"]


def test_adversarial_a_named_candidate_named_none_is_not_a_phantom() -> None:
    """ADVERSARIAL/precision: the cell `None` used to be parsed as a REAL
    candidate named NONE with EXACT identity -- a phantom admitted into the
    independent-review denominator."""
    body = "| Finding ID | Disposition |\n|---|---|\n| None | NOT_APPLICABLE_PROPOSAL |\n"
    assert _identities(body) == []


# ===========================================================================
# GATE 7 -- methodology self-report  (precision only; can no longer discard)
# ===========================================================================


@pytest.mark.parametrize(
    "subject", ["Check", "Subject", "Mechanism", "Scenario", "Path", "Operator", "Invariant"]
)
def test_metamorphic_methodology_subject_vocabulary(subject: str) -> None:
    """Renaming the first column to a synonym the allowlist omitted harvested a
    phantom and discarded the artifact.  Whatever the word, the artifact now
    publishes."""
    body = (
        f"| {subject} | Verdict |\n|---|---|\n"
        "| replay check before state changes | NOT_APPLICABLE_PROPOSAL |\n"
    )
    assert _staged(body)[0] is True, subject


def test_metamorphic_an_extra_self_report_row_changes_nothing() -> None:
    """Appending one free-text row used to RESCUE the artifact; removing it
    discarded it."""
    lean = (
        "| Mechanism | Verdict |\n|---|---|\n"
        "| ordering divergence | NOT_APPLICABLE_PROPOSAL |\n"
    )
    padded = lean + "| ordering | HOLDS (no divergence) |\n"
    assert _staged(lean)[0] is _staged(padded)[0] is True


# ===========================================================================
# GATES 8/9/10/11/12 -- restatement / claim / representation / mixed / N/A
#            (all: format.*, visible debt, never a discarded artifact)
# ===========================================================================


def test_metamorphic_a_restated_candidate_no_longer_discards_the_artifact() -> None:
    """REAL BYTES: appending the byte-identical section a second time used to
    reject the whole 126,589-byte analysis."""
    original = _staged(RUN48_DS6)
    restated = _staged(RUN48_DS6 + "\n## Appendix\n\n" + RUN48_DS6)
    assert original[0] is True
    assert restated[0] is True, restated


def test_metamorphic_a_trailing_period_no_longer_conflicts_a_claim() -> None:
    """Two restatements of ONE candidate differing by one character used to be
    'conflicting semantic claims' and discard the artifact."""
    base = (
        "### Finding [A-2]: Rounding loss on withdraw\n**Verdict**: REFUTED\n"
        "**Reason**: guard blocks\n**Evidence**: src/A.sol:L2\n"
    )
    dotted = (
        "\n### Finding [A-2]: Rounding loss on withdraw.\n**Verdict**: REFUTED\n"
        "**Reason**: guard blocks.\n**Evidence**: src/A.sol:L2\n"
    )
    assert "CONFLICTING_ENTITY_CLAIM" not in _codes(base + dotted)
    assert _staged(base + dotted)[0] is True


def test_metamorphic_a_summary_row_no_longer_discards_the_artifact() -> None:
    """The ordinary summary cell `N/A` in a `Status` column produced FIVE
    rejection reasons; writing `—` in the same cell, or renaming the column
    `Severity`, produced none."""
    finding = (
        "## Finding [DS-6]: refutation\n\n**Verdict**: REFUTATION_PROPOSAL\n"
        "**Evidence**: src/A.sol:L2\n"
    )
    with_na = finding + "\n| Finding ID | Status | Note |\n|---|---|---|\n| DS-6 | N/A | nothing further |\n"
    with_dash = finding + "\n| Finding ID | Status | Note |\n|---|---|---|\n| DS-6 | — | nothing further |\n"
    assert _staged(with_na)[0] is True, _staged(with_na)
    assert _staged(with_dash)[0] is True


def test_adversarial_a_genuinely_conflicting_restatement_is_still_visible() -> None:
    """ADVERSARIAL: degrading to debt must not degrade to SILENCE.

    A candidate given two different dispositions is still recorded, still
    INPUT_DEBT, still CONFLICTED, and still routed to independent review.
    """
    body = (
        "### Finding [A-2]: first mechanism\n**Verdict**: REFUTED\n"
        "**Evidence**: src/A.sol:L2\n\n"
        "### Finding [A-2]: different mechanism\n**Verdict**: SAFE\n"
        "**Evidence**: src/B.sol:L8\n"
    )
    ledger = _ledger(body)
    codes = {str(issue.get("code")) for issue in ledger["issues"]}
    assert ledger["status"] == "INPUT_DEBT"
    assert {"DUPLICATE_SOURCE_ITEM_ID", "CONFLICTING_ENTITY_CLAIM"} <= codes
    assert ledger["families"][0]["identity_state"] == "CONFLICTED"
    assert len(ledger["families"][0]["event_ids"]) == 2


def test_metamorphic_real_run46_enum_artifact_publishes() -> None:
    """REAL BYTES: `Outcome: **NOT_APPLICABLE_PROPOSAL**. §5 is gated on ...`"""
    accepted, reasons = _staged(RUN46_ENUM, phase="breadth")
    assert accepted is True, reasons


# ===========================================================================
# GATE 13 -- _FIELD_RE  (property: disposition.producer_enum, recall)
# ===========================================================================


@pytest.mark.parametrize(
    "line",
    [
        "**Verdict**: REFUTATION_PROPOSAL",
        "**Verdict:** REFUTATION_PROPOSAL",
        "Verdict: REFUTATION_PROPOSAL",
        "- **Verdict**: REFUTATION_PROPOSAL",
        "1. Verdict: REFUTATION_PROPOSAL",
        "> **Verdict**: REFUTATION_PROPOSAL",
        "`**Verdict**: REFUTATION_PROPOSAL`",
        "**Determination**: REFUTATION_PROPOSAL",
        "**Finding Status**: REFUTATION_PROPOSAL",
        "| **Verdict** | REFUTATION_PROPOSAL |",
    ],
)
def test_metamorphic_disposition_field_shapes(line: str) -> None:
    """Every `0` here was a producer negative that silently never reached
    independent review -- recall loss, invisible in the receipt."""
    body = f"## Finding [DE-9]: probe\n\n{line}\n"
    assert _identities(body) == ["DE-9"], line


# ===========================================================================
# GATE 14/15 -- obligation receipts and the obligation join key
# ===========================================================================


@pytest.mark.parametrize(
    "receipt",
    [
        "[OBLIG:OB-12] STATUS: D KEY: guard present at L44",
        "`[OBLIG:OB-12] STATUS: D KEY: guard present at L44`",
        "**[OBLIG:OB-12] STATUS: D KEY: guard present at L44**",
        "- [OBLIG:OB-12] STATUS: D KEY: guard present at L44",
        "1. [OBLIG:OB-12] STATUS: D KEY: guard present at L44",
        "> [OBLIG:OB-12] STATUS: D KEY: guard present at L44",
        "    [OBLIG:OB-12] STATUS: D KEY: guard present at L44",
        "| [OBLIG:OB-12] | STATUS: D | KEY: guard present at L44 |",
        "[OBLIG:OB-12] STATUS: DISMISSED KEY: guard present at L44",
    ],
)
def test_metamorphic_obligation_receipt_decoration(receipt: str) -> None:
    """Backtick-wrapping the receipt -- the literal run48 worker behaviour --
    harvested ZERO events, dropping the dismissal from the denominator."""
    body = f"## Obligation Dispositions\n\n{receipt}\n"
    ledger = _ledger(body)
    kinds = [event["harvest_kind"] for event in ledger["events"]]
    assert kinds == ["STRICT_OBLIGATION_RECEIPT"], receipt
    assert ledger["events"][0]["source_item_id"] == "OBLIG:OB-12"


def test_metamorphic_real_run48_receipt_publishes() -> None:
    accepted, reasons = _staged(RUN48_DS6 + "\n" + RUN48_RECEIPTS)
    assert accepted is True, reasons


def test_metamorphic_a_prose_mention_no_longer_rewrites_the_join_key() -> None:
    """Adding the explanatory clause '(this also answers [OBLIG:OB-9])' moved
    the candidate to a DIFFERENT family, so the ledger/plan join key was
    unstable across retries."""
    plain = (
        "## Finding [DEPTH-TF-3]: rounding\n\n**Verdict**: REFUTATION_PROPOSAL\n"
        "**Reason**: the guard blocks it\n"
    )
    mentioning = plain.replace(
        "the guard blocks it",
        "the guard blocks it (this also answers the driver row [OBLIG:OB-9])",
    )
    assert (
        _ledger(plain)["events"][0]["methodology_obligation_id"]
        == _ledger(mentioning)["events"][0]["methodology_obligation_id"]
        == "CANDIDATE:DEPTH-TF-3"
    )
    assert (
        _ledger(plain)["families"][0]["family_id"]
        == _ledger(mentioning)["families"][0]["family_id"]
    )


def test_adversarial_an_asserted_obligation_still_binds_the_family() -> None:
    """ADVERSARIAL: a receipt that really does ASSERT an obligation must still
    key on it -- the mention/assertion split must not blind the harvester."""
    body = "## Obligation Dispositions\n\n[OBLIG:OB-9] STATUS: D KEY: guarded\n"
    assert _ledger(body)["events"][0]["methodology_obligation_id"] == "OBLIG:OB-9"


# ===========================================================================
# GATE 16/17/18 -- committed invariant block, fields, locus extension
# ===========================================================================


@pytest.mark.parametrize(
    "header",
    [
        "committed-invariant [CI-6]",
        "**committed-invariant [CI-6]**",
        "#### committed-invariant [CI-6]",
        "- committed-invariant [CI-6]",
    ],
)
def test_metamorphic_committed_invariant_header_decoration(header: str) -> None:
    body = RUN48_DS6.replace("committed-invariant [CI-6]", header, 1)
    commitment = _ledger(body)["events"][0]["invariant_commitment"]
    assert commitment["status"] == "COMPLETE", (header, commitment["reason"])


@pytest.mark.parametrize(
    "rendered",
    [
        "Locus: contracts/GatewayCrossChain.sol:L517",
        "**Locus**: contracts/GatewayCrossChain.sol:L517",
        "- Locus: contracts/GatewayCrossChain.sol:L517",
        "`Locus`: contracts/GatewayCrossChain.sol:L517",
    ],
)
def test_metamorphic_committed_invariant_field_decoration(rendered: str) -> None:
    body = RUN48_DS6.replace(
        "Locus: contracts/GatewayCrossChain.sol:L517", rendered, 1
    )
    commitment = _ledger(body)["events"][0]["invariant_commitment"]
    assert commitment["status"] == "COMPLETE", (rendered, commitment["reason"])


@pytest.mark.parametrize(
    "value", ["boundary", "boundary.", "Boundary", "**boundary**", "BOUNDARY"]
)
def test_metamorphic_falsify_class_punctuation(value: str) -> None:
    body = RUN48_DS6.replace("Falsify Class: boundary", f"Falsify Class: {value}", 1)
    commitment = _ledger(body)["events"][0]["invariant_commitment"]
    assert commitment["status"] == "COMPLETE", (value, commitment["reason"])


@pytest.mark.parametrize("declaration", ["CI:CI-6", "`CI:CI-6`", "**CI:CI-6**"])
def test_metamorphic_invariant_commitment_declaration_decoration(declaration: str) -> None:
    body = RUN48_DS6.replace("**Invariant Commitment**: CI:CI-6",
                             f"**Invariant Commitment**: {declaration}", 1)
    commitment = _ledger(body)["events"][0]["invariant_commitment"]
    assert commitment["status"] == "COMPLETE", (declaration, commitment["reason"])


@pytest.mark.parametrize("ext", ["sol", "vy", "cairo", "sw", "daml", "move", "rs"])
def test_metamorphic_production_locus_language(ext: str) -> None:
    """A first-class language outside the 14-entry extension allowlist made a
    finding LOCATION-LESS, which then fed the blocking claim hash."""
    body = RUN48_DS6.replace(".sol:L517", f".{ext}:L517").replace(
        ".sol:517", f".{ext}:517"
    )
    commitment = _ledger(body)["events"][0]["invariant_commitment"]
    assert commitment["status"] == "COMPLETE", (ext, commitment["reason"])


def test_adversarial_a_malformed_invariant_is_still_debt() -> None:
    """ADVERSARIAL: tolerance of DECORATION must not become tolerance of a
    MISSING invariant."""
    body = RUN48_DS6.replace("Falsify Class: boundary", "Falsify Class: vibes", 1)
    commitment = _ledger(body)["events"][0]["invariant_commitment"]
    assert commitment["status"] == "DEBT"
    assert "falsify class" in commitment["reason"]
    body = RUN48_DS6.replace("**Invariant Commitment**: CI:CI-6", "", 1)
    assert _ledger(body)["events"][0]["invariant_commitment"]["status"] == "DEBT"


def test_adversarial_an_absolute_or_escaping_locus_is_still_rejected() -> None:
    """ADVERSARIAL: the locus must still point INSIDE the production tree."""
    for locus in ("/etc/passwd.sol:L1", "../../secrets/A.sol:L1"):
        body = RUN48_DS6.replace("contracts/GatewayCrossChain.sol:L517", locus, 1)
        assert _ledger(body)["events"][0]["invariant_commitment"]["status"] == "DEBT"


# ===========================================================================
# GATE 19 -- non-value-bearing exemption
# ===========================================================================


_NON_VALUE = """## Finding [DOC-1]: comment typo
**Verdict**: REFUTATION_PROPOSAL
**Non-Value-Bearing Category**: DOCUMENTATION_ONLY
**Invariant Commitment**: NOT_REQUIRED_NON_VALUE_BEARING: comment-only typo{tail}
"""


@pytest.mark.parametrize(
    "tail",
    ["", " (no revert possible)", " with no access impact", " and never a token transfer"],
)
def test_metamorphic_negated_value_words_do_not_void_the_exemption(tail: str) -> None:
    """A phrase that explicitly DENIES value-bearing harm used to be scored as
    value-bearing."""
    commitment = _ledger(_NON_VALUE.format(tail=tail))["events"][0][
        "invariant_commitment"
    ]
    assert commitment["status"] == "NOT_REQUIRED_NON_VALUE_BEARING", (tail, commitment)


def test_adversarial_real_value_bearing_content_still_voids_the_exemption() -> None:
    """ADVERSARIAL: an affirmative fund-loss claim must still lose the
    exemption -- otherwise a real refutation escapes its committed invariant."""
    body = _NON_VALUE.format(tail="; depositors lose funds on withdraw")
    assert _ledger(body)["events"][0]["invariant_commitment"]["status"] == "DEBT"


# ===========================================================================
# GATE 20 -- external-assumption flag
# ===========================================================================


def test_metamorphic_a_denied_external_leg_is_not_an_external_assumption() -> None:
    assert CN._external_assumption("the guard blocks it") is False
    assert (
        CN._external_assumption("the guard blocks it (off-chain relayer irrelevant)")
        is False
    )


def test_adversarial_a_real_external_premise_is_still_flagged() -> None:
    assert CN._external_assumption("safe only if the oracle is fresh") is True


# ===========================================================================
# GATE 21 -- generator prompt contract  (property: disposition.generator_grant)
# ===========================================================================


def test_metamorphic_a_soft_wrapped_prohibition_is_not_a_grant() -> None:
    """Moving the SAME prohibition onto the next physical line used to flip a
    DENY_LAUNCH; so did phrasing it as a prohibition at all."""
    for prompt in (
        "Verdicts: REFUTATION_PROPOSAL, UNRESOLVED (never SAFE)",
        "Verdicts: REFUTATION_PROPOSAL, UNRESOLVED\n(never SAFE)",
        "Verdicts: REFUTATION_PROPOSAL, UNRESOLVED -- do not emit SAFE",
        "## Outcomes: SAFE is forbidden",
    ):
        CN.validate_generator_prompt_negative_contract(prompt, phase="depth")


def test_adversarial_a_real_terminal_grant_is_still_denied() -> None:
    """ADVERSARIAL: the FAIL_CLOSED grant check still blocks."""
    with pytest.raises(CN.CandidateNegativeAuthorityError):
        CN.validate_generator_prompt_negative_contract(
            "Allowed Verdicts: CONFIRMED | SAFE | NO_FINDING", phase="depth"
        )
    # Independent consumers keep terminal authority.
    CN.validate_generator_prompt_negative_contract(
        "Verdict: CONFIRMED | REFUTED | FALSE_POSITIVE", phase="verify_high"
    )


# ===========================================================================
# GATE 22 -- attention-repair verdict allowlist
# ===========================================================================


@pytest.mark.parametrize(
    "verdict", ["SAFE", "safe", "SAFE.", "NO_FINDING", "NO_FINDINGS", "no issue"]
)
def test_metamorphic_attention_repair_negative_vocabulary(verdict: str) -> None:
    """A row spelled `NO_FINDINGS` or lower-case was silently OUTSIDE the
    negative denominator -- a fail-OPEN recall hole."""
    assert CN._normalize_legacy(verdict) in {"SAFE", "NO_FINDING"}


def test_adversarial_a_positive_attention_repair_row_stays_out() -> None:
    """ADVERSARIAL: CONFIRMED / NEEDS_HUMAN rows must NOT enter the
    candidate-negative denominator."""
    for verdict in ("CONFIRMED", "NEEDS_HUMAN", "ESCALATE"):
        assert CN._normalize_legacy(verdict) not in {"SAFE", "NO_FINDING"}


# ===========================================================================
# STEP 6 -- the call site that actually stopped the discards
# ===========================================================================


def test_closure_of_every_issue_code_is_read_not_judged() -> None:
    """The closure is mechanical: `closure_for_property` returns FAIL_CLOSED
    iff the dotted name's first segment is one of the four closed families."""
    for code, prop in CN._CANDIDATE_NEGATIVE_ISSUE_PROPERTIES.items():
        blocking = code not in CN._NON_BLOCKING_CANDIDATE_NEGATIVE_DEBT
        assert (AS.closure_for_property(prop) == AS.FAIL_CLOSED) is blocking, code


def test_debt_defects_carry_a_physical_repair_hint() -> None:
    """Principle 3: a failing check hands back specific repair information."""
    body = "## An unnamed refutation\n\n**Verdict**: REFUTATION_PROPOSAL\n"
    result = CN.candidate_negative_check_result(_ledger(body), producer_phase="depth")
    assert result.should_discard is False
    assert result.debt_defects
    hint = result.debt_defects[0].repair_hint
    assert "Finding ID" in hint or "Finding [" in hint


def test_a_staged_artifact_is_never_discarded_for_a_debt_defect() -> None:
    """STEP 6: branch on `should_discard`, not on `not accepted`."""
    body = (
        "## An unnamed refutation\n\n**Verdict**: REFUTATION_PROPOSAL\n"
        "**Evidence**: src/A.sol:L2\n"
    )
    accepted, reasons = _staged(body)
    assert accepted is True, reasons
    assert reasons == ()
    assert _ledger(body)["status"] == "INPUT_DEBT"


def test_idempotence_of_the_normalized_view_for_a_real_artifact() -> None:
    once = AS.normalized_text(RUN48_DS6)
    twice = AS.normalized_text(once)
    assert once == twice
    assert _ledger(once)["events"][0]["source_item_id"] == "DS-6"
