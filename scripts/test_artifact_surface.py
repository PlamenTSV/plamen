"""Metamorphic and property tests for the normalize-once admission surface.

Every fixture in this file is REAL worker output. The bytes were copied in
from the DODO run46/run47/run48 validation scratchpads; the tests do NOT read
those directories, so they run anywhere.

The organising principle is Principle 4 from ``artifact_surface``: for every
mutation kind in the measured gate inventory, a semantically equivalent input
must produce an equivalent verdict. Each test below names the measured defect
it retires.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import artifact_surface as A  # noqa: E402


# ==========================================================================
# REAL FIXTURES (verbatim bytes from run46 / run48 worker output)
# ==========================================================================

#: run48 worker.validation-sweep attempt-1f723e9ac5914b9e9a55c39a,
#: validation_sweep_findings.md (934 lines, complete analysis, 6 findings).
#: The staged obligation validator reported 10 issues and DISCARDED it. The
#: whole cause was that '### Obligation evidence bindings for [VS-1]' is an H3
#: SIBLING of '### Finding [VS-1]', so heading-depth arithmetic ended the
#: finding's section before its own markers.
RUN48_VALIDATION_SWEEP = '''### Finding [VS-1]: Both ZEVM contracts arm the revert handler but null the abort handler on every message they originate, so their own `onAbort`/`refundInfos`/`claimRefund` recovery chain can never fire for an outbound withdrawal

**Verdict**: CONFIRMED
**Step Execution**: ✓CHECK-3, ✓CHECK-4, ✓CHECK-8 | ✗CHECK-1(no operator in scope) | ✗CHECK-7(not an accumulator)
**Rules Applied**: [R4:✓, R5:✓, R6:✗(no semi-trusted role in this path), R8:✓, R10:✓]
**Preferred Tag**: CODE-TRACE
**Severity**: High
**Location**: contracts/GatewayCrossChain.sol:261-268
**Material Harm**: A depositor whose outbound withdrawal aborts loses the refund entirely.

### Obligation evidence bindings for [VS-1]

<!-- PLAMEN_SECURITY_OBLIGATION_EVIDENCE: {"alias_id":"SOT-B4C4D3ACCEAA694472BB5FE7","object_id":"","relation_id":"","schema_version":"plamen.security-obligation-evidence-binding.v1","subject_id":"locus:GatewayCrossChain.sol:L277","symbol":""} -->
<!-- PLAMEN_SECURITY_OBLIGATION_EVIDENCE: {"alias_id":"SOT-36169ED2CB7B75440F516BF9","object_id":"","relation_id":"","schema_version":"plamen.security-obligation-evidence-binding.v1","subject_id":"locus:contracts/GatewayTransferNative.sol:L286","symbol":""} -->

---

### Finding [VS-2]: GatewaySend._doMixSwap approves a DODOApprove address that no setter can rotate

**Verdict**: CONFIRMED
**Severity**: Medium
**Location**: contracts/GatewaySend.sol:370
**Material Harm**: Users' approvals point at an address that cannot be revoked.
'''

#: run48 worker.validation-sweep, the receipts block, verbatim.
RUN48_RECEIPTS = (
    "[OBLIG:security_obligations.md:SO-001] ALIAS:SOT-B4C4D3ACCEAA694472BB5FE7 "
    "STATUS:R KEY:GatewayCrossChain.withdraw builds a RevertOptions that arms the "
    "revert handler and nulls the abort handler, so the custody path for a failed "
    "withdrawal terminates in no recorded liability -> VS-1\n"
    "[OBLIG:security_obligations.md:SO-001] ALIAS:SOT-36169ED2CB7B75440F516BF9 "
    "STATUS:R KEY:GatewayTransferNative.withdraw builds the same RevertOptions with "
    "abortAddress address(0), disarming its own onAbort/refundInfos/claimRefund "
    "custody-recovery chain -> VS-1\n"
)

#: run48 worker.depth-state-trace.attempt-0002 attempt-0a9e36d6f6904587b2576d2e,
#: depth_state_trace_findings.md (126,589 bytes, receipt subtype=success,
#: staged verdict accepted=True). Deleting exactly the two characters '[' and
#: ']' from this ONE heading flipped it to accepted=False and discarded the
#: whole analysis carrying DS-6/DS-7/DS-8.
RUN48_DS6 = '''## Finding [DS-6]: Mechanical "writes state with no access gate" on the inbound handlers — refutation proposal

**Verdict**: REFUTATION_PROPOSAL
**Step Execution**: ✓1,2,3,4,6 | ✗5(refutation, no exploitation model) | ✓7
**Rules Applied**: [R4:✓, R5:✗(single mechanism), R6:✗(no semi-trusted role)]
**Preferred Tag**: CODE-TRACE
**Severity**: Informational
**Location**: contracts/GatewayCrossChain.sol:517, contracts/GatewayCrossChain.sol:550
**Description**: Upstream mechanical candidates INV-092, INV-093 assert that `onAbort`/`onRevert` "writes state with no access gate". Source contradicts both.
**Impact**: none — the asserted gap does not exist.
**Material Harm**: none; this candidate describes a detector artefact, not a protocol behaviour.
**Evidence**:
```solidity
// contracts/GatewayTransferNative.sol:90-93
modifier onlyGateway() {
    if (msg.sender != address(gateway)) revert Unauthorized();
    _;
}
```
'''

#: run48 worker.depth-state-trace, the graph-consumption acknowledgements,
#: verbatim. Note the worker wrapped each marker in BACKTICKS and followed it
#: with prose -- the exact presentation the driver's literal substring check
#: happened to tolerate, while it rejected the equally-correct spellings.
RUN48_GRAPH_ACK = '''`[GRAPH-ARTIFACT: CONSUMED:caller_map.md]` — Status POPULATED. Decisive rows: `GatewayTransferNative.withdraw@L286` has callers `_handleBitcoinWithdraw@L451` **and** `onCall@L357`.

`[GRAPH-ARTIFACT: CONSUMED:callee_map.md]` — Status POPULATED. Used to build the entry-point traces in Target 4.

`[GRAPH-ARTIFACT: CONSUMED:state_write_map.md]` — Status **UNAVAILABLE** (`mechanical provider emitted no state write-site facts; use direct source`). `[GRAPH-ARTIFACT: UNAVAILABLE:state_write_map.md]`

`[GRAPH-ARTIFACT: CONSUMED:function_summary.md]` — Status POPULATED but semantically empty for this role.
'''

#: run46 worker.pc5.attempt-0003 attempt-8b87888822414134b595fc3b,
#: analysis_percontract_IUniswapV2Factory.md (10,220 bytes). REJECTED today,
#: solely because it wrote its zero-candidate attestation as FIELDS rather than
#: as a table row: `_block_attests_zero_candidates` scans only lines starting
#: with '|'. Note also the soft-wrapped Finding ID value.
RUN46_ZERO_CANDIDATE_FIELDS = '''## No Findings

**Disposition**: `NOT_APPLICABLE_PROPOSAL`
**Finding ID**: — (no new candidate; see RS-X exclusion above for the one
identified candidate, referred to `[B4-5]`)
**Rationale**: `IUniswapV2Factory.sol` is a call-shape interface stub with no
first-party implementation and zero call sites anywhere in `contracts/`.
'''

#: run46 breadth methodology_repair.model (70,540 bytes of successful worker
#: output). REJECTED today because of ONE sentence-ending period after a
#: CORRECT nonterminal enum.
RUN46_ENUM_WITH_PERIOD = (
    "Outcome: **NOT_APPLICABLE_PROPOSAL**. §5 is gated on "
    '"IF emission/rebase detected".'
)

#: run48 .scratchpad/caller_map.md, a real row, plus a real escaped-pipe row
#: from a run48 depth artifact (GFM REQUIRES the `\\|\\|` escape).
RUN48_TABLE = (
    "| Function | Location | Callers |\n"
    "|---|---|---|\n"
    "| `GatewayCrossChain.claimRefund` | `contracts/GatewayCrossChain.sol:571` "
    "| no modifier; internal `require(bots[msg.sender] \\|\\| "
    "msg.sender==receiver)` at L578 |\n"
)


# ==========================================================================
# Totality: never raise, on anything
# ==========================================================================

_HOSTILE = [
    None,
    "",
    b"",
    b"\xff\xfe\x00bad",
    0,
    3.5,
    [],
    {},
    object(),
    "```",
    "~~~\n~~~\n~~~",
    "<!--",
    "<!-- unterminated",
    "|",
    "||||||",
    "#" * 400,
    "a" * 300_000,
    "\n" * 5_000,
    "\x00\x01\x02",
    "\ud800",  # lone surrogate
    "| a | b |\n|---|\n| c |",
    "1." * 5_000,
    "**" * 5_000,
    "`" * 5_000,
]


@pytest.mark.parametrize("value", _HOSTILE, ids=range(len(_HOSTILE)))
def test_surface_is_total_and_never_raises(value: object) -> None:
    surf = A.surface(value)
    assert isinstance(surf, A.ArtifactSurface)
    assert A.normalized_text(surf) is not None
    assert A.read_tables(surf) is not None
    assert A.read_fields(surf) is not None
    for line in surf.lines:
        assert A.classify_token(line, "PLAMEN_STATUS") is None or True


@pytest.mark.parametrize("value", _HOSTILE, ids=range(len(_HOSTILE)))
def test_helpers_are_total(value: object) -> None:
    assert isinstance(A.strip_decoration(value), str)
    assert isinstance(A.normalize_label(value), str)
    assert isinstance(A.normalize_enum(value), str)
    assert isinstance(A.is_zero_candidate_placeholder(value), bool)
    ident = A.candidate_identity(value)
    assert ident is None or isinstance(ident, A.Identity)


def test_classify_token_is_total_on_non_lines() -> None:
    assert A.classify_token(None, "X") is None  # type: ignore[arg-type]
    assert A.classify_token("not a line", "X") is None  # type: ignore[arg-type]
    line = A.surface("hello").lines[0]
    assert A.classify_token(line, None) is None
    assert A.classify_token(line, "") is None


# ==========================================================================
# Property: normalization is IDEMPOTENT
# ==========================================================================

_REAL_ARTIFACTS = {
    "validation_sweep": RUN48_VALIDATION_SWEEP,
    "receipts": RUN48_RECEIPTS,
    "ds6": RUN48_DS6,
    "graph_ack": RUN48_GRAPH_ACK,
    "zero_candidate": RUN46_ZERO_CANDIDATE_FIELDS,
    "table": RUN48_TABLE,
}


@pytest.mark.parametrize("name", sorted(_REAL_ARTIFACTS))
def test_normalization_is_idempotent_on_real_artifacts(name: str) -> None:
    doc = _REAL_ARTIFACTS[name]
    once = A.normalized_text(doc)
    twice = A.normalized_text(once)
    thrice = A.normalized_text(twice)
    assert once == twice, f"normalize(normalize(x)) != normalize(x) for {name}"
    assert twice == thrice


@pytest.mark.parametrize("value", _HOSTILE, ids=range(len(_HOSTILE)))
def test_normalization_is_idempotent_on_hostile_input(value: object) -> None:
    once = A.normalized_text(value)
    assert A.normalized_text(once) == once


@pytest.mark.parametrize(
    "text",
    [
        "**bold**", "`code`", "***both***", "~~gone~~", "_em_", "__strong__",
        "a * b", "my_var_name", "**Finding [DS-6]**", "a &nbsp; b",
        "x y", "​z", "  spaced   out  ", "`**nested**`",
    ],
)
def test_strip_decoration_is_idempotent(text: str) -> None:
    once = A.strip_decoration(text)
    assert A.strip_decoration(once) == once


def test_strip_decoration_preserves_non_delimiter_punctuation() -> None:
    # Solidity multiplication and snake_case identifiers are not emphasis.
    assert A.strip_decoration("uint a = b * c;") == "uint a = b * c;"
    assert A.strip_decoration("my_var_name") == "my_var_name"
    # Brackets are IDENTITY, never decoration.
    assert "[DS-6]" in A.strip_decoration("**Finding [DS-6]**")


# ==========================================================================
# METAMORPHIC: identity survives every measured presentation mutation
# ==========================================================================

_IDENTITY_SPELLINGS = [
    "## Finding [DS-6]: title",
    "## Finding DS-6: title",           # measured discard: 2 chars deleted
    "### Finding [DS-6]: title",
    "#### Finding [DS-6]: title",       # measured: heading-depth allowlist
    "##### Finding [DS-6]",
    "## **Finding [DS-6]**: title",
    "## Finding `[DS-6]`: title",       # measured: backticks -> rejected
    "## Finding `DS-6`: title",
    "## Candidate [DS-6]: title",       # blessed by finding-output-format.md
    "## Candidate DS-6: title",
    "## Issue [DS-6]: title",           # blessed by finding-output-format.md
    "## Issue DS-6: title",
    "## [DS-6] title",
    "##   Finding   [DS-6]  :  title",
    "## Finding [ DS-6 ]: title",
]


@pytest.mark.parametrize("spelling", _IDENTITY_SPELLINGS)
def test_candidate_identity_is_representation_invariant(spelling: str) -> None:
    ident = A.candidate_identity(spelling)
    assert ident is not None, f"identity lost for {spelling!r}"
    assert ident.key == "DS-6"


def test_identity_is_invariant_under_bracket_deletion_on_real_bytes() -> None:
    """The measured 126,589-byte discard: delete '[' and ']' from one heading."""
    original = RUN48_DS6
    mutated = original.replace("## Finding [DS-6]:", "## Finding DS-6:")
    assert mutated != original

    def heading_ids(doc: str) -> list[str]:
        return [
            i.key
            for h in A.surface(doc).headings()
            if (i := A.candidate_identity(h.heading_text)) is not None
        ]

    assert heading_ids(original) == heading_ids(mutated) == ["DS-6"]


def test_table_cell_identity_agrees_with_heading_identity() -> None:
    """One property, one answer.

    The census found TWO independent regexes for this ONE property in a single
    module: ``_DECORATED_TABLE_ID_RE.fullmatch('Finding DEPTH-TF-3')`` yields
    'DEPTH-TF-3' while ``_source_item_identity('Finding DEPTH-TF-3')`` yields a
    derived hash that then DISCARDED the artifact.
    """
    for spelling in (
        "Finding DEPTH-TF-3",
        "Candidate DEPTH-TF-3",
        "DEPTH-TF-3",
        "[DEPTH-TF-3]",
        "`DEPTH-TF-3`",
        "**[DEPTH-TF-3]**",
    ):
        heading = A.candidate_identity(f"## Finding [{spelling}]".replace("[[", "[").replace("]]", "]"))
        cell = A.candidate_identity(spelling)
        assert cell is not None and cell.key == "DEPTH-TF-3", spelling
        assert heading is not None and heading.key == "DEPTH-TF-3", spelling


# ==========================================================================
# METAMORPHIC: assertion vs mention (the run48 killer)
# ==========================================================================

_ASSERTIONS = [
    # run48 'malformed obligation receipt-like line rejected' x4 family.
    "[OBLIG:OB-12] STATUS: D KEY: guard present at L44 -> DT-1",
    "`[OBLIG:OB-12] STATUS: D KEY: guard present at L44 -> DT-1`",
    "- [OBLIG:OB-12] STATUS: D KEY: guard present at L44 -> DT-1",
    "* [OBLIG:OB-12] STATUS: D KEY: guard present at L44 -> DT-1",
    "1. [OBLIG:OB-12] STATUS: D KEY: guard present at L44 -> DT-1",
    "> [OBLIG:OB-12] STATUS: D KEY: guard present at L44 -> DT-1",
    "**[OBLIG:OB-12]** STATUS: D KEY: guard present at L44 -> DT-1",
    "    [OBLIG:OB-12] STATUS: D KEY: guard present at L44 -> DT-1",
    "Receipt: [OBLIG:OB-12] STATUS: D KEY: guard present at L44 -> DT-1",
]


@pytest.mark.parametrize("text", _ASSERTIONS)
def test_receipt_spellings_all_assert(text: str) -> None:
    line = A.surface(text).lines[0]
    occ = A.classify_token(line, "OBLIG:OB-12")
    assert occ is not None and occ.is_assertion, f"{text!r} -> {occ}"


_MENTIONS = [
    # run48 'malformed structured obligation evidence ignored' x3 family:
    # a PROSE sentence NAMED the marker token.
    (
        "<!-- note: PLAMEN_SECURITY_OBLIGATION_EVIDENCE markers placed per alias -->",
        "PLAMEN_SECURITY_OBLIGATION_EVIDENCE",
    ),
    (
        "I placed one PLAMEN_SECURITY_OBLIGATION_EVIDENCE marker under each finding.",
        "PLAMEN_SECURITY_OBLIGATION_EVIDENCE",
    ),
    (
        "The payload is delimited by <!-- PLAMEN_TRACE_BEGIN --> and the end token.",
        "PLAMEN_TRACE_BEGIN",
    ),
    # _depth_artifact_is_stub: a 143KB artifact declared a stub by a sentence.
    (
        "Note: the reservation header said `Writing in progress` until this "
        "final overwrite.",
        "writing in progress",
    ),
    (
        "Operators note the batch is writing in progress when paused.",
        "writing in progress",
    ),
    # _validate_crossbatch_quality: correctly reporting the ABSENCE of problems.
    ("No schema violations detected.", "schema violations"),
    ("0 severity mismatches.", "severity mismatches"),
    ("No missing severity field anywhere.", "missing severity field"),
    ("No evidence-tag mismatches.", "evidence-tag mismatches"),
    # _validate_report_body: prose NEGATION read as an assertion.
    (
        "This finding is not [REPORT-BLOCKED]; evidence is complete.",
        "REPORT-BLOCKED",
    ),
    # is_artifact_complete: a promise is not a completion.
    (
        "I will end with `<!-- PLAMEN_STATUS: COMPLETE -->` when done, but I am "
        "not done.",
        "PLAMEN_STATUS: COMPLETE",
    ),
    # _findings_section_has_body: analysis that quotes the placeholder word.
    (
        "This placeholder discussion is about a real placeholder bug in the code.",
        "placeholder",
    ),
    # _parse_obligation_table_receipts: a negated mention flipped a disposition.
    ("confirmed, not a false positive", "false positive"),
]


@pytest.mark.parametrize("text,token", _MENTIONS, ids=range(len(_MENTIONS)))
def test_prose_mentions_never_assert(text: str, token: str) -> None:
    surf = A.surface(text)
    assert not any(A.line_asserts(l, token) for l in surf.lines), (
        f"{text!r} must MENTION, not ASSERT, {token!r}"
    )
    assert any(A.line_mentions(l, token) for l in surf.lines)


def test_real_markers_assert_while_prose_about_them_does_not() -> None:
    """Both halves of the run48 rejection, in one artifact."""
    token = "PLAMEN_SECURITY_OBLIGATION_EVIDENCE"
    doc = (
        RUN48_VALIDATION_SWEEP
        + "\nI placed one "
        + token
        + " marker under each finding above.\n"
    )
    assertions = A.find_assertions(doc, token)
    mentions = A.find_mentions(doc, token)
    assert len(assertions) == 2, [o.reason for o in assertions]
    assert len(mentions) == 1
    assert mentions[0].reason in ("NARRATIVE_HEAD", "NARRATIVE_TAIL")


def test_quoting_a_marker_in_a_fence_keeps_the_real_assertion() -> None:
    """Measured M10: quoting for the reader AND asserting normally -> DISCARD.

    The fenced copy is a quotation: it neither counts nor rejects.
    """
    token = "PLAMEN_SECURITY_OBLIGATION_EVIDENCE"
    doc = (
        "For reference the marker shape is:\n\n"
        "```\n"
        '<!-- PLAMEN_SECURITY_OBLIGATION_EVIDENCE: {"alias_id":"SOT-EXAMPLE"} -->\n'
        "```\n\n" + RUN48_VALIDATION_SWEEP
    )
    assert len(A.find_assertions(doc, token)) == 2


def test_prose_naming_a_marker_inside_an_html_comment_is_a_mention() -> None:
    """Measured M13: the sentence inside <!-- --> caused a DISCARD.

    Membership in a comment decides nothing: real markers ARE HTML comments.
    The assertion GRAMMAR decides.
    """
    token = "PLAMEN_SECURITY_OBLIGATION_EVIDENCE"
    real = A.surface(
        '<!-- PLAMEN_SECURITY_OBLIGATION_EVIDENCE: {"alias_id":"SOT-B4"} -->'
    ).lines[0]
    narration = A.surface(
        "<!-- note: PLAMEN_SECURITY_OBLIGATION_EVIDENCE markers placed per alias -->"
    ).lines[0]
    assert A.line_asserts(real, token)
    assert A.line_mentions(narration, token)


def test_receipt_survives_soft_wrapping() -> None:
    """Measured R16: soft-wrapping the KEY across two physical lines rejected."""
    one_line = RUN48_RECEIPTS.split("\n")[0]
    wrapped = one_line.replace(
        "that arms the ", "that arms the\n"
    )
    for doc in (one_line, wrapped):
        surf = A.surface(doc)
        occ = [
            A.classify_token(l, "OBLIG:security_obligations.md:SO-001")
            for l in surf.lines
        ]
        assert any(o and o.is_assertion for o in occ), doc[:60]
    # And the joined logical line carries the whole KEY either way.
    assert "custody path" in A.surface(wrapped).lines[0].text


def test_assertion_reports_the_original_physical_line() -> None:
    """Principle 3: the defect must point a human at the real bytes."""
    doc = "line one\nline two\n\n[OBLIG:OB-9] STATUS: D KEY: x -> y\n"
    occ = A.find_assertions(doc, "OBLIG:OB-9")
    assert len(occ) == 1
    assert occ[0].physical_line == 4


# ==========================================================================
# METAMORPHIC: graph acknowledgement survives presentation and stray fences
# ==========================================================================

def _consumed(doc: str) -> set[str]:
    import re

    out: set[str] = set()
    for line in A.surface(doc).lines:
        occ = A.classify_token(line, "GRAPH-ARTIFACT")
        if occ is not None and occ.is_assertion:
            out |= set(re.findall(r"CONSUMED:\s*([\w./-]+)", line.text))
    return out


def test_graph_acknowledgement_reads_the_real_run48_artifact() -> None:
    assert _consumed(RUN48_GRAPH_ACK) == {
        "caller_map.md",
        "callee_map.md",
        "state_write_map.md",
        "function_summary.md",
    }


@pytest.mark.parametrize(
    "mutation",
    [
        lambda d: d.replace("CONSUMED:caller_map.md", "CONSUMED: caller_map.md"),
        lambda d: d.replace("`[GRAPH-ARTIFACT", "[GRAPH-ARTIFACT").replace("]`", "]"),
        lambda d: d.replace("[GRAPH-ARTIFACT", "**[GRAPH-ARTIFACT"),
        lambda d: "- " + d.replace("\n\n", "\n\n- "),
        lambda d: d.replace("\n", "\r\n"),
        lambda d: d.replace("—", "&mdash;"),
    ],
    ids=["space-after-colon", "unbackticked", "bolded", "list-items", "crlf", "entity"],
)
def test_graph_acknowledgement_is_presentation_invariant(mutation) -> None:
    assert _consumed(mutation(RUN48_GRAPH_ACK)) == _consumed(RUN48_GRAPH_ACK)


@pytest.mark.parametrize("position", [0, 1, 3, 5])
def test_one_stray_fence_does_not_blind_the_gate(position: int) -> None:
    """The measured three-character discard.

    Inserting ONE ``` line into a real depth artifact made the driver report
    that the worker acknowledged NO graph projection, returned
    rc=-2 staged_semantic_rejected, and destroyed a 25-minute analysis.
    """
    lines = RUN48_GRAPH_ACK.split("\n")
    lines.insert(position, "```")
    mutated = "\n".join(lines)
    assert _consumed(mutated) == _consumed(RUN48_GRAPH_ACK)
    surf = A.surface(mutated)
    # The ambiguity is VISIBLE as debt -- and it is debt, never a discard.
    assert any(d.property_violated == "format.unterminated_fence" for d in surf.defects)
    assert all(d.closure == A.DEBT for d in surf.defects)


# ==========================================================================
# METAMORPHIC: enum normalization (the one-period discard)
# ==========================================================================

@pytest.mark.parametrize(
    "spelling",
    [
        "NOT_APPLICABLE_PROPOSAL",
        "NOT_APPLICABLE_PROPOSAL.",            # measured 70,540-byte discard
        "NOT_APPLICABLE_PROPOSAL: no emission",
        "NOT_APPLICABLE_PROPOSAL (no emission)",
        "NOT_APPLICABLE_PROPOSAL - no emission",
        "**NOT_APPLICABLE_PROPOSAL**",
        "**NOT_APPLICABLE_PROPOSAL**.",
        "`NOT_APPLICABLE_PROPOSAL`",
        "not_applicable_proposal",
        "NOT-APPLICABLE-PROPOSAL",
        "  NOT_APPLICABLE_PROPOSAL  ",
    ],
)
def test_nonterminal_enum_never_collapses_to_the_legacy_terminal(spelling: str) -> None:
    assert A.normalize_enum(spelling) == "NOT_APPLICABLE_PROPOSAL"


def test_legacy_terminal_is_still_distinguishable() -> None:
    """Normalizing must not blur the distinction the gate actually protects."""
    assert A.normalize_enum("NOT_APPLICABLE") == "NOT_APPLICABLE"
    assert A.normalize_enum("N/A") == "N_A"
    assert A.normalize_enum("NOT_APPLICABLE_PROPOSAL") != A.normalize_enum(
        "NOT_APPLICABLE"
    )


def test_real_run46_enum_with_trailing_period() -> None:
    """The live cause of a 70,540-byte breadth rejection."""
    field = A.read_field(RUN46_ENUM_WITH_PERIOD, "verdict")
    assert field is not None
    assert field.enum == "NOT_APPLICABLE_PROPOSAL"


@pytest.mark.parametrize(
    "spelling,expected",
    [
        ("REFUTATION_PROPOSAL.", "REFUTATION_PROPOSAL"),
        ("Medium", "MEDIUM"),
        ("medium", "MEDIUM"),
        ("Medium (High x Low)", "MEDIUM"),
        ("**High**", "HIGH"),
        ("CONFIRMED", "CONFIRMED"),
        ("", ""),
    ],
)
def test_enum_normalization_cases(spelling: str, expected: str) -> None:
    assert A.normalize_enum(spelling) == expected


# ==========================================================================
# METAMORPHIC: zero-candidate placeholders
# ==========================================================================

@pytest.mark.parametrize(
    "cell",
    [
        "—", "–", "-", "--", "N/A", "n/a", "NA", "(none)", "None",
        "none new", "None new", "&mdash;", "&ndash;", "no new candidates",
        "No new candidates", "— (zero rows)", "`—`", "**—**",
        "nil", "0", "", "   ",
    ],
)
def test_zero_candidate_placeholders_are_recognized(cell: str) -> None:
    """Measured: exactly TWO strings were accepted; every other spelling minted
    a phantom candidate whose derived identity then DISCARDED the artifact."""
    assert A.is_zero_candidate_placeholder(cell)


@pytest.mark.parametrize("cell", ["DS-6", "[VS-1]", "Finding DT-3", "0x00", "no-op bug"])
def test_real_candidates_are_not_placeholders(cell: str) -> None:
    assert not A.is_zero_candidate_placeholder(cell)


def test_zero_candidate_attestation_is_read_from_fields_not_only_tables() -> None:
    """The real run46 rejection: the attestation was written as FIELDS.

    ``_block_attests_zero_candidates`` scans only lines starting with '|', so a
    correct field-form attestation was invisible and the 10,220-byte artifact
    was discarded with DERIVED_SOURCE_ITEM_ID.
    """
    field_form = A.read_field(RUN46_ZERO_CANDIDATE_FIELDS, "verdict")
    assert field_form is not None
    assert field_form.enum == "NOT_APPLICABLE_PROPOSAL"

    ids = A.read_fields(
        RUN46_ZERO_CANDIDATE_FIELDS, "candidate_id",
        roles={"candidate_id": ("finding id", "candidate id", "issue id")},
    )
    assert ids, "the Finding ID field must be visible in field form"
    assert A.is_zero_candidate_placeholder(ids[0].value)

    table_form = (
        "| Finding ID | Disposition |\n|---|---|\n"
        "| — | NOT_APPLICABLE_PROPOSAL |\n"
    )
    table = A.find_table(table_form, required_roles=("candidate_id", "disposition"))
    assert table is not None
    assert A.is_zero_candidate_placeholder(table.rows[0].get("candidate_id"))
    # Both representations agree on both facts.
    assert A.normalize_enum(table.rows[0].get("disposition")) == field_form.enum


# ==========================================================================
# METAMORPHIC: tables addressed by ROLE, never by position
# ==========================================================================

_TABLE_VARIANTS = {
    "canonical": "| Finding ID | Verdict |\n|---|---|\n| DS-6 | REFUTATION_PROPOSAL |",
    "extra_id_column": (
        "| ID | Finding ID | Verdict |\n|---|---|---|\n"
        "| 1 | DS-6 | REFUTATION_PROPOSAL |"
    ),
    "nbsp_header": (
        "| Finding&nbsp;ID | Verdict |\n|---|---|\n| DS-6 | REFUTATION_PROPOSAL |"
    ),
    "no_outer_pipes": "Finding ID | Verdict\n---|---\nDS-6 | REFUTATION_PROPOSAL",
    "reordered": "| Verdict | Finding ID |\n|---|---|\n| REFUTATION_PROPOSAL | DS-6 |",
    "synonyms": (
        "| Candidate | Determination |\n|---|---|\n| DS-6 | REFUTATION_PROPOSAL |"
    ),
    "decorated": (
        "| **Finding ID** | **Verdict** |\n|---|---|\n"
        "| **DS-6** | `REFUTATION_PROPOSAL` |"
    ),
    "no_separator": "| Finding ID | Verdict |\n| DS-6 | REFUTATION_PROPOSAL |",
    "extra_column": (
        "| Finding ID | Verdict | Notes |\n|---|---|---|\n"
        "| DS-6 | REFUTATION_PROPOSAL | see also |"
    ),
    "labelled_cell": (
        "| Finding ID | Verdict |\n|---|---|\n| Finding DS-6 | REFUTATION_PROPOSAL |"
    ),
    "crlf": "| Finding ID | Verdict |\r\n|---|---|\r\n| DS-6 | REFUTATION_PROPOSAL |",
    "padded": (
        "|   Finding ID   |   Verdict   |\n|---|---|\n"
        "|   DS-6   |   REFUTATION_PROPOSAL   |"
    ),
}


@pytest.mark.parametrize("name", sorted(_TABLE_VARIANTS))
def test_table_role_reading_is_representation_invariant(name: str) -> None:
    table = A.find_table(
        _TABLE_VARIANTS[name], required_roles=("candidate_id", "disposition")
    )
    assert table is not None, f"no table found for {name}"
    assert len(table.rows) == 1
    row = table.rows[0]
    ident = row.identity()
    assert ident is not None and ident.key == "DS-6", name
    assert A.normalize_enum(row.get("disposition")) == "REFUTATION_PROPOSAL", name


def test_adding_a_more_informative_column_does_not_drop_identity() -> None:
    """Measured: '| ID | Finding ID | Verdict |' set identity_index=None for
    EVERY row, because exactly-one-match was required. Adding a correct,
    MORE informative column made the gate strictly worse."""
    table = A.find_table(_TABLE_VARIANTS["extra_id_column"])
    assert table is not None
    assert table.rows[0].get("candidate_id") == "DS-6"
    # The ambiguity is recorded -- as debt, never as a loss.
    assert any(
        d.property_violated.startswith("format.ambiguous_column_role")
        for d in table.ambiguities
    )
    assert all(d.closure == A.DEBT for d in table.ambiguities)


def test_absent_role_is_none_never_a_positional_fallback() -> None:
    table = A.find_table("| Subject | Note |\n|---|---|\n| a | b |")
    assert table is not None
    assert table.role_index("severity") is None
    assert table.rows[0].get("severity") is None
    assert table.rows[0].get("severity", "DEFAULT") == "DEFAULT"


def test_severity_column_is_never_read_as_a_disposition() -> None:
    """The one exclusion the measured gate got RIGHT; preserve it."""
    table = A.find_table("| Finding ID | Severity |\n|---|---|\n| DS-6 | N/A |")
    assert table is not None
    assert table.role_index("disposition") is None
    assert table.rows[0].get("severity") == "N/A"


def test_escaped_pipes_in_a_real_solidity_cell() -> None:
    """GFM REQUIRES `\\|\\|` for a literal pipe; splitting on every '|' turned a
    4-column row into 6 and failed a whole recon phase."""
    table = A.find_table(RUN48_TABLE)
    assert table is not None
    assert len(table.rows) == 1
    assert len(table.rows[0].cells) == 3
    assert "||" in table.rows[0].cells[2]


def test_pipe_bearing_prose_is_not_a_table() -> None:
    doc = (
        'depth_candidates.md "Second Opinion Targets" contains a single row: '
        "| - | - | No canonical REFUTED findings | - |. There are none.\n"
    )
    assert A.read_tables(doc) == ()


# ==========================================================================
# METAMORPHIC: labelled fields read by MEANING
# ==========================================================================

_FIELD_SPELLINGS = [
    "**Severity**: High",
    "**Severity:** High",          # measured: colon inside bold -> field lost
    "Severity: High",
    "- **Severity**: High",        # measured: list item -> field lost
    "* **Severity**: High",
    "1. Severity: High",           # measured: numbered -> 0 events
    "> **Severity**: High",        # measured: blockquote -> 0 events
    "**Severity** — High",    # measured: em dash -> field lost
    "**Severity** = High",
    "`Severity`: High",
    "**Severity** : High",
    "  **Severity**: High  ",
    "| Severity | High |",         # measured: table form -> 0 events
    "_Severity_: High",            # measured: italics -> field lost
]


@pytest.mark.parametrize("text", _FIELD_SPELLINGS)
def test_field_reading_is_representation_invariant(text: str) -> None:
    field = A.read_field(text, "severity")
    assert field is not None, f"field lost for {text!r}"
    assert A.normalize_enum(field.value) == "HIGH"


def test_material_harm_parenthetical_qualifier_is_tolerated() -> None:
    """Measured: '**Material Harm** (MANDATORY):' -- the spelling printed in the
    pipeline's OWN bound contract -- was rejected by its own gate."""
    for text in (
        "**Material Harm** (MANDATORY): users lose funds",
        "**Material Harm (MANDATORY)**: users lose funds",
        "**Material Harm**: users lose funds",
        "Material Harm (MANDATORY): users lose funds",
    ):
        field = A.read_field(text, "material_harm")
        assert field is not None, text
        assert field.value == "users lose funds"


def test_soft_wrapped_field_value_is_joined() -> None:
    """Measured: '**Impact**:\\n  Depositors lose 25%...' -> field observed 0."""
    doc = "**Impact**:\nDepositors lose 25-50% of their pro-rata share.\n"
    field = A.read_field(doc, "impact")
    assert field is not None
    assert "25-50%" in field.value


def test_adjacent_field_lines_are_not_fused() -> None:
    doc = "**Verdict**: CONFIRMED\n**Severity**: High\n**Location**: a.sol:L1\n"
    assert A.read_field(doc, "verdict").value == "CONFIRMED"
    assert A.read_field(doc, "severity").value == "High"
    assert A.read_field(doc, "location").value == "a.sol:L1"


def test_real_ds6_fields_are_all_readable() -> None:
    assert A.read_field(RUN48_DS6, "verdict").enum == "REFUTATION_PROPOSAL"
    assert A.read_field(RUN48_DS6, "severity").enum == "INFORMATIONAL"
    assert A.read_field(RUN48_DS6, "material_harm") is not None
    assert "GatewayCrossChain.sol:517" in A.read_field(RUN48_DS6, "location").value


def test_fields_inside_a_fence_are_not_harvested_by_default() -> None:
    doc = "```\n**Severity**: Critical\n```\n**Severity**: Low\n"
    assert A.read_field(doc, "severity").value == "Low"
    assert len(A.read_fields(doc, "severity", include_fenced=True)) == 2


# ==========================================================================
# The measured H3-sibling discard: identity-scoped sections
# ==========================================================================

def test_sibling_heading_does_not_orphan_its_own_findings_markers() -> None:
    """THE surviving run48 rejection, on the real bytes.

    The worker wrote '### Obligation evidence bindings for [VS-1]' -- an H3
    SIBLING of '### Finding [VS-1]' -- then its markers. Heading-depth
    arithmetic ended VS-1's section at the sibling, so its own markers looked
    like they belonged to nothing. Verdict BEFORE = 10 issues, artifact
    DISCARDED. Adding five '#' characters (zero words changed) = 0 issues.
    """
    token = "PLAMEN_SECURITY_OBLIGATION_EVIDENCE"

    def markers_bound_to_vs1(doc: str) -> int:
        surf = A.surface(doc)
        section = surf.section_containing("VS-1")
        return sum(1 for line in section if A.line_asserts(line, token))

    h3 = RUN48_VALIDATION_SWEEP
    h4 = h3.replace(
        "### Obligation evidence bindings for",
        "#### Obligation evidence bindings for",
    )
    h2 = h3.replace(
        "### Obligation evidence bindings for",
        "## Obligation evidence bindings for",
    )
    assert h3 != h4 != h2
    assert markers_bound_to_vs1(h3) == 2
    assert markers_bound_to_vs1(h4) == 2
    assert markers_bound_to_vs1(h2) == 2


def test_identity_scoped_section_stops_at_a_different_candidate() -> None:
    surf = A.surface(RUN48_VALIDATION_SWEEP)
    vs1 = surf.section_containing("VS-1")
    vs2 = surf.section_containing("VS-2")
    assert vs1 and vs2
    assert not (set(l.index for l in vs1) & set(l.index for l in vs2))
    assert any("GatewaySend.sol:370" in l.text for l in vs2)
    assert not any("GatewaySend.sol:370" in l.text for l in vs1)


def test_finding_headings_survive_every_heading_depth() -> None:
    for depth in range(1, 7):
        doc = RUN48_VALIDATION_SWEEP.replace("### Finding [VS-", "#" * depth + " Finding [VS-")
        ids = {
            i.key
            for h in A.surface(doc).headings()
            if (i := A.candidate_identity(h.heading_text)) is not None
            and i.key.startswith("VS-")
        }
        assert ids == {"VS-1", "VS-2"}, depth


# ==========================================================================
# The classification rule
# ==========================================================================

@pytest.mark.parametrize(
    "name",
    [
        "identity.candidate_id",
        "identity.alias_binding",
        "dedup.merge_decision",
        "severity.final_tier",
        "disposition.body_or_appendix",
        "IDENTITY.upper_case_family",
    ],
)
def test_the_four_closed_families_are_fail_closed(name: str) -> None:
    assert A.closure_for_property(name) == A.FAIL_CLOSED


@pytest.mark.parametrize(
    "name",
    [
        "receipt.line_grammar",
        "marker.placement",
        "format.unterminated_fence",
        "schema.unknown_key",
        "count.exactly_one_marker",
        "vocabulary.header_synonym",
        "completeness.status_marker",
        "graph.consumption_acknowledgement",
        "ordering.receipt_field_order",
        "",
        "no_family",
        None,
        123,
    ],
)
def test_everything_else_degrades_with_debt(name: object) -> None:
    assert A.closure_for_property(name) == A.DEBT


def test_closed_families_are_exactly_four() -> None:
    assert A.FAIL_CLOSED_PROPERTY_FAMILIES == frozenset(
        {"identity", "dedup", "severity", "disposition"}
    )


def test_check_result_only_discards_on_a_closed_defect() -> None:
    debt = A.CheckResult(
        (
            A.Defect(
                property_violated="receipt.line_grammar",
                physical_line=812,
                observed="receipt wrapped in backticks",
                expected="a parseable receipt",
                repair_hint="Emit the receipt without surrounding backticks.",
                closure=A.closure_for_property("receipt.line_grammar"),
            ),
        )
    )
    assert not debt.accepted
    assert not debt.should_discard          # <- the whole point
    assert debt.debt_defects and not debt.blocking_defects

    closed = A.CheckResult(
        (
            A.Defect(
                property_violated="identity.candidate_id",
                physical_line=630,
                observed="no candidate ID in heading or table cell",
                expected="one stable candidate ID",
                repair_hint="Add 'Finding [ID]' to the heading.",
                closure=A.closure_for_property("identity.candidate_id"),
            ),
        )
    )
    assert closed.should_discard
    assert A.ACCEPTED.accepted and not A.ACCEPTED.should_discard
    merged = debt.merge(closed, A.ACCEPTED)
    assert len(merged.defects) == 2 and merged.should_discard


def test_defects_carry_actionable_repair_information() -> None:
    """Principle 3: rejection alone is the worst available outcome."""
    surf = A.surface("```\nunclosed\n")
    assert surf.defects
    rendered = surf.defects[0].render()
    for part in ("DEBT", "format.unterminated_fence", "Nothing was rejected"):
        assert part in rendered
    assert surf.defects[0].physical_line == 1


# ==========================================================================
# Fenced / comment / prose classification is exposed, not silently dropped
# ==========================================================================

def test_callers_can_distinguish_prose_fence_and_comment() -> None:
    doc = (
        "<!-- PLAMEN_STATUS: COMPLETE -->\n"
        "prose line\n"
        "```solidity\n"
        "uint x = 1;\n"
        "```\n"
        "more prose\n"
    )
    surf = A.surface(doc)
    kinds = {l.physical_start: l.kind for l in surf.lines}
    assert kinds[1] == A.HTML_COMMENT
    assert kinds[2] == A.PROSE
    assert kinds[3] == A.FENCE_DELIMITER
    assert kinds[4] == A.FENCE_CONTENT
    assert kinds[6] == A.PROSE
    assert len(surf.comment_lines()) == 1
    assert len(surf.fenced_lines()) == 3
    assert "uint x = 1;" in A.normalized_text(surf)


def test_real_ds6_solidity_evidence_block_is_preserved_as_fenced() -> None:
    surf = A.surface(RUN48_DS6)
    fenced = [l for l in surf.fenced_lines() if l.kind == A.FENCE_CONTENT]
    assert any("modifier onlyGateway()" in l.raw for l in fenced)
    # Its content must NOT be mistaken for fields or tables.
    assert A.read_field(RUN48_DS6, "severity").value == "Informational"


def test_crlf_and_trailing_whitespace_are_invisible() -> None:
    base = RUN48_DS6
    for mutated in (
        base.replace("\n", "\r\n"),
        "\n".join(line + "   " for line in base.split("\n")),
        base.replace("\n", "\n"),
    ):
        assert A.normalized_text(mutated) == A.normalized_text(base)


def test_source_digest_is_recorded_for_provenance() -> None:
    surf = A.surface(RUN48_DS6)
    assert len(surf.source_sha256) == 64
    assert A.surface(RUN48_DS6).source_sha256 == surf.source_sha256
