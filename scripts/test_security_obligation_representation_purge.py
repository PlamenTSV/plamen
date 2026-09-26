"""Representation-bound gate purge for the security-obligation modules.

Every test here is metamorphic or adversarial:

* a METAMORPHIC test asserts that two semantically equivalent spellings of the
  same worker output produce the SAME verdict.  Each mutation used is one that
  was measured to flip the gate in a real DODO run (run46/run47/run48);
* an ADVERSARIAL control asserts that a mutation which really does change
  MEANING is still rejected, so the purge cannot be satisfied by a gate that
  accepts everything.

The bytes in ``_RUN48_*`` are copied verbatim out of
``dodo-v3-validation-run48 .../worker.validation-sweep/.../
validation_sweep_findings.md`` (934 lines, model work that SUCCEEDED and was
then discarded by the staged gate for 10 presentation-only issues).
"""
from __future__ import annotations

import json

import pytest

import artifact_surface as AS
import security_obligation_authority as A
import security_obligation_lifecycle as L


# ---------------------------------------------------------------------------
# Real run48 bytes: an H3 sibling heading that NAMES the same finding.
# ---------------------------------------------------------------------------

_RUN48_MARKER_A = (
    '<!-- PLAMEN_SECURITY_OBLIGATION_EVIDENCE: {"alias_id":'
    '"SOT-B4C4D3ACCEAA694472BB5FE7","object_id":"","relation_id":"",'
    '"schema_version":"plamen.security-obligation-evidence-binding.v1",'
    '"subject_id":"locus:GatewayCrossChain.sol:L277","symbol":""} -->'
)
_RUN48_MARKER_B = (
    '<!-- PLAMEN_SECURITY_OBLIGATION_EVIDENCE: {"alias_id":'
    '"SOT-36169ED2CB7B75440F516BF9","object_id":"","relation_id":"",'
    '"schema_version":"plamen.security-obligation-evidence-binding.v1",'
    '"subject_id":"locus:contracts/GatewayTransferNative.sol:L286",'
    '"symbol":""} -->'
)

_RUN48_SECTION = "\n".join(
    (
        "## Findings",
        "",
        "### Finding [VS-1]: Both ZEVM contracts arm the revert handler but "
        "null the abort handler",
        "",
        "**Verdict**: CONFIRMED",
        "",
        "#### Postcondition Analysis",
        "**Postcondition Types**: [STATE, BALANCE, EXTERNAL]",
        "",
        "### Obligation evidence bindings for [VS-1]",
        "",
        _RUN48_MARKER_A,
        _RUN48_MARKER_B,
        "",
        "---",
        "",
        "### Finding [VS-2]: GatewaySend can rotate its DODO route proxy",
        "",
        "**Verdict**: CONFIRMED",
        "",
        "## Obligation Receipts",
        "",
        "[OBLIG:security_obligations.md:SO-001] "
        "ALIAS:SOT-B4C4D3ACCEAA694472BB5FE7 STATUS:R KEY:fixture -> VS-1",
    )
)

# run48 depth-edge-case attempt-0002 wrapped every receipt in backticks.
_RUN48_BACKTICKED_RECEIPT = (
    "`[OBLIG:security_obligations.md:SO-001] "
    "ALIAS:SOT-0CD90FD1A8E615C833DEDF75 STATUS:R "
    "KEY:slippage declaration is the unbound input to amountInMax -> DE-1`"
)

# run48 prose that merely NAMED the marker token while explaining placement.
_RUN48_PROSE_MENTION = (
    "Each alias above carries the generated "
    "PLAMEN_SECURITY_OBLIGATION_EVIDENCE marker inside its own finding "
    "section, so every reported alias is structurally bound."
)


def _sections(text: str, issues: list[str] | None = None) -> dict[str, str]:
    return A._finding_sections(
        text, issues=issues if issues is not None else [], source_label="d.md"
    )


# ---------------------------------------------------------------------------
# Gate A -- identity-scoped finding sections
# ---------------------------------------------------------------------------


def test_run48_sibling_heading_naming_same_finding_keeps_its_markers() -> None:
    """THE measured run48 discard: 10 issues, 934 lines of work thrown away."""
    issues: list[str] = []
    sections = _sections(_RUN48_SECTION, issues)

    assert issues == []
    assert "vs-1" in sections
    assert _RUN48_MARKER_A in sections["vs-1"]
    assert _RUN48_MARKER_B in sections["vs-1"]


@pytest.mark.parametrize(
    "declaration",
    (
        "## Finding [VS-1]: title",
        "### Finding [VS-1]: title",
        "#### Finding [VS-1]: title",
        "### **Finding [VS-1]**: title",
        "### Finding `VS-1`: title",
        "### Finding VS-1: title",
        "### Candidate [VS-1]: title",
        "### Issue [VS-1]: title",
    ),
)
def test_finding_declaration_spellings_are_one_identity(
    declaration: str,
) -> None:
    """METAMORPHIC: decoration, label word and heading depth are presentation."""
    text = "\n".join(
        (declaration, "body", "### Obligation evidence bindings for [VS-1]", _RUN48_MARKER_A)
    )

    sections = _sections(text)

    assert set(sections) == {"vs-1"}
    assert _RUN48_MARKER_A in sections["vs-1"]


def test_sibling_heading_naming_a_different_finding_ends_the_section() -> None:
    """ADVERSARIAL: a DIFFERENT identity is a real boundary, not decoration."""
    text = "\n".join(
        (
            "### Finding [VS-1]: first",
            "body",
            "### Obligation evidence bindings for [VS-2]",
            _RUN48_MARKER_A,
        )
    )

    sections = _sections(text)

    assert _RUN48_MARKER_A not in sections.get("vs-1", "")


def test_shallower_generic_heading_still_ends_the_section() -> None:
    """ADVERSARIAL: a document-level heading is not part of the finding."""
    text = "\n".join(
        (
            "### Finding [VS-1]: first",
            "body",
            "## Obligation Receipts",
            _RUN48_MARKER_A,
        )
    )

    assert _RUN48_MARKER_A not in _sections(text).get("vs-1", "")


def test_duplicate_finding_declarations_remain_fail_closed() -> None:
    """ADVERSARIAL: ambiguous identity must STILL block. Closed family."""
    issues: list[str] = []
    sections = _sections(
        "## Finding [BLIND-A-1]: first\nfirst\n"
        "#### Finding [blind-a-1] - duplicate\nsecond\n"
        "## Finding [UNIQUE-2]\nkept\n",
        issues,
    )

    assert set(sections) == {"unique-2"}
    assert any("blind-a-1" in issue for issue in issues)


def test_fenced_finding_heading_creates_no_section() -> None:
    """ADVERSARIAL: a quoted example is not a declaration."""
    text = "```markdown\n## Finding [FENCED-5]: example\n```\n"

    assert _sections(text) == {}


# ---------------------------------------------------------------------------
# Gate B -- evidence markers read by meaning
# ---------------------------------------------------------------------------


def _bindings(section: str) -> tuple[list[dict[str, str]], list[str]]:
    issues: list[str] = []
    rows = A._finding_alias_evidence_bindings(
        section, issues=issues, source_label="d.md"
    )
    return rows, issues


def test_prose_naming_the_marker_token_is_neither_harvested_nor_rejected() -> None:
    """The measured run48 'malformed structured obligation evidence' x3."""
    rows, issues = _bindings(_RUN48_PROSE_MENTION)

    assert rows == []
    assert issues == []


@pytest.mark.parametrize(
    "decorated",
    (
        "{marker}",
        "- {marker}",
        "1. {marker}",
        "> {marker}",
        "- SO-001 `SOT-B4C4D3ACCEAA694472BB5FE7`: {marker}",
        "  {marker}",
    ),
)
def test_marker_decoration_does_not_change_the_binding(decorated: str) -> None:
    """METAMORPHIC: run46/run47 render every marker inside a list item."""
    plain, _ = _bindings(_RUN48_MARKER_A)
    rows, issues = _bindings(decorated.format(marker=_RUN48_MARKER_A))

    assert rows == plain
    assert rows and rows[0]["alias_id"] == "SOT-B4C4D3ACCEAA694472BB5FE7"
    assert issues == []


def test_marker_for_a_different_alias_is_not_accepted_for_this_one() -> None:
    """ADVERSARIAL: the alias binding is identity, not decoration."""
    rows, _ = _bindings(_RUN48_MARKER_B)

    assert rows and rows[0]["alias_id"] == "SOT-36169ED2CB7B75440F516BF9"


def test_malformed_marker_payload_is_debt_not_a_blocking_reject() -> None:
    rows, issues = _bindings(
        "<!-- PLAMEN_SECURITY_OBLIGATION_EVIDENCE: {not json} -->"
    )

    assert rows == []
    assert issues  # visible debt, with a repair hint
    assert all("[FAIL_CLOSED]" not in issue for issue in issues)


# ---------------------------------------------------------------------------
# Gate C -- receipts read by meaning
# ---------------------------------------------------------------------------


def _claim(line: str):
    surf = AS.surface(line)
    assert surf.lines
    return A._receipt_claim(surf.lines[0])


_PLAIN_RECEIPT = (
    "[OBLIG:security_obligations.md:SO-001] "
    "ALIAS:SOT-000000000000000000000001 STATUS:R KEY:fixture -> BLIND-A-1"
)


@pytest.mark.parametrize(
    "decorated",
    (
        "{r}",
        "`{r}`",
        "- {r}",
        "1. {r}",
        "> {r}",
        "  {r}",
        "- `{r}`",
        "**{r}**",
    ),
)
def test_receipt_decoration_does_not_change_the_parse(decorated: str) -> None:
    """METAMORPHIC: backticks are the literal run48 x4 rejection cause."""
    _, plain = _claim(_PLAIN_RECEIPT)
    _, got = _claim(decorated.format(r=_PLAIN_RECEIPT))

    assert plain is not None
    assert got is not None
    assert got.group("display") == plain.group("display")
    assert got.group("alias") == plain.group("alias")
    assert got.group("status") == plain.group("status")
    assert got.group("target").strip() == plain.group("target").strip()


def test_run48_backticked_receipt_parses() -> None:
    _, match = _claim(_RUN48_BACKTICKED_RECEIPT)

    assert match is not None
    assert match.group("alias").upper() == "SOT-0CD90FD1A8E615C833DEDF75"
    assert match.group("target").strip() == "DE-1"


def test_narrative_mention_of_a_receipt_opener_is_not_a_claim() -> None:
    """ADVERSARIAL: prose about receipts must not be parsed as one."""
    _, match = _claim(
        "Every receipt line begins with "
        "[OBLIG:security_obligations.md: and ends with the finding id."
    )

    assert match is None


# ---------------------------------------------------------------------------
# Gate D -- the staged validator's failure action
# ---------------------------------------------------------------------------


STAGED_OUTPUT = "scratchpad:depth_state_trace_findings.md"


def _alias(ordinal: int = 1) -> dict[str, str]:
    return {
        "alias_id": f"SOT-{ordinal:024X}",
        "subject_id": "src/Vault.sol::withdraw",
        "relation_id": f"REL-{ordinal}",
        "object_id": f"asset:{ordinal}",
        "symbol": f"wCOIN{ordinal}",
    }


def _pre_authority(pairs) -> bytes:
    obligations = []
    for ordinal, (display, aliases) in enumerate(pairs, start=1):
        obligations.append(
            {
                "obligation_id": f"SOBL-{ordinal:024X}",
                "display_id": display,
                "rule_id": f"security.fixture.{ordinal}.v1",
                "rule_version": "1.0.0",
                "fact_ids": [f"SFF-{ordinal:024X}"],
                "target_ids": [aliases[0]["subject_id"]] if aliases else [],
                "trigger_aliases": aliases,
            }
        )
    run_binding = {
        "run_id": "b7a1c2d3-4e5f-4a6b-8c9d-0e1f2a3b4c5d",
        "source_snapshot_digest": "C" * 64,
        "source_scope_digest": "D" * 64,
        "ecosystem": "evm",
        "mode": "thorough",
        "pipeline": "sc",
    }
    run_binding["binding_digest"] = A._sha256_value(run_binding)
    authority = {
        "schema_version": A.OBLIGATION_SCHEMA,
        "stage": A.PRE_DEPTH_STAGE,
        "run_binding": run_binding,
        "authority_universe_digest": A._universe_digest(obligations),
        "obligation_count": len(obligations),
        "obligations": obligations,
    }
    authority["authority_digest"] = A._payload_digest(authority)
    return json.dumps(authority, sort_keys=True, separators=(",", ":")).encode()


def _context(pairs=None) -> dict:
    if pairs is None:
        pairs = (("SO-001", [_alias()]),)
    return A.compile_depth_staged_gate_context(_pre_authority(pairs), STAGED_OUTPUT)


def _marker(alias: dict[str, str]) -> str:
    return (
        "<!-- PLAMEN_SECURITY_OBLIGATION_EVIDENCE: "
        + json.dumps(
            A._alias_evidence_binding(alias),
            sort_keys=True,
            separators=(",", ":"),
        )
        + " -->"
    )


def _receipt(display="SO-001", alias_id="SOT-000000000000000000000001",
             status="R", target="BLIND-A-1") -> str:
    alias = f" ALIAS:{alias_id}" if alias_id is not None else ""
    return (
        f"[OBLIG:security_obligations.md:{display}]{alias} "
        f"STATUS:{status} KEY:fixture -> {target}"
    )


def _check(text: str, context=None):
    return A.staged_depth_obligation_receipt_check(
        {STAGED_OUTPUT: text.encode()}, context if context is not None else _context()
    )


def test_run48_sibling_heading_layout_no_longer_discards_the_artifact() -> None:
    """The whole point: a successful analysis must PUBLISH."""
    alias = _alias()
    text = "\n".join(
        (
            "### Finding [BLIND-A-1]: real",
            "body",
            "### Obligation evidence bindings for [BLIND-A-1]",
            _marker(alias),
            "",
            "## Obligation Receipts",
            _receipt(),
        )
    )

    result = _check(text)

    assert result.should_discard is False
    assert A.staged_depth_obligation_receipt_validator(
        {STAGED_OUTPUT: text.encode()}, _context()
    ) == []


def test_backticked_receipt_and_listed_marker_do_not_discard() -> None:
    """METAMORPHIC across the two measured run48 mutation kinds at once."""
    alias = _alias()
    plain = "\n".join(
        ("### Finding [BLIND-A-1]: real", _marker(alias), _receipt())
    )
    decorated = "\n".join(
        (
            "### Finding [BLIND-A-1]: real",
            f"- SO-001 `{alias['alias_id']}`: {_marker(alias)}",
            f"`{_receipt()}`",
        )
    )

    assert _check(plain).should_discard is False
    assert _check(decorated).should_discard is False


def test_prose_mentioning_the_marker_token_does_not_discard() -> None:
    alias = _alias()
    text = "\n".join(
        (
            "### Finding [BLIND-A-1]: real",
            _marker(alias),
            _RUN48_PROSE_MENTION,
            _receipt(),
        )
    )

    assert _check(text).should_discard is False


def test_missing_marker_is_visible_debt_not_a_discard() -> None:
    """The evidence binding is a supporting record: DEBT, with a repair hint."""
    text = "\n".join(("### Finding [BLIND-A-1]: real", "body", _receipt()))

    result = _check(text)

    assert result.should_discard is False
    assert result.debt_defects
    assert all(d.repair_hint for d in result.debt_defects)
    assert all(d.physical_line > 0 for d in result.debt_defects)


@pytest.mark.parametrize(
    "receipt, why",
    (
        (_receipt(display="SO-999"), "display not in the roster"),
        (_receipt(alias_id="SOT-0000000000000000000000FF"), "alias not in roster"),
        (_receipt(target="NO-SUCH-FINDING-9"), "referent does not resolve"),
    ),
)
def test_identity_defects_still_block(receipt: str, why: str) -> None:
    """ADVERSARIAL: the closed families must NOT have been widened."""
    alias = _alias()
    text = "\n".join(("### Finding [BLIND-A-1]: real", _marker(alias), receipt))

    result = _check(text)

    assert result.should_discard is True, why
    assert result.blocking_defects
    assert all(
        d.property_violated.split(".", 1)[0] in AS.FAIL_CLOSED_PROPERTY_FAMILIES
        for d in result.blocking_defects
    )


def test_duplicate_alias_claim_still_blocks() -> None:
    """ADVERSARIAL: dedup is a closed family."""
    alias = _alias()
    text = "\n".join(
        (
            "### Finding [BLIND-A-1]: real",
            _marker(alias),
            _receipt(),
            _receipt(),
        )
    )

    result = _check(text)

    assert result.should_discard is True
    assert any(
        d.property_violated.startswith("dedup.") for d in result.blocking_defects
    )


def test_identity_block_survives_decoration() -> None:
    """A genuinely unknown display blocks whether or not it wears backticks."""
    alias = _alias()
    bad = _receipt(display="SO-999")
    plain = "\n".join(("### Finding [BLIND-A-1]: x", _marker(alias), bad))
    ticked = "\n".join(("### Finding [BLIND-A-1]: x", _marker(alias), f"`{bad}`"))

    assert _check(plain).should_discard is True
    assert _check(ticked).should_discard is True


def test_every_defect_carries_the_mechanical_closure_for_its_family() -> None:
    text = "\n".join(("### Finding [BLIND-A-1]: real", "body", _receipt()))

    for defect in _check(text).defects:
        assert defect.closure == AS.closure_for_property(defect.property_violated)


# ---------------------------------------------------------------------------
# Gate E -- the lifecycle verifier-verdict reader
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "spelling",
    (
        "**Verdict**: CONFIRMED",
        "**Verdict:** CONFIRMED",
        "Verdict: CONFIRMED",
        "- **Verdict**: CONFIRMED",
        "> **Verdict**: CONFIRMED",
        "**Verdict** \u2014 CONFIRMED",
        "**Verdict** \u2013 CONFIRMED",
        "**Verdict** = CONFIRMED",
        "| Verdict | CONFIRMED |",
        "**Verdict**: **CONFIRMED**",
        "**Verdict**: `CONFIRMED`",
        "**Verdict**: CONFIRMED.",
        "**Verdict**: confirmed",
        "**Verdict** (final): CONFIRMED",
    ),
)
def test_verifier_verdict_spellings_are_one_verdict(spelling: str) -> None:
    """METAMORPHIC: the verdict is a MEANING, not a line shape."""
    text = f"# Verify\n\n{spelling}\n\n**Severity**: High\n"

    assert L._verifier_verdict(text) == "CONFIRMED"


def test_fenced_verdict_template_cannot_override_the_real_verdict() -> None:
    """ADVERSARIAL: the measured token-order bug -- a quoted menu won.

    The old reader scanned the WHOLE document for 'CONFIRMED' first, so a
    fenced template listing the allowed verdicts silently reported CONFIRMED
    for an artifact whose real verdict was REFUTED.
    """
    text = (
        "# Verify\n\n"
        "```markdown\n"
        "**Verdict**: CONFIRMED / CONTESTED / REFUTED\n"
        "```\n\n"
        "**Verdict**: REFUTED\n"
    )

    assert L._verifier_verdict(text) == "REFUTED"


def test_narrative_mention_of_a_verdict_is_not_a_verdict() -> None:
    """ADVERSARIAL: prose about verdicts must not mint one."""
    text = (
        "# Verify\n\n"
        "I will record the Verdict: CONFIRMED only after the PoC compiles.\n"
    )

    assert L._verifier_verdict(text) is None


def test_two_conflicting_asserted_verdicts_stay_unresolved() -> None:
    """ADVERSARIAL: disposition is fail-closed; ambiguity is not a guess."""
    text = "# Verify\n\n**Verdict**: CONFIRMED\n\n**Verdict**: REFUTED\n"

    assert L._verifier_verdict(text) is None


def test_absent_verdict_stays_none() -> None:
    assert L._verifier_verdict("# Verify\n\n**Severity**: High\n") is None


def test_drop_prefixed_verdict_is_not_truncated_to_its_suffix() -> None:
    """ADVERSARIAL: DROP_FALSE_POSITIVE is not FALSE_POSITIVE."""
    text = "# Verify\n\n**Verdict**: DROP_FALSE_POSITIVE\n"

    assert L._verifier_verdict(text) == "DROP_FALSE_POSITIVE"


# ---------------------------------------------------------------------------
# The recall justification for reclassifying the marker check to DEBT
# ---------------------------------------------------------------------------


def test_marker_debt_still_cannot_discharge_the_obligation() -> None:
    """Downgrading the marker check to DEBT loses NO recall.

    This is the load-bearing control for the whole reclassification.  The
    staged gate no longer discards an artifact whose alias marker is missing,
    misplaced or corrupted -- but the derivation path's
    ``_reported_receipt_matches_alias`` still requires the EXACT marker inside
    the referent section, so the alias stays undischarged and queued for
    repair.  Only the destruction of a complete analysis was removed.
    """
    alias = _alias()
    good_section = "\n".join(("### Finding [BLIND-A-1]: real", _marker(alias)))
    corrupted = good_section.replace(alias["alias_id"], "SOT-" + "0" * 24)

    def covered(section: str) -> bool:
        rows = A._finding_alias_evidence_bindings(
            section, issues=[], source_label="d.md"
        )
        return A._reported_receipt_matches_alias(
            {"referent_alias_bindings": rows}, alias
        )

    assert covered(good_section) is True
    assert covered(corrupted) is False
    assert covered("### Finding [BLIND-A-1]: real\nno marker at all") is False

    # ...and the staged gate reports it rather than discarding the artifact.
    result = _check("\n".join((corrupted, _receipt())))
    assert result.should_discard is False
    assert "evidence.same_section_alias_marker" in {
        d.property_violated for d in result.debt_defects
    }
