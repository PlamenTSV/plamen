"""Plamen V2 — the single normalize-once admission surface for worker artifacts.

Layer 0. Standard library ONLY: no ``plamen_*`` imports, no ``markdown_it``.
Every public function is pure, total, and **never raises** on any input.

WHY THIS EXISTS
===============

Measured, not theoretical. DODO run48 (2026-09-20): every core depth worker
SUCCEEDED — receipts show ``subtype=success``, $6-9 and 17-28 minutes each;
``depth-token-flow`` wrote 6 findings, ``validation-sweep`` wrote 723 lines of
complete analysis. Each staged its artifact. The staged obligation validator
rejected them and NOTHING published, so the phase retried the entire 15-job
wave. The exact reasons from the run receipts were:

* ``malformed obligation receipt-like line rejected`` x4 — because the worker
  wrapped each receipt in BACKTICKS so it renders as code.
* ``malformed structured obligation evidence ignored`` x3 — because a PROSE
  sentence NAMED the marker token while explaining where markers were placed.

Neither line had any semantic defect. Both were presentation.

The bug class is one sentence: **a gate tests a REPRESENTATION (exact line
shape, decoration, whole-line anchoring, exact occurrence counts, column
position, string equality, vocabulary allowlists) instead of the PROPERTY it
exists to protect, and then fails CLOSED by discarding the artifact.**

A census of the pipeline found this shape in ~90 distinct gates across
``candidate_negative_authority.py``, ``security_obligation_authority.py``,
``plamen_validators.py``, ``plamen_driver.py``, ``plamen_parsers.py``,
``inventory_reconciliation.py``, ``semantic_invariant_authority.py`` and
``plamen_markdown.py``. Representative measured flips, each a
zero-semantic-change edit to real worker bytes:

* ``## Finding [DS-6]`` -> ``## Finding DS-6``  (delete two characters)
  discarded a 126,589-byte accepted artifact.
* ``### Obligation evidence bindings`` -> ``#### Obligation evidence bindings``
  (add five ``#``) turned 10 issues into 0 on the run48 validation-sweep file.
* ``NOT_APPLICABLE_PROPOSAL`` -> ``NOT_APPLICABLE_PROPOSAL.`` (one period)
  collapsed the correct nonterminal enum to the legacy terminal and discarded
  a 70,540-byte breadth artifact.
* ``| Finding ID | Verdict |`` -> ``| ID | Finding ID | Verdict |`` (add a
  correct, MORE informative column) dropped identity for every row.
* ``| — |`` -> ``| – |`` (EN dash for EM dash) minted a phantom candidate and
  discarded the artifact.
* One stray ```` ``` ```` line (three characters) blinded the graph-consumption
  gate to every acknowledgement below it and destroyed a 25-minute analysis.

THE FOUR PRINCIPLES THIS MODULE IMPLEMENTS
==========================================

1. **Tolerant reader / Postel's law** (Fowler). Parse by MEANING, not by
   POSITION or decoration. Ignore what you do not need. A field a gate does
   not consume can never make an artifact invalid. Concretely: column ROLE not
   column INDEX; label MEANING not label BYTES; unknown keys and extra columns
   are ignored, not fatal.

2. **Parse, don't validate** (Alexis King) + **make illegal states
   unrepresentable** (Minsky). Normalize ONCE at the boundary into a
   constrained value — :func:`surface` — then let every downstream check read
   that value. Do NOT re-derive syntax at each call site with another ad-hoc
   regex. The proliferation of per-site regexes IS the disease: the census
   found two independent identity regexes for ONE property in a single module
   (``_source_item_identity`` rejects ``Finding DEPTH-TF-3``;
   ``_DECORATED_TABLE_ID_RE`` accepts it), and two parsers for ONE completion
   marker that return opposite verdicts on identical bytes
   (``_recon_worker_complete`` vs ``_depth_worker_has_complete_signal``).

3. **Repair, don't reject.** A failing check returns SPECIFIC repair
   information — :class:`Defect` carries ``property_violated``,
   ``physical_line``, ``observed``, ``expected``, ``repair_hint``. Non-identity
   defects degrade with VISIBLE DEBT rather than discarding the artifact.
   Rejection alone is the worst available outcome: it throws away an analysis
   that already cost money and time, and it throws away the evidence a human
   would need to fix the prompt.

4. **Metamorphic / property-based testing.** Semantically equivalent inputs
   must produce equivalent verdicts. :func:`normalized_text` gives every gate a
   canonical view whose stability under the mutation kinds in the evidence is
   directly testable, and whose idempotence — ``surface(normalized_text(x))``
   yields the same ``normalized_text`` — is a property test, not an opinion.

THE CLASSIFICATION RULE (fixer agents apply this verbatim)
==========================================================

Exactly four property families stay **FAIL_CLOSED**. Everything else degrades
with visible debt.

FAIL_CLOSED families — a defect here may block, because being wrong here
silently loses or fabricates a real security candidate:

* ``identity``   — WHICH candidate/obligation/finding this record is about, and
                   whether two records name the same one. Includes join keys,
                   alias binding, and cross-artifact referents.
* ``dedup``      — whether two records are the SAME candidate (a merge closes a
                   candidate; a bad merge deletes a real bug).
* ``severity``   — the tier a finding is reported at, and any cap/demotion.
* ``disposition``— whether a candidate is open, refuted, deferred, excluded,
                   body or appendix; whether a negative proposal is terminal.

Everything else is **DEBT**: supporting records, receipts, markers, evidence
bindings, counts, ordering, placement, formatting, vocabulary, schema extras,
completeness attestations, graph/bound-input acknowledgements, trace tables,
coverage ledgers, prompt-contract lint. A defect in these degrades the
artifact's assurance and MUST be surfaced to the reader, but it must never
discard a worker's analysis.

WHY THIS SPLIT AND NOT ANOTHER
------------------------------

The asymmetry is recall. Burying or discarding a real finding is the
unacceptable error; an extra flagged record is cheap. The four closed families
are exactly the ones where a permissive answer *removes a candidate from human
attention* — a wrong identity silently merges two bugs into one, a wrong dedup
deletes one, a wrong severity buries it below the reporting floor, a wrong
disposition closes it. Every other family, when permissive, at worst ships a
record with a visible quality caveat attached.

FAIL_CLOSED IS NOT REPRESENTATION-BOUND
---------------------------------------

This is the part every prior fix got wrong. "Fail closed" means *the decision
is conservative*, NOT *the bytes must be exact*. The correct order is always:

    1. NORMALIZE the bytes through this module (``surface`` / ``normalize_*``).
    2. Apply the closed check to the NORMALIZED VALUE.
    3. On failure emit a ``FAIL_CLOSED`` :class:`Defect` naming the normalized
       value it saw and the normalized value it needed.

``Finding [DS-6]``, ``Finding DS-6``, ``finding `DS-6` `` and
``**Finding [DS-6]**`` are the SAME identity. A gate that accepts the first and
discards the others is not fail-closed on identity; it is fail-closed on
punctuation, which protects nothing and costs everything.

WHAT THIS MODULE DELIBERATELY DOES NOT DO
=========================================

It does not decide policy. It reports what an artifact *says*. Whether a
missing identity blocks, whether a fenced receipt counts, whether an extra
disposition row is a conflict — those are the caller's decisions, made against
the classification rule above. This module's contract is only that two
semantically equivalent artifacts produce the same answer.

PUBLIC API
==========

Boundary
    ``surface(raw)``                     -> :class:`ArtifactSurface`
    ``normalized_text(surface_or_raw)``  -> canonical, idempotent text view

Assertion vs mention (the run48 killer)
    ``classify_token(line, token)``      -> :class:`TokenOccurrence` | None
    ``line_asserts(line, token)``        -> bool
    ``line_mentions(line, token)``       -> bool
    ``find_assertions(surface, token)``  -> tuple[:class:`TokenOccurrence`, ...]

Tables by ROLE
    ``read_tables(surface, roles=...)``  -> tuple[:class:`Table`, ...]
    ``find_table(surface, required_roles=...)``
    ``Table.role_index(role)`` / ``TableRow.get(role)`` -> None when absent

Labelled fields by MEANING
    ``read_field(surface, role)``        -> :class:`Field` | None
    ``read_fields(surface, role)``       -> tuple[:class:`Field`, ...]

Values
    ``normalize_label(text)`` ``normalize_enum(text)`` ``normalize_cell(text)``
    ``strip_decoration(text)`` ``is_zero_candidate_placeholder(text)``
    ``candidate_identity(text)`` -> :class:`Identity` | None

Verdicts
    ``ACCEPTED`` / ``CheckResult`` / ``Defect`` / ``closure_for_property(name)``
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass, field as _dc_field
from typing import Callable, Iterable, Mapping, Optional, Sequence

__all__ = [
    "ACCEPTED",
    "ArtifactSurface",
    "CheckResult",
    "DEBT",
    "DEFAULT_COLUMN_ROLES",
    "DEFAULT_FIELD_ROLES",
    "Defect",
    "FAIL_CLOSED",
    "FAIL_CLOSED_PROPERTY_FAMILIES",
    "Field",
    "Identity",
    "IGNORE_ROLE_VALUE",
    "IgnoredRoleValue",
    "LogicalLine",
    "RoleAssertion",
    "RoleResolution",
    "Table",
    "TableRow",
    "TokenOccurrence",
    "candidate_identity",
    "classify_token",
    "closure_for_property",
    "find_assertions",
    "find_table",
    "is_zero_candidate_placeholder",
    "line_asserts",
    "line_mentions",
    "normalize_cell",
    "normalize_enum",
    "normalize_label",
    "normalized_text",
    "read_field",
    "read_fields",
    "read_tables",
    "strip_decoration",
    "surface",
]

# --------------------------------------------------------------------------
# Bounds. Exceeding a bound TRUNCATES with recorded debt; it never raises and
# it never rejects. (Contrast plamen_markdown.inline_code_source_spans, whose
# combinatorial bound RAISES and whose raise is converted upstream into a hard
# reconciliation failure for the whole artifact.)
# --------------------------------------------------------------------------
MAX_PHYSICAL_LINES = 400_000
MAX_LINE_CHARS = 262_144
MAX_JOIN_SPAN = 64

# Line kinds.
BLANK = "BLANK"
HEADING = "HEADING"
PROSE = "PROSE"
TABLE_HEADER = "TABLE_HEADER"
TABLE_SEPARATOR = "TABLE_SEPARATOR"
TABLE_ROW = "TABLE_ROW"
FENCE_DELIMITER = "FENCE_DELIMITER"
FENCE_CONTENT = "FENCE_CONTENT"
HTML_COMMENT = "HTML_COMMENT"
THEMATIC_BREAK = "THEMATIC_BREAK"
SETEXT_UNDERLINE = "SETEXT_UNDERLINE"

# Closure classes.
FAIL_CLOSED = "FAIL_CLOSED"
DEBT = "DEBT"

#: The ONLY property families that may block an artifact. See the module
#: docstring, section "THE CLASSIFICATION RULE".
FAIL_CLOSED_PROPERTY_FAMILIES = frozenset(
    {"identity", "dedup", "severity", "disposition"}
)

# Occurrence kinds.
ASSERTION = "ASSERTION"
MENTION = "MENTION"


# --------------------------------------------------------------------------
# Character-level normalization
# --------------------------------------------------------------------------

_HTML_SPACE_ENTITIES = ("&nbsp;", "&#160;", "&#xa0;", "&#xA0;", "&ensp;", "&emsp;")
_HTML_DASH_ENTITIES = {
    "&mdash;": "—",
    "&ndash;": "–",
    "&#8212;": "—",
    "&#8211;": "–",
}
_UNICODE_SPACES = "               　﻿​"
_ZERO_WIDTH = "​‌‍﻿"

_ARROWS = (("→", "->"), ("⇒", "->"), ("=>", "->"))

_EMPH_STAR_RE = re.compile(r"\*{1,3}(?=\S)(.+?)(?<=\S)\*{1,3}", re.DOTALL)
_EMPH_UNDER_RE = re.compile(r"(?<![\w`])_{1,3}(?=\S)([^_\n]+?)(?<=\S)_{1,3}(?!\w)")
_STRIKE_RE = re.compile(r"~~(?=\S)(.+?)(?<=\S)~~", re.DOTALL)
_CODE_SPAN_RE = re.compile(r"(`+)(?!`)(.+?)(?<!`)\1(?!`)", re.DOTALL)
_WS_RE = re.compile(r"[ \t]+")

_BLOCKQUOTE_RE = re.compile(r"^(?:[ \t]{0,3}>[ \t]?)+")
_LIST_MARKER_RE = re.compile(r"^[ \t]{0,8}(?:[-*+•]|\d{1,4}[.)]|[a-zA-Z][.)])[ \t]+")
_ATX_RE = re.compile(r"^[ \t]{0,3}(#{1,6})[ \t]*(.*?)[ \t]*#*[ \t]*$")
_FENCE_RE = re.compile(r"^[ \t]{0,3}(`{3,}|~{3,})[ \t]*(\S*)[ \t]*$")
_THEMATIC_RE = re.compile(r"^[ \t]{0,3}(?:(?:\*[ \t]*){3,}|(?:_[ \t]*){3,}|(?:-[ \t]*){3,})$")
_SETEXT_RE = re.compile(r"^[ \t]{0,3}(=+|-+)[ \t]*$")
_TABLE_SEP_CELL_RE = re.compile(r"^:?-{1,}:?$")
_TERMINAL_PUNCT = ".!?…"


def _as_text(raw: object) -> tuple[str, tuple["Defect", ...]]:
    """Coerce anything to text. Never raises. Reports lossy decoding as debt."""
    defects: list[Defect] = []
    if raw is None:
        return "", ()
    if isinstance(raw, str):
        text = raw
    elif isinstance(raw, (bytes, bytearray, memoryview)):
        try:
            data = bytes(raw)
        except Exception:
            return "", (
                Defect(
                    property_violated="encoding.uncoercible_input",
                    physical_line=0,
                    observed=type(raw).__name__,
                    expected="readable bytes",
                    repair_hint="Pass readable artifact bytes or text.",
                    closure=DEBT,
                ),
            )
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = data.decode("utf-8", errors="replace")
            defects.append(
                Defect(
                    property_violated="encoding.not_strict_utf8",
                    physical_line=0,
                    observed="undecodable byte sequence",
                    expected="strict UTF-8",
                    repair_hint=(
                        "Artifact contains non-UTF-8 bytes; they were replaced "
                        "with U+FFFD so the analysis is still readable. Re-emit "
                        "the artifact as UTF-8."
                    ),
                    closure=DEBT,
                )
            )
    else:
        try:
            text = str(raw)
        except Exception:  # pragma: no cover - defensive totality
            return "", (
                Defect(
                    property_violated="encoding.uncoercible_input",
                    physical_line=0,
                    observed=type(raw).__name__,
                    expected="str or bytes",
                    repair_hint="Pass artifact bytes or text.",
                    closure=DEBT,
                ),
            )
    return text, tuple(defects)


def _canonical_chars(text: str) -> str:
    """Fold presentation-only codepoints. Idempotent by construction."""
    if not text:
        return ""
    out = text.replace("\r\n", "\n").replace("\r", "\n")
    for entity in _HTML_SPACE_ENTITIES:
        out = out.replace(entity, " ")
    for entity, replacement in _HTML_DASH_ENTITIES.items():
        out = out.replace(entity, replacement)
    if any(ch in out for ch in _UNICODE_SPACES):
        out = "".join(
            " " if ch in _UNICODE_SPACES and ch not in _ZERO_WIDTH else ch
            for ch in out
        )
    if any(ch in out for ch in _ZERO_WIDTH):
        out = "".join(ch for ch in out if ch not in _ZERO_WIDTH)
    try:
        out = unicodedata.normalize("NFC", out)
    except Exception:  # pragma: no cover - defensive totality
        pass
    return out


def strip_decoration(text: object) -> str:
    """Remove Markdown presentation from a logical line. Total and idempotent.

    Strips inline-code delimiters, ``*``/``_`` emphasis, ``~~`` strikethrough,
    HTML space/dash entities and stray zero-width characters; collapses runs of
    spaces/tabs. Does NOT remove brackets (``[DS-6]`` is identity, not
    decoration) and does NOT touch ``*`` or ``_`` that are not paired
    delimiters, so ``a * b`` and ``my_var_name`` survive intact.
    """
    if not isinstance(text, str):
        text, _ = _as_text(text)
    out = _canonical_chars(text)
    if not out:
        return ""
    for _ in range(4):
        before = out
        out = _CODE_SPAN_RE.sub(lambda m: m.group(2), out)
        out = _STRIKE_RE.sub(lambda m: m.group(1), out)
        out = _EMPH_STAR_RE.sub(lambda m: m.group(1), out)
        out = _EMPH_UNDER_RE.sub(lambda m: m.group(1), out)
        if out == before:
            break
    out = _WS_RE.sub(" ", out)
    return out.strip()


def normalize_cell(text: object) -> str:
    """Canonical form of a table cell / field value. Total and idempotent."""
    return strip_decoration(text)


def normalize_label(text: object) -> str:
    """Canonical form of a column header or field label. Total, idempotent.

    ``**Finding&nbsp;ID**:`` -> ``finding id``.
    ``Material Harm (MANDATORY)`` -> ``material harm``.
    """
    value = strip_decoration(text)
    if not value:
        return ""
    value = re.sub(r"\((?:[^()]{0,80})\)", " ", value)
    value = re.sub(r"\[(?:[^\[\]]{0,80})\]", " ", value)
    value = value.strip().strip(":*_-–— \t")
    value = _WS_RE.sub(" ", value).strip()
    return value.casefold()


_ENUM_LEAD_RE = re.compile(r"[A-Za-z][A-Za-z0-9]*(?:[_\-/][A-Za-z0-9]+)*")


def normalize_enum(text: object) -> str:
    """Canonical enum token from a decorated, punctuated, annotated value.

    This is the direct fix for the measured ``NOT_APPLICABLE_PROPOSAL.``
    collapse: the leading token run is extracted BEFORE any alias table is
    consulted, so a sentence-ending period, a trailing colon-annotation, a
    parenthetical or a dash-annotation can no longer downgrade a correct
    nonterminal enum to a legacy terminal one.

    ``NOT_APPLICABLE_PROPOSAL.``             -> ``NOT_APPLICABLE_PROPOSAL``
    ``NOT_APPLICABLE_PROPOSAL: no emission`` -> ``NOT_APPLICABLE_PROPOSAL``
    ``Medium (High x Low)``                  -> ``MEDIUM``
    ``NOT_APPLICABLE``                       -> ``NOT_APPLICABLE`` (unchanged)
    """
    value = strip_decoration(text)
    if not value:
        return ""
    value = value.lstrip("[(<{ \t")
    match = _ENUM_LEAD_RE.match(value)
    if not match:
        return ""
    token = match.group(0)
    token = token.replace("-", "_").replace("/", "_")
    return token.upper()


_ZERO_PLACEHOLDERS = frozenset(
    {
        "",
        "-",
        "--",
        "---",
        "‐",
        "‑",
        "‒",
        "–",
        "—",
        "―",
        "−",
        "0",
        "empty",
        "n/a",
        "n.a.",
        "na",
        "nil",
        "no candidate",
        "no candidates",
        "no findings",
        "no finding",
        "no new candidate",
        "no new candidates",
        "none",
        "none new",
        "not applicable",
        "nothing",
        "null",
        "zero",
    }
)


def is_zero_candidate_placeholder(text: object) -> bool:
    """True when a cell explicitly attests 'there is no candidate here'.

    Tolerates every dash codepoint, the HTML entities, a parenthetical
    qualifier and surrounding decoration. The measured defect this replaces
    accepted exactly two strings (``—`` and ``none new``) and minted a phantom
    candidate — which then discarded the artifact — for ``–``, ``-``, ``N/A``,
    ``(none)``, ``&mdash;`` and ``no new candidates``.
    """
    value = strip_decoration(text)
    if not value:
        return True
    value = re.sub(r"\((?:[^()]{0,120})\)", " ", value)
    value = _WS_RE.sub(" ", value).strip().strip(".,;:").strip()
    return value.casefold() in _ZERO_PLACEHOLDERS


# --------------------------------------------------------------------------
# Identity
# --------------------------------------------------------------------------

_ID_CORE = r"[A-Za-z][A-Za-z0-9]{0,15}(?:-[A-Za-z0-9]{1,24}){1,3}"
_ID_LABEL = r"(?:finding|candidate|issue|hypothesis|obligation|chain)"
_BRACKETED_ID_RE = re.compile(r"\[\s*(" + _ID_CORE + r")\s*\]")
_LABELLED_ID_RE = re.compile(
    r"(?i)\b" + _ID_LABEL + r"\b[\s:#]*\[?\s*(" + _ID_CORE
    + r")(?![A-Za-z0-9_-])\s*\]?"
)
_BARE_ID_RE = re.compile(r"(?<![A-Za-z0-9_-])(" + _ID_CORE + r")(?![A-Za-z0-9_-])")


@dataclass(frozen=True)
class Identity:
    """A candidate identity read from a heading, cell or line."""

    value: str
    form: str  # BRACKETED | LABELLED | BARE
    offset: int

    @property
    def key(self) -> str:
        """Case-folded join key. Two spellings of one identity share this."""
        return self.value.replace("_", "-").upper()


def candidate_identity(text: object) -> Optional[Identity]:
    """Read ONE stable candidate identity from arbitrary text. Never raises.

    Decoration- and depth-agnostic by design. All of these are the SAME
    identity and all return ``DS-6``::

        ## Finding [DS-6]: title            #### Finding [DS-6]
        ## Finding DS-6: title              ## **Finding [DS-6]**
        ## Candidate [DS-6]                 ## Issue DS-6
        | Finding DS-6 | ...                | `DS-6` | ...

    The measured defect this replaces derived an opaque ``ENTITY-<hash>`` for
    the bracket-free spellings and then used that derivation as grounds to
    discard the whole artifact — while a SECOND regex in the same module
    accepted the very same string in a table cell.

    Returns ``None`` when no identity is present. That is a fact for the caller
    to classify, not a verdict: whether a missing identity blocks is the
    caller's FAIL_CLOSED ``identity`` decision, made on this normalized answer.
    """
    value = strip_decoration(text)
    if not value:
        return None
    bracketed = _BRACKETED_ID_RE.search(value)
    labelled = _LABELLED_ID_RE.search(value)
    # A labelled subject precedes references in its title. Conversely, an
    # initial bracketed subject must not be replaced by a later labelled
    # reference. Preserve BRACKETED when both patterns identify the same span.
    if labelled and (bracketed is None or labelled.start(1) < bracketed.start(1)):
        return Identity(labelled.group(1), "LABELLED", labelled.start(1))
    if bracketed:
        return Identity(bracketed.group(1), "BRACKETED", bracketed.start(1))
    match = _BARE_ID_RE.search(value)
    if match:
        return Identity(match.group(1), "BARE", match.start(1))
    return None


# --------------------------------------------------------------------------
# Verdicts
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Defect:
    """A specific, repairable defect. Principle 3: repair, don't reject."""

    property_violated: str
    physical_line: int
    observed: str
    expected: str
    repair_hint: str
    closure: str = DEBT

    @property
    def blocking(self) -> bool:
        return self.closure == FAIL_CLOSED

    def render(self) -> str:
        where = f":{self.physical_line}" if self.physical_line else ""
        return (
            f"[{self.closure}] {self.property_violated}{where}: "
            f"observed {self.observed!r}, expected {self.expected!r}. "
            f"{self.repair_hint}"
        )


@dataclass(frozen=True)
class CheckResult:
    """ACCEPTED, or a set of typed defects."""

    defects: tuple[Defect, ...] = ()

    @property
    def accepted(self) -> bool:
        return not self.defects

    @property
    def blocking_defects(self) -> tuple[Defect, ...]:
        return tuple(d for d in self.defects if d.closure == FAIL_CLOSED)

    @property
    def debt_defects(self) -> tuple[Defect, ...]:
        return tuple(d for d in self.defects if d.closure != FAIL_CLOSED)

    @property
    def should_discard(self) -> bool:
        """The ONLY question a staged validator may ask before discarding."""
        return bool(self.blocking_defects)

    def merge(self, *others: "CheckResult") -> "CheckResult":
        merged = list(self.defects)
        for other in others:
            if isinstance(other, CheckResult):
                merged.extend(other.defects)
        return CheckResult(tuple(merged))

    def render(self) -> tuple[str, ...]:
        return tuple(d.render() for d in self.defects)


ACCEPTED = CheckResult(())


def closure_for_property(property_name: object) -> str:
    """Mechanically apply the classification rule to a property name.

    The name is dotted, family first: ``identity.candidate_id``,
    ``receipt.line_grammar``, ``dedup.merge_decision``. Only the four families
    in :data:`FAIL_CLOSED_PROPERTY_FAMILIES` may block; everything else is
    DEBT. A fixer agent never decides this by judgement — it names the family
    and reads the answer here.
    """
    if not isinstance(property_name, str) or not property_name:
        return DEBT
    family = property_name.split(".", 1)[0].strip().casefold()
    return FAIL_CLOSED if family in FAIL_CLOSED_PROPERTY_FAMILIES else DEBT


# --------------------------------------------------------------------------
# Logical lines
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class LogicalLine:
    """One logical line: soft-wrap joined, decoration stripped, line-numbered.

    ``physical_start``/``physical_end`` are 1-indexed and always point back at
    the worker's real bytes, so every :class:`Defect` can tell a human exactly
    where to look even though the check ran against the normalized view.
    """

    index: int
    physical_start: int
    physical_end: int
    kind: str
    raw: str
    text: str
    indent: int = 0
    list_marker: str = ""
    blockquote_depth: int = 0
    heading_level: int = 0
    heading_text: str = ""
    fence_depth: int = 0
    comment_depth: int = 0
    table_index: int = -1
    cells: tuple[str, ...] = ()

    @property
    def in_fence(self) -> bool:
        return self.fence_depth > 0 or self.kind in (FENCE_CONTENT, FENCE_DELIMITER)

    @property
    def in_comment(self) -> bool:
        return self.comment_depth > 0 or self.kind == HTML_COMMENT

    @property
    def is_prose(self) -> bool:
        return self.kind in (PROSE, HEADING)

    @property
    def is_table_row(self) -> bool:
        return self.kind in (TABLE_HEADER, TABLE_ROW)


def _split_unescaped_pipes(line: str) -> list[str]:
    """Split a GFM row on unescaped pipes outside inline-code spans."""
    cells: list[str] = []
    buf: list[str] = []
    i = 0
    n = len(line)
    tick_run = 0
    while i < n:
        ch = line[i]
        if ch == "\\" and i + 1 < n:
            buf.append(ch)
            buf.append(line[i + 1])
            i += 2
            continue
        if ch == "`":
            run = 0
            while i + run < n and line[i + run] == "`":
                run += 1
            if tick_run == 0:
                tick_run = run
            elif tick_run == run:
                tick_run = 0
            buf.append("`" * run)
            i += run
            continue
        if ch == "|" and tick_run == 0:
            cells.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    cells.append("".join(buf))
    return cells


def _row_cells(line: str) -> Optional[tuple[str, ...]]:
    """Cells of a pipe row, or None when the line is not row-shaped."""
    stripped = line.strip()
    if "|" not in stripped:
        return None
    parts = _split_unescaped_pipes(stripped)
    if len(parts) < 2:
        return None
    if parts and parts[0].strip() == "":
        parts = parts[1:]
    if parts and parts[-1].strip() == "":
        parts = parts[:-1]
    if not parts:
        return None
    return tuple(part.replace("\\|", "|").strip() for part in parts)


def _is_separator_row(cells: Optional[Sequence[str]]) -> bool:
    if not cells:
        return False
    return all(_TABLE_SEP_CELL_RE.match(c.strip().replace(" ", "")) for c in cells)


def _bounded_row(line: str) -> bool:
    """A pipe line delimited by pipes: unambiguously a table row."""
    stripped = line.strip()
    return "|" in stripped and (stripped.startswith("|") or stripped.endswith("|"))


def _looks_like_row(line: str) -> bool:
    """Candidate table row.

    A bare pipe-bearing PROSE sentence is NOT a row. Requiring either bounding
    pipes or a separator row (resolved in pass 3) is what makes the normalized
    view idempotent: without it, a normalized prose line that happens to quote
    ``| - | - | none | - |`` mid-sentence re-parses as a table on the second
    pass. GFM tables that omit their outer pipes are still recognized — they
    are admitted by their separator row, not by their punctuation.
    """
    stripped = line.strip()
    if "|" not in stripped:
        return False
    if _bounded_row(stripped):
        return True
    cells = _row_cells(line)
    return bool(cells and len(cells) >= 2)


@dataclass(frozen=True)
class ArtifactSurface:
    """The normalized view of one artifact. Built once, read by every gate."""

    lines: tuple[LogicalLine, ...] = ()
    source_sha256: str = ""
    physical_line_count: int = 0
    defects: tuple[Defect, ...] = ()
    truncated: bool = False

    def __iter__(self):
        return iter(self.lines)

    def __len__(self) -> int:
        return len(self.lines)

    def prose_lines(self) -> tuple[LogicalLine, ...]:
        return tuple(l for l in self.lines if l.is_prose)

    def fenced_lines(self) -> tuple[LogicalLine, ...]:
        return tuple(l for l in self.lines if l.in_fence)

    def comment_lines(self) -> tuple[LogicalLine, ...]:
        return tuple(l for l in self.lines if l.in_comment)

    def headings(self) -> tuple[LogicalLine, ...]:
        return tuple(l for l in self.lines if l.kind == HEADING)

    def sections(self, predicate=None) -> tuple[tuple[LogicalLine, tuple[LogicalLine, ...]], ...]:
        """Heading -> its body, bounded by the next heading of <= depth.

        Depth-agnostic for the CALLER's purposes: a section simply ends at the
        next equal-or-shallower heading. The measured defect this replaces let
        an H3 sibling ('### Obligation evidence bindings for [VS-1]') terminate
        its own finding's section, so correct markers landed 'outside' the
        finding and 10 issues discarded a 934-line artifact. Callers that need
        'this heading plus everything nested under it' should instead use
        :meth:`section_containing`, which never splits on a sibling whose text
        names the same identity.
        """
        out: list[tuple[LogicalLine, tuple[LogicalLine, ...]]] = []
        heads = [i for i, l in enumerate(self.lines) if l.kind == HEADING]
        for pos, idx in enumerate(heads):
            head = self.lines[idx]
            if predicate is not None:
                try:
                    if not predicate(head):
                        continue
                except Exception:  # pragma: no cover - defensive totality
                    continue
            end = len(self.lines)
            for nxt in heads[pos + 1 :]:
                if self.lines[nxt].heading_level <= head.heading_level:
                    end = nxt
                    break
            out.append((head, tuple(self.lines[idx + 1 : end])))
        return tuple(out)

    def section_containing(self, identity_key: str) -> tuple[LogicalLine, ...]:
        """Every line whose nearest identity-bearing heading is ``identity_key``.

        Identity-scoped, not depth-scoped. A sibling heading that names the
        same identity ('### Obligation evidence bindings for [VS-1]') extends
        the section instead of terminating it; a heading naming a DIFFERENT
        identity ends it. This is the property the depth check actually wanted:
        'is this marker attached to VS-1', not 'is this marker physically
        before the next H3'.
        """
        key = (identity_key or "").replace("_", "-").upper()
        if not key:
            return ()
        out: list[LogicalLine] = []
        current: Optional[str] = None
        for line in self.lines:
            if line.kind == HEADING:
                ident = candidate_identity(line.heading_text)
                if ident is not None:
                    current = ident.key
                    if current == key:
                        out.append(line)
                    continue
                # A heading with no identity does not change ownership.
                if current == key:
                    out.append(line)
                continue
            if current == key:
                out.append(line)
        return tuple(out)


def _prescan_blocks(
    raw_lines: Sequence[str],
) -> tuple[list[int], list[int], list[Defect], set[int]]:
    """Resolve fence and HTML-comment spans BEFORE any line is classified.

    Unterminated spans are demoted to ordinary prose with recorded DEBT. This
    is deliberate and recall-safe: the measured defect let one stray ```` ``` ````
    swallow the remainder of a 1047-line artifact, blinding the gate to every
    acknowledgement below it and discarding a 25-minute analysis. Seeing
    content as prose can only ADD visibility; treating it as fenced can silently
    remove it.
    """
    n = len(raw_lines)
    fence_depth = [0] * n
    comment_depth = [0] * n
    defects: list[Defect] = []

    # Fences cannot nest. A delimiter of another type, a shorter delimiter,
    # or an apparent opener inside a fence is quoted content.
    open_stack: list[tuple[int, str]] = []
    pairs: list[tuple[int, int]] = []
    delimiters: set[int] = set()
    for i, line in enumerate(raw_lines):
        m = _FENCE_RE.match(line)
        if not m:
            continue
        marker = m.group(1)
        if not open_stack:
            open_stack.append((i, marker))
        else:
            start, opening = open_stack[-1]
            if marker[0] == opening[0] and len(marker) >= len(opening) and not m.group(2):
                open_stack.pop()
                pairs.append((start, i))
                delimiters.add(start)
                delimiters.add(i)
    if open_stack:
        # RECALL-SAFE: an unbalanced document has NO trustworthy fence
        # structure, because every delimiter after the stray one pairs with the
        # wrong partner. Rather than let a mis-pairing silently reclassify real
        # assertions as quotations, fence classification is abandoned for the
        # whole artifact and the ambiguity is recorded as debt.
        #
        # This is the measured stray-fence discard: inserting ONE ``` line
        # (three characters, no content change) into a real 1047-line depth
        # artifact made the driver report that the worker "does not acknowledge
        # graph projection(s): caller_map.md, callee_map.md, state_write_map.md,
        # function_summary.md" and destroyed a $6-9, 25-minute analysis.
        for start, _marker in open_stack:
            defects.append(
                Defect(
                    property_violated="format.unterminated_fence",
                    physical_line=start + 1,
                    observed="code fence opened and never closed",
                    expected="balanced code fences",
                    repair_hint=(
                        "Fence structure is ambiguous, so fenced-block "
                        "detection was DISABLED for this artifact and all "
                        "content was read as prose. Nothing was rejected. "
                        "Close the fence so quoted blocks are unambiguous."
                    ),
                    closure=DEBT,
                )
            )
        fence_depth = [0] * n
        delimiters.clear()
        pairs = []
    for start, end in pairs:
        for i in range(start, end + 1):
            fence_depth[i] += 1

    # HTML comments, only outside fences.
    i = 0
    while i < n:
        if fence_depth[i]:
            i += 1
            continue
        line = raw_lines[i]
        pos = line.find("<!--")
        if pos < 0:
            i += 1
            continue
        if "-->" in line[pos + 4 :]:
            comment_depth[i] += 1
            i += 1
            continue
        end = -1
        interrupted = False
        for j in range(i + 1, min(n, i + MAX_JOIN_SPAN * 8)):
            closing = raw_lines[j].find("-->")
            opening = raw_lines[j].find("<!--")
            if opening >= 0 and (closing < 0 or opening < closing):
                # Recover at the next record instead of borrowing its closer
                # for a malformed earlier opener. Ordinary multiline comment
                # bodies still join when no new opener intervenes.
                interrupted = True
                break
            if closing >= 0:
                end = j
                break
        if end < 0:
            defects.append(
                Defect(
                    property_violated="format.unterminated_html_comment",
                    physical_line=i + 1,
                    observed=(
                        "a new '<!--' appeared before this comment closed"
                        if interrupted else "'<!--' opened and never closed"
                    ),
                    expected="a matching '-->'",
                    repair_hint=(
                        "An unclosed HTML comment was IGNORED rather than "
                        "allowed to hide the rest of the artifact."
                    ),
                    closure=DEBT,
                )
            )
            i += 1
            continue
        for j in range(i, end + 1):
            comment_depth[j] += 1
        i = end + 1
    return fence_depth, comment_depth, defects, delimiters


def _strip_prefixes(line: str) -> tuple[str, int, int, str]:
    """-> (payload, indent, blockquote_depth, list_marker)."""
    indent = len(line) - len(line.lstrip(" \t"))
    rest = line
    depth = 0
    while True:
        m = _BLOCKQUOTE_RE.match(rest)
        if not m:
            break
        depth += m.group(0).count(">")
        rest = rest[m.end() :]
    marker = ""
    m = _LIST_MARKER_RE.match(rest)
    if m:
        marker = m.group(0).strip()
        rest = rest[m.end() :]
        return rest, indent, depth, marker
    # A marker hidden behind emphasis (``**1. Slippage.** ...``) is still a
    # marker. Detecting it only on raw bytes breaks idempotence: pass one
    # strips the emphasis and pass two then sees an ordinary ordered-list item.
    if rest.lstrip()[:1] in ("*", "_", "`"):
        undecorated = strip_decoration(rest)
        m2 = _LIST_MARKER_RE.match(undecorated)
        if m2:
            return undecorated[m2.end() :], indent, depth, m2.group(0).strip()
    return rest, indent, depth, marker


def surface(raw: object) -> ArtifactSurface:
    """THE boundary. Turn raw artifact bytes/text into the normalized view.

    Pure, total, never raises. Call this ONCE per artifact and pass the result
    to every check. Do not re-derive Markdown syntax downstream — that is the
    per-site regex proliferation this module exists to end.
    """
    text, defects_list = _as_text(raw)
    defects = list(defects_list)
    digest = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
    text = _canonical_chars(text)
    raw_lines = text.split("\n")
    truncated = False
    if len(raw_lines) > MAX_PHYSICAL_LINES:
        defects.append(
            Defect(
                property_violated="format.artifact_truncated_for_analysis",
                physical_line=MAX_PHYSICAL_LINES,
                observed=f"{len(raw_lines)} physical lines",
                expected=f"<= {MAX_PHYSICAL_LINES} physical lines",
                repair_hint=(
                    "Only the first "
                    f"{MAX_PHYSICAL_LINES} lines were normalized. Split the "
                    "artifact; nothing was rejected."
                ),
                closure=DEBT,
            )
        )
        raw_lines = raw_lines[:MAX_PHYSICAL_LINES]
        truncated = True
    for i, line in enumerate(raw_lines):
        if len(line) <= MAX_LINE_CHARS:
            continue
        defects.append(
            Defect(
                property_violated="format.line_truncated_for_analysis",
                physical_line=i + 1,
                observed=f"{len(line)} characters",
                expected=f"<= {MAX_LINE_CHARS} characters per physical line",
                repair_hint="Split this line; its excess characters were not analyzed.",
                closure=DEBT,
            )
        )
        raw_lines[i] = line[:MAX_LINE_CHARS]
        truncated = True

    fence_depth, comment_depth, block_defects, fence_delimiters = _prescan_blocks(raw_lines)
    defects.extend(block_defects)

    # ---- pass 1: classify each physical line -----------------------------
    records: list[dict] = []
    for i, line in enumerate(raw_lines):
        pno = i + 1
        fd = fence_depth[i]
        cd = comment_depth[i]
        if fd:
            kind = FENCE_DELIMITER if i in fence_delimiters else FENCE_CONTENT
            records.append(
                dict(
                    p=pno, kind=kind, raw=line, payload=line.strip(), indent=0,
                    bq=0, marker="", level=0, htext="", fd=fd, cd=cd, cells=None,
                )
            )
            continue
        payload, indent, bq, marker = _strip_prefixes(line)
        stripped = payload.strip()
        if cd:
            kind = HTML_COMMENT
        elif not stripped:
            kind = BLANK
        elif _ATX_RE.match(payload):
            kind = HEADING
        elif _THEMATIC_RE.match(payload) and not _SETEXT_RE.match(payload):
            kind = THEMATIC_BREAK
        elif _SETEXT_RE.match(payload):
            kind = SETEXT_UNDERLINE
        elif _looks_like_row(payload):
            kind = TABLE_ROW
        else:
            kind = PROSE
        level = 0
        htext = ""
        if kind == HEADING:
            m = _ATX_RE.match(payload)
            level = len(m.group(1))
            htext = m.group(2)
        cells = _row_cells(payload) if kind == TABLE_ROW else None
        records.append(
            dict(
                p=pno, kind=kind, raw=line, payload=payload, indent=indent,
                bq=bq, marker=marker, level=level, htext=htext, fd=fd, cd=cd,
                cells=cells,
            )
        )

    # ---- pass 2: setext headings ----------------------------------------
    for i, rec in enumerate(records):
        if rec["kind"] != SETEXT_UNDERLINE:
            continue
        prev = records[i - 1] if i else None
        if prev is not None and prev["kind"] == PROSE and prev["payload"].strip():
            prev["kind"] = HEADING
            prev["level"] = 1 if rec["payload"].strip().startswith("=") else 2
            prev["htext"] = prev["payload"].strip()
        elif rec["payload"].strip().startswith("-"):
            rec["kind"] = THEMATIC_BREAK
        else:
            rec["kind"] = PROSE

    # ---- pass 3: table blocks -------------------------------------------
    table_index = [-1] * len(records)
    tno = 0
    i = 0
    while i < len(records):
        if records[i]["kind"] != TABLE_ROW:
            i += 1
            continue
        start = i
        j = i
        while j < len(records) and records[j]["kind"] == TABLE_ROW:
            j += 1
        block = list(range(start, j))
        sep_at = None
        for k in block:
            if _is_separator_row(records[k]["cells"]):
                sep_at = k
                break
        if sep_at is not None:
            records[sep_at]["kind"] = TABLE_SEPARATOR
            if sep_at > start:
                records[sep_at - 1]["kind"] = TABLE_HEADER
        elif len(block) >= 2 and all(_bounded_row(records[k]["payload"]) for k in block):
            # Tolerant reader: a table with no separator row is still a table,
            # as long as its rows are pipe-delimited and it is not one lone
            # sentence that happens to contain pipes.
            records[start]["kind"] = TABLE_HEADER
        else:
            for k in block:
                records[k]["kind"] = PROSE
                # A lone pipe-delimited line is not a TABLE, but it may still
                # be a two-cell FIELD (``| Severity | High |``). Keep its cells
                # so field reading by meaning still sees it; ``table_index``
                # stays -1 so no table reader can pick it up.
                if not _bounded_row(records[k]["payload"]):
                    records[k]["cells"] = None
            i = j
            continue
        for k in block:
            table_index[k] = tno
        tno += 1
        i = j

    # ---- pass 4: soft-wrap joining --------------------------------------
    lines: list[LogicalLine] = []
    idx = 0
    i = 0
    n = len(records)
    while i < n:
        rec = records[i]
        start_p = rec["p"]
        end_p = rec["p"]
        raws = [rec["raw"]]
        payloads = [rec["payload"] if rec["kind"] != HTML_COMMENT else rec["raw"]]
        if rec["kind"] in (PROSE, HTML_COMMENT):
            span = 0
            while i + 1 < n and span < MAX_JOIN_SPAN:
                nxt = records[i + 1]
                if rec["kind"] == HTML_COMMENT:
                    if nxt["kind"] != HTML_COMMENT or nxt["cd"] != rec["cd"]:
                        break
                    # Only join a comment that is genuinely still open.
                    if "-->" in payloads[-1]:
                        break
                else:
                    if nxt["kind"] != PROSE:
                        break
                    prev_tail = payloads[-1].rstrip()
                    if prev_tail and prev_tail[-1] in _TERMINAL_PUNCT:
                        break
                    if nxt["marker"] or nxt["bq"] != rec["bq"]:
                        break
                    nxt_norm = strip_decoration(nxt["payload"])
                    # A line that OPENS a new structural unit is never a
                    # continuation: a labelled field, a bracketed construct or
                    # an HTML marker starts its own logical line.
                    if _FIELD_START_RE.match(nxt_norm):
                        break
                    if nxt_norm[:1] in ("[", "<"):
                        break
                i += 1
                span += 1
                end_p = records[i]["p"]
                raws.append(records[i]["raw"])
                payloads.append(
                    records[i]["payload"]
                    if records[i]["kind"] != HTML_COMMENT
                    else records[i]["raw"]
                )
        joined_raw = "\n".join(raws)
        joined_payload = " ".join(p.strip() for p in payloads if p.strip())
        kind = rec["kind"]
        if kind == HEADING:
            norm = strip_decoration(rec["htext"])
        elif kind in (TABLE_HEADER, TABLE_ROW, TABLE_SEPARATOR):
            norm = strip_decoration(rec["payload"])
        elif kind in (FENCE_CONTENT, FENCE_DELIMITER):
            norm = rec["raw"].strip()
        else:
            norm = strip_decoration(joined_payload)
        cells = rec["cells"]
        lines.append(
            LogicalLine(
                index=idx,
                physical_start=start_p,
                physical_end=end_p,
                kind=kind,
                raw=joined_raw,
                text=norm,
                indent=rec["indent"],
                list_marker=rec["marker"],
                blockquote_depth=rec["bq"],
                heading_level=rec["level"],
                heading_text=strip_decoration(rec["htext"]) if kind == HEADING else "",
                fence_depth=rec["fd"],
                comment_depth=rec["cd"],
                table_index=table_index[i],
                cells=tuple(normalize_cell(c) for c in cells) if cells else (),
            )
        )
        idx += 1
        i += 1

    return ArtifactSurface(
        lines=tuple(lines),
        source_sha256=digest,
        physical_line_count=len(raw_lines),
        defects=tuple(defects),
        truncated=truncated,
    )


def normalized_text(value: object) -> str:
    """Canonical, re-parseable serialization of the semantic view.

    The metamorphic contract every gate relies on::

        normalized_text(mutated) == normalized_text(original)

    for every presentation-only mutation, and the idempotence contract::

        normalized_text(normalized_text(x)) == normalized_text(x)
    """
    surf = value if isinstance(value, ArtifactSurface) else surface(value)
    out: list[str] = []
    for line in surf.lines:
        if line.kind == SETEXT_UNDERLINE:
            # The preceding heading already serializes the underline's role.
            continue
        if line.kind == BLANK:
            out.append("")
        elif line.kind == HEADING:
            out.append("#" * max(1, line.heading_level) + " " + line.heading_text)
        elif line.kind in (TABLE_HEADER, TABLE_ROW):
            # Re-escape pipes so a Solidity `a || b` in a cell round-trips.
            out.append(
                "| " + " | ".join(c.replace("|", "\\|") for c in line.cells) + " |"
            )
        elif line.kind == TABLE_SEPARATOR:
            out.append("|" + "|".join(["---"] * max(1, len(line.cells))) + "|")
        elif line.kind == THEMATIC_BREAK:
            out.append("***")
        elif line.kind == FENCE_DELIMITER:
            # Keep delimiter type and length: changing either can turn quoted
            # delimiter-looking payload into the end of the block on reparse.
            out.append(line.raw.strip())
        elif line.kind == FENCE_CONTENT:
            out.append(line.raw.rstrip())
        elif line.kind == HTML_COMMENT:
            body = line.raw.strip()
            body = re.sub(r"\s*\n\s*", " ", body)
            out.append(body)
        else:
            # Preserve list-block structure with a canonical marker. Without
            # it, two adjacent bullet lines lose their boundary on the second
            # normalization pass and fuse into one logical line.
            prefix = "- " if line.list_marker else ""
            out.append(prefix + line.text if line.text else prefix.rstrip())
        if line.blockquote_depth:
            # Quote boundaries also delimit soft wrapping. Dropping them
            # would fuse a quoted line with adjacent prose on the next pass.
            out[-1] = "> " * line.blockquote_depth + out[-1]
    return "\n".join(out)


# --------------------------------------------------------------------------
# Assertion vs mention — the exact distinction that killed run48
# --------------------------------------------------------------------------

_NEGATORS = frozenset(
    {
        "no", "not", "never", "none", "neither", "nor", "without", "zero",
        "absent", "lacks", "lacking", "missing", "0", "excluding", "except",
        "unlike", "rather",
    }
)
_WORD_RE = re.compile(r"[A-Za-z][A-Za-z'’-]*")
_LABEL_HEAD_RE = re.compile(r"^[A-Za-z][A-Za-z0-9 _/\-]{0,30}[:=–—-]\s*$")
#: A line that OPENS a new labelled field. Used by the soft-wrap joiner so a
#: run of ``**Verdict**: X`` / ``**Severity**: Y`` field lines is never fused
#: into one logical line, while a field whose VALUE was soft-wrapped onto the
#: next physical line still joins.
_FIELD_START_RE = re.compile(
    r"^[A-Za-z][A-Za-z0-9 _/()\-]{0,48}?\s*[:=–—]"
)
_STRUCTURAL_TAIL_CHARS = ":{}|=[]<>\"'"


@dataclass(frozen=True)
class TokenOccurrence:
    """One occurrence of a token, classified as ASSERTION or MENTION."""

    kind: str
    token: str
    line_index: int
    physical_line: int
    offset: int
    head: str
    tail: str
    negated: bool
    in_fence: bool
    in_comment: bool
    reason: str

    @property
    def is_assertion(self) -> bool:
        return self.kind == ASSERTION


def _head_is_structural(head: str) -> bool:
    """A head that is prefix material, not narration."""
    h = head.strip()
    if not h:
        return True
    # An opening bracket/quote belongs to the construct, not to the prefix:
    # ``Receipt: [OBLIG:...]`` has the label prefix ``Receipt:`` and the
    # construct ``[OBLIG:...]``.
    h_label = h.rstrip("[({<\"'‘“ ").strip()
    if not h_label:
        return True
    if _LABEL_HEAD_RE.match(h_label):
        return True
    # Pure punctuation/prefix noise.
    return not _WORD_RE.search(h)


def _tail_is_structured(tail: str) -> bool:
    """A tail that continues a structured construct rather than a sentence."""
    t = tail.strip()
    if not t:
        return True
    window = t[:64]
    if any(ch in window for ch in _STRUCTURAL_TAIL_CHARS):
        return True
    if "->" in window:
        return True
    words = _WORD_RE.findall(t)
    lower_words = [w for w in words if w[:1].islower()]
    # Fewer than two lowercase words is an annotation, not a sentence.
    return len(lower_words) < 2


def _is_negated(head: str) -> bool:
    words = [w.casefold() for w in _WORD_RE.findall(head)]
    digits = re.findall(r"(?<![\w.])0(?![\w.])", head)
    return bool(digits) or any(w in _NEGATORS for w in words)


def classify_token(
    line: LogicalLine,
    token: object,
    *,
    case_sensitive: bool = False,
    fence_is_quotation: bool = True,
) -> Optional[TokenOccurrence]:
    """Does this logical line ASSERT ``token``, or merely MENTION it?

    This is the run48 killer, isolated into one testable predicate.

    An occurrence is an **ASSERTION** when all three hold, evaluated against the
    DECORATION-STRIPPED, SOFT-WRAP-JOINED logical text:

    1. nothing before the token is narration (the head is empty, punctuation,
       or a short ``Label:``-shaped prefix),
    2. the token is not negated by the head,
    3. what follows the token is structured (empty, or carrying ``:``/``{``/
       ``|``/``->``/``=``/quotes within the next 64 characters, or fewer than
       two lowercase words) rather than a running sentence.

    Otherwise it is a **MENTION**.

    A MENTION is never harvested AND never rejected. That single rule retires
    the entire run48 failure family:

    * ``[OBLIG:OB-12] STATUS: D KEY: ...``            -> ASSERTION
    * ``` `[OBLIG:OB-12] STATUS: D KEY: ...` ```      -> ASSERTION (backticks
      are decoration; this is the literal x4 rejection cause)
    * ``- [OBLIG:...]`` / ``1. [OBLIG:...]`` / ``> [OBLIG:...]`` -> ASSERTION
    * ``<!-- PLAMEN_SECURITY_OBLIGATION_EVIDENCE: {...} -->``    -> ASSERTION
    * ``<!-- note: PLAMEN_SECURITY_OBLIGATION_EVIDENCE markers placed per
      alias -->``                                    -> MENTION (the literal x3
      rejection cause)
    * ``The payload is delimited by <!-- ..._BEGIN --> and ...``  -> MENTION
    * ``No schema violations detected.``              -> MENTION (negated)
    * ``I will end with PLAMEN_STATUS: COMPLETE when done.``      -> MENTION

    With ``fence_is_quotation`` (the default) an occurrence inside a fenced
    block is demoted to MENTION: a worker who ALSO quotes a real marker in a
    fence for the reader keeps its genuine assertion, and the quotation neither
    counts nor rejects.
    """
    if not isinstance(line, LogicalLine):
        return None
    needle, _ = _as_text(token)
    needle = _canonical_chars(needle).strip()
    if not needle:
        return None
    hay = line.text if line.kind != HTML_COMMENT else strip_decoration(line.raw)
    if line.kind in (FENCE_CONTENT, FENCE_DELIMITER):
        hay = line.raw
    probe_hay = hay if case_sensitive else hay.casefold()
    probe_needle = needle if case_sensitive else needle.casefold()
    if probe_needle not in probe_hay:
        return None

    best: Optional[TokenOccurrence] = None
    start = 0
    while True:
        pos = probe_hay.find(probe_needle, start)
        if pos < 0:
            break
        start = pos + 1
        # A marker is an identifier, not a substring of a longer one. Apply
        # boundaries only at identifier-shaped token edges, so structured
        # prefixes such as "[RECEIPT:" remain valid search tokens.
        end = pos + len(probe_needle)
        comment_open = line.kind == HTML_COMMENT and probe_hay[:pos].endswith("<!--")
        comment_close = line.kind == HTML_COMMENT and probe_hay[end:].startswith("-->")
        if (
            (probe_needle[0].isalnum() or probe_needle[0] in "_-")
            and pos > 0
            and (probe_hay[pos - 1].isalnum() or probe_hay[pos - 1] in "_-")
            and not comment_open
        ) or (
            (probe_needle[-1].isalnum() or probe_needle[-1] in "_-")
            and end < len(probe_hay)
            and (probe_hay[end].isalnum() or probe_hay[end] in "_-")
            and not comment_close
        ):
            continue
        head = hay[:pos]
        tail = hay[pos + len(needle) :]
        if line.kind == HTML_COMMENT:
            head = re.sub(r"^\s*<!--\s*", "", head)
            tail = re.sub(r"\s*-->\s*$", "", tail)
        negated = _is_negated(head)
        head_ok = _head_is_structural(head)
        tail_ok = _tail_is_structured(tail)
        in_fence = line.in_fence
        if negated:
            kind, reason = MENTION, "NEGATED_BY_HEAD"
        elif not head_ok:
            kind, reason = MENTION, "NARRATIVE_HEAD"
        elif not tail_ok:
            kind, reason = MENTION, "NARRATIVE_TAIL"
        elif in_fence and fence_is_quotation:
            kind, reason = MENTION, "QUOTED_IN_FENCE"
        else:
            kind, reason = ASSERTION, "STRUCTURAL_ASSERTION"
        occ = TokenOccurrence(
            kind=kind,
            token=needle,
            line_index=line.index,
            physical_line=line.physical_start,
            offset=pos,
            head=head,
            tail=tail,
            negated=negated,
            in_fence=in_fence,
            in_comment=line.in_comment,
            reason=reason,
        )
        if occ.kind == ASSERTION:
            return occ
        if best is None:
            best = occ
    return best


def line_asserts(line: LogicalLine, token: object, **kwargs) -> bool:
    occ = classify_token(line, token, **kwargs)
    return bool(occ and occ.is_assertion)


def line_mentions(line: LogicalLine, token: object, **kwargs) -> bool:
    occ = classify_token(line, token, **kwargs)
    return bool(occ and not occ.is_assertion)


def find_assertions(
    value: object, token: object, **kwargs
) -> tuple[TokenOccurrence, ...]:
    """Every ASSERTION of ``token`` in an artifact. Mentions are excluded."""
    surf = value if isinstance(value, ArtifactSurface) else surface(value)
    out: list[TokenOccurrence] = []
    for line in surf.lines:
        occ = classify_token(line, token, **kwargs)
        if occ is not None and occ.is_assertion:
            out.append(occ)
    return tuple(out)


def find_mentions(value: object, token: object, **kwargs) -> tuple[TokenOccurrence, ...]:
    surf = value if isinstance(value, ArtifactSurface) else surface(value)
    out: list[TokenOccurrence] = []
    for line in surf.lines:
        occ = classify_token(line, token, **kwargs)
        if occ is not None and not occ.is_assertion:
            out.append(occ)
    return tuple(out)


# --------------------------------------------------------------------------
# Tables read by COLUMN ROLE
# --------------------------------------------------------------------------

#: role -> synonyms, MOST SPECIFIC FIRST. Specificity resolves the measured
#: defect where ``| ID | Finding ID | Verdict |`` dropped identity for every
#: row because two columns matched: the more specific ``finding id`` now wins
#: and the ambiguity is recorded as debt instead of losing the column.
DEFAULT_COLUMN_ROLES: Mapping[str, tuple[str, ...]] = {
    "candidate_id": (
        "finding id", "candidate id", "issue id", "hypothesis id",
        "finding identifier", "candidate identifier", "internal hypothesis",
        "report id", "finding", "candidate", "issue", "hypothesis", "id",
    ),
    "disposition": (
        "producer disposition", "finding status", "verdict / status",
        "disposition", "determination", "verdict", "status", "proposal",
        "outcome", "result", "decision",
    ),
    "severity": ("severity", "risk level", "risk", "tier", "impact level"),
    "location": (
        "source location", "code location", "locus", "location", "file",
        "site", "path",
    ),
    "title": ("title", "name", "summary", "subject", "mechanism", "check"),
    "notes": ("notes", "note", "comment", "comments", "remarks", "rationale", "reason"),
    "evidence": ("evidence", "evidence tag", "proof", "receipt"),
}


@dataclass(frozen=True)
class TableRow:
    """One data row. ``get(role)`` returns None when the role is absent."""

    line: LogicalLine
    cells: tuple[str, ...]
    _roles: Mapping[str, Optional[int]] = _dc_field(default_factory=dict)

    @property
    def physical_line(self) -> int:
        return self.line.physical_start

    def get(self, role: str, default: Optional[str] = None) -> Optional[str]:
        idx = self._roles.get(role)
        if idx is None or idx < 0 or idx >= len(self.cells):
            return default
        return self.cells[idx]

    def identity(self, role: str = "candidate_id") -> Optional[Identity]:
        return candidate_identity(self.get(role) or "")


@dataclass(frozen=True)
class IgnoredRoleValue:
    """An explicit caller decision that a cell makes no claim for this role."""


IGNORE_ROLE_VALUE = IgnoredRoleValue()


@dataclass(frozen=True)
class RoleAssertion:
    column: int
    header: str
    raw: Optional[str]
    normalized: Optional[str]
    state: str
    physical_line: int


@dataclass(frozen=True)
class RoleResolution:
    """A checked role value, retaining every competing cell and its defects.

    Only RESOLVED carries a value. MISSING, IGNORED, UNKNOWN and CONFLICT
    are deliberately distinct; callers must not turn a conflict into an
    absent-column positional fallback or an authoritative negative decision.
    """

    state: str
    value: Optional[str]
    assertions: tuple[RoleAssertion, ...]
    defects: tuple[Defect, ...] = ()


@dataclass(frozen=True)
class Table:
    """A GFM table addressed by column ROLE, never by column index."""

    index: int
    header: Optional[LogicalLine]
    headers: tuple[str, ...]
    rows: tuple[TableRow, ...]
    roles: Mapping[str, Optional[int]] = _dc_field(default_factory=dict)
    has_separator: bool = True
    ambiguities: tuple[Defect, ...] = ()
    _role_matches: Mapping[str, tuple[int, ...]] = _dc_field(default_factory=dict)

    def role_index(self, role: str) -> Optional[int]:
        return self.roles.get(role)

    def role_indices(self, role: str) -> tuple[int, ...]:
        """All matching columns, including those hidden by legacy get()."""
        if role in self._role_matches:
            return self._role_matches[role]
        index = self.role_index(role)
        return () if index is None else (index,)

    def resolve_role(
        self,
        row: TableRow,
        role: str,
        *,
        normalizer: Callable[[str], str | None | IgnoredRoleValue],
        property_name: str,
    ) -> RoleResolution:
        """Check every matching cell using the caller's semantic vocabulary.

        The normalizer receives the normalized cell text and returns a
        canonical nonempty string, None for an UNKNOWN assertion, or
        IGNORE_ROLE_VALUE for an explicitly ancillary value (for example an
        ordinal in an ID column). Blank/absent cells are MISSING and never
        passed to the normalizer. Exceptions and invalid normalizer results
        are UNKNOWN, never permission to prefer another column.

        Equivalent assertions resolve regardless of header rank or order.
        Unknown assertions prevent resolution; distinct known assertions
        conflict. Neither state discards the row or its original cells.
        Semantic defects use the supplied property's closure family;
        duplicate-column and missing companion-cell details remain debt.
        """
        assertions: list[RoleAssertion] = []
        defects = [
            defect for defect in self.ambiguities
            if defect.property_violated == f"format.ambiguous_column_role.{role}"
        ]
        for index in self.role_indices(role):
            raw = row.cells[index] if 0 <= index < len(row.cells) else None
            cell = normalize_cell(raw) if raw is not None else ""
            normalized = None
            state = "MISSING"
            if cell:
                try:
                    value = normalizer(cell)
                except Exception:
                    value = None
                if value is IGNORE_ROLE_VALUE:
                    state = "IGNORED"
                elif isinstance(value, str) and value.strip():
                    normalized, state = value, "RESOLVED"
                else:
                    state = "UNKNOWN"
            assertions.append(RoleAssertion(
                column=index,
                header=self.headers[index] if 0 <= index < len(self.headers) else "",
                raw=raw,
                normalized=normalized,
                state=state,
                physical_line=row.physical_line,
            ))
        values = {item.normalized for item in assertions if item.state == "RESOLVED"}
        unknown = any(item.state == "UNKNOWN" for item in assertions)
        if len(values) > 1:
            state = "CONFLICT"
        elif unknown:
            state = "UNKNOWN"
        elif values:
            state = "RESOLVED"
        elif any(item.state == "MISSING" for item in assertions) or not assertions:
            state = "MISSING"
        else:
            state = "IGNORED"
        if state in {"CONFLICT", "UNKNOWN", "MISSING"}:
            prop = f"{property_name}.{state.lower()}"
            defects.append(Defect(
                property_violated=prop,
                physical_line=row.physical_line,
                observed=repr([
                    (item.column, item.header, item.raw, item.normalized, item.state)
                    for item in assertions
                ]),
                expected=f"one unambiguous normalized value for role {role!r}",
                repair_hint=(
                    "Resolve the competing or unreadable role assertions using "
                    "their source evidence; preserve this row and all candidate "
                    "references while the decision is unresolved."
                ),
                closure=closure_for_property(prop),
            ))
        elif state == "RESOLVED" and any(
            item.state == "MISSING" for item in assertions
        ):
            defects.append(Defect(
                property_violated=f"format.missing_companion_role_cell.{role}",
                physical_line=row.physical_line,
                observed="a matching column has an empty or absent cell",
                expected="equivalent values in matching columns",
                repair_hint="Fill or remove the empty companion column.",
                closure=DEBT,
            ))
        return RoleResolution(
            state=state,
            value=next(iter(values)) if state == "RESOLVED" else None,
            assertions=tuple(assertions),
            defects=tuple(defects),
        )

    def has_role(self, role: str) -> bool:
        return self.roles.get(role) is not None

    def column(self, role: str) -> tuple[Optional[str], ...]:
        return tuple(r.get(role) for r in self.rows)


def _assign_roles(
    headers: Sequence[str],
    roles: Mapping[str, Sequence[str]],
    header_line: Optional[LogicalLine],
) -> tuple[dict[str, Optional[int]], list[Defect], dict[str, tuple[int, ...]]]:
    normalized = [normalize_label(h) for h in headers]
    assigned: dict[str, Optional[int]] = {}
    ambiguities: list[Defect] = []
    role_matches: dict[str, tuple[int, ...]] = {}
    for role, synonyms in roles.items():
        normalized_synonyms = tuple(normalize_label(syn) for syn in synonyms)
        best_idx: Optional[int] = None
        best_rank = len(normalized_synonyms) + 1
        matches: list[int] = []
        for col, label in enumerate(normalized):
            if not label:
                continue
            for rank, syn in enumerate(normalized_synonyms):
                if label == syn:
                    matches.append(col)
                    if rank < best_rank:
                        best_rank = rank
                        best_idx = col
                    break
        assigned[role] = best_idx
        role_matches[role] = tuple(matches)
        if len(matches) > 1:
            ambiguities.append(
                Defect(
                    property_violated=f"format.ambiguous_column_role.{role}",
                    physical_line=header_line.physical_start if header_line else 0,
                    observed=(
                        "columns "
                        + ", ".join(repr(normalized[c]) for c in matches)
                        + f" all match role {role!r}"
                    ),
                    expected=f"one column for role {role!r}",
                    repair_hint=(
                        f"Resolved to the most specific header "
                        f"{normalized[best_idx]!r}. Rename the other column so "
                        "the role is unambiguous. Nothing was dropped."
                    ),
                    closure=DEBT,
                )
            )
    return assigned, ambiguities, role_matches


def read_tables(
    value: object,
    *,
    roles: Optional[Mapping[str, Sequence[str]]] = None,
) -> tuple[Table, ...]:
    """Every table, with columns addressed by ROLE. Never raises.

    Tolerates: missing leading/trailing pipes, a missing separator row, extra
    columns, reordered columns, ``&nbsp;`` in a header, decorated headers and
    decorated cells. An unknown column is IGNORED, never fatal. A role that is
    absent yields ``None``, never a positional fallback.
    """
    surf = value if isinstance(value, ArtifactSurface) else surface(value)
    role_map = dict(roles) if roles else dict(DEFAULT_COLUMN_ROLES)
    grouped: dict[int, list[LogicalLine]] = {}
    for line in surf.lines:
        if line.table_index >= 0:
            grouped.setdefault(line.table_index, []).append(line)
    tables: list[Table] = []
    for tidx in sorted(grouped):
        block = grouped[tidx]
        header_line = next((l for l in block if l.kind == TABLE_HEADER), None)
        has_sep = any(l.kind == TABLE_SEPARATOR for l in block)
        headers = tuple(header_line.cells) if header_line else ()
        assigned, ambiguities, role_matches = _assign_roles(headers, role_map, header_line)
        rows: list[TableRow] = []
        for line in block:
            if line.kind != TABLE_ROW:
                continue
            rows.append(TableRow(line=line, cells=line.cells, _roles=assigned))
        tables.append(
            Table(
                index=tidx,
                header=header_line,
                headers=headers,
                rows=tuple(rows),
                roles=assigned,
                has_separator=has_sep,
                ambiguities=tuple(ambiguities),
                _role_matches=role_matches,
            )
        )
    return tuple(tables)


def find_table(
    value: object,
    *,
    required_roles: Sequence[str] = (),
    roles: Optional[Mapping[str, Sequence[str]]] = None,
) -> Optional[Table]:
    """The first table carrying every required role, else None."""
    for table in read_tables(value, roles=roles):
        if all(table.has_role(r) for r in required_roles):
            return table
    return None


# --------------------------------------------------------------------------
# Labelled fields read by MEANING
# --------------------------------------------------------------------------

DEFAULT_FIELD_ROLES: Mapping[str, tuple[str, ...]] = {
    "verdict": (
        "verdict", "disposition", "producer disposition", "determination",
        "finding status", "status", "outcome", "proposal",
    ),
    "severity": ("severity", "risk level", "risk", "tier"),
    "location": ("location", "source location", "code location", "locus"),
    "impact": ("impact", "material harm", "harm", "consequence"),
    "material_harm": ("material harm", "harm"),
    "description": ("description", "summary", "mechanism", "root cause"),
    "evidence": ("evidence", "evidence tag", "preferred tag"),
    "rules_applied": ("rules applied", "rules"),
    "step_execution": ("step execution", "steps", "step trace"),
    "source_ids": ("source ids", "source id", "sources", "source", "internal refs"),
    "invariant_commitment": ("invariant commitment", "committed invariant"),
    "reason": ("reason", "rationale", "refutation basis", "why this blocks", "notes"),
}

_FIELD_LINE_RE = re.compile(
    r"^(?P<label>[A-Za-z][A-Za-z0-9 _/()\-]{0,48}?)"
    r"\s*[:=–—]\s*"
    r"(?P<value>.*)$",
    re.DOTALL,
)


@dataclass(frozen=True)
class Field:
    """A labelled field located by MEANING, not by bold/colon byte shape."""

    role: str
    label: str
    value: str
    line: LogicalLine
    source: str  # FIELD_LINE | TABLE_ROW

    @property
    def physical_line(self) -> int:
        return self.line.physical_start

    @property
    def enum(self) -> str:
        return normalize_enum(self.value)


def _field_from_line(
    line: LogicalLine, role_map: Mapping[str, Sequence[str]]
) -> Optional[tuple[str, str, str, str]]:
    """-> (role, label, value, source) for the first matching role."""
    if line.kind in (FENCE_DELIMITER, BLANK, TABLE_SEPARATOR):
        return None
    if len(line.cells) == 2:
        label = normalize_label(line.cells[0])
        value = line.cells[1]
        source = "TABLE_ROW"
    else:
        m = _FIELD_LINE_RE.match(strip_decoration(line.text))
        if not m:
            return None
        label_raw = m.group("label")
        if len(label_raw.split()) > 6:
            return None
        label = normalize_label(label_raw)
        value = m.group("value").strip()
        source = "FIELD_LINE"
    if not label:
        return None
    for role, synonyms in role_map.items():
        if label in {normalize_label(s) for s in synonyms}:
            return role, label, value, source
    return None


def read_fields(
    value: object,
    role: Optional[str] = None,
    *,
    roles: Optional[Mapping[str, Sequence[str]]] = None,
    include_fenced: bool = False,
) -> tuple[Field, ...]:
    """Every labelled field, or every field for one role. Never raises.

    Tolerates, because all of these mean the same thing::

        **Severity**: High          **Severity:** High       Severity: High
        - **Severity**: High        > **Severity**: High     1. Severity: High
        **Severity** — High         | Severity | High |      `Severity`: High
        **Material Harm** (MANDATORY): ...
        **Material Harm (MANDATORY)**: ...

    and a value soft-wrapped onto the following physical line, because
    :func:`surface` joined it before this function ever saw it.
    """
    surf = value if isinstance(value, ArtifactSurface) else surface(value)
    role_map = dict(roles) if roles else dict(DEFAULT_FIELD_ROLES)
    if role is not None:
        role_map = {role: role_map.get(role, (role.replace("_", " "),))}
    # A horizontal table header describes columns, not scalar values. The
    # tolerant table parser also assigns TABLE_HEADER to the first row of a
    # headerless vertical field list; retain that row when every row has a
    # recognized field label and there is no explicit separator.
    field_labels = {
        normalize_label(label)
        for mapping in (DEFAULT_FIELD_ROLES, role_map)
        for synonyms in mapping.values()
        for label in synonyms
    }
    table_lines: dict[int, list[LogicalLine]] = {}
    for line in surf.lines:
        if line.table_index >= 0:
            table_lines.setdefault(line.table_index, []).append(line)
    vertical_tables = {
        index
        for index, lines in table_lines.items()
        if all(
            line.kind in (TABLE_HEADER, TABLE_ROW)
            and len(line.cells) == 2
            and normalize_label(line.cells[0]) in field_labels
            for line in lines
        )
    }
    out: list[Field] = []
    for line in surf.lines:
        if line.in_fence and not include_fenced:
            continue
        if line.kind == TABLE_HEADER and line.table_index not in vertical_tables:
            continue
        found = _field_from_line(line, role_map)
        if found is None:
            continue
        r, label, val, source = found
        out.append(Field(role=r, label=label, value=val, line=line, source=source))
    return tuple(out)


def read_field(
    value: object,
    role: str,
    *,
    roles: Optional[Mapping[str, Sequence[str]]] = None,
    include_fenced: bool = False,
) -> Optional[Field]:
    """The first field for ``role``, or None. Absence is a fact, not a verdict."""
    fields = read_fields(value, role, roles=roles, include_fenced=include_fenced)
    return fields[0] if fields else None
