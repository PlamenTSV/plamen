"""Provenance-aware privacy classification for colliding legacy identities.

``EIP-N`` is a public Ethereum standards namespace.  Historical Plamen niche
workers also used that spelling for private producer-local finding IDs.  Token
shape therefore carries no privacy authority.  This module recognizes the
legacy private meaning only at explicit structured lineage boundaries, in an
internal Markdown anchor, or through an exact caller-supplied legacy-ID set.

The classifier returns source spans so sanitizers and delivery validators use
the same decision rather than maintaining separate keyword heuristics.  Its
Unicode skeleton is comparison-only: public text is never normalized or
rewritten merely because it resembles an EIP reference.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
import unicodedata
from typing import Iterable


@dataclass(frozen=True, order=True)
class PrivateLegacyIdentity:
    """One private legacy identity occurrence in the original source text."""

    start: int
    end: int
    canonical_id: str
    provenance: str


_LEGACY_EIP_RE = re.compile(
    r"(?<![a-z0-9_])eip-(?P<number>[0-9]+)(?![a-z0-9_])"
)
_STRUCTURED_FIELD_RE = re.compile(
    r"(?im)^[ \t]*(?:[-*][ \t]*)?(?:\*{0,2})?"
    r"(?:finding[ _-]?id|internal[ _-]+ids?|source[ _-]+ids?|"
    r"producer[ _-]+ids?|lineage[ _-]+ids?|legacy[ _-]+finding[ _-]+id)"
    r"(?:\*{0,2})?[ \t]*:[ \t]*(?P<value>[^\r\n]*)"
)
_INTERNAL_DECLARATION_RE = re.compile(
    r"(?i)\binternal[ \t]+(?:producer|finding|candidate|id|identity)"
    r"[ \t]*(?:is[ \t]+|[:=#][ \t]*)?"
    r"(?P<identity>eip-[0-9]+)(?![a-z0-9_])"
)
_FINDING_ID_DECLARATION_RE = re.compile(
    r"(?i)\bfinding[ _-]+id[ \t]*(?:is[ \t]+|[:=#][ \t]*)?"
    r"(?P<identity>eip-[0-9]+)(?![a-z0-9_])"
)
_BRACKETED_FINDING_HEADING_RE = re.compile(
    r"(?im)^[ \t]*#{2,4}[ \t]+(?:finding[ \t]+)?"
    r"\[(?P<identity>eip-[0-9]+)\](?:[ \t]*[:\-]|[ \t]|$)"
)
_INTERNAL_ANCHOR_RE = re.compile(
    r"(?i)#(?:finding|candidate|internal)-(?P<identity>eip-[0-9]+)"
    r"(?![a-z0-9_])"
)
_INTERNAL_MARKDOWN_LINK_RE = re.compile(
    r"(?i)\[(?P<label>eip-[0-9]+)\]"
    r"\((?P<destination>#(?:finding|candidate|internal)-"
    r"(?P<target>eip-[0-9]+))(?:[ \t]+[^)]*)?\)"
)


def _comparison_skeleton(text: str) -> tuple[str, list[tuple[int, int]]]:
    """Return an ASCII-like comparison form plus original-source spans.

    NFKD folds full-width digits and compatibility forms.  Combining marks are
    removed so dotted-I aliases compare as ``i``.  Every Unicode dash is
    represented as ``-``.  The map keeps all decisions attached to original
    bytes/characters and permits exact redaction without rewriting public text.
    """

    chars: list[str] = []
    source_spans: list[tuple[int, int]] = []
    for index, original in enumerate(text or ""):
        decomposed = unicodedata.normalize("NFKD", original)
        for char in decomposed:
            if unicodedata.combining(char):
                continue
            folded = char.casefold()
            for unit in folded:
                if unicodedata.category(unit) == "Pd":
                    unit = "-"
                chars.append(unit)
                source_spans.append((index, index + 1))
    return "".join(chars), source_spans


def _original_span(
    source_spans: list[tuple[int, int]], start: int, end: int
) -> tuple[int, int]:
    if start >= end or not source_spans:
        return 0, 0
    return source_spans[start][0], source_spans[end - 1][1]


def _canonical_eip(value: str) -> str:
    skeleton, _ = _comparison_skeleton(value or "")
    match = _LEGACY_EIP_RE.fullmatch(skeleton.strip())
    return f"EIP-{match.group('number')}" if match else ""


def _candidate_occurrences(
    skeleton: str, source_spans: list[tuple[int, int]]
) -> list[PrivateLegacyIdentity]:
    out: list[PrivateLegacyIdentity] = []
    for match in _LEGACY_EIP_RE.finditer(skeleton):
        start, end = _original_span(source_spans, *match.span())
        out.append(
            PrivateLegacyIdentity(
                start=start,
                end=end,
                canonical_id=f"EIP-{match.group('number')}",
                provenance="candidate",
            )
        )
    return out


def _is_explicit_public_standard_occurrence(
    source: str, occurrence: PrivateLegacyIdentity
) -> bool:
    """Keep an occurrence public when its own clause identifies a standard."""

    skeleton, source_spans = _comparison_skeleton(source)
    official_url_re = re.compile(
        r"https?://eips\.ethereum\.org/eips/eip-(?P<number>[0-9]+)"
    )
    for match in official_url_re.finditer(skeleton):
        start, end = _original_span(source_spans, *match.span())
        if occurrence.start >= start and occurrence.end <= end:
            return True
    official_link_re = re.compile(
        r"\[(?P<label>eip-(?P<label_number>[0-9]+))\]"
        r"\(https?://eips\.ethereum\.org/eips/"
        r"eip-(?P<target_number>[0-9]+)(?:[ \t]+[^)]*)?\)"
    )
    for match in official_link_re.finditer(skeleton):
        if match.group("label_number") != match.group("target_number"):
            continue
        label_start, label_end = _original_span(
            source_spans, *match.span("label")
        )
        if (
            occurrence.start >= label_start
            and occurrence.end <= label_end
            and occurrence.canonical_id
            == f"EIP-{match.group('label_number')}"
        ):
            return True

    # Standards prose is clause-local. A cue in a later sentence or sibling
    # semicolon clause cannot launder this private occurrence.
    clause_start = max(
        source.rfind(delimiter, 0, occurrence.start)
        for delimiter in ("\n", ".", ";", "!", "?")
    ) + 1
    clause_ends = [
        index
        for delimiter in ("\n", ".", ";", "!", "?")
        if (index := source.find(delimiter, occurrence.end)) >= 0
    ]
    clause_end = min(clause_ends) if clause_ends else len(source)
    clause = source[clause_start:clause_end]
    clause_skeleton, clause_spans = _comparison_skeleton(clause)
    standard_patterns = (
        re.compile(
            r"(?:\bethereum[ \t]+improvement[ \t]+proposal[ \t]+)?"
            r"\b(?P<identity>eip-[0-9]+)[ \t]+"
            r"(?:standard|specification|proposal)\b"
        ),
        re.compile(
            r"\b(?:standard|specification|proposal)[ \t]+"
            r"(?P<identity>eip-[0-9]+)\b"
        ),
    )
    for pattern in standard_patterns:
        for match in pattern.finditer(clause_skeleton):
            local_start, local_end = _original_span(
                clause_spans, *match.span("identity")
            )
            if (
                occurrence.start == clause_start + local_start
                and occurrence.end == clause_start + local_end
                and occurrence.canonical_id
                == _canonical_eip(match.group("identity"))
            ):
                return True
    return False


def classify_private_legacy_eip_ids(
    text: str,
    *,
    known_internal_ids: Iterable[str] = (),
) -> tuple[PrivateLegacyIdentity, ...]:
    """Classify private legacy ``EIP-N`` occurrences using provenance.

    Ordinary prose, headings, code spans, and official EIP links are public by
    default.  A legacy token becomes private only when it is:

    * inside an explicit structured finding/lineage field;
    * the object of an ``Internal producer|finding|candidate|ID`` declaration;
    * part of an internal ``#finding-EIP-N``-style Markdown anchor; or
    * an exact member of ``known_internal_ids`` supplied by an authoritative
      pipeline identity source.
    """

    source = text or ""
    skeleton, source_spans = _comparison_skeleton(source)
    candidates = _candidate_occurrences(skeleton, source_spans)
    known = {
        canonical
        for value in known_internal_ids
        if (canonical := _canonical_eip(str(value or "")))
    }
    decisions: dict[tuple[int, int, str], PrivateLegacyIdentity] = {}

    def add_range(start: int, end: int, provenance: str) -> None:
        original_start, original_end = _original_span(source_spans, start, end)
        for candidate in candidates:
            if (
                candidate.start >= original_start
                and candidate.end <= original_end
            ):
                key = (candidate.start, candidate.end, candidate.canonical_id)
                decisions.setdefault(
                    key,
                    PrivateLegacyIdentity(
                        candidate.start,
                        candidate.end,
                        candidate.canonical_id,
                        provenance,
                    ),
                )

    for field in _STRUCTURED_FIELD_RE.finditer(skeleton):
        value_start, value_end = field.span("value")
        value = skeleton[value_start:value_end]
        clause_end = re.search(r"[.!?][ \t]+", value)
        if clause_end:
            value_end = value_start + clause_end.start() + 1
        add_range(value_start, value_end, "structured_field")

    for declaration in _INTERNAL_DECLARATION_RE.finditer(skeleton):
        add_range(*declaration.span("identity"), "internal_declaration")

    for declaration in _FINDING_ID_DECLARATION_RE.finditer(skeleton):
        add_range(*declaration.span("identity"), "finding_id_declaration")

    for heading in _BRACKETED_FINDING_HEADING_RE.finditer(skeleton):
        add_range(*heading.span("identity"), "finding_heading")

    for anchor in _INTERNAL_ANCHOR_RE.finditer(skeleton):
        add_range(*anchor.span("identity"), "markdown_anchor")

    # If the visible Markdown label is the same private identity as its
    # internal target, redact both.  Otherwise the target alone is sufficient
    # evidence of a privacy leak and the unrelated label remains untouched.
    for link in _INTERNAL_MARKDOWN_LINK_RE.finditer(skeleton):
        if _canonical_eip(link.group("label")) == _canonical_eip(
            link.group("target")
        ):
            add_range(*link.span("label"), "markdown_anchor_label")

    if known:
        for candidate in candidates:
            if (
                candidate.canonical_id in known
                and not _is_explicit_public_standard_occurrence(source, candidate)
            ):
                key = (candidate.start, candidate.end, candidate.canonical_id)
                decisions.setdefault(
                    key,
                    PrivateLegacyIdentity(
                        candidate.start,
                        candidate.end,
                        candidate.canonical_id,
                        "known_internal_id",
                    ),
                )

    return tuple(sorted(decisions.values()))


def redact_private_legacy_eip_ids(
    text: str,
    *,
    known_internal_ids: Iterable[str] = (),
    replacement: str = "upstream finding",
) -> str:
    """Redact exactly the classifier-approved legacy identity spans."""

    clean = text or ""
    occurrences = classify_private_legacy_eip_ids(
        clean, known_internal_ids=known_internal_ids
    )
    for occurrence in reversed(occurrences):
        rendered = (
            replacement.replace(" ", "-")
            if occurrence.provenance == "markdown_anchor"
            else replacement
        )
        clean = clean[: occurrence.start] + rendered + clean[occurrence.end :]
    return clean
