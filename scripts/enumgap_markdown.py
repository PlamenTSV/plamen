"""Single operational Markdown authority for exploration finding blocks."""
from __future__ import annotations

import hashlib
import re
from typing import Callable

from operational_markdown import operational_markdown_field_view
from plamen_markdown import mapped_headings


EXPL_REQUIRED_FIELDS = ("Severity", "Location", "Description")
ENUMGAP_ACTION_ID_RE = re.compile(r"NEXP-\d+", re.IGNORECASE)
_GENERIC_FINDING_CONTENT_RE = re.compile(
    r"^Finding[ \t]+\[[ \t]*"
    r"(?P<id>[A-Za-z]{2,6}(?:-[A-Za-z0-9]+)+)[ \t]*\]"
    r"[ \t]*:[ \t]*(?P<title>.+?)[ \t]*$"
)
_GENERIC_REFERENCE_CONTENT_RE = re.compile(
    r"^Finding[ \t]+\[[ \t]*"
    r"(?P<id>[A-Za-z]{2,6}(?:-[A-Za-z0-9]+)+)[ \t]*\]"
    r"(?:[ \t]*:[ \t]*.*)?$"
)
_MARKDOWN_SECTION_HEADING_RE = re.compile(
    r"^(?P<marks>#{2,6})[ \t]+", re.MULTILINE
)


def markdown_section_end(text: str, match: re.Match) -> int:
    """Legacy regex-match helper retained for non-authority compatibility.

    New authority readers use ``mapped_headings`` and ``_section_end`` below.
    """

    level = len(match.group("marks"))
    for heading in _MARKDOWN_SECTION_HEADING_RE.finditer(text, match.end()):
        if len(heading.group("marks")) <= level:
            return heading.start()
    return len(text)


def _section_end(
    source_length: int,
    headings: list[dict],
    heading_index: int,
) -> int:
    current_level = int(headings[heading_index]["level"])
    for later in headings[heading_index + 1 :]:
        if int(later["level"]) <= current_level:
            return int(later["start"])
    return source_length


def exploration_field(block: str, name: str) -> str:
    structural_block = operational_markdown_field_view(block)
    match = re.search(
        r"(?ims)^[ \t]*(?:[-*][ \t]+)?\*\*"
        + re.escape(name)
        + r"\*\*[ \t]*:[ \t]*(?P<value>.*?)"
        + r"(?=^[ \t]*(?:[-*][ \t]+)?\*\*[^*\n]+\*\*[ \t]*:"
        + r"|^[ \t]*#{1,6}[ \t]+|\Z)",
        structural_block,
    )
    if not match:
        return ""
    start, end = match.span("value")
    # Container markers are syntax, not field data.  The field view is
    # offset-equivalent to ``block`` and already excludes non-operational
    # spans, so normalize the semantic value from that view while retaining
    # the exact original bytes in the separately hashed finding block.
    value = structural_block[start:end]
    return " ".join(
        line.strip() for line in value.splitlines() if line.strip()
    ).strip()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def parse_exploration_finding_blocks(
    text: str,
    *,
    id_filter: Callable[[str], bool] | None = None,
    required_fields: tuple[str, ...] = EXPL_REQUIRED_FIELDS,
) -> tuple[dict, ...]:
    """Return unique, complete H2-H4 finding sections from one fresh AST.

    A finding section terminates at the next mapped heading of equal or higher
    level.  Lower-level headings remain part of the section.  The same heading
    map therefore decides both membership and exact source slicing for every
    exploration consumer.
    """

    source = str(text or "")
    headings = mapped_headings(source)
    candidates: list[tuple[int, dict, re.Match[str]]] = []
    counts: dict[str, int] = {}
    for index, heading in enumerate(headings):
        if int(heading["level"]) not in {2, 3, 4}:
            continue
        match = _GENERIC_FINDING_CONTENT_RE.fullmatch(
            str(heading["content"]).strip()
        )
        if match is None:
            continue
        finding_id = match.group("id").strip().upper()
        if id_filter is not None and not id_filter(finding_id):
            continue
        candidates.append((index, heading, match))
        counts[finding_id] = counts.get(finding_id, 0) + 1

    findings: list[dict] = []
    for heading_index, heading, match in candidates:
        finding_id = match.group("id").strip().upper()
        if counts.get(finding_id) != 1:
            continue
        start = int(heading["start"])
        end = _section_end(len(source), headings, heading_index)
        block = source[start:end].strip()
        fields = {
            name: exploration_field(block, name)
            for name in required_fields
        }
        if not all(fields.values()):
            continue
        findings.append(
            {
                "id": finding_id,
                "title": match.group("title").strip(),
                "block": block,
                "block_sha256": sha256_text(block),
                "fields": fields,
            }
        )
    return tuple(findings)


def parse_enumgap_exploration_findings(text: str) -> tuple[dict, ...]:
    """Return unique, complete, operational NEXP action blocks."""

    return parse_exploration_finding_blocks(
        text,
        id_filter=lambda finding_id: bool(
            ENUMGAP_ACTION_ID_RE.fullmatch(finding_id)
        ),
    )


def enumgap_reference_heading_ids(text: str) -> frozenset[str]:
    """Return acknowledgement-level IDs from the same mapped H2-H4 set.

    Required fields are intentionally not checked here: an incomplete finding
    may acknowledge attempted work, while strict delivery still requires
    ``parse_enumgap_exploration_findings`` and its complete field contract.
    """

    source = str(text or "")
    ids: set[str] = set()
    for heading in mapped_headings(source):
        if int(heading["level"]) not in {2, 3, 4}:
            continue
        match = _GENERIC_REFERENCE_CONTENT_RE.fullmatch(
            str(heading["content"]).strip()
        )
        if match is None:
            continue
        finding_id = match.group("id").strip().upper()
        if ENUMGAP_ACTION_ID_RE.fullmatch(finding_id):
            ids.add(finding_id)
    return frozenset(ids)


__all__ = [
    "ENUMGAP_ACTION_ID_RE",
    "EXPL_REQUIRED_FIELDS",
    "enumgap_reference_heading_ids",
    "exploration_field",
    "markdown_section_end",
    "parse_enumgap_exploration_findings",
    "parse_exploration_finding_blocks",
    "sha256_text",
]
