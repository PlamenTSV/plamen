"""Offset-preserving operational view of CommonMark authority artifacts.

One reviewed ``markdown-it-py`` token stream decides which block containers
are code/HTML and which headings are real Markdown.  Masking retains every
source character position and newline byte spelling so downstream offsets and
hashes stay bound to the original decoded text.
"""
from __future__ import annotations

import re

from plamen_markdown import (
    MarkdownParserContractError,
    inline_code_source_spans,
    parse_authoritative,
    source_line_offsets,
    token_source_span,
)


_MASKED_BLOCK_TOKEN_TYPES = frozenset({"fence", "code_block", "html_block"})
_CONTAINER_PREFIX_RE = re.compile(
    r"(?m)^(?P<prefix>"
    r"(?:[ \t]{0,3}(?:>[ \t]?|(?:[-+*]|[0-9]{1,9}[.)])[ \t]+))+"
    r")"
)


def _mask_span(chars: list[str], start: int, end: int) -> None:
    for index in range(max(0, start), min(len(chars), end)):
        if chars[index] not in "\r\n":
            chars[index] = " "


def operational_markdown_view(text: str) -> str:
    """Blank parser-confirmed non-operational spans without moving offsets.

    Fences (including list-contained fences), indented code, and CommonMark HTML
    blocks are mapped directly from tokens. Inline code is mapped only from
    provenance attached by the reviewed parser operation that emitted each
    ``code_inline`` child; raw parent-token backticks are never paired here.
    """

    source = str(text or "")
    # Raw Token objects are mutable caller capabilities and are never accepted
    # here. Both block masking and inline-child spans originate in fresh,
    # version-checked parses of these exact source bytes.
    parsed = parse_authoritative(source)
    offsets = source_line_offsets(source)
    chars = list(source)
    for token in parsed:
        if token.type in _MASKED_BLOCK_TOKEN_TYPES:
            span = token_source_span(source, token, offsets=offsets)
            if span is None:
                raise MarkdownParserContractError(
                    f"{token.type} token has no source map"
                )
            _mask_span(chars, *span)

    for span in inline_code_source_spans(source):
        _mask_span(chars, *span)

    masked = "".join(chars)
    if len(masked) != len(source):
        raise MarkdownParserContractError(
            "operational Markdown view changed source offsets"
        )
    if [char for char in masked if char in "\r\n"] != [
        char for char in source if char in "\r\n"
    ]:
        raise MarkdownParserContractError(
            "operational Markdown view changed source newlines"
        )
    return masked


def operational_markdown_field_view(text: str) -> str:
    """Return an offset-stable view suitable for section-local field parsing.

    ``operational_markdown_view`` first removes every parser-confirmed code,
    HTML, and inline-code span.  Only then are CommonMark blockquote/list
    prefixes blanked.  This lets a field inside ``>`` or ``-`` containers keep
    the same meaning as an uncontained field without promoting a code or HTML
    decoy.  Source offsets and CR/LF spelling remain exact.
    """

    source = operational_markdown_view(text)
    chars = list(source)
    for match in _CONTAINER_PREFIX_RE.finditer(source):
        _mask_span(chars, *match.span("prefix"))
    masked = "".join(chars)
    if len(masked) != len(source):
        raise MarkdownParserContractError(
            "operational Markdown field view changed source offsets"
        )
    if [char for char in masked if char in "\r\n"] != [
        char for char in source if char in "\r\n"
    ]:
        raise MarkdownParserContractError(
            "operational Markdown field view changed source newlines"
        )
    return masked


__all__ = ["operational_markdown_field_view", "operational_markdown_view"]
