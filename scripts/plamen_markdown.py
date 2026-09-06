"""Plamen V2 — section-scoped Markdown AST utilities (Ship A).

Layer 0: no internal plamen_* imports. Depends only on stdlib + markdown-it-py.

WHY THIS EXISTS
---------------
The recurring pipeline failure (an instantiate halt observed in a prior run,
swarm clusters 1-3) is
the driver parsing LLM-authored Markdown as a machine protocol with loose,
un-anchored regex: a parser locates a table by a "header has these words"
heuristic, then scans line-by-line until a non-pipe line — which silently bleeds
into the NEXT table when a later section has a similar header (e.g. the breadth
manifest parser scanning past `## Breadth Agents` into `## Required Template
Coverage`).

These helpers replace "scan-until-non-pipe-line" with **section-scoped AST
parsing**: locate the heading, take only the tokens belonging to that section
(up to the next heading of equal-or-higher level), and read the FIRST GFM table
in that section via a real Markdown token stream. A table in another section
can never affect the result.

Public API
----------
- ``section_tokens(md, heading_re, level=None)`` -> tokens of the matched section
- ``tables_in_tokens(tokens)`` -> list of tables, each a list of row dicts keyed
  by normalized header
- ``first_section_table(md, heading_re, *, level=None, required_columns=None)``
  -> the first table's rows in the matched section (``[]`` if none)
- ``normalize_header(text)`` -> canonical column key
- ``source_fingerprint(path)`` -> {mtime_ns, sha256, size} (generic; mirrors
  plamen_parsers._judge_source_fingerprint so the contract layer and parsers can
  share one fingerprint convention without an import cycle)
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import re
from itertools import product
from pathlib import Path
from typing import Optional

from markdown_it import MarkdownIt
from markdown_it.rules_inline.backticks import backtick as _markdown_it_backtick

# CommonMark + the GFM table extension ONLY. Deliberately NOT "gfm-like":
# that preset enables linkify, which requires the optional linkify-it-py
# dependency we do not ship. Tables are all we need for machine artifacts.
REVIEWED_MARKDOWN_IT_VERSION = "4.2.0"
_INLINE_CODE_SOURCE_META = "plamen_inline_source_span_v1"
_MAX_INLINE_ALIGNMENT_CANDIDATES = 4096
_MAX_INLINE_ALIGNMENT_STATES = 16384


class MarkdownParserContractError(RuntimeError):
    """The authority parser is absent, unreviewed, or failed tokenization."""


def _backtick_with_relative_source_span(state, silent: bool) -> bool:
    """Delegate grammar to markdown-it and stamp its emitted code child.

    The reviewed upstream rule is the sole delimiter recognizer.  Recording
    ``state.pos`` around that same operation avoids reconstructing backtick
    grammar later from the raw parent token (where HTML attributes and link
    destinations are indistinguishable from actual code delimiters).
    """

    start = int(state.pos)
    token_count = len(state.tokens)
    handled = _markdown_it_backtick(state, silent)
    if not handled or silent:
        return handled
    emitted = [
        token
        for token in state.tokens[token_count:]
        if token.type == "code_inline"
    ]
    if not emitted:
        return handled
    if len(emitted) != 1 or int(state.pos) <= start:
        raise MarkdownParserContractError(
            "reviewed backticks rule emitted an ambiguous code child"
        )
    emitted[0].meta[_INLINE_CODE_SOURCE_META] = [start, int(state.pos)]
    return handled


# CommonMark + the GFM table extension ONLY. Deliberately NOT "gfm-like":
# that preset enables linkify, which requires the optional linkify-it-py
# dependency we do not ship. Tables are all we need for machine artifacts.
_MD = MarkdownIt("commonmark").enable("table")
_MD.inline.ruler.at("backticks", _backtick_with_relative_source_span)


def runtime_markdown_it_version() -> str:
    try:
        return importlib.metadata.version("markdown-it-py")
    except importlib.metadata.PackageNotFoundError:
        return "MISSING"


def assert_reviewed_parser_version(*, runtime_version: str | None = None) -> None:
    """Fail closed when the installed CommonMark grammar is not reviewed.

    Reconciliation artifacts are persisted authority.  A future parser release
    must not silently reinterpret the same Markdown bytes, so the runtime and
    dependency lock are deliberately exact rather than a floating major range.
    ``runtime_version`` exists for the deterministic contract fixture only.
    """

    actual = runtime_version or runtime_markdown_it_version()
    if actual != REVIEWED_MARKDOWN_IT_VERSION:
        raise MarkdownParserContractError(
            "markdown-it-py runtime version "
            f"{actual!r} is not the reviewed {REVIEWED_MARKDOWN_IT_VERSION!r}; "
            "install the existing hash-locked requirements-ci.lock environment "
            "before producing Markdown-derived authority"
        )


def parse_authoritative(md: str, *, check_version: bool = True):
    """Return CommonMark tokens or fail closed at an authority boundary."""

    if check_version:
        assert_reviewed_parser_version()
    try:
        return _MD.parse(md or "")
    except Exception as exc:
        raise MarkdownParserContractError(
            f"markdown-it-py failed to tokenize input: {type(exc).__name__}: {exc}"
        ) from exc


def source_line_offsets(md: str) -> list[int]:
    """Return source offsets for Markdown line indexes, preserving CR/LF.

    The last element is always ``len(md)``.  Token ``map`` values are line
    indexes into the normalized CommonMark view; this table maps them back to
    exact original byte-decoded character offsets without rewriting newlines.
    """

    source = str(md or "")
    offsets = [0]
    for match in re.finditer(r"\r\n|\r|\n", source):
        offsets.append(match.end())
    if offsets[-1] != len(source):
        offsets.append(len(source))
    return offsets


def token_source_span(
    md: str, token, *, offsets: list[int] | None = None
) -> tuple[int, int] | None:
    """Map one token's line map to exact source offsets."""

    mapping = getattr(token, "map", None)
    if not mapping or len(mapping) != 2:
        return None
    line_offsets = offsets if offsets is not None else source_line_offsets(md)
    start_line, end_line = int(mapping[0]), int(mapping[1])
    if (
        start_line < 0
        or end_line < start_line
        or start_line >= len(line_offsets)
        or end_line >= len(line_offsets)
    ):
        raise MarkdownParserContractError(
            f"markdown token has invalid source line map {mapping!r}"
        )
    return line_offsets[start_line], line_offsets[end_line]


def _line_body_span(source: str, offsets: list[int], line: int) -> tuple[int, int]:
    start = offsets[line]
    end = offsets[line + 1]
    if end > start and source[end - 1] in "\r\n":
        end -= 1
        if end > start and source[end - 1] == "\r":
            end -= 1
    return start, end


def _minimal_subsequence_maps(target: str, source: str) -> list[tuple[int, ...]]:
    """Map one normalized inline line into its exact source line.

    Markdown-it block rules only remove source characters before inline
    parsing (container prefixes, table delimiters/escaped-pipe backslashes,
    and CR from CRLF).  We therefore accept only a shortest source window in
    which the exact inline characters occur in order.  Prefix and suffix text
    are free because a table cell/heading is a slice of its mapped source line.
    All equally minimal windows remain candidates for the global ordered
    assignment; uncertainty is never resolved by an arbitrary first match.
    """

    if not target:
        return [tuple()]
    starts = [index for index, char in enumerate(source) if char == target[0]]
    best_cost: int | None = None
    mappings: list[tuple[int, ...]] = []
    for start in starts:
        positions = [start]
        cursor = start + 1
        for char in target[1:]:
            found = source.find(char, cursor)
            if found < 0:
                positions = []
                break
            positions.append(found)
            cursor = found + 1
        if not positions:
            continue
        cost = positions[-1] - positions[0] + 1 - len(target)
        if best_cost is None or cost < best_cost:
            best_cost = cost
            mappings = [tuple(positions)]
        elif cost == best_cost:
            mappings.append(tuple(positions))
        if len(mappings) > _MAX_INLINE_ALIGNMENT_CANDIDATES:
            raise MarkdownParserContractError(
                "inline source alignment exceeds the reviewed candidate bound"
            )
    return mappings


def _relative_code_spans(token) -> list[tuple[int, int, str]]:
    content = str(token.content or "")
    spans: list[tuple[int, int, str]] = []
    for child in token.children or []:
        if child.type != "code_inline":
            continue
        raw = child.meta.get(_INLINE_CODE_SOURCE_META)
        if (
            not isinstance(raw, list)
            or len(raw) != 2
            or type(raw[0]) is not int
            or type(raw[1]) is not int
        ):
            raise MarkdownParserContractError(
                "code_inline child lacks same-parse source provenance"
            )
        start, end = raw
        markup = str(child.markup or "")
        if (
            start < 0
            or end <= start
            or end > len(content)
            or not markup
            or content[start : start + len(markup)] != markup
            or content[end - len(markup) : end] != markup
        ):
            raise MarkdownParserContractError(
                "code_inline child has invalid same-parse source provenance"
            )
        spans.append((start, end, markup))
    if spans != sorted(spans) or any(
        left[1] > right[0] for left, right in zip(spans, spans[1:])
    ):
        raise MarkdownParserContractError(
            "code_inline child provenance is not ordered and non-overlapping"
        )
    return spans


def _inline_alignment_candidates(
    source: str,
    token,
    *,
    offsets: list[int],
) -> list[dict]:
    mapping = getattr(token, "map", None)
    content = str(token.content or "")
    relative_spans = _relative_code_spans(token)
    if not mapping or len(mapping) != 2 or not content:
        if relative_spans:
            raise MarkdownParserContractError(
                "code_inline parent has no mappable source content"
            )
        return []
    start_line, end_line = int(mapping[0]), int(mapping[1])
    if start_line < 0 or end_line <= start_line or end_line >= len(offsets):
        raise MarkdownParserContractError(
            f"inline token has invalid source line map {mapping!r}"
        )

    target_lines = content.split("\n")
    if len(target_lines) != end_line - start_line:
        raise MarkdownParserContractError(
            "inline content/source line cardinality is not uniquely mappable"
        )

    per_line: list[list[tuple[int, ...]]] = []
    body_spans: list[tuple[int, int]] = []
    for relative_line, target_line in enumerate(target_lines):
        body_start, body_end = _line_body_span(
            source, offsets, start_line + relative_line
        )
        body_spans.append((body_start, body_end))
        local = _minimal_subsequence_maps(
            target_line, source[body_start:body_end]
        )
        if not local:
            raise MarkdownParserContractError(
                "inline content cannot be mapped to its parser source line"
            )
        per_line.append(local)

    combination_count = 1
    for choices in per_line:
        combination_count *= len(choices)
        if combination_count > _MAX_INLINE_ALIGNMENT_CANDIDATES:
            raise MarkdownParserContractError(
                "inline source alignment exceeds the reviewed product bound"
            )

    candidates: dict[tuple, dict] = {}
    for combination in product(*per_line):
        char_map: list[int] = []
        for line_index, local_map in enumerate(combination):
            base = body_spans[line_index][0]
            char_map.extend(base + position for position in local_map)
            if line_index + 1 < len(combination):
                newline_end = offsets[start_line + line_index + 1]
                char_map.append(newline_end - 1)
        if len(char_map) != len(content):
            raise MarkdownParserContractError(
                "inline source alignment changed content offsets"
            )
        if any(left >= right for left, right in zip(char_map, char_map[1:])):
            raise MarkdownParserContractError(
                "inline source alignment is not strictly ordered"
            )

        code_spans: list[tuple[int, int]] = []
        for relative_start, relative_end, markup in relative_spans:
            source_start = char_map[relative_start]
            source_end = char_map[relative_end - 1] + 1
            if (
                source[source_start : source_start + len(markup)] != markup
                or source[source_end - len(markup) : source_end] != markup
            ):
                raise MarkdownParserContractError(
                    "inline code provenance does not map to exact delimiters"
                )
            code_spans.append((source_start, source_end))
        extent = (char_map[0], char_map[-1] + 1)
        key = (extent, tuple(code_spans))
        candidates[key] = {"extent": extent, "code_spans": tuple(code_spans)}
    return list(candidates.values())


def inline_code_source_spans(md: str) -> list[tuple[int, int]]:
    """Return exact source spans for parser-emitted inline-code children.

    Parent inline tokens that share a source line (notably GFM table cells) are
    assigned together in parser order.  Exactly one ordered, non-overlapping
    child-span outcome must survive.  An unmappable or ambiguous outcome raises
    before any Markdown-derived authority can be persisted.
    """

    source = str(md or "")
    # Authority never accepts caller-owned token objects. The source is parsed
    # inside this call under the exact reviewed-runtime check, and the stamped
    # children remain local until only immutable integer spans are returned.
    parsed = parse_authoritative(source)
    offsets = source_line_offsets(source)
    groups: dict[tuple[int, int], list[tuple[int, object]]] = {}
    for token_index, token in enumerate(parsed):
        if token.type != "inline" or not str(token.content or ""):
            continue
        span = token_source_span(source, token, offsets=offsets)
        if span is None:
            if any(child.type == "code_inline" for child in token.children or []):
                raise MarkdownParserContractError(
                    "code_inline parent token has no source map"
                )
            continue
        groups.setdefault(span, []).append((token_index, token))

    resolved: list[tuple[int, int, int, int]] = []
    for mapped_group in groups.values():
        if not any(
            child.type == "code_inline"
            for _token_index, token in mapped_group
            for child in token.children or []
        ):
            continue
        group = [
            (
                token_index,
                token,
                _inline_alignment_candidates(source, token, offsets=offsets),
            )
            for token_index, token in mapped_group
        ]
        outcomes: set[tuple[tuple[int, int, int, int], ...]] = set()
        states = 0

        def visit(index: int, prior_end: int, selected: list[tuple]) -> None:
            nonlocal states
            states += 1
            if states > _MAX_INLINE_ALIGNMENT_STATES:
                raise MarkdownParserContractError(
                    "inline ordered assignment exceeds the reviewed state bound"
                )
            if index == len(group):
                outcome: list[tuple[int, int, int, int]] = []
                for token_index, code_spans in selected:
                    outcome.extend(
                        (token_index, child_index, start, end)
                        for child_index, (start, end) in enumerate(code_spans)
                    )
                outcomes.add(tuple(outcome))
                return
            token_index, _token, candidates = group[index]
            for candidate in candidates:
                start, end = candidate["extent"]
                if start < prior_end:
                    continue
                visit(
                    index + 1,
                    end,
                    selected + [(token_index, candidate["code_spans"])],
                )

        visit(0, -1, [])
        if len(outcomes) != 1:
            reason = "unmappable" if not outcomes else "ambiguous"
            raise MarkdownParserContractError(
                f"inline child source provenance is {reason}"
            )
        resolved.extend(next(iter(outcomes)))

    resolved.sort()
    spans = [(start, end) for _token, _child, start, end in resolved]
    if any(
        start < 0 or end <= start or end > len(source) for start, end in spans
    ) or any(left[1] > right[0] for left, right in zip(spans, spans[1:])):
        raise MarkdownParserContractError(
            "inline code source spans are not exact, ordered, and non-overlapping"
        )
    return spans


def mapped_headings(md: str) -> list[dict]:
    """Return actual CommonMark headings with exact source spans.

    Container headings (for example ``- ### Finding [...]``) and headings with
    zero through three leading spaces are represented because the token stream,
    not a column-zero regular expression, decides heading membership.
    """

    source = str(md or "")
    # Do not accept a token capability from a caller: heading authority is
    # always derived by a fresh version-checked parse of these exact bytes.
    parsed = parse_authoritative(source)
    offsets = source_line_offsets(source)
    headings: list[dict] = []
    for index, token in enumerate(parsed):
        if token.type != "heading_open":
            continue
        span = token_source_span(source, token, offsets=offsets)
        if span is None:
            raise MarkdownParserContractError("heading token has no source map")
        inline = parsed[index + 1] if index + 1 < len(parsed) else None
        if inline is None or inline.type != "inline":
            raise MarkdownParserContractError("heading token has no inline content")
        headings.append(
            {
                "level": _heading_level(token.tag),
                "start": span[0],
                "end": span[1],
                "content": inline.content or "",
                "markup": token.markup or "",
            }
        )
    return headings


def normalize_header(text: str) -> str:
    """Canonicalize a table column header to a stable key: lowercase, runs of
    non-alphanumerics collapsed to a single underscore, edges stripped.

      "Expected Output" -> "expected_output"
      "Required?"       -> "required"
      "Template (Required=YES)" -> "template_required_yes"

    Mirrors plamen_parsers._normalize_manifest_header so callers migrating off
    the legacy parser get identical keys.
    """
    return re.sub(r"[^a-z0-9]+", "_", (text or "").strip().lower()).strip("_")


def _heading_level(tag: str) -> int:
    """`h2` -> 2. Returns 99 for a non-heading tag (sorts after any heading)."""
    if tag and len(tag) == 2 and tag[0] == "h" and tag[1].isdigit():
        return int(tag[1])
    return 99


def parse(md: str):
    """Parse Markdown to a token list (commonmark + tables). Never raises on
    ordinary input; returns [] on a hard tokenizer error."""
    try:
        return _MD.parse(md or "")
    except Exception:
        return []


def section_tokens(
    md: str, heading_re, *, level: Optional[int] = None
) -> list:
    """Return the token slice belonging to the FIRST heading whose text matches
    ``heading_re`` (a compiled regex or a string pattern, searched
    case-insensitively), up to — but excluding — the next heading of
    equal-or-higher level. ``[]`` if no heading matches.

    Section membership uses heading LEVEL, not raw line scanning, so a `###`
    subsection inside the matched `##` section stays included while the next
    `##`/`#` ends it.

    If ``level`` is given, only headings of exactly that level are eligible to
    match (defensive — callers usually leave it None and rely on heading text).
    """
    if isinstance(heading_re, str):
        heading_re = re.compile(heading_re, re.IGNORECASE)
    toks = parse(md)
    n = len(toks)
    start_idx = -1
    start_level = 0
    i = 0
    while i < n:
        t = toks[i]
        if t.type == "heading_open":
            lvl = _heading_level(t.tag)
            # The heading's text is the immediately following inline token.
            text = ""
            if i + 1 < n and toks[i + 1].type == "inline":
                text = toks[i + 1].content or ""
            if start_idx == -1:
                if (level is None or lvl == level) and heading_re.search(text):
                    start_idx = i
                    start_level = lvl
            else:
                # Already inside the matched section: a heading of
                # equal-or-higher level closes it.
                if lvl <= start_level:
                    return toks[start_idx:i]
        i += 1
    if start_idx == -1:
        return []
    return toks[start_idx:]


def section_text(md: str, heading_re, *, level: Optional[int] = None) -> str:
    """Return the SOURCE Markdown substring of the first heading matching
    ``heading_re``, from the heading line up to (excluding) the next heading of
    equal-or-higher level. ``""`` if no heading matches — callers then fall back
    to the full document (backward compatibility with artifacts that omit the
    section heading).

    Unlike ``section_tokens`` (which returns parsed tokens), this returns raw
    text so a caller can keep its existing line-based row parser but bounded to
    the correct section — the minimal, behavior-preserving way to kill the
    cross-section table bleed.
    """
    if isinstance(heading_re, str):
        heading_re = re.compile(heading_re, re.IGNORECASE)
    toks = parse(md)
    n = len(toks)
    lines = md.splitlines()
    start_line = -1
    start_level = 0
    i = 0
    while i < n:
        t = toks[i]
        if t.type == "heading_open" and t.map:
            lvl = _heading_level(t.tag)
            text = ""
            if i + 1 < n and toks[i + 1].type == "inline":
                text = toks[i + 1].content or ""
            if start_line == -1:
                if (level is None or lvl == level) and heading_re.search(text):
                    start_line = t.map[0]
                    start_level = lvl
            elif lvl <= start_level:
                return "\n".join(lines[start_line:t.map[0]])
        i += 1
    if start_line == -1:
        return ""
    return "\n".join(lines[start_line:])


def _table_rows(toks: list, table_start: int) -> tuple[list[dict], int]:
    """Parse one GFM table starting at ``table_start`` (a table_open token).
    Returns (rows_keyed_by_header, index_after_table_close). Header cells are
    normalized via ``normalize_header``; body cells are stripped strings."""
    n = len(toks)
    headers: list[str] = []
    rows: list[dict] = []
    in_head = False
    in_body = False
    cur_cells: list[str] = []
    i = table_start + 1
    while i < n:
        t = toks[i]
        ty = t.type
        if ty == "table_close":
            i += 1
            break
        elif ty == "thead_open":
            in_head, in_body = True, False
        elif ty == "thead_close":
            in_head = False
        elif ty == "tbody_open":
            in_body, in_head = True, False
        elif ty == "tbody_close":
            in_body = False
        elif ty == "tr_open":
            cur_cells = []
        elif ty == "tr_close":
            if in_head and not headers:
                headers = [normalize_header(c) for c in cur_cells]
            elif headers:
                row = {}
                for col, val in zip(headers, cur_cells):
                    row[col] = val
                # Preserve positional access for callers that need it.
                row["_cells"] = list(cur_cells)
                rows.append(row)
        elif ty == "inline":
            cur_cells.append((t.content or "").strip())
        i += 1
    return rows, i


def tables_in_tokens(toks: list) -> list[list[dict]]:
    """Return every GFM table found in ``toks``, each as a list of row dicts
    keyed by normalized header (plus ``_cells`` positional list)."""
    out: list[list[dict]] = []
    i = 0
    n = len(toks)
    while i < n:
        if toks[i].type == "table_open":
            rows, i = _table_rows(toks, i)
            out.append(rows)
        else:
            i += 1
    return out


def first_section_table(
    md: str,
    heading_re,
    *,
    level: Optional[int] = None,
    required_columns: Optional[list[str]] = None,
) -> list[dict]:
    """High-level helper: section-scope to the FIRST heading matching
    ``heading_re``, then return the rows of the FIRST GFM table in that section
    (keyed by normalized header). ``[]`` when the section or a table is absent.

    If ``required_columns`` is given (normalized names), the first table in the
    section that contains ALL of them is chosen (skips a leading table that is
    not the intended one). If none match, returns the first table's rows anyway
    so callers can produce a precise "missing column X" diagnostic rather than
    an opaque empty result.
    """
    sect = section_tokens(md, heading_re, level=level)
    if not sect:
        return []
    tables = tables_in_tokens(sect)
    if not tables:
        return []
    if required_columns:
        req = {normalize_header(c) for c in required_columns}
        for tbl in tables:
            if tbl and req.issubset(set(tbl[0].keys())):
                return tbl
    return tables[0]


def source_fingerprint(path: Path) -> dict:
    """Generic identity record for a source file (mtime_ns + sha256 + size),
    used by the contract layer to detect that a JSON sidecar is stale relative
    to its companion Markdown. Mirrors plamen_parsers._judge_source_fingerprint
    but lives at Layer 0 so the contract layer can import it without a cycle.
    Returns {} on read error."""
    try:
        stat = path.stat()
        data = path.read_bytes()
    except OSError:
        return {}
    return {
        "source_mtime_ns": stat.st_mtime_ns,
        "source_sha256": hashlib.sha256(data).hexdigest(),
        "source_size": stat.st_size,
    }
