"""Static consistency checks for fully rendered restricted-Claude leaf prompts.

The runtime tool policy is the authority.  This module catches explicit prompt
instructions that ask a leaf worker to cross that authority before provider
spawn.  It deliberately does not attempt to classify arbitrary prose: only
imperative clauses, labelled directive lists, and concrete path/tool spellings
are considered.
"""
from __future__ import annotations

from dataclasses import dataclass
import ntpath
import posixpath
import re
from pathlib import PurePath
from typing import Iterable


MAX_PROMPT_CHARS = 2_000_000
_ARTIFACT_SUFFIXES = (
    "md", "json", "jsonl", "txt", "toml", "yaml", "yml", "sol", "rs",
    "move", "cairo", "wasm", "csv", "xml", "py", "js", "jsx", "ts",
    "tsx", "go", "lock",
)
_ARTIFACT_SUFFIX_PATTERN = "|".join(_ARTIFACT_SUFFIXES)
_PATH_TOKEN_RE = re.compile(
    rf"`([^`\r\n]+)`|"
    rf'"([^"\r\n]+)"|'
    rf"'([^'\r\n]+)'|"
    rf"((?:[A-Za-z]:[\\/]|~[/\\]|\.{{1,2}}[/\\]|"
    rf"(?:scratchpad|project):)[^\s,;|<>]+)|"
    rf"((?<![A-Za-z0-9_:])/(?!/)[^\s,;|<>`\"']+)|"
    rf"([A-Za-z0-9_.@+-]+(?:[/\\][A-Za-z0-9_.@+ -]+)*\."
    rf"(?:{_ARTIFACT_SUFFIX_PATTERN}))",
    re.IGNORECASE,
)
_UNRESOLVED_CLAUDE_RE = re.compile(r"(?i)(?<![A-Za-z0-9_])~[/\\]\.claude(?:[/\\]|\b)")
_NEGATION_RE = re.compile(
    r"(?i)\b(?:do\s+not|don't|never|must\s+not|may\s+not|should\s+not|"
    r"cannot|can't|without)\b"
)
_DIRECTIVE_PREFIX_RE = re.compile(
    r"(?ix)^\s*"
    r"(?:[-*+]\s+|\d+[.)]\s+)?"
    r"(?:\[[^\]\r\n]{1,40}\]\s*)?"
    r"(?:scope|task|instruction|instructions|required action|worker action)?\s*:?[ \t]*"
    r"(?:(?:first|then|next|finally)\s*,?\s+)?"
    r"(?:if\b[^,\r\n]{0,220},\s*)?"
    r"(?:please\s+)?"
    r"(?:you\s+)?"
    r"(?:(?:must|may|should|can|will|shall)\s+|"
    r"(?:need|required|expected|allowed|instructed)\s+to\s+|"
    r"are\s+(?:required|expected|allowed|instructed)\s+to\s+)?"
    r"(?P<verb>[A-Za-z][A-Za-z-]*)\b"
)
_TASK_IS_TO_RE = re.compile(
    r"(?ix)\b(?:task|instruction|responsibility|scope)\s+is\s+to\s+"
    r"(?P<verb>[A-Za-z][A-Za-z-]*)\b"
)
_MID_SENTENCE_DIRECTIVE_RE = re.compile(
    r"(?ix)^\s*"
    r"(?:(?:the|this|each|a|an)\s+)?"
    r"(?:worker|agent|model|assistant|auditor|you)\s+"
    r"(?:(?:must|may|should|can|will|shall|has\s+to|needs\s+to)\s+|"
    r"(?:is|are)\s+(?:required|expected|allowed|instructed)\s+to\s+)"
    r"(?P<verb>[A-Za-z][A-Za-z-]*)\b"
)
_READ_VERBS = frozenset({
    "read", "open", "load", "consume", "consult", "review", "inspect",
})
_WRITE_VERBS = frozenset({
    "write", "save", "create", "emit", "append", "update", "modify",
    "edit", "overwrite", "produce",
})
_SEARCH_VERBS = frozenset({
    "search", "scan", "glob", "grep", "find", "enumerate", "list", "walk",
    "recurse",
})
_TOOL_ACTION_VERBS = frozenset({
    "use", "run", "invoke", "call", "launch", "execute", "spawn",
    "delegate", "ask", "message", "coordinate",
})
_ALL_DIRECTIVE_VERBS = (
    _READ_VERBS | _WRITE_VERBS | _SEARCH_VERBS | _TOOL_ACTION_VERBS
    | frozenset({"move", "traverse", "ascend"})
)
_PROJECT_ROOT_RE = re.compile(
    r"(?i)(?:\bPROJECT_ROOT\b|\bproject\s+root\b|\brepository\s+root\b|"
    r"\brepo\s+root\b)"
)
_SCRATCHPAD_ROOT_RE = re.compile(
    r"(?i)(?:\bSCRATCHPAD(?:_ROOT)?\b|(?<![A-Za-z0-9_])\.scratchpad(?:[/\\]|\b)|"
    r"\bscratchpad\s+root\b)"
)
_PARENT_TRAVERSAL_RE = re.compile(
    r"(?i)(?:\b(?:parent|parents|ancestor|ancestors)\b|(?<!\.)\.\.(?:[/\\]|\b)|"
    r"\b(?:one|two|three|\d+)\s+(?:directory\s+levels?|levels?)\s+up\b)"
)
_COORDINATOR_RE = re.compile(
    r"(?i)\b(?:sub-?agents?|agents?|workers?|coordinator|orchestrator|"
    r"Agent\s+tool|Task\s+tool)\b"
)
_SHELL_RE = re.compile(
    r"(?i)(?:\bBash\b|\bPowerShell\b|\bshell\b|\bterminal\b|"
    r"\bcommand\s+(?:line|prompt)\b|\bforge\s+(?:build|test)\b|"
    r"\bnpm\s+(?:run|test|install|ci)\b|\bcargo\s+(?:build|test)\b|"
    r"\bgit(?:\.exe)?\b|\bcmd(?:\.exe)?\b|"
    r"\bpython(?:3(?:\.\d+)*)?(?:\.exe)?\b|\bpy(?:\.exe)?\b|"
    r"\b(?:ba|z|fi|k|c)?sh(?:\.exe)?\b|"
    r"\blist_functions\b|\banalyze_modifiers\b|"
    r"\b(?:run|execute)\s+(?:the\s+)?(?:tests?|build|compiler|linter|"
    r"static\s+tools?|slither|medusa|echidna|halmos)\b)"
)
_MCP_RE = re.compile(r"(?i)(?:\bMCP\b|\bmcp__[A-Za-z0-9_-]+)")
_NAMED_TOOL_RE = re.compile(
    r"\b(?:Bash|PowerShell|Agent|Task|WebSearch|WebFetch|Read|Write|Edit|"
    r"Glob|Grep|NotebookEdit)\b"
)
_ADDITIONAL_OUTPUT_RE = re.compile(
    r"(?i)\b(?:additional|another|alternate|other|extra|secondary)\s+"
    r"(?:output|artifact|file)s?\b"
)
_EXAMPLE_OR_COMMENT_PREFIX_RE = re.compile(
    r"(?ix)^\s*(?:(?:bad|good|negative|positive|illustrative)\s+)?"
    r"(?:example|illustration|comment|note)\s*(?:only\s*)?(?::|[-–—])\s*"
)
_NOMINAL_NON_DIRECTIVE_RE = {
    "review": re.compile(r"(?i)^\s*review\s+of\b"),
    "read": re.compile(r"(?i)^\s*read\s+(?:access|permission|policy|capability)\b"),
    "search": re.compile(r"(?i)^\s*search\s+(?:results?|permission|policy|capability)\b"),
    "write": re.compile(r"(?i)^\s*write\s+(?:access|permission|policy|capability)\b"),
    "use": re.compile(r"(?i)^\s*use\s+of\b"),
}
_LIST_ITEM_RE = re.compile(r"^\s*(?:[-*+]\s+|\d+[.)]\s+)")
_REVERSE_LIST_HEADING_RE = re.compile(
    r"(?ix)^\s*"
    r"(?P<object>files?|artifacts?|inputs?|sources?|paths?|outputs?|output\s+files?)"
    r"\s+(?:to|for)\s+"
    r"(?P<verb>read|open|load|consume|consult|review|inspect|"
    r"write|save|create|emit|append|update|modify|edit|overwrite|produce|"
    r"search|scan|glob|grep|find|enumerate|list|walk|recurse)\s*:?\s*$"
)
_NOUN_LIST_HEADING_RE = re.compile(
    r"(?ix)^\s*(?P<object>"
    r"input\s+(?:files?|artifacts?|paths?)|sources?|read\s+(?:files?|artifacts?|paths?)|"
    r"output\s+(?:files?|artifacts?|paths?)|outputs?|"
    r"search\s+(?:roots?|paths?|directories))\s*:?\s*$"
)


class ClaudeWorkerPromptConsistencyError(ValueError):
    """Raised when prompt/tool authority inputs are malformed or inconsistent."""

    def __init__(self, issues: tuple["PromptConsistencyIssue", ...]):
        self.issues = issues
        summary = "; ".join(
            f"{issue.code}@{issue.line}:{issue.subject}" for issue in issues
        )
        super().__init__(summary or "Claude worker prompt is inconsistent")


@dataclass(frozen=True, slots=True)
class PromptConsistencyIssue:
    """One deterministic prompt/policy contradiction."""

    code: str
    line: int
    subject: str
    directive: str


def _bounded_strings(values: Iterable[str | PurePath], field: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes, PurePath)):
        raise TypeError(f"{field} must be an iterable of paths, not one path")
    result: list[str] = []
    for value in values:
        if not isinstance(value, (str, PurePath)):
            raise TypeError(f"{field} entries must be strings or paths")
        text = str(value).strip()
        if not text or any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
            raise ValueError(f"{field} contains an empty or control-bearing entry")
        if len(text) > 32_768:
            raise ValueError(f"{field} entry is too long")
        result.append(text)
    if len(result) > 20_000:
        raise ValueError(f"{field} contains too many entries")
    return tuple(result)


def _strip_token(value: str) -> str:
    # Keep ``.`` and ``..`` intact: in a search directive they are security-
    # significant root/parent spellings, not sentence punctuation.
    return value.strip().strip("`\"'").rstrip(",;:)").strip()


def _slash_norm(value: str) -> str:
    value = _strip_token(value).replace("\\", "/")
    if re.match(r"^[A-Za-z]:/", value):
        return ntpath.normcase(ntpath.normpath(value.replace("/", "\\"))).replace(
            "\\", "/"
        )
    return posixpath.normpath(value)


def _resolve_identity(
    value: str,
    *,
    project_root: str,
    scratchpad_root: str,
) -> str:
    text = _strip_token(value)
    lower = text.lower()
    if lower.startswith("scratchpad:"):
        text = scratchpad_root.rstrip("/\\") + "/" + text.split(":", 1)[1].lstrip("/\\")
    elif lower.startswith("project:"):
        text = project_root.rstrip("/\\") + "/" + text.split(":", 1)[1].lstrip("/\\")
    elif re.match(r"(?i)^\$?\{?project_root\}?[/\\]", text):
        suffix = re.sub(r"(?i)^\$?\{?project_root\}?[/\\]", "", text)
        text = project_root.rstrip("/\\") + "/" + suffix
    elif re.match(r"(?i)^\$?\{?scratchpad(?:_root)?\}?[/\\]", text):
        suffix = re.sub(r"(?i)^\$?\{?scratchpad(?:_root)?\}?[/\\]", "", text)
        text = scratchpad_root.rstrip("/\\") + "/" + suffix
    elif lower.startswith(".scratchpad/") or lower.startswith(".scratchpad\\"):
        text = project_root.rstrip("/\\") + "/" + text
    elif not re.match(r"^[A-Za-z]:[\\/]", text) and not text.startswith("/"):
        text = project_root.rstrip("/\\") + "/" + text
    return _slash_norm(text)


@dataclass(frozen=True, slots=True)
class _PathAuthority:
    exact: frozenset[str]
    unique_basenames: frozenset[str]
    case_insensitive: bool

    def contains(self, token: str, *, project_root: str, scratchpad_root: str) -> bool:
        resolved = _resolve_identity(
            token, project_root=project_root, scratchpad_root=scratchpad_root
        )
        if resolved in self.exact:
            return True
        # Fully rendered prompts often use a bare artifact basename.  Admit it
        # only when that basename identifies exactly one registered path.
        raw = _slash_norm(token)
        basename = raw.casefold() if self.case_insensitive else raw
        return "/" not in raw and basename in self.unique_basenames


def _contains_exact_project_artifact(
    authority: _PathAuthority,
    token: str,
    *,
    project_root: str,
    scratchpad_root: str,
) -> bool:
    """Require the exact project file when prose explicitly locates it there.

    Bare artifact names otherwise use a unique-basename convenience.  That is
    intentionally insufficient for an explicit PROJECT_ROOT directive: a
    same-named scratchpad or methodology input is a different capability.
    """

    raw = _strip_token(token)
    if not raw:
        return False
    if re.match(r"^[A-Za-z]:[\\/]", raw) or raw.startswith("/"):
        resolved = _resolve_identity(
            raw, project_root=project_root, scratchpad_root=scratchpad_root
        )
    elif raw.lower().startswith("project:") or re.match(
        r"(?i)^\$?\{?project_root\}?[\\/]", raw
    ):
        resolved = _resolve_identity(
            raw, project_root=project_root, scratchpad_root=scratchpad_root
        )
    else:
        resolved = _resolve_identity(
            "project:" + raw,
            project_root=project_root,
            scratchpad_root=scratchpad_root,
        )
    return resolved in authority.exact


def _path_authority(
    values: tuple[str, ...], *, project_root: str, scratchpad_root: str
) -> _PathAuthority:
    exact = {
        _resolve_identity(v, project_root=project_root, scratchpad_root=scratchpad_root)
        for v in values
    }
    case_insensitive = re.match(r"^[A-Za-z]:[\\/]", project_root) is not None
    counts: dict[str, int] = {}
    for value in exact:
        base = value.rsplit("/", 1)[-1]
        if case_insensitive:
            base = base.casefold()
        counts[base] = counts.get(base, 0) + 1
    return _PathAuthority(
        exact=frozenset(exact),
        unique_basenames=frozenset(k for k, count in counts.items() if count == 1),
        case_insensitive=case_insensitive,
    )


def _directive_verb(line: str) -> str | None:
    candidate = line.strip()
    # Labels such as ``SCOPE: Write ...`` are common in worker prompts.
    candidate = re.sub(
        r"(?i)^\s*(?:[-*+]\s+|\d+[.)]\s+)?"
        r"(?:scope|task|instruction|instructions|required action|worker action)\s*:\s*",
        "",
        candidate,
    )
    for match in (
        _DIRECTIVE_PREFIX_RE.match(candidate),
        _MID_SENTENCE_DIRECTIVE_RE.match(candidate),
        _TASK_IS_TO_RE.search(candidate),
    ):
        if match is None:
            continue
        verb = match.group("verb").lower()
        if verb not in _ALL_DIRECTIVE_VERBS:
            continue
        nominal = _NOMINAL_NON_DIRECTIVE_RE.get(verb)
        if nominal is not None and nominal.match(candidate):
            continue
        return verb
    return None


def _is_negated(line: str, verb: str) -> bool:
    match = re.search(rf"(?i)\b{re.escape(verb)}\b", line)
    if match is None:
        return False
    return _NEGATION_RE.search(line[: match.start()]) is not None


def _known_path_matches(
    line: str,
    known_paths: tuple[str, ...],
) -> tuple[tuple[int, int, str], ...]:
    """Find complete authority paths, including unquoted paths with spaces."""

    matches: list[tuple[int, int, str]] = []
    seen: set[tuple[int, int]] = set()
    # Longest first makes overlapping authority entries deterministic.
    for path in sorted(set(known_paths), key=lambda item: (-len(item), item)):
        if not path:
            continue
        pieces: list[str] = []
        for char in path:
            if char in "/\\":
                pieces.append(r"[/\\]")
            elif char in " \t":
                pieces.append(r"[ \t]+")
            else:
                pieces.append(re.escape(char))
        flags = re.IGNORECASE if re.match(r"^[A-Za-z]:[/\\]", path) else 0
        pattern = re.compile(
            r"(?<![A-Za-z0-9_.-])" + "".join(pieces)
            + r"(?=$|[\s,;:)]|\.(?:\s|$))",
            flags,
        )
        for match in pattern.finditer(line):
            span = match.span()
            if span in seen or any(
                start <= span[0] and span[1] <= end for start, end, _ in matches
            ):
                continue
            seen.add(span)
            matches.append((span[0], span[1], match.group(0)))
    return tuple(sorted(matches))


def _path_tokens(line: str, *, known_paths: tuple[str, ...] = ()) -> tuple[str, ...]:
    result: list[str] = []
    known = _known_path_matches(line, known_paths)
    result.extend(value for _, _, value in known)
    for match in _PATH_TOKEN_RE.finditer(line):
        start, end = match.span()
        if any(start < known_end and end > known_start for known_start, known_end, _ in known):
            continue
        token = next((group for group in match.groups() if group is not None), "")
        token = _strip_token(token)
        if token:
            result.append(token)
    return tuple(dict.fromkeys(result))


def _clean_model_visible_clause(value: str) -> str:
    """Remove markup that does not hide text from the model."""

    text = value.strip()
    text = re.sub(r"^\s*(?:<!--\s*)+", "", text)
    text = re.sub(r"(?:\s*-->)+\s*$", "", text)
    text = re.sub(r"^\s*(?:>\s*)+", "", text)
    text = _EXAMPLE_OR_COMMENT_PREFIX_RE.sub("", text)
    text = re.sub(
        r"(?i)^\s*(?:\*\*|__)\s*"
        r"(?:mandatory|required|instruction|task|scope)\s*"
        r"(?:\*\*|__)\s*:\s*",
        "",
        text,
    )
    if len(text) >= 2 and text.startswith("`") and text.endswith("`"):
        text = text[1:-1].strip()
    return text


def _directive_clauses(line: str) -> tuple[str, ...]:
    """Split explicit mixed instructions so negation remains clause-local."""

    text = _clean_model_visible_clause(line)
    if not text:
        return ()
    # Worker prompts conventionally separate independent imperatives with
    # semicolons, sentence boundaries, or explicit sequencing conjunctions.
    # Path/token lists separated by commas or plain ``and`` remain intact.
    text = re.sub(
        r"(?i),?\s+\b(?:and\s+then|then|next|finally|but|however)\b\s+",
        ";",
        text,
    )
    text = re.sub(
        r"(?i)\s+\band\b\s+(?=(?:do\s+not|don't|never|must\s+not|"
        r"may\s+not|should\s+not|read|open|load|consume|consult|review|"
        r"inspect|write|save|create|emit|append|update|modify|edit|overwrite|"
        r"produce|search|scan|glob|grep|find|enumerate|list|walk|recurse|"
        r"use|run|invoke|call|launch|execute|spawn|delegate|ask|message|"
        r"coordinate)\b)",
        ";",
        text,
    )
    text = re.sub(
        r"(?i)(?<=[.!?])\s+(?=(?:first|then|next|finally|please|you|the\s+worker|"
        r"do\s+not|don't|never|must|may|should|read|open|load|consume|review|"
        r"write|save|create|append|search|scan|glob|grep|find|walk|use|run|"
        r"invoke|call|execute|spawn|delegate)\b)",
        ";",
        text,
    )
    return tuple(
        cleaned
        for part in text.split(";")
        if (cleaned := _clean_model_visible_clause(part))
    )


def _list_heading_mode(line: str, verb: str | None, tokens: tuple[str, ...]) -> str | None:
    stripped = line.strip()
    reverse = _REVERSE_LIST_HEADING_RE.match(stripped)
    if reverse is not None:
        verb = reverse.group("verb").lower()
    else:
        noun = _NOUN_LIST_HEADING_RE.match(stripped)
        if noun is not None:
            obj = noun.group("object").lower()
            if obj.startswith(("output", "outputs")):
                return "write"
            if obj.startswith("search"):
                return "search"
            return "read"
    if verb is None or tokens:
        return None
    if not (
        stripped.endswith(":")
        or re.search(
            r"(?i)\b(?:these|following|files?|artifacts?|inputs?|sources?|"
            r"paths?|outputs?|roots?|directories)\b\s*:?\s*$",
            stripped,
        )
    ):
        return None
    if verb in _READ_VERBS:
        return "read"
    if verb in _WRITE_VERBS:
        return "write"
    if verb in _SEARCH_VERBS:
        return "search"
    return None


def _looks_like_artifact(token: str) -> bool:
    token = _strip_token(token)
    return re.search(rf"(?i)\.(?:{_ARTIFACT_SUFFIX_PATTERN})$", token) is not None


def _line_excerpt(line: str) -> str:
    compact = " ".join(line.strip().split())
    return compact[:500]


def _target_is_safe_root(
    token: str,
    *,
    safe_roots: frozenset[str],
    project_root: str,
    scratchpad_root: str,
) -> bool:
    return _resolve_identity(
        token, project_root=project_root, scratchpad_root=scratchpad_root
    ) in safe_roots


def validate_claude_worker_prompt_consistency(
    prompt: str,
    *,
    phase_io_inputs: Iterable[str | PurePath],
    phase_io_outputs: Iterable[str | PurePath],
    policy_tools: Iterable[str],
    safe_search_roots: Iterable[str | PurePath],
    project_root: str | PurePath,
    scratchpad_root: str | PurePath,
) -> tuple[PromptConsistencyIssue, ...]:
    """Return deterministic contradictions between a leaf prompt and policy.

    Paths are compared lexically; no filesystem state is consulted.  Bare
    artifact names are accepted only when unique in their registered PhaseIO
    denominator.
    """

    if not isinstance(prompt, str):
        raise TypeError("prompt must be a string")
    if not prompt or len(prompt) > MAX_PROMPT_CHARS or "\x00" in prompt:
        raise ValueError("prompt is empty, NUL-bearing, or exceeds the size bound")
    project = str(project_root).strip()
    scratchpad = str(scratchpad_root).strip()
    if not project or not scratchpad:
        raise ValueError("project_root and scratchpad_root must be non-empty")
    input_values = _bounded_strings(phase_io_inputs, "phase_io_inputs")
    output_values = _bounded_strings(phase_io_outputs, "phase_io_outputs")
    tool_values = _bounded_strings(policy_tools, "policy_tools")
    safe_values = _bounded_strings(safe_search_roots, "safe_search_roots")
    input_authority = _path_authority(
        input_values, project_root=project, scratchpad_root=scratchpad
    )
    output_authority = _path_authority(
        output_values, project_root=project, scratchpad_root=scratchpad
    )
    safe_roots = frozenset(
        _resolve_identity(v, project_root=project, scratchpad_root=scratchpad)
        for v in safe_values
    )
    allowed_tools = frozenset(tool_values)
    known_paths = tuple(dict.fromkeys((
        *input_values,
        *output_values,
        *safe_values,
        project,
        scratchpad,
        *(
            _resolve_identity(v, project_root=project, scratchpad_root=scratchpad)
            for v in (*input_values, *output_values, *safe_values)
        ),
    )))

    issues: list[PromptConsistencyIssue] = []
    seen: set[tuple[str, int, str]] = set()

    def add(code: str, number: int, subject: str, line: str) -> None:
        key = (code, number, subject)
        if key in seen:
            return
        seen.add(key)
        issues.append(PromptConsistencyIssue(code, number, subject, _line_excerpt(line)))

    list_mode: str | None = None
    carried_project_artifact_tokens: tuple[str, ...] = ()
    for number, line in enumerate(prompt.splitlines(), 1):
        if _UNRESOLVED_CLAUDE_RE.search(line):
            add("UNRESOLVED_CLAUDE_PATH", number, "~/.claude", line)

        visible_line = _clean_model_visible_clause(line)
        stripped = visible_line.strip()
        if not stripped:
            # A standalone HTML-comment delimiter does not terminate a list
            # embedded inside that model-visible comment.
            if stripped not in {"<!--", "-->"}:
                list_mode = None
                carried_project_artifact_tokens = ()
            continue
        if stripped.startswith("#"):
            list_mode = None
            carried_project_artifact_tokens = ()
            continue

        clauses = _directive_clauses(visible_line)
        line_is_list_item = _LIST_ITEM_RE.match(stripped) is not None
        next_list_mode: str | None = None
        prior_clause_tokens = carried_project_artifact_tokens
        prior_clause_locates_project_artifact = bool(
            carried_project_artifact_tokens
        )

        for clause in clauses:
            verb = _directive_verb(clause)
            tokens = _path_tokens(clause, known_paths=known_paths)
            heading_mode = _list_heading_mode(clause, verb, tokens)
            if heading_mode is not None:
                next_list_mode = heading_mode
                continue
            if list_mode and line_is_list_item and verb is None:
                verb = list_mode
            negated = bool(verb and _is_negated(clause, verb))

            search_directive = bool(
                verb
                and not negated
                and (
                    verb in _SEARCH_VERBS | frozenset({"move", "traverse", "ascend"})
                    or (
                        verb in _TOOL_ACTION_VERBS
                        and re.search(r"\b(?:Glob|Grep)\b", clause) is not None
                    )
                )
            )
            read_directive = bool(
                verb
                and not negated
                and (
                    verb in _READ_VERBS
                    or (
                        verb in _TOOL_ACTION_VERBS
                        and re.search(r"\bRead\b", clause) is not None
                    )
                )
            )
            write_directive = bool(
                verb
                and not negated
                and (
                    verb in _WRITE_VERBS
                    or (
                        verb in _TOOL_ACTION_VERBS
                        and re.search(r"\b(?:Write|Edit)\b", clause) is not None
                    )
                )
            )

            if search_directive:
                if _PARENT_TRAVERSAL_RE.search(clause):
                    add("UNSAFE_PARENT_SEARCH_DIRECTIVE", number, "parent traversal", clause)
                if _PROJECT_ROOT_RE.search(clause) or re.search(
                    r"(?i)(?:path\s*[=:]\s*[`\"']?\.[`\"']?|\bat\s+[`\"']?\.[`\"']?)",
                    clause,
                ):
                    add("UNSAFE_PROJECT_SEARCH_DIRECTIVE", number, "project root", clause)
                if _SCRATCHPAD_ROOT_RE.search(clause):
                    add("UNSAFE_SCRATCHPAD_SEARCH_DIRECTIVE", number, "scratchpad", clause)
                for token in tokens:
                    if _looks_like_artifact(token):
                        if not input_authority.contains(
                            token, project_root=project, scratchpad_root=scratchpad
                        ):
                            add("UNREGISTERED_ARTIFACT_READ", number, token, clause)
                        continue
                    bare_target = _strip_token(token)
                    if _PROJECT_ROOT_RE.fullmatch(bare_target):
                        continue
                    if _SCRATCHPAD_ROOT_RE.fullmatch(bare_target):
                        continue
                    if _PARENT_TRAVERSAL_RE.fullmatch(bare_target):
                        continue
                    resolved_target = _resolve_identity(
                        token, project_root=project, scratchpad_root=scratchpad
                    )
                    if resolved_target == _slash_norm(project):
                        add("UNSAFE_PROJECT_SEARCH_DIRECTIVE", number, "project root", clause)
                    elif resolved_target == _slash_norm(scratchpad):
                        add("UNSAFE_SCRATCHPAD_SEARCH_DIRECTIVE", number, "scratchpad", clause)
                    elif not _target_is_safe_root(
                        token,
                        safe_roots=safe_roots,
                        project_root=project,
                        scratchpad_root=scratchpad,
                    ):
                        add("UNSAFE_SEARCH_ROOT_DIRECTIVE", number, token, clause)

            if read_directive:
                project_tokens = tokens
                project_location = _PROJECT_ROOT_RE.search(clause) is not None
                # Fully rendered prompts use the explicit form
                # ``artifact.md is present in PROJECT_ROOT. Read it.`` Keep the
                # anaphora bounded to the immediately preceding clause on the
                # same physical line; do not infer across general prose.
                if (
                    not project_tokens
                    and prior_clause_locates_project_artifact
                    and re.search(r"(?i)\b(?:it|them|these)\b", clause)
                ):
                    project_tokens = prior_clause_tokens
                    project_location = True
                for token in tokens:
                    if _looks_like_artifact(token) and not input_authority.contains(
                        token, project_root=project, scratchpad_root=scratchpad
                    ):
                        add("UNREGISTERED_ARTIFACT_READ", number, token, clause)
                if project_location:
                    for token in project_tokens:
                        if (
                            _looks_like_artifact(token)
                            and not _contains_exact_project_artifact(
                                input_authority,
                                token,
                                project_root=project,
                                scratchpad_root=scratchpad,
                            )
                        ):
                            add(
                                "UNREGISTERED_ARTIFACT_READ",
                                number,
                                token,
                                clause,
                            )

            if write_directive:
                if _ADDITIONAL_OUTPUT_RE.search(clause):
                    add("ALTERNATE_OUTPUT_WRITE", number, "additional output", clause)
                for token in tokens:
                    if _looks_like_artifact(token) and not output_authority.contains(
                        token, project_root=project, scratchpad_root=scratchpad
                    ):
                        add("UNREGISTERED_OUTPUT_WRITE", number, token, clause)

            if verb and not negated and verb in _TOOL_ACTION_VERBS:
                if _COORDINATOR_RE.search(clause):
                    required = (
                        "Task" if re.search(r"(?i)\bTask\s+tool\b", clause) else "Agent"
                    )
                    if required not in allowed_tools:
                        add("DENIED_COORDINATOR_INSTRUCTION", number, required, clause)
                if _SHELL_RE.search(clause) and not ({"Bash", "PowerShell"} & allowed_tools):
                    add("DENIED_TOOL_INSTRUCTION", number, "shell", clause)
                if _MCP_RE.search(clause) and not any(
                    tool.startswith("mcp__") for tool in allowed_tools
                ):
                    add("DENIED_TOOL_INSTRUCTION", number, "MCP", clause)
                for match in _NAMED_TOOL_RE.finditer(clause):
                    tool = match.group(0)
                    # Read/write/search verbs may appear as ordinary action words.
                    # Capitalized exact tool names in a use/run/call clause are
                    # nevertheless unambiguous provider-tool instructions.
                    if tool not in allowed_tools:
                        add("DENIED_TOOL_INSTRUCTION", number, tool, clause)

            prior_clause_tokens = tuple(
                token for token in tokens if _looks_like_artifact(token)
            )
            prior_clause_locates_project_artifact = bool(
                prior_clause_tokens and _PROJECT_ROOT_RE.search(clause)
            )

        if next_list_mode is not None:
            list_mode = next_list_mode
        elif not line_is_list_item:
            list_mode = None
        carried_project_artifact_tokens = (
            prior_clause_tokens if prior_clause_locates_project_artifact else ()
        )

    return tuple(sorted(issues, key=lambda issue: (issue.line, issue.code, issue.subject)))


def require_claude_worker_prompt_consistency(
    prompt: str,
    **authority: object,
) -> None:
    """Raise :class:`ClaudeWorkerPromptConsistencyError` on any contradiction."""

    issues = validate_claude_worker_prompt_consistency(prompt, **authority)  # type: ignore[arg-type]
    if issues:
        raise ClaudeWorkerPromptConsistencyError(issues)


__all__ = [
    "ClaudeWorkerPromptConsistencyError",
    "MAX_PROMPT_CHARS",
    "PromptConsistencyIssue",
    "require_claude_worker_prompt_consistency",
    "validate_claude_worker_prompt_consistency",
]
