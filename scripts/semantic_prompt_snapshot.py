"""Pure provider-neutral prompt snapshot compilation for ``semantic_v1``.

The snapshot is compiled and content-addressed before a backend transport is
selected.  A transport overlay is a separate, closed record bound only to the
snapshot digest; it cannot mutate prompt content, methodology, obligations,
logical I/O, output schema, or completion semantics.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
import hashlib
from pathlib import Path
import re
from types import MappingProxyType
from typing import Any, ClassVar

from program_facts_types import (
    ProgramFactsTypeError,
    canonical_file_bytes,
    canonical_json_bytes,
    strict_json_loads,
)
from semantic_work_plan import (
    ANALYSIS_TEMPLATE_ID,
    NATIVE_TEMPLATE_ID,
    REPORT_TEMPLATE_ID,
    SEMANTIC_TEMPLATE_IDS,
    SemanticSchemaError,
    SemanticWorkPlan,
)


SEMANTIC_PROMPT_SNAPSHOT_SCHEMA = "plamen.semantic-prompt-snapshot.v1"
TRANSPORT_OVERLAY_SCHEMA = "plamen.transport-overlay.v1"
PROMPT_ENCODING = "utf-8"
PROMPT_NEWLINE = "LF"
SEMANTIC_PROMPT_COMPILER_VERSION = "semantic-prompt-compiler.v1"
SEMANTIC_COMPLETION_LANGUAGE = (
    "Finish only after the assigned output is complete and every assigned "
    "obligation has an evidence disposition."
)
_SEMANTIC_TEMPLATE_REGISTRY = MappingProxyType(
    {
    ANALYSIS_TEMPLATE_ID: (
        "Analyze the immutable inputs using the bound methodology. "
        "Disposition every assigned obligation with evidence. Write only "
        "the assigned output."
    ),
    NATIVE_TEMPLATE_ID: (
        "Execute only the bound native capability request against the "
        "immutable inputs. Record exact evidence in the assigned output."
    ),
    REPORT_TEMPLATE_ID: (
        "Project only the bound verified records into the assigned output. "
        "Preserve every identity, disposition, and limitation."
    ),
    }
)
if frozenset(_SEMANTIC_TEMPLATE_REGISTRY) != SEMANTIC_TEMPLATE_IDS:
    raise RuntimeError("semantic template registry does not match plan schema")
SEMANTIC_TEMPLATES = _SEMANTIC_TEMPLATE_REGISTRY
_COMPILER_CLOSURE_FILES = (
    ("semantic_prompt_snapshot.py", "semantic_prompt_snapshot.py"),
    ("semantic_work_plan.py", "semantic_work_plan.py"),
    ("program_facts_types.py", "program_facts_types.py"),
)

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,191}$", re.ASCII)
_LOGICAL_URI_RE = re.compile(
    r"^(?P<scheme>workspace|artifact|methodology)://"
    r"(?P<path>[A-Za-z0-9][A-Za-z0-9._/-]*)$",
    re.ASCII,
)
_PROVIDER_LANGUAGE_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_])"
    r"(?:claude|codex|openai|anthropic|chatgpt|"
    r"gpt(?:[-_.][A-Za-z0-9]+)*|"
    r"o[134](?:[-_.][A-Za-z0-9]+)*|opus|sonnet|haiku|gemini|llama|"
    r"mistral|grok|task|agent|spawn_agent|apply_patch|shell_command|"
    r"exec_command|bash|powershell|cmd\.exe|zsh|fish|pty|"
    r"session[ -]?(?:framing|management))"
    r"(?![A-Za-z0-9_])"
)
_PROVIDER_ARTIFACT_RE = re.compile(
    r"(?i)(?:"
    r"(?<![A-Za-z0-9_])--[a-z][a-z0-9-]*"
    r"|(?<![A-Za-z0-9_])[A-Z]:[\\/]"
    r"|\\\\[^\\\s]+\\"
    r"|/(?:root|home|users|private|var|tmp|usr|opt|etc|srv|mnt|media)"
    r"(?:/|(?=$|\s))"
    r"|(?<![A-Za-z0-9_])~[\\/]"
    r"|(?<![A-Za-z0-9_])\.(?:claude|codex)[\\/]"
    r")"
)
_PROVIDER_URI_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_])"
    r"(?:claude|codex|openai|anthropic|chatgpt|"
    r"gpt(?:[-_.][A-Za-z0-9]+)*|opus|sonnet|haiku|gemini|llama|"
    r"mistral|grok)"
    r"(?![A-Za-z0-9_])"
)

_SECTION_ORDER = (
    "identity",
    "assignment",
    "methodology",
    "obligations",
    "inputs",
    "outputs",
    "completion",
)
_SECTION_HEADINGS = {
    "identity": "## Semantic identity",
    "assignment": "## Assignment",
    "methodology": "## Methodology",
    "obligations": "## Obligations",
    "inputs": "## Immutable inputs",
    "outputs": "## Assigned outputs",
    "completion": "## Completion",
}
_METHODOLOGY_KEYS = frozenset(
    {"logical_uri", "size_bytes", "content_sha256"}
)
_SECTION_KEYS = frozenset(
    {"section_id", "heading", "content", "content_sha256"}
)
_SNAPSHOT_KEYS = frozenset(
    {
        "schema",
        "semantic_work_unit_key",
        "plan_prompt_binding_digest",
        "role_id",
        "assignment_id",
        "semantic_template_id",
        "semantic_content",
        "methodology_files",
        "obligation_ids",
        "logical_input_uris",
        "logical_output_uris",
        "output_schema",
        "completion_language",
        "compiler_version",
        "compiler_code_digest",
        "prompt_encoding",
        "prompt_newline",
        "prompt_text",
        "prompt_size_bytes",
        "prompt_sha256",
        "sections",
        "snapshot_digest",
    }
)
_OVERLAY_KEYS = frozenset(
    {
        "schema",
        "snapshot_digest",
        "adapter_id",
        "stdin_mode",
        "stream_format",
        "completion_framing",
        "overlay_digest",
    }
)

_STDIN_MODES = frozenset({"PROMPT_UTF8"})
_STREAM_FORMATS = frozenset({"TEXT", "JSON", "JSONL"})
_COMPLETION_FRAMINGS = frozenset(
    {
        "TURN_END_OBSERVATION",
        "PROCESS_EXIT_OBSERVATION",
        "STREAM_EVENT_OBSERVATION",
    }
)


class PromptSnapshotError(ValueError):
    """Prompt or overlay data is ambiguous, open-ended, or digest-invalid."""


def _raise_as_prompt_error(exc: Exception) -> "NoReturn":  # type: ignore[name-defined]
    raise PromptSnapshotError(str(exc)) from exc


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        return canonical_json_bytes(value)
    except ProgramFactsTypeError as exc:
        _raise_as_prompt_error(exc)


def _canonical_file(value: Mapping[str, Any]) -> bytes:
    try:
        return canonical_file_bytes(value)
    except ProgramFactsTypeError as exc:
        _raise_as_prompt_error(exc)


def _decode_record(raw: bytes) -> Mapping[str, Any]:
    try:
        value = strict_json_loads(raw, require_final_lf=True)
    except ProgramFactsTypeError as exc:
        _raise_as_prompt_error(exc)
    if not isinstance(value, Mapping):
        raise PromptSnapshotError("record must be a JSON object")
    return value


def _require_exact_keys(
    value: Mapping[str, Any], expected: frozenset[str], context: str
) -> None:
    if not isinstance(value, Mapping):
        raise PromptSnapshotError(f"{context} must be an object")
    actual = set(value)
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    reasons: list[str] = []
    if missing:
        reasons.append("missing fields: " + ", ".join(missing))
    if extra:
        reasons.append("unexpected fields: " + ", ".join(extra))
    if reasons:
        raise PromptSnapshotError(f"{context} " + "; ".join(reasons))


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or _HEX64_RE.fullmatch(value) is None:
        raise PromptSnapshotError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _safe_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or _SAFE_ID_RE.fullmatch(value) is None:
        raise PromptSnapshotError(f"{field} must be an ASCII semantic token")
    if value in {".", ".."}:
        raise PromptSnapshotError(f"{field} cannot be a path segment")
    return value


def _text(value: Any, field: str, *, nonempty: bool = True) -> str:
    if not isinstance(value, str):
        raise PromptSnapshotError(f"{field} must be text")
    if nonempty and not value:
        raise PromptSnapshotError(f"{field} must not be empty")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise PromptSnapshotError(f"{field} must be valid UTF-8 text") from exc
    if "\x00" in value:
        raise PromptSnapshotError(f"{field} contains NUL")
    if "\r" in value:
        raise PromptSnapshotError(f"{field} must use LF newlines")
    return value


def _positive_or_zero_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PromptSnapshotError(f"{field} must be an integer")
    if value < 0:
        raise PromptSnapshotError(f"{field} must be non-negative")
    return value


def _closed_value(value: Any, allowed: frozenset[str], field: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise PromptSnapshotError(
            f"{field} must be one of {', '.join(sorted(allowed))}"
        )
    return value


def _provider_neutral_text(value: Any, field: str) -> str:
    text = _text(value, field)
    if _PROVIDER_LANGUAGE_RE.search(text) or _PROVIDER_ARTIFACT_RE.search(text):
        raise PromptSnapshotError(
            f"{field} must use provider-neutral language; "
            "provider/model/tool/transport and physical-host language "
            "are forbidden"
        )
    return text


def _registered_template_content(
    template_id: Any,
    *,
    registry: Mapping[str, str] = _SEMANTIC_TEMPLATE_REGISTRY,
) -> tuple[str, str]:
    """Resolve from the source-captured registry, not a rebindable export."""

    normalized = _closed_value(
        template_id,
        frozenset(registry),
        "semantic_template_id",
    )
    return normalized, registry[normalized]


def _logical_uri(
    value: Any,
    field: str,
    *,
    allowed_schemes: frozenset[str],
) -> str:
    if not isinstance(value, str):
        raise PromptSnapshotError(f"{field} logical_uri must be text")
    match = _LOGICAL_URI_RE.fullmatch(value)
    if match is None or match.group("scheme") not in allowed_schemes:
        raise PromptSnapshotError(
            f"{field} logical_uri must use an allowed logical scheme"
        )
    path = match.group("path")
    if _PROVIDER_URI_RE.search(value):
        raise PromptSnapshotError(
            f"{field} logical_uri contains provider/model identity"
        )
    segments = path.split("/")
    if any(segment in {"", ".", ".."} for segment in segments):
        raise PromptSnapshotError(
            f"{field} logical_uri contains an ambiguous path segment"
        )
    # The first segment is a logical authority, never a host.  Keep it
    # lowercase to avoid host/case ambiguity while preserving case-sensitive
    # source and methodology filenames in subsequent segments.
    if segments[0] != segments[0].lower():
        raise PromptSnapshotError(
            f"{field} logical_uri authority must be lowercase and host-independent"
        )
    return value


def _unique_sorted_ids(values: Iterable[Any], field: str) -> tuple[str, ...]:
    try:
        raw = tuple(values)
    except TypeError as exc:
        raise PromptSnapshotError(f"{field} must be an array") from exc
    result = tuple(sorted(_safe_id(value, field) for value in raw))
    if not result:
        raise PromptSnapshotError(f"{field} must not be empty")
    if len(result) != len(set(result)):
        raise PromptSnapshotError(f"{field} contains duplicate values")
    return result


def _unique_sorted_uris(
    values: Iterable[Any],
    field: str,
    allowed_schemes: frozenset[str],
) -> tuple[str, ...]:
    try:
        raw = tuple(values)
    except TypeError as exc:
        raise PromptSnapshotError(f"{field} must be an array") from exc
    result = tuple(
        sorted(
            _logical_uri(
                value,
                field,
                allowed_schemes=allowed_schemes,
            )
            for value in raw
        )
    )
    if not result:
        raise PromptSnapshotError(f"{field} must not be empty")
    if len(result) != len(set(result)):
        raise PromptSnapshotError(f"{field} contains duplicate logical URIs")
    return result


@dataclass(frozen=True, slots=True)
class MethodologyFileIdentity:
    """Content-addressed methodology identity without a physical host path."""

    logical_uri: str
    size_bytes: int
    content_sha256: str

    def __post_init__(self) -> None:
        _logical_uri(
            self.logical_uri,
            "methodology",
            allowed_schemes=frozenset({"methodology"}),
        )
        _positive_or_zero_int(self.size_bytes, "methodology.size_bytes")
        if self.size_bytes == 0:
            raise PromptSnapshotError(
                "methodology.size_bytes must be greater than zero"
            )
        _sha256(self.content_sha256, "methodology.content_sha256")

    def to_dict(self) -> dict[str, Any]:
        return {
            "logical_uri": self.logical_uri,
            "size_bytes": self.size_bytes,
            "content_sha256": self.content_sha256,
        }

    @classmethod
    def from_dict(
        cls, value: Mapping[str, Any]
    ) -> "MethodologyFileIdentity":
        _require_exact_keys(value, _METHODOLOGY_KEYS, "methodology file")
        return cls(
            logical_uri=value["logical_uri"],
            size_bytes=value["size_bytes"],
            content_sha256=value["content_sha256"],
        )

    @classmethod
    def capture(
        cls,
        *,
        logical_uri: str,
        content: bytes,
    ) -> "MethodologyFileIdentity":
        if not isinstance(content, bytes):
            raise PromptSnapshotError("methodology content must be bytes")
        if not content:
            raise PromptSnapshotError("methodology content must not be empty")
        return cls(
            logical_uri=logical_uri,
            size_bytes=len(content),
            content_sha256=_sha256_bytes(content),
        )


@dataclass(frozen=True, slots=True)
class SemanticPromptSection:
    """One fixed-order section and its exact UTF-8 content digest."""

    section_id: str
    heading: str
    content: str

    def __post_init__(self) -> None:
        if self.section_id not in _SECTION_ORDER:
            raise PromptSnapshotError("unknown semantic prompt section_id")
        expected_heading = _SECTION_HEADINGS[self.section_id]
        if self.heading != expected_heading:
            raise PromptSnapshotError(
                f"heading for {self.section_id} must be {expected_heading!r}"
            )
        _provider_neutral_text(self.content, f"section {self.section_id}")

    @property
    def content_sha256(self) -> str:
        return _sha256_bytes(self.content.encode(PROMPT_ENCODING))

    def to_dict(self) -> dict[str, Any]:
        return {
            "section_id": self.section_id,
            "heading": self.heading,
            "content": self.content,
            "content_sha256": self.content_sha256,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SemanticPromptSection":
        _require_exact_keys(value, _SECTION_KEYS, "semantic prompt section")
        claimed = _sha256(value["content_sha256"], "section.content_sha256")
        section = cls(
            section_id=value["section_id"],
            heading=value["heading"],
            content=value["content"],
        )
        if claimed != section.content_sha256:
            raise PromptSnapshotError("section content_sha256 digest mismatch")
        return section


def _coerce_methodologies(
    values: Iterable[MethodologyFileIdentity],
) -> tuple[MethodologyFileIdentity, ...]:
    try:
        raw = tuple(values)
    except TypeError as exc:
        raise PromptSnapshotError("methodology_files must be an array") from exc
    if not raw:
        raise PromptSnapshotError("methodology_files must not be empty")
    if not all(isinstance(item, MethodologyFileIdentity) for item in raw):
        raise PromptSnapshotError(
            "methodology_files entries must be MethodologyFileIdentity"
        )
    result = tuple(sorted(raw, key=lambda item: item.logical_uri))
    uris = tuple(item.logical_uri for item in result)
    if len(uris) != len(set(uris)):
        raise PromptSnapshotError(
            "methodology_files contains duplicate logical_uri"
        )
    return result


def capture_methodology_files(
    sources: Mapping[str, bytes],
) -> tuple[MethodologyFileIdentity, ...]:
    """Capture exact methodology bytes under logical, host-free identities."""

    if not isinstance(sources, Mapping) or not sources:
        raise PromptSnapshotError(
            "methodology_sources must be a nonempty mapping"
        )
    return _coerce_methodologies(
        MethodologyFileIdentity.capture(logical_uri=uri, content=content)
        for uri, content in sources.items()
    )


def methodology_bundle_digest(
    files: Iterable[MethodologyFileIdentity],
) -> str:
    captured = _coerce_methodologies(files)
    return _digest(
        {
            "schema": "plamen.methodology-bundle-binding.v1",
            "files": [item.to_dict() for item in captured],
        }
    )


def obligation_bundle_digest(obligation_ids: Iterable[str]) -> str:
    obligations = _unique_sorted_ids(obligation_ids, "obligation_ids")
    return _digest(
        {
            "schema": "plamen.obligation-bundle-binding.v1",
            "obligation_ids": list(obligations),
        }
    )


def semantic_input_manifest_digest(
    logical_input_uris: Iterable[str],
) -> str:
    inputs = _unique_sorted_uris(
        logical_input_uris,
        "logical_input_uris",
        frozenset({"workspace", "artifact"}),
    )
    return _digest(
        {
            "schema": "plamen.semantic-input-manifest.v1",
            "logical_input_uris": list(inputs),
        }
    )


def output_contract_digest(
    *,
    logical_output_uris: Iterable[str],
    output_schema: str,
    completion_language: str,
) -> str:
    outputs = _unique_sorted_uris(
        logical_output_uris,
        "logical_output_uris",
        frozenset({"artifact"}),
    )
    if not all(uri.startswith("artifact://output/") for uri in outputs):
        raise PromptSnapshotError(
            "logical_output_uris must be under artifact://output/"
        )
    return _digest(
        {
            "schema": "plamen.output-contract-binding.v1",
            "logical_output_uris": list(outputs),
            "output_schema": _safe_id(output_schema, "output_schema"),
            "completion_language": _provider_neutral_text(
                completion_language, "completion_language"
            ),
        }
    )


def compiler_source_digest(sources: Mapping[str, bytes]) -> str:
    """Digest exact logical compiler source bytes without physical paths."""

    if not isinstance(sources, Mapping) or not sources:
        raise PromptSnapshotError(
            "compiler_sources must be a nonempty mapping"
        )
    rows: list[dict[str, Any]] = []
    for logical_id, content in sources.items():
        _safe_id(logical_id, "compiler source logical_id")
        if not isinstance(content, bytes) or not content:
            raise PromptSnapshotError(
                "compiler source content must be nonempty bytes"
            )
        rows.append(
            {
                "logical_id": logical_id,
                "size_bytes": len(content),
                "content_sha256": _sha256_bytes(content),
            }
        )
    rows.sort(key=lambda row: row["logical_id"])
    if len({row["logical_id"] for row in rows}) != len(rows):
        raise PromptSnapshotError(
            "compiler_sources contains duplicate logical identities"
        )
    return _digest(
        {
            "schema": "plamen.semantic-prompt-compiler-sources.v1",
            "sources": rows,
        }
    )


def current_compiler_code_digest() -> str:
    """Digest the exact local source closure that determines prompt bytes."""

    root = Path(__file__).resolve().parent
    sources: dict[str, bytes] = {}
    for logical_id, filename in _COMPILER_CLOSURE_FILES:
        try:
            source_bytes = (root / filename).read_bytes()
        except OSError as exc:
            raise PromptSnapshotError(
                "semantic prompt compiler closure source bytes are "
                f"unavailable: {logical_id}"
            ) from exc
        if not source_bytes:
            raise PromptSnapshotError(
                "semantic prompt compiler closure source bytes are empty: "
                f"{logical_id}"
            )
        sources[logical_id] = source_bytes
    return compiler_source_digest(sources)


def _list_block(items: Iterable[str]) -> str:
    return "\n".join(f"- {item}" for item in items)


def _opaque_reference(kind: str, ordinal: int, value: str) -> str:
    """Render a stable alias and digest, never caller-controlled identifier text."""

    return (
        f"{kind}-{ordinal:04d} "
        f"identity_sha256={_sha256_bytes(value.encode('utf-8'))}"
    )


def _compile_sections(
    *,
    semantic_work_unit_key: str,
    plan_prompt_binding_digest: str,
    role_id: str,
    assignment_id: str,
    semantic_content: str,
    methodology_files: tuple[MethodologyFileIdentity, ...],
    obligation_ids: tuple[str, ...],
    logical_input_uris: tuple[str, ...],
    logical_output_uris: tuple[str, ...],
    output_schema: str,
    completion_language: str,
) -> tuple[SemanticPromptSection, ...]:
    content_by_id = {
        "identity": (
            f"semantic_work_unit_key: {semantic_work_unit_key}\n"
            "plan_prompt_binding_digest: "
            f"{plan_prompt_binding_digest}\n"
            "role_identity_sha256: "
            f"{_sha256_bytes(role_id.encode('utf-8'))}"
        ),
        "assignment": (
            "assignment_identity_sha256: "
            f"{_sha256_bytes(assignment_id.encode('utf-8'))}\n\n"
            f"{semantic_content}"
        ),
        "methodology": _list_block(
            (
                f"{_opaque_reference('methodology', index, item.logical_uri)} "
                f"bytes={item.size_bytes} "
                f"sha256={item.content_sha256}"
            )
            for index, item in enumerate(methodology_files, start=1)
        ),
        "obligations": _list_block(
            _opaque_reference("obligation", index, item)
            for index, item in enumerate(obligation_ids, start=1)
        ),
        "inputs": _list_block(
            _opaque_reference("input", index, item)
            for index, item in enumerate(logical_input_uris, start=1)
        ),
        "outputs": (
            "output_schema_identity_sha256: "
            f"{_sha256_bytes(output_schema.encode('utf-8'))}\n"
            + _list_block(
                _opaque_reference("output", index, item)
                for index, item in enumerate(
                    logical_output_uris, start=1
                )
            )
        ),
        "completion": completion_language,
    }
    return tuple(
        SemanticPromptSection(
            section_id=section_id,
            heading=_SECTION_HEADINGS[section_id],
            content=content_by_id[section_id],
        )
        for section_id in _SECTION_ORDER
    )


def _render_prompt(sections: tuple[SemanticPromptSection, ...]) -> str:
    parts = ["# Plamen semantic worker contract"]
    parts.extend(
        f"{section.heading}\n{section.content}" for section in sections
    )
    return "\n\n".join(parts).rstrip() + "\n"


@dataclass(frozen=True, slots=True)
class SemanticPromptSnapshot:
    """Immutable semantic prompt bytes and all compilation bindings."""

    semantic_work_unit_key: str
    plan_prompt_binding_digest: str
    role_id: str
    assignment_id: str
    semantic_template_id: str
    semantic_content: str
    methodology_files: tuple[MethodologyFileIdentity, ...]
    obligation_ids: tuple[str, ...]
    logical_input_uris: tuple[str, ...]
    logical_output_uris: tuple[str, ...]
    output_schema: str
    completion_language: str
    compiler_version: str
    compiler_code_digest: str
    sections: tuple[SemanticPromptSection, ...]
    prompt_text: str

    schema: ClassVar[str] = SEMANTIC_PROMPT_SNAPSHOT_SCHEMA
    prompt_encoding: ClassVar[str] = PROMPT_ENCODING
    prompt_newline: ClassVar[str] = PROMPT_NEWLINE

    def __post_init__(self) -> None:
        _sha256(self.semantic_work_unit_key, "semantic_work_unit_key")
        _sha256(
            self.plan_prompt_binding_digest,
            "plan_prompt_binding_digest",
        )
        _safe_id(self.role_id, "role_id")
        _safe_id(self.assignment_id, "assignment_id")
        template_id, registered_content = _registered_template_content(
            self.semantic_template_id
        )
        semantic_content = _provider_neutral_text(
            self.semantic_content, "semantic_content"
        )
        if semantic_content != registered_content:
            raise PromptSnapshotError(
                "semantic_content does not match semantic_template_id"
            )
        methodologies = _coerce_methodologies(self.methodology_files)
        obligations = _unique_sorted_ids(self.obligation_ids, "obligation_ids")
        inputs = _unique_sorted_uris(
            self.logical_input_uris,
            "logical_input_uris",
            frozenset({"workspace", "artifact"}),
        )
        outputs = _unique_sorted_uris(
            self.logical_output_uris,
            "logical_output_uris",
            frozenset({"artifact"}),
        )
        if not all(uri.startswith("artifact://output/") for uri in outputs):
            raise PromptSnapshotError(
                "logical_output_uris must be under artifact://output/"
            )
        output_schema = _safe_id(self.output_schema, "output_schema")
        completion = _provider_neutral_text(
            self.completion_language, "completion_language"
        )
        if completion != SEMANTIC_COMPLETION_LANGUAGE:
            raise PromptSnapshotError(
                "completion_language must use the registered semantic "
                "completion template"
            )
        compiler_version = _safe_id(
            self.compiler_version, "compiler_version"
        )
        if compiler_version != SEMANTIC_PROMPT_COMPILER_VERSION:
            raise PromptSnapshotError(
                "compiler_version must match the executing compiler"
            )
        _sha256(self.compiler_code_digest, "compiler_code_digest")

        expected_sections = _compile_sections(
            semantic_work_unit_key=self.semantic_work_unit_key,
            plan_prompt_binding_digest=self.plan_prompt_binding_digest,
            role_id=self.role_id,
            assignment_id=self.assignment_id,
            semantic_content=semantic_content,
            methodology_files=methodologies,
            obligation_ids=obligations,
            logical_input_uris=inputs,
            logical_output_uris=outputs,
            output_schema=output_schema,
            completion_language=completion,
        )
        supplied_sections = tuple(self.sections)
        if supplied_sections != expected_sections:
            raise PromptSnapshotError(
                "sections do not match canonical semantic compilation"
            )
        expected_prompt = _render_prompt(expected_sections)
        if self.prompt_text != expected_prompt:
            raise PromptSnapshotError(
                "prompt_text does not match canonical semantic sections"
            )
        _provider_neutral_text(self.prompt_text, "prompt_text")

        object.__setattr__(self, "semantic_content", semantic_content)
        object.__setattr__(self, "semantic_template_id", template_id)
        object.__setattr__(self, "methodology_files", methodologies)
        object.__setattr__(self, "obligation_ids", obligations)
        object.__setattr__(self, "logical_input_uris", inputs)
        object.__setattr__(self, "logical_output_uris", outputs)
        object.__setattr__(self, "output_schema", output_schema)
        object.__setattr__(self, "completion_language", completion)
        object.__setattr__(self, "compiler_version", compiler_version)
        object.__setattr__(self, "sections", expected_sections)

    @property
    def prompt_bytes(self) -> bytes:
        return self.prompt_text.encode(PROMPT_ENCODING)

    @property
    def prompt_size_bytes(self) -> int:
        return len(self.prompt_bytes)

    @property
    def prompt_sha256(self) -> str:
        return _sha256_bytes(self.prompt_bytes)

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "semantic_work_unit_key": self.semantic_work_unit_key,
            "plan_prompt_binding_digest": self.plan_prompt_binding_digest,
            "role_id": self.role_id,
            "assignment_id": self.assignment_id,
            "semantic_template_id": self.semantic_template_id,
            "semantic_content": self.semantic_content,
            "methodology_files": [
                item.to_dict() for item in self.methodology_files
            ],
            "obligation_ids": list(self.obligation_ids),
            "logical_input_uris": list(self.logical_input_uris),
            "logical_output_uris": list(self.logical_output_uris),
            "output_schema": self.output_schema,
            "completion_language": self.completion_language,
            "compiler_version": self.compiler_version,
            "compiler_code_digest": self.compiler_code_digest,
            "prompt_encoding": self.prompt_encoding,
            "prompt_newline": self.prompt_newline,
            "prompt_text": self.prompt_text,
            "prompt_size_bytes": self.prompt_size_bytes,
            "prompt_sha256": self.prompt_sha256,
            "sections": [section.to_dict() for section in self.sections],
        }

    @property
    def snapshot_digest(self) -> str:
        return _digest(self._unsigned_dict())

    def to_dict(self) -> dict[str, Any]:
        return {**self._unsigned_dict(), "snapshot_digest": self.snapshot_digest}

    def to_bytes(self) -> bytes:
        return _canonical_file(self.to_dict())

    @classmethod
    def from_dict(
        cls, value: Mapping[str, Any]
    ) -> "SemanticPromptSnapshot":
        _require_exact_keys(value, _SNAPSHOT_KEYS, "semantic prompt snapshot")
        if value["schema"] != SEMANTIC_PROMPT_SNAPSHOT_SCHEMA:
            raise PromptSnapshotError(
                "unsupported semantic prompt snapshot schema"
            )
        if value["prompt_encoding"] != PROMPT_ENCODING:
            raise PromptSnapshotError("prompt_encoding must be utf-8")
        if value["prompt_newline"] != PROMPT_NEWLINE:
            raise PromptSnapshotError("prompt_newline must be LF")
        claimed_snapshot = _sha256(value["snapshot_digest"], "snapshot_digest")
        claimed_prompt = _sha256(value["prompt_sha256"], "prompt_sha256")
        methodologies = tuple(
            MethodologyFileIdentity.from_dict(item)
            for item in value["methodology_files"]
        )
        sections = tuple(
            SemanticPromptSection.from_dict(item) for item in value["sections"]
        )
        snapshot = cls(
            semantic_work_unit_key=value["semantic_work_unit_key"],
            plan_prompt_binding_digest=value[
                "plan_prompt_binding_digest"
            ],
            role_id=value["role_id"],
            assignment_id=value["assignment_id"],
            semantic_template_id=value["semantic_template_id"],
            semantic_content=value["semantic_content"],
            methodology_files=methodologies,
            obligation_ids=tuple(value["obligation_ids"]),
            logical_input_uris=tuple(value["logical_input_uris"]),
            logical_output_uris=tuple(value["logical_output_uris"]),
            output_schema=value["output_schema"],
            completion_language=value["completion_language"],
            compiler_version=value["compiler_version"],
            compiler_code_digest=value["compiler_code_digest"],
            sections=sections,
            prompt_text=value["prompt_text"],
        )
        if value["prompt_size_bytes"] != snapshot.prompt_size_bytes:
            raise PromptSnapshotError("prompt_size_bytes mismatch")
        if claimed_prompt != snapshot.prompt_sha256:
            raise PromptSnapshotError("prompt_sha256 digest mismatch")
        if claimed_snapshot != snapshot.snapshot_digest:
            raise PromptSnapshotError("snapshot_digest digest mismatch")
        return snapshot

    @classmethod
    def from_bytes(cls, raw: bytes) -> "SemanticPromptSnapshot":
        return cls.from_dict(_decode_record(raw))


@dataclass(frozen=True, slots=True)
class SemanticPlanPromptBundle:
    """A fully replayed, acyclic plan/snapshot authority pair.

    A caller-supplied 64-hex ``plan_prompt_binding_digest`` is never
    authority by itself.
    Both typed objects are round-tripped through their strict decoders before
    the two content-addressed edges and shared semantic identities are
    accepted.
    """

    plan: SemanticWorkPlan
    snapshot: SemanticPromptSnapshot

    def __post_init__(self) -> None:
        if not isinstance(self.plan, SemanticWorkPlan):
            raise PromptSnapshotError("plan must be SemanticWorkPlan")
        if not isinstance(self.snapshot, SemanticPromptSnapshot):
            raise PromptSnapshotError(
                "snapshot must be SemanticPromptSnapshot"
            )
        try:
            plan = SemanticWorkPlan.from_bytes(self.plan.to_bytes())
        except SemanticSchemaError as exc:
            raise PromptSnapshotError(
                "semantic plan failed strict replay"
            ) from exc
        snapshot = SemanticPromptSnapshot.from_bytes(self.snapshot.to_bytes())
        if snapshot.semantic_work_unit_key != plan.semantic_work_unit_key:
            raise PromptSnapshotError(
                "snapshot semantic_work_unit_key does not match plan"
            )
        if (
            snapshot.plan_prompt_binding_digest
            != plan.prompt_binding_digest
        ):
            raise PromptSnapshotError(
                "snapshot plan_prompt_binding_digest does not match plan "
                "prompt binding"
            )
        if plan.semantic_prompt_snapshot_digest != snapshot.snapshot_digest:
            raise PromptSnapshotError(
                "plan semantic_prompt_snapshot_digest does not match snapshot"
            )
        if (
            methodology_bundle_digest(snapshot.methodology_files)
            != plan.methodology_bundle_digest
        ):
            raise PromptSnapshotError(
                "snapshot methodology files do not match plan"
            )
        if (
            obligation_bundle_digest(snapshot.obligation_ids)
            != plan.obligation_bundle_digest
        ):
            raise PromptSnapshotError(
                "snapshot obligation IDs do not match plan"
            )
        if (
            semantic_input_manifest_digest(snapshot.logical_input_uris)
            != plan.semantic_input_manifest_digest
        ):
            raise PromptSnapshotError(
                "snapshot logical inputs do not match plan"
            )
        if (
            output_contract_digest(
                logical_output_uris=snapshot.logical_output_uris,
                output_schema=snapshot.output_schema,
                completion_language=snapshot.completion_language,
            )
            != plan.output_contract_digest
        ):
            raise PromptSnapshotError(
                "snapshot output contract does not match plan"
            )
        if snapshot.compiler_code_digest != current_compiler_code_digest():
            raise PromptSnapshotError(
                "snapshot compiler_code_digest does not match current "
                "compiler source"
            )
        if snapshot.role_id != plan.role_id:
            raise PromptSnapshotError("snapshot role_id does not match plan")
        if snapshot.assignment_id != plan.assignment_id:
            raise PromptSnapshotError(
                "snapshot assignment_id does not match plan"
            )
        if snapshot.semantic_template_id != plan.semantic_template_id:
            raise PromptSnapshotError(
                "snapshot semantic_template_id does not match plan"
            )
        object.__setattr__(self, "plan", plan)
        object.__setattr__(self, "snapshot", snapshot)

    @property
    def bundle_digest(self) -> str:
        return _digest(
            {
                "schema": "plamen.semantic-plan-prompt-bundle.v1",
                "semantic_digest": self.plan.semantic_digest,
                "snapshot_digest": self.snapshot.snapshot_digest,
            }
        )


@dataclass(frozen=True, slots=True)
class SemanticSnapshotTransportBundle:
    """Strictly bind a transport-only overlay to one prompt snapshot."""

    plan_prompt_bundle: SemanticPlanPromptBundle
    overlay: "TransportOverlay"

    def __post_init__(self) -> None:
        if not isinstance(
            self.plan_prompt_bundle, SemanticPlanPromptBundle
        ):
            raise PromptSnapshotError(
                "plan_prompt_bundle must be SemanticPlanPromptBundle"
            )
        if not isinstance(self.overlay, TransportOverlay):
            raise PromptSnapshotError("overlay must be TransportOverlay")
        bound = SemanticPlanPromptBundle(
            plan=self.plan_prompt_bundle.plan,
            snapshot=self.plan_prompt_bundle.snapshot,
        )
        overlay = TransportOverlay.from_bytes(self.overlay.to_bytes())
        if overlay.snapshot_digest != bound.snapshot.snapshot_digest:
            raise PromptSnapshotError(
                "overlay snapshot_digest does not match snapshot"
            )
        object.__setattr__(self, "plan_prompt_bundle", bound)
        object.__setattr__(self, "overlay", overlay)

    @property
    def snapshot(self) -> SemanticPromptSnapshot:
        return self.plan_prompt_bundle.snapshot


def _compile_semantic_prompt_snapshot_unbound(
    *,
    semantic_work_unit_key: str,
    plan_prompt_binding_digest: str,
    role_id: str,
    assignment_id: str,
    semantic_template_id: str,
    semantic_content: str,
    methodology_files: Iterable[MethodologyFileIdentity],
    obligation_ids: Iterable[str],
    logical_input_uris: Iterable[str],
    logical_output_uris: Iterable[str],
    output_schema: str,
    completion_language: str,
    compiler_version: str,
    compiler_code_digest: str,
) -> SemanticPromptSnapshot:
    """Internal compiler after a typed plan has supplied all identities."""

    methodologies = _coerce_methodologies(methodology_files)
    obligations = _unique_sorted_ids(obligation_ids, "obligation_ids")
    inputs = _unique_sorted_uris(
        logical_input_uris,
        "logical_input_uris",
        frozenset({"workspace", "artifact"}),
    )
    outputs = _unique_sorted_uris(
        logical_output_uris,
        "logical_output_uris",
        frozenset({"artifact"}),
    )
    content = _provider_neutral_text(semantic_content, "semantic_content")
    completion = _provider_neutral_text(
        completion_language, "completion_language"
    )
    sections = _compile_sections(
        semantic_work_unit_key=_sha256(
            semantic_work_unit_key, "semantic_work_unit_key"
        ),
        plan_prompt_binding_digest=_sha256(
            plan_prompt_binding_digest,
            "plan_prompt_binding_digest",
        ),
        role_id=_safe_id(role_id, "role_id"),
        assignment_id=_safe_id(assignment_id, "assignment_id"),
        semantic_content=content,
        methodology_files=methodologies,
        obligation_ids=obligations,
        logical_input_uris=inputs,
        logical_output_uris=outputs,
        output_schema=_safe_id(output_schema, "output_schema"),
        completion_language=completion,
    )
    return SemanticPromptSnapshot(
        semantic_work_unit_key=semantic_work_unit_key,
        plan_prompt_binding_digest=plan_prompt_binding_digest,
        role_id=role_id,
        assignment_id=assignment_id,
        semantic_template_id=semantic_template_id,
        semantic_content=content,
        methodology_files=methodologies,
        obligation_ids=obligations,
        logical_input_uris=inputs,
        logical_output_uris=outputs,
        output_schema=output_schema,
        completion_language=completion,
        compiler_version=compiler_version,
        compiler_code_digest=compiler_code_digest,
        sections=sections,
        prompt_text=_render_prompt(sections),
    )


def compile_semantic_prompt_snapshot(
    *,
    plan: SemanticWorkPlan,
    methodology_sources: Mapping[str, bytes],
    obligation_ids: Iterable[str],
    logical_input_uris: Iterable[str],
    logical_output_uris: Iterable[str],
    output_schema: str,
) -> SemanticPromptSnapshot:
    """Compile exact provider-neutral bytes from a strictly replayed plan.

    Backend, model, transport, and caller-supplied identity digests are not
    accepted by this public authority boundary.
    """

    if not isinstance(plan, SemanticWorkPlan):
        raise PromptSnapshotError("plan must be SemanticWorkPlan")
    try:
        plan = SemanticWorkPlan.from_bytes(plan.to_bytes())
    except SemanticSchemaError as exc:
        raise PromptSnapshotError("semantic plan failed strict replay") from exc
    methodology_files = capture_methodology_files(methodology_sources)
    template_id, template_content = _registered_template_content(
        plan.semantic_template_id
    )
    if methodology_bundle_digest(methodology_files) != plan.methodology_bundle_digest:
        raise PromptSnapshotError(
            "methodology sources do not match plan methodology_bundle_digest"
        )
    if obligation_bundle_digest(obligation_ids) != plan.obligation_bundle_digest:
        raise PromptSnapshotError(
            "obligation IDs do not match plan obligation_bundle_digest"
        )
    if (
        semantic_input_manifest_digest(logical_input_uris)
        != plan.semantic_input_manifest_digest
    ):
        raise PromptSnapshotError(
            "logical inputs do not match plan semantic_input_manifest_digest"
        )
    if (
        output_contract_digest(
            logical_output_uris=logical_output_uris,
            output_schema=output_schema,
            completion_language=SEMANTIC_COMPLETION_LANGUAGE,
        )
        != plan.output_contract_digest
    ):
        raise PromptSnapshotError(
            "outputs do not match plan output_contract_digest"
        )
    return _compile_semantic_prompt_snapshot_unbound(
        semantic_work_unit_key=plan.semantic_work_unit_key,
        plan_prompt_binding_digest=plan.prompt_binding_digest,
        role_id=plan.role_id,
        assignment_id=plan.assignment_id,
        semantic_template_id=template_id,
        semantic_content=template_content,
        methodology_files=methodology_files,
        obligation_ids=obligation_ids,
        logical_input_uris=logical_input_uris,
        logical_output_uris=logical_output_uris,
        output_schema=output_schema,
        completion_language=SEMANTIC_COMPLETION_LANGUAGE,
        compiler_version=SEMANTIC_PROMPT_COMPILER_VERSION,
        compiler_code_digest=current_compiler_code_digest(),
    )


def bind_semantic_prompt_snapshot(
    plan: SemanticWorkPlan,
    snapshot: SemanticPromptSnapshot,
) -> SemanticPlanPromptBundle:
    """Return the final plan/snapshot pair with both digest edges closed."""

    if not isinstance(plan, SemanticWorkPlan):
        raise PromptSnapshotError("plan must be SemanticWorkPlan")
    if not isinstance(snapshot, SemanticPromptSnapshot):
        raise PromptSnapshotError("snapshot must be SemanticPromptSnapshot")
    try:
        plan = SemanticWorkPlan.from_bytes(plan.to_bytes())
    except SemanticSchemaError as exc:
        raise PromptSnapshotError("semantic plan failed strict replay") from exc
    snapshot = SemanticPromptSnapshot.from_bytes(snapshot.to_bytes())
    if snapshot.plan_prompt_binding_digest != plan.prompt_binding_digest:
        raise PromptSnapshotError(
            "snapshot plan_prompt_binding_digest does not match plan"
        )
    if snapshot.semantic_work_unit_key != plan.semantic_work_unit_key:
        raise PromptSnapshotError(
            "snapshot semantic_work_unit_key does not match plan"
        )
    bound = replace(
        plan,
        semantic_prompt_snapshot_digest=snapshot.snapshot_digest,
    )
    return SemanticPlanPromptBundle(plan=bound, snapshot=snapshot)


@dataclass(frozen=True, slots=True)
class TransportOverlay:
    """Transport-only framing bound to immutable semantic snapshot bytes."""

    snapshot_digest: str
    adapter_id: str
    stdin_mode: str
    stream_format: str
    completion_framing: str

    schema: ClassVar[str] = TRANSPORT_OVERLAY_SCHEMA

    def __post_init__(self) -> None:
        _sha256(self.snapshot_digest, "snapshot_digest")
        _safe_id(self.adapter_id, "adapter_id")
        _closed_value(self.stdin_mode, _STDIN_MODES, "stdin_mode")
        _closed_value(self.stream_format, _STREAM_FORMATS, "stream_format")
        _closed_value(
            self.completion_framing,
            _COMPLETION_FRAMINGS,
            "completion_framing",
        )

    @classmethod
    def create(
        cls,
        *,
        snapshot_digest: str,
        adapter_id: str,
        stdin_mode: str,
        stream_format: str,
        completion_framing: str,
    ) -> "TransportOverlay":
        return cls(
            snapshot_digest=snapshot_digest,
            adapter_id=adapter_id,
            stdin_mode=stdin_mode,
            stream_format=stream_format,
            completion_framing=completion_framing,
        )

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "snapshot_digest": self.snapshot_digest,
            "adapter_id": self.adapter_id,
            "stdin_mode": self.stdin_mode,
            "stream_format": self.stream_format,
            "completion_framing": self.completion_framing,
        }

    @property
    def overlay_digest(self) -> str:
        return _digest(self._unsigned_dict())

    def to_dict(self) -> dict[str, Any]:
        return {**self._unsigned_dict(), "overlay_digest": self.overlay_digest}

    def to_bytes(self) -> bytes:
        return _canonical_file(self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "TransportOverlay":
        _require_exact_keys(value, _OVERLAY_KEYS, "transport overlay")
        if value["schema"] != TRANSPORT_OVERLAY_SCHEMA:
            raise PromptSnapshotError("unsupported transport overlay schema")
        claimed = _sha256(value["overlay_digest"], "overlay_digest")
        overlay = cls(
            snapshot_digest=value["snapshot_digest"],
            adapter_id=value["adapter_id"],
            stdin_mode=value["stdin_mode"],
            stream_format=value["stream_format"],
            completion_framing=value["completion_framing"],
        )
        if claimed != overlay.overlay_digest:
            raise PromptSnapshotError("overlay_digest digest mismatch")
        return overlay

    @classmethod
    def from_bytes(cls, raw: bytes) -> "TransportOverlay":
        return cls.from_dict(_decode_record(raw))


__all__ = [
    "MethodologyFileIdentity",
    "PROMPT_ENCODING",
    "PROMPT_NEWLINE",
    "PromptSnapshotError",
    "SEMANTIC_PROMPT_SNAPSHOT_SCHEMA",
    "SEMANTIC_PROMPT_COMPILER_VERSION",
    "SEMANTIC_COMPLETION_LANGUAGE",
    "SEMANTIC_TEMPLATES",
    "SemanticPlanPromptBundle",
    "SemanticPromptSection",
    "SemanticPromptSnapshot",
    "SemanticSnapshotTransportBundle",
    "TRANSPORT_OVERLAY_SCHEMA",
    "TransportOverlay",
    "bind_semantic_prompt_snapshot",
    "capture_methodology_files",
    "compiler_source_digest",
    "compile_semantic_prompt_snapshot",
    "current_compiler_code_digest",
    "methodology_bundle_digest",
    "obligation_bundle_digest",
    "output_contract_digest",
    "semantic_input_manifest_digest",
]
