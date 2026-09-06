"""Strict, bounded evidence parser for Claude CLI ``stream-json`` stdout.

This module parses evidence; it does not authenticate its producer.  In
particular, a successful parse must remain only one conjunct in a completion
decision that also proves the launched executable, normal process-tree closure,
and stable parser-valid assigned outputs.

The supported protocol intentionally assumes Claude CLI print mode without
``--include-partial-messages``.  Its grammar is:

    system/init, zero or more supported non-result events, result/success,
    zero or more documented trailing prompt_suggestion events, EOF

Every JSON text is terminated by LF.  A partial final line is never accepted.
Current Anthropic documentation says a small number of system events, such as
``prompt_suggestion``, may follow ``result``.  Completion is therefore decided
only at exact EOF; the parser does not stop reading when it sees ``result``.

Protocol assumptions are pinned to Anthropic's "Run Claude Code
programmatically" and Agent SDK message references (``code.claude.com``).
Those sources document ``system/api_retry`` and warn that synchronous plugin
installation plus SessionStart/Setup hooks can emit events before
``system/init``.  This parser intentionally rejects every pre-init event:
Plamen's isolated launch profile must suppress those startup side effects, and
their appearance is configuration drift rather than an alternate valid order.

The CLI headless contract does not require ``stop_reason`` or
``terminal_reason`` on its final result JSON.  They are therefore optional
diagnostics here.  The ordinary terminal semantic basis is the conjunction of
a final root assistant ``end_turn`` and a root ``result/success`` row.  Claude
Code 2.1.252 is additionally pinned to its observed final-envelope shape: a
same-session root assistant with non-empty text and a null ``stop_reason``,
followed by the successful root result.  Neither row is sufficient alone.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
from typing import Any, Mapping


EVIDENCE_SCHEMA = "plamen.claude-stream-json-evidence/v1"
PROVIDER_PROTOCOL = "claude-cli-stream-json/no-partials/v1"
PRODUCER_EXCLUSIVITY = "NOT_ESTABLISHED_BY_PARSER"
EXPECTED_INIT_SCHEMA = "plamen.claude-expected-init/v1"
EXPECTED_INIT_SECURITY_SCHEMA = "plamen.claude-expected-init/v2"

RESTRICTED_ANALYSIS_CAPABILITY = "vendor-restricted-analysis"
RESTRICTED_WEB_ANALYSIS_CAPABILITY = "vendor-restricted-web-analysis"
REVIEWED_RESTRICTED_INIT_VERSION = "2.1.252"
REVIEWED_RESTRICTED_INIT_AGENTS = tuple(
    sorted(("claude", "Explore", "general-purpose", "Plan", "statusline-setup"))
)
REVIEWED_RESTRICTED_INIT_CAPABILITIES = tuple(
    sorted(
        (
            "interrupt_receipt_v1",
            "interrupt_cancel_queued_v1",
            "msg_lifecycle_v1",
        )
    )
)
REVIEWED_RESTRICTED_INIT_TOOLS = tuple(
    sorted(("Edit", "Glob", "Grep", "Read", "Write"))
)
REVIEWED_RESTRICTED_WEB_INIT_TOOLS = tuple(
    sorted(("Edit", "Glob", "Grep", "Read", "WebFetch", "WebSearch", "Write"))
)
REVIEWED_RESTRICTED_WEB_AUXILIARY_USAGE_MODELS = (
    "claude-haiku-4-5-20251001",
)
_REVIEWED_RESTRICTED_CAPABILITIES = frozenset(
    {RESTRICTED_ANALYSIS_CAPABILITY, RESTRICTED_WEB_ANALYSIS_CAPABILITY}
)

DEFAULT_MAX_LINE_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_STREAM_BYTES = 64 * 1024 * 1024
HARD_MAX_LINE_BYTES = 16 * 1024 * 1024
HARD_MAX_STREAM_BYTES = 512 * 1024 * 1024

_SYSTEM_AUXILIARY_SUBTYPES = frozenset(
    {
        "api_retry",
        "background_tasks_changed",
        "commands_changed",
        "compact_boundary",
        "files_persisted",
        "hook_progress",
        "hook_response",
        "hook_started",
        "informational",
        "local_command_output",
        "permission_denied",
        "plugin_install",
        "session_state_changed",
        "status",
        "task_notification",
        "task_progress",
        "task_started",
        "task_updated",
        "thinking_tokens",
        "worker_shutting_down",
    }
)

# These are the documented non-core SDK/CLI event envelopes for the pinned
# protocol family.  Unknown types fail closed rather than being treated as
# harmless progress.
_AUXILIARY_EVENT_TYPES = frozenset(
    {
        "auth_status",
        "conversation_reset",
        "elicitation_complete",
        "memory_recall",
        "mirror_error",
        "notification",
        "prompt_suggestion",
        "rate_limit_event",
        "tool_progress",
        "tool_use_summary",
    }
)

_PARENT_ATTRIBUTED_TYPES = frozenset({"assistant", "user", "tool_progress"})


class ClaudeStreamJsonEvidenceError(ValueError):
    """The provider stream is not valid proof input for the pinned protocol."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _fail(code: str, message: str) -> None:
    raise ClaudeStreamJsonEvidenceError(code, message)


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            _fail("JSON_DUPLICATE_KEY", f"duplicate object key {key!r}")
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    _fail("JSON_NONFINITE_NUMBER", f"unsupported JSON constant {value!r}")


def _finite_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:  # pragma: no cover - json has already tokenized it
        raise ClaudeStreamJsonEvidenceError(
            "JSON_NUMBER_INVALID", "JSON number is invalid"
        ) from exc
    if not math.isfinite(parsed):
        _fail("JSON_NONFINITE_NUMBER", "JSON number overflows finite range")
    return parsed


def _enforce_json_structure_and_unicode(value: Any) -> None:
    """Bound traversal depth/items and reject Unicode scalar violations."""

    stack: list[tuple[Any, int]] = [(value, 0)]
    observed = 0
    while stack:
        item, depth = stack.pop()
        observed += 1
        if observed > 100_000 or depth > 128:
            _fail(
                "JSON_STRUCTURE_BUDGET",
                "JSON structure exceeds its depth or item budget",
            )
        if isinstance(item, str):
            if any(0xD800 <= ord(character) <= 0xDFFF for character in item):
                _fail(
                    "JSON_UNICODE_INVALID",
                    "JSON contains an unpaired surrogate",
                )
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
        elif isinstance(item, dict):
            for key, child in item.items():
                stack.append((key, depth + 1))
                stack.append((child, depth + 1))


def _load_object(raw_line: bytes) -> dict[str, Any]:
    if not raw_line:
        _fail("NDJSON_EMPTY_LINE", "empty JSONL rows are unsupported")
    try:
        text = raw_line.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ClaudeStreamJsonEvidenceError(
            "NDJSON_UTF8_INVALID", "row is not strict UTF-8"
        ) from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
    except ClaudeStreamJsonEvidenceError:
        raise
    except RecursionError as exc:
        raise ClaudeStreamJsonEvidenceError(
            "JSON_STRUCTURE_BUDGET",
            "JSON decoder recursion budget was exceeded",
        ) from exc
    except (json.JSONDecodeError, ValueError) as exc:
        raise ClaudeStreamJsonEvidenceError(
            "NDJSON_JSON_INVALID", "row is not strict JSON"
        ) from exc
    if not isinstance(value, dict):
        _fail("NDJSON_ROW_NOT_OBJECT", "every JSONL row must be an object")
    _enforce_json_structure_and_unicode(value)
    return value


def _nonempty_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        _fail("EVENT_FIELD_INVALID", f"{label} must be a non-empty string")
    return value


def _nonnegative_int(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        _fail("EVENT_FIELD_INVALID", f"{label} must be a non-negative integer")
    return value


def _finite_nonnegative_number(value: Any, label: str) -> int | float:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(value)
        or value < 0
    ):
        _fail("EVENT_FIELD_INVALID", f"{label} must be finite and non-negative")
    return value


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _unique_string_list(value: Any, label: str) -> list[str]:
    if (
        not isinstance(value, list)
        or any(not isinstance(item, str) or not item for item in value)
        or len(set(value)) != len(value)
    ):
        _fail("CONFIG_INVALID", f"{label} must be a unique string array")
    return sorted(value)


def _object_list(value: Any, label: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or any(
        not isinstance(item, dict) for item in value
    ):
        _fail("CONFIG_INVALID", f"{label} must be an object array")
    normalized = [dict(item) for item in value]
    normalized.sort(key=lambda item: _canonical_json(item))
    return normalized


def _normalize_expected_init_v1(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    fields = {
        "schema",
        "claude_code_version",
        "cwd",
        "accepted_models",
        "permission_mode",
        "expected_tools",
        "expected_mcp_servers",
        "expected_plugins",
        "expected_skills",
        "expected_agents",
        "accepted_api_key_sources",
        "required_capabilities",
        "expected_slash_commands",
        "expected_output_style",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        _fail("CONFIG_INVALID", "expected init contract has schema drift")
    if value.get("schema") != EXPECTED_INIT_SCHEMA:
        _fail("CONFIG_INVALID", "expected init contract schema is unsupported")
    result = {
        "schema": EXPECTED_INIT_SCHEMA,
        "claude_code_version": _nonempty_string(
            value.get("claude_code_version"),
            "expected_init.claude_code_version",
        ),
        "cwd": _nonempty_string(value.get("cwd"), "expected_init.cwd"),
        "accepted_models": _unique_string_list(
            value.get("accepted_models"),
            "expected_init.accepted_models",
        ),
        "permission_mode": _nonempty_string(
            value.get("permission_mode"),
            "expected_init.permission_mode",
        ),
        "expected_tools": _unique_string_list(
            value.get("expected_tools"),
            "expected_init.expected_tools",
        ),
        "expected_mcp_servers": _object_list(
            value.get("expected_mcp_servers"),
            "expected_init.expected_mcp_servers",
        ),
        "expected_plugins": _object_list(
            value.get("expected_plugins"),
            "expected_init.expected_plugins",
        ),
        "expected_skills": _unique_string_list(
            value.get("expected_skills"),
            "expected_init.expected_skills",
        ),
        "expected_agents": _unique_string_list(
            value.get("expected_agents"),
            "expected_init.expected_agents",
        ),
        "accepted_api_key_sources": _unique_string_list(
            value.get("accepted_api_key_sources"),
            "expected_init.accepted_api_key_sources",
        ),
        "required_capabilities": _unique_string_list(
            value.get("required_capabilities"),
            "expected_init.required_capabilities",
        ),
        "expected_slash_commands": _unique_string_list(
            value.get("expected_slash_commands"),
            "expected_init.expected_slash_commands",
        ),
        "expected_output_style": _nonempty_string(
            value.get("expected_output_style"),
            "expected_init.expected_output_style",
        ),
    }
    if not result["accepted_models"]:
        _fail("CONFIG_INVALID", "expected init accepts no model")
    if not result["accepted_api_key_sources"]:
        _fail("CONFIG_INVALID", "expected init accepts no auth source")
    return result


def _normalize_expected_init_v2(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Normalize a fail-closed capability policy for current Claude init.

    V1 compares the complete tool list exactly.  That remains useful for a
    fully pinned provider fixture, but it is too brittle for an MCP-enabled
    production launch: MCP tool names are discovered only after connecting to
    the already-bound server configuration.  V2 therefore permits an exact
    built-in denominator plus the single documented ``mcp__`` namespace, and
    separately binds the allowed/required MCP server names.  Every other
    observed tool is rejected.
    """

    fields = {
        "schema",
        "claude_code_version",
        "cwd",
        "accepted_models",
        "permission_mode",
        "allowed_tools",
        "allowed_tool_prefixes",
        "required_tools",
        "forbidden_tools",
        "allowed_mcp_servers",
        "required_mcp_servers",
        "expected_plugins",
        "expected_skills",
        "expected_agents",
        "accepted_api_key_sources",
        "required_capabilities",
        "expected_native_capabilities",
        "forbidden_capabilities",
        "expected_slash_commands",
        "accepted_output_styles",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        _fail("CONFIG_INVALID", "expected init v2 contract has schema drift")
    if value.get("schema") != EXPECTED_INIT_SECURITY_SCHEMA:
        _fail("CONFIG_INVALID", "expected init v2 schema is unsupported")
    result = {
        "schema": EXPECTED_INIT_SECURITY_SCHEMA,
        "claude_code_version": _nonempty_string(
            value.get("claude_code_version"),
            "expected_init.claude_code_version",
        ),
        "cwd": _nonempty_string(value.get("cwd"), "expected_init.cwd"),
        "accepted_models": _unique_string_list(
            value.get("accepted_models"),
            "expected_init.accepted_models",
        ),
        "permission_mode": _nonempty_string(
            value.get("permission_mode"),
            "expected_init.permission_mode",
        ),
        "allowed_tools": _unique_string_list(
            value.get("allowed_tools"),
            "expected_init.allowed_tools",
        ),
        "allowed_tool_prefixes": _unique_string_list(
            value.get("allowed_tool_prefixes"),
            "expected_init.allowed_tool_prefixes",
        ),
        "required_tools": _unique_string_list(
            value.get("required_tools"),
            "expected_init.required_tools",
        ),
        "forbidden_tools": _unique_string_list(
            value.get("forbidden_tools"),
            "expected_init.forbidden_tools",
        ),
        "allowed_mcp_servers": _unique_string_list(
            value.get("allowed_mcp_servers"),
            "expected_init.allowed_mcp_servers",
        ),
        "required_mcp_servers": _unique_string_list(
            value.get("required_mcp_servers"),
            "expected_init.required_mcp_servers",
        ),
        "expected_plugins": _object_list(
            value.get("expected_plugins"),
            "expected_init.expected_plugins",
        ),
        "expected_skills": _unique_string_list(
            value.get("expected_skills"),
            "expected_init.expected_skills",
        ),
        "expected_agents": _unique_string_list(
            value.get("expected_agents"),
            "expected_init.expected_agents",
        ),
        "accepted_api_key_sources": _unique_string_list(
            value.get("accepted_api_key_sources"),
            "expected_init.accepted_api_key_sources",
        ),
        "required_capabilities": _unique_string_list(
            value.get("required_capabilities"),
            "expected_init.required_capabilities",
        ),
        "expected_native_capabilities": _unique_string_list(
            value.get("expected_native_capabilities"),
            "expected_init.expected_native_capabilities",
        ),
        "forbidden_capabilities": _unique_string_list(
            value.get("forbidden_capabilities"),
            "expected_init.forbidden_capabilities",
        ),
        "expected_slash_commands": _unique_string_list(
            value.get("expected_slash_commands"),
            "expected_init.expected_slash_commands",
        ),
        "accepted_output_styles": _unique_string_list(
            value.get("accepted_output_styles"),
            "expected_init.accepted_output_styles",
        ),
    }
    if not result["accepted_models"]:
        _fail("CONFIG_INVALID", "expected init v2 accepts no model")
    if not result["accepted_api_key_sources"]:
        _fail("CONFIG_INVALID", "expected init v2 accepts no auth source")
    if not result["accepted_output_styles"]:
        _fail("CONFIG_INVALID", "expected init v2 accepts no output style")
    # Dynamic provider tools are deliberately limited to Anthropic's MCP
    # namespace.  Accepting an arbitrary prefix would silently expand the
    # provider capability surface after the arm was compiled.
    if any(
        prefix != "mcp__"
        for prefix in result["allowed_tool_prefixes"]
    ):
        _fail(
            "CONFIG_INVALID",
            "expected init v2 permits only the mcp__ dynamic tool namespace",
        )
    allowed_tools = set(result["allowed_tools"])
    required_tools = set(result["required_tools"])
    forbidden_tools = set(result["forbidden_tools"])
    if not required_tools.issubset(allowed_tools):
        _fail(
            "CONFIG_INVALID",
            "expected init v2 required tools exceed the allowed denominator",
        )
    if allowed_tools & forbidden_tools:
        _fail(
            "CONFIG_INVALID",
            "expected init v2 allowed and forbidden tools overlap",
        )
    allowed_mcp = set(result["allowed_mcp_servers"])
    required_mcp = set(result["required_mcp_servers"])
    if not required_mcp.issubset(allowed_mcp):
        _fail(
            "CONFIG_INVALID",
            "expected init v2 required MCP servers exceed the allowed set",
        )
    if allowed_mcp and "mcp__" not in result["allowed_tool_prefixes"]:
        _fail(
            "CONFIG_INVALID",
            "expected init v2 MCP servers lack an MCP tool namespace",
        )
    if (
        set(result["required_capabilities"])
        & set(result["forbidden_capabilities"])
    ):
        _fail(
            "CONFIG_INVALID",
            "expected init v2 required and forbidden capabilities overlap",
        )
    restricted_fs = RESTRICTED_ANALYSIS_CAPABILITY in result["required_capabilities"]
    restricted_web = (
        RESTRICTED_WEB_ANALYSIS_CAPABILITY in result["required_capabilities"]
    )
    if restricted_fs and restricted_web:
        _fail(
            "CONFIG_INVALID",
            "restricted filesystem and web capabilities are mutually exclusive",
        )
    restricted = restricted_fs or restricted_web
    if result["permission_mode"] == "default" and not restricted:
        _fail(
            "CONFIG_INVALID",
            "default permission mode is restricted to the reviewed analysis lane",
        )
    if restricted_fs and (
        result["claude_code_version"]
        != REVIEWED_RESTRICTED_INIT_VERSION
        or result["permission_mode"] != "default"
        or result["allowed_tools"]
        != list(REVIEWED_RESTRICTED_INIT_TOOLS)
        or result["allowed_tool_prefixes"] != []
        or result["allowed_mcp_servers"] != []
        or result["required_mcp_servers"] != []
        or result["expected_agents"]
        != list(REVIEWED_RESTRICTED_INIT_AGENTS)
        or result["expected_native_capabilities"]
        != list(REVIEWED_RESTRICTED_INIT_CAPABILITIES)
        or "remote-agents" not in result["forbidden_capabilities"]
    ):
        _fail(
            "CONFIG_INVALID",
            "restricted init contract differs from its pinned reviewed denominator",
        )
    if restricted_web and (
        result["claude_code_version"]
        != REVIEWED_RESTRICTED_INIT_VERSION
        or result["permission_mode"] != "default"
        or result["allowed_tools"]
        != list(REVIEWED_RESTRICTED_WEB_INIT_TOOLS)
        or result["allowed_tool_prefixes"] != []
        or result["allowed_mcp_servers"] != []
        or result["required_mcp_servers"] != []
        or result["expected_agents"]
        != list(REVIEWED_RESTRICTED_INIT_AGENTS)
        or result["expected_native_capabilities"]
        != list(REVIEWED_RESTRICTED_INIT_CAPABILITIES)
        or "remote-agents" not in result["forbidden_capabilities"]
    ):
        _fail(
            "CONFIG_INVALID",
            "restricted web init contract differs from its pinned reviewed denominator",
        )
    return result


def _normalize_expected_init_contract(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _fail("CONFIG_INVALID", "expected init contract must be an object")
    schema = value.get("schema")
    if schema == EXPECTED_INIT_SCHEMA:
        return _normalize_expected_init_v1(value)
    if schema == EXPECTED_INIT_SECURITY_SCHEMA:
        return _normalize_expected_init_v2(value)
    _fail("CONFIG_INVALID", "expected init contract schema is unsupported")


@dataclass(frozen=True)
class ClaudeStreamJsonEvidence:
    """Immutable semantic summary linked to the exact accepted raw byte stream."""

    raw_sha256: str
    raw_byte_count: int
    line_count: int
    session_id: str
    init_uuid: str
    result_uuid: str
    claude_code_version: str
    event_counts: tuple[tuple[str, int], ...]
    root_attributed_event_count: int
    subagent_attributed_event_count: int
    unattributed_event_count: int
    post_result_event_count: int
    protocol_adverse_event_count: int
    assistant_end_turn_count: int
    root_assistant_end_turn_count: int
    result_text_sha256: str
    init_event_sha256: str
    init_applicability: str
    expected_init_contract_sha256: str | None
    result_event_sha256: str
    result_subtype: str
    result_stop_reason_observed: str | None
    result_terminal_reason_observed: str | None
    terminal_basis: str

    def _core_summary(self) -> dict[str, Any]:
        return {
            "schema": EVIDENCE_SCHEMA,
            "provider_protocol": PROVIDER_PROTOCOL,
            "producer_exclusivity": PRODUCER_EXCLUSIVITY,
            "raw_sha256": self.raw_sha256,
            "raw_byte_count": self.raw_byte_count,
            "line_count": self.line_count,
            "session_id": self.session_id,
            "init_uuid": self.init_uuid,
            "result_uuid": self.result_uuid,
            "claude_code_version": self.claude_code_version,
            "event_counts": dict(self.event_counts),
            "root_attributed_event_count": self.root_attributed_event_count,
            "subagent_attributed_event_count": self.subagent_attributed_event_count,
            "unattributed_event_count": self.unattributed_event_count,
            "post_result_event_count": self.post_result_event_count,
            "protocol_adverse_event_count": (
                self.protocol_adverse_event_count
            ),
            "assistant_end_turn_count": self.assistant_end_turn_count,
            "root_assistant_end_turn_count": self.root_assistant_end_turn_count,
            "result_text_sha256": self.result_text_sha256,
            "init_event_sha256": self.init_event_sha256,
            "init_applicability": self.init_applicability,
            "expected_init_contract_sha256": (
                self.expected_init_contract_sha256
            ),
            "result_event_sha256": self.result_event_sha256,
            "result_subtype": self.result_subtype,
            "result_is_error": False,
            "result_stop_reason_observed": self.result_stop_reason_observed,
            "result_terminal_reason_observed": (
                self.result_terminal_reason_observed
            ),
            "terminal_basis": self.terminal_basis,
        }

    def canonical_summary(self) -> dict[str, Any]:
        """Return the canonical versioned summary used by receipts and replay."""

        core = self._core_summary()
        return {
            **core,
            "canonical_summary_sha256": hashlib.sha256(
                _canonical_json(core)
            ).hexdigest(),
        }

    def canonical_summary_bytes(self) -> bytes:
        return _canonical_json(self.canonical_summary())


class ClaudeStreamJsonEvidenceParser:
    """Incrementally parse a bounded Claude CLI stdout stream."""

    def __init__(
        self,
        *,
        expected_session_id: str | None = None,
        expected_init_contract: Mapping[str, Any] | None = None,
        max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
        max_stream_bytes: int = DEFAULT_MAX_STREAM_BYTES,
    ) -> None:
        if expected_session_id is not None:
            _nonempty_string(expected_session_id, "expected_session_id")
        self._expected_init_contract = (
            None
            if expected_init_contract is None
            else _normalize_expected_init_contract(expected_init_contract)
        )
        self._restricted_web_analysis = bool(
            self._expected_init_contract is not None
            and RESTRICTED_WEB_ANALYSIS_CAPABILITY
            in self._expected_init_contract.get("required_capabilities", [])
        )
        if (
            not isinstance(max_line_bytes, int)
            or isinstance(max_line_bytes, bool)
            or max_line_bytes <= 0
            or max_line_bytes > HARD_MAX_LINE_BYTES
        ):
            _fail("CONFIG_INVALID", "max_line_bytes is outside its hard bound")
        if (
            not isinstance(max_stream_bytes, int)
            or isinstance(max_stream_bytes, bool)
            or max_stream_bytes <= 0
            or max_stream_bytes > HARD_MAX_STREAM_BYTES
            or max_stream_bytes < max_line_bytes + 1
        ):
            _fail("CONFIG_INVALID", "max_stream_bytes is outside its hard bound")

        self._expected_session_id = expected_session_id
        self._max_line_bytes = max_line_bytes
        self._max_stream_bytes = max_stream_bytes
        self._line_buffer = bytearray()
        self._raw_hasher = hashlib.sha256()
        self._raw_byte_count = 0
        self._line_count = 0
        self._session_id: str | None = None
        self._init_event: dict[str, Any] | None = None
        self._result_event: dict[str, Any] | None = None
        self._event_counts: dict[str, int] = {}
        self._root_count = 0
        self._subagent_count = 0
        self._unattributed_count = 0
        self._post_result_event_count = 0
        self._protocol_adverse_event_count = 0
        self._event_uuids: set[str] = set()
        self._assistant_end_turn_count = 0
        self._root_assistant_end_turn_count = 0
        self._last_root_assistant_stop_reason: str | None = None
        self._pinned_null_stop_terminal_candidate = False
        self._terminal_basis: str | None = None
        self._web_search_messages: dict[str, str] = {}
        self._web_search_results: set[str] = set()
        self._web_assistant_message_ids: set[str] = set()
        self._failed = False
        self._finished: ClaudeStreamJsonEvidence | None = None

    def feed(self, chunk: bytes) -> None:
        """Consume one arbitrary byte chunk; chunk boundaries have no semantics."""

        if self._failed:
            _fail("PARSER_FAILED", "parser cannot continue after a rejected stream")
        if not isinstance(chunk, bytes):
            self._failed = True
            _fail("CHUNK_INVALID", "stream chunks must be bytes")
        if self._finished is not None:
            if chunk:
                self._failed = True
                _fail("BYTES_AFTER_FINISH", "bytes arrived after parser finish")
            return
        if not chunk:
            return
        if self._raw_byte_count + len(chunk) > self._max_stream_bytes:
            self._failed = True
            _fail("STREAM_CEILING", "provider stream exceeds its byte ceiling")

        self._raw_hasher.update(chunk)
        self._raw_byte_count += len(chunk)
        offset = 0
        try:
            while offset < len(chunk):
                newline = chunk.find(b"\n", offset)
                if newline < 0:
                    self._line_buffer.extend(chunk[offset:])
                    if len(self._line_buffer) > self._max_line_bytes:
                        _fail("LINE_CEILING", "JSONL row exceeds its byte ceiling")
                    break
                segment = chunk[offset:newline]
                if len(self._line_buffer) + len(segment) > self._max_line_bytes:
                    _fail("LINE_CEILING", "JSONL row exceeds its byte ceiling")
                self._line_buffer.extend(segment)
                raw_line = bytes(self._line_buffer)
                self._line_buffer.clear()
                self._consume_line(raw_line)
                offset = newline + 1
        except ClaudeStreamJsonEvidenceError:
            self._failed = True
            raise

    def _consume_line(self, raw_line: bytes) -> None:
        event = _load_object(raw_line)
        self._line_count += 1
        event_type = _nonempty_string(event.get("type"), "event.type")

        if self._init_event is None:
            if event_type != "system" or event.get("subtype") != "init":
                _fail(
                    "ORDER_INIT_REQUIRED",
                    "the first row must be exactly system/init",
                )
            self._accept_init(event)
        elif self._result_event is not None:
            self._accept_post_result(event_type, event)
        elif event_type == "system" and event.get("subtype") == "init":
            _fail("ORDER_MULTIPLE_INIT", "more than one system/init row")
        elif event_type == "result":
            self._accept_result(event)
        else:
            self._accept_progress(event_type, event)

        self._event_counts[event_type] = self._event_counts.get(event_type, 0) + 1

    def _accept_post_result(
        self, event_type: str, event: dict[str, Any]
    ) -> None:
        """Accept only the documented non-terminal tail at exact EOF.

        Anthropic documents that ``prompt_suggestion`` system events can
        follow the result.  No assistant, user, result, tool, hook, or other
        system event is allowed in this tail.  This keeps the terminal grammar
        narrow while remaining compatible with the current provider stream.
        """

        if event_type != "prompt_suggestion":
            _fail(
                "POST_RESULT_EVENT_REJECTED",
                "only prompt_suggestion may follow result",
            )
        if "parent_tool_use_id" in event:
            _fail(
                "POST_RESULT_EVENT_REJECTED",
                "post-result system events cannot be subagent-attributed",
            )
        self._require_session(event, "post_result.prompt_suggestion")
        _nonempty_string(
            event.get("suggestion"),
            "post_result.prompt_suggestion.suggestion",
        )
        self._post_result_event_count += 1
        self._unattributed_count += 1

    def _accept_init(self, event: dict[str, Any]) -> None:
        if "parent_tool_use_id" in event:
            _fail("INIT_NOT_ROOT", "system/init cannot carry parent_tool_use_id")
        session_id = _nonempty_string(event.get("session_id"), "init.session_id")
        if (
            self._expected_session_id is not None
            and session_id != self._expected_session_id
        ):
            _fail("SESSION_MISMATCH", "init session does not match the armed session")
        self._accept_uuid(event, "init")
        _nonempty_string(
            event.get("claude_code_version"), "init.claude_code_version"
        )
        _nonempty_string(event.get("cwd"), "init.cwd")
        _nonempty_string(event.get("model"), "init.model")
        _nonempty_string(event.get("permissionMode"), "init.permissionMode")
        tools = event.get("tools")
        if not isinstance(tools, list) or any(
            not isinstance(item, str) or not item for item in tools
        ):
            _fail("EVENT_FIELD_INVALID", "init.tools must be a string array")
        api_key_source = event.get("apiKeySource")
        if api_key_source is not None and (
            not isinstance(api_key_source, str) or not api_key_source
        ):
            _fail(
                "EVENT_FIELD_INVALID",
                "init.apiKeySource must be a non-empty string or null",
            )
        for field in (
            "mcp_servers",
            "slash_commands",
            "skills",
            "plugins",
            "agents",
            "betas",
            "capabilities",
        ):
            if field in event and not isinstance(event[field], list):
                _fail(
                    "EVENT_FIELD_INVALID",
                    f"init.{field} must be an array",
                )
        for field in (
            "slash_commands",
            "skills",
            "agents",
            "betas",
            "capabilities",
        ):
            values = event.get(field, [])
            if any(not isinstance(item, str) or not item for item in values):
                _fail(
                    "EVENT_FIELD_INVALID",
                    f"init.{field} must contain non-empty strings",
                )
        mcp_servers = event.get("mcp_servers", [])
        for server in mcp_servers:
            if (
                not isinstance(server, dict)
                or not isinstance(server.get("name"), str)
                or not server["name"]
                or not isinstance(server.get("status"), str)
                or not server["status"]
            ):
                _fail(
                    "EVENT_FIELD_INVALID",
                    "init.mcp_servers rows require non-empty name/status",
                )
            # Anthropic's MCP integration guidance treats every status other
            # than "connected" as a connection failure.  Such a worker cannot
            # prove that its armed methodology/tool surface was available.
            if server["status"] != "connected":
                self._reject_adverse(
                    "provider init reported an unconnected MCP server"
                )
        plugins = event.get("plugins", [])
        for plugin in plugins:
            if (
                not isinstance(plugin, dict)
                or not isinstance(plugin.get("name"), str)
                or not plugin["name"]
                or not isinstance(plugin.get("path"), str)
                or not plugin["path"]
            ):
                _fail(
                    "EVENT_FIELD_INVALID",
                    "init.plugins rows require non-empty name/path",
                )
        plugin_errors = event.get("plugin_errors", [])
        if not isinstance(plugin_errors, list):
            _fail(
                "EVENT_FIELD_INVALID",
                "init.plugin_errors must be an array when present",
            )
        if plugin_errors:
            self._reject_adverse(
                "provider init reported plugin loading errors"
            )
        if "output_style" in event and not isinstance(
            event["output_style"], str
        ):
            _fail(
                "EVENT_FIELD_INVALID",
                "init.output_style must be a string",
            )
        self._validate_init_applicability(event)
        self._session_id = session_id
        self._init_event = event
        self._unattributed_count += 1

    def _validate_init_applicability(
        self,
        event: Mapping[str, Any],
    ) -> None:
        expected = self._expected_init_contract
        if expected is None:
            return
        observed_lists: dict[str, list[Any]] = {}
        for field in (
            "tools",
            "mcp_servers",
            "plugins",
            "skills",
            "agents",
            "capabilities",
            "slash_commands",
        ):
            raw = event.get(field, [])
            if not isinstance(raw, list):
                _fail(
                    "INIT_APPLICABILITY_MISMATCH",
                    f"init.{field} is not an array",
                )
            observed_lists[field] = raw

        def canonical_objects(values: list[Any], label: str) -> list[dict[str, Any]]:
            if any(not isinstance(item, dict) for item in values):
                _fail(
                    "INIT_APPLICABILITY_MISMATCH",
                    f"init.{label} contains a non-object",
                )
            result = [dict(item) for item in values]
            result.sort(key=lambda item: _canonical_json(item))
            return result

        mismatches: list[str] = []
        if event.get("claude_code_version") != expected["claude_code_version"]:
            mismatches.append("claude_code_version")
        if event.get("cwd") != expected["cwd"]:
            mismatches.append("cwd")
        if event.get("model") not in expected["accepted_models"]:
            mismatches.append("model")
        if event.get("permissionMode") != expected["permission_mode"]:
            mismatches.append("permissionMode")
        if expected["schema"] == EXPECTED_INIT_SCHEMA:
            if sorted(observed_lists["tools"]) != expected["expected_tools"]:
                mismatches.append("tools")
            if canonical_objects(
                observed_lists["mcp_servers"], "mcp_servers"
            ) != expected["expected_mcp_servers"]:
                mismatches.append("mcp_servers")
        else:
            observed_tools = observed_lists["tools"]
            if len(set(observed_tools)) != len(observed_tools):
                mismatches.append("tools")
            allowed_tools = set(expected["allowed_tools"])
            allowed_prefixes = tuple(expected["allowed_tool_prefixes"])
            unknown_tools = {
                tool
                for tool in observed_tools
                if tool not in allowed_tools
                and not any(
                    tool.startswith(prefix)
                    for prefix in allowed_prefixes
                )
            }
            if (
                unknown_tools
                or not set(expected["required_tools"]).issubset(
                    observed_tools
                )
                or set(expected["forbidden_tools"]) & set(observed_tools)
            ):
                mismatches.append("tools")
            if (
                _REVIEWED_RESTRICTED_CAPABILITIES
                & set(expected["required_capabilities"])
                and sorted(observed_tools) != expected["allowed_tools"]
            ):
                mismatches.append("tools")
            observed_servers = canonical_objects(
                observed_lists["mcp_servers"], "mcp_servers"
            )
            observed_server_names = [
                str(server.get("name") or "")
                for server in observed_servers
            ]
            if (
                len(set(observed_server_names))
                != len(observed_server_names)
                or not set(observed_server_names).issubset(
                    expected["allowed_mcp_servers"]
                )
                or not set(expected["required_mcp_servers"]).issubset(
                    observed_server_names
                )
            ):
                mismatches.append("mcp_servers")
            observed_mcp_tools = [
                tool
                for tool in observed_tools
                if tool.startswith("mcp__")
            ]
            if any(
                not any(
                    tool.startswith(f"mcp__{server_name}__")
                    for server_name in observed_server_names
                )
                for tool in observed_mcp_tools
            ):
                mismatches.append("tools")
            # A dynamic MCP tool is meaningful only when at least one
            # explicitly allowed server was actually connected.  This closes
            # the otherwise-permissive "mcp__" prefix with an empty server
            # denominator.
            if (
                any(
                    tool.startswith("mcp__")
                    for tool in observed_tools
                )
                and not observed_server_names
            ):
                mismatches.append("mcp_servers")
        if canonical_objects(
            observed_lists["plugins"], "plugins"
        ) != expected["expected_plugins"]:
            mismatches.append("plugins")
        if sorted(observed_lists["skills"]) != expected["expected_skills"]:
            mismatches.append("skills")
        if sorted(observed_lists["agents"]) != expected["expected_agents"]:
            mismatches.append("agents")
        if event.get("apiKeySource") not in expected[
            "accepted_api_key_sources"
        ]:
            mismatches.append("apiKeySource")
        if expected["schema"] == EXPECTED_INIT_SECURITY_SCHEMA:
            if (
                _REVIEWED_RESTRICTED_CAPABILITIES
                & set(expected["required_capabilities"])
            ):
                if sorted(observed_lists["capabilities"]) != expected[
                    "expected_native_capabilities"
                ]:
                    mismatches.append("capabilities")
            elif not set(expected["expected_native_capabilities"]).issubset(
                observed_lists["capabilities"]
            ):
                mismatches.append("capabilities")
        elif not set(expected["required_capabilities"]).issubset(
            observed_lists["capabilities"]
        ):
            mismatches.append("capabilities")
        if (
            expected["schema"] == EXPECTED_INIT_SECURITY_SCHEMA
            and set(expected["forbidden_capabilities"])
            & set(observed_lists["capabilities"])
        ):
            mismatches.append("capabilities")
        if sorted(observed_lists["slash_commands"]) != expected[
            "expected_slash_commands"
        ]:
            mismatches.append("slash_commands")
        if expected["schema"] == EXPECTED_INIT_SCHEMA:
            if event.get("output_style") != expected["expected_output_style"]:
                mismatches.append("output_style")
        elif event.get("output_style") not in expected[
            "accepted_output_styles"
        ]:
            mismatches.append("output_style")
        if mismatches:
            _fail(
                "INIT_APPLICABILITY_MISMATCH",
                "provider init differs from armed fields: "
                + ",".join(sorted(mismatches)),
            )

    def _accept_uuid(self, event: dict[str, Any], label: str) -> str:
        event_uuid = _nonempty_string(event.get("uuid"), f"{label}.uuid")
        if event_uuid in self._event_uuids:
            _fail(
                "EVENT_UUID_DUPLICATE",
                f"{label} repeats an existing event UUID",
            )
        self._event_uuids.add(event_uuid)
        return event_uuid

    def _require_session(self, event: dict[str, Any], label: str) -> None:
        session_id = _nonempty_string(event.get("session_id"), f"{label}.session_id")
        if session_id != self._session_id:
            _fail("SESSION_MISMATCH", f"{label} belongs to another session")
        self._accept_uuid(event, label)

    def _accept_progress(
        self, event_type: str, event: dict[str, Any]
    ) -> None:
        # The pinned 2.1.252 null-stop exception is an exact terminal envelope
        # pair.  Ordinary Claude subscription telemetry may place a structured
        # ``rate_limit_event`` with status ``allowed`` (or ``allowed_warning``)
        # between the final assistant text and the successful result.  That row
        # is not another turn and must not erase the candidate.  Malformed or
        # rejected rate-limit rows still invalidate/fail closed below.
        rate_info = (
            event.get("rate_limit_info")
            if event_type == "rate_limit_event"
            else None
        )
        preserve_terminal_candidate = (
            isinstance(rate_info, dict)
            and rate_info.get("status") in {"allowed", "allowed_warning"}
        )
        if not preserve_terminal_candidate:
            self._pinned_null_stop_terminal_candidate = False
        if event_type == "stream_event":
            _fail(
                "PARTIAL_EVENT_UNSUPPORTED",
                "partial-message streaming is not supported by this protocol",
            )
        if event_type == "system":
            subtype = _nonempty_string(event.get("subtype"), "system.subtype")
            if subtype not in _SYSTEM_AUXILIARY_SUBTYPES:
                _fail(
                    "EVENT_TYPE_UNSUPPORTED",
                    f"unsupported system subtype {subtype!r}",
                )
            if subtype == "api_retry":
                self._validate_api_retry(event)
            elif subtype == "thinking_tokens":
                total = _nonnegative_int(
                    event.get("estimated_tokens"),
                    "thinking_tokens.estimated_tokens",
                )
                delta = _nonnegative_int(
                    event.get("estimated_tokens_delta"),
                    "thinking_tokens.estimated_tokens_delta",
                )
                if delta > total:
                    _fail(
                        "EVENT_FIELD_INVALID",
                        "thinking token delta exceeds the running total",
                    )
            elif subtype == "background_tasks_changed":
                if not isinstance(event.get("tasks"), list):
                    _fail(
                        "EVENT_FIELD_INVALID",
                        "background_tasks_changed.tasks must be an array",
                    )
            elif subtype == "files_persisted":
                if (
                    not isinstance(event.get("files"), list)
                    or not isinstance(event.get("failed"), list)
                ):
                    _fail(
                        "EVENT_FIELD_INVALID",
                        "files_persisted denominators must be arrays",
                    )
                if event["failed"]:
                    self._reject_adverse(
                        "files_persisted reported failed checkpoints"
                    )
            elif subtype == "local_command_output":
                if not isinstance(event.get("content"), str):
                    _fail(
                        "EVENT_FIELD_INVALID",
                        "local_command_output.content must be text",
                    )
            elif subtype == "informational":
                _nonempty_string(
                    event.get("content"),
                    "informational.content",
                )
                if event.get("level") not in {
                    "info",
                    "notice",
                    "suggestion",
                    "warning",
                }:
                    _fail(
                        "EVENT_FIELD_INVALID",
                        "informational.level is unsupported",
                    )
                if event.get("prevent_continuation") is True:
                    self._reject_adverse(
                        "informational event prevented continuation"
                    )
            elif subtype == "worker_shutting_down":
                self._reject_adverse(
                    "worker_shutting_down cannot precede proof completion"
                )
            elif subtype == "permission_denied":
                self._reject_adverse(
                    "provider permission system denied a tool call"
                )
            elif subtype == "plugin_install" and event.get("status") == "failed":
                self._reject_adverse("plugin installation failed")
            elif subtype == "hook_response" and event.get("outcome") in {
                "error",
                "cancelled",
            }:
                self._reject_adverse("hook execution did not succeed")
        elif event_type not in {"assistant", "user"} | _AUXILIARY_EVENT_TYPES:
            _fail(
                "EVENT_TYPE_UNSUPPORTED",
                f"unsupported top-level event type {event_type!r}",
            )
        elif event_type == "prompt_suggestion":
            _nonempty_string(
                event.get("suggestion"),
                "prompt_suggestion.suggestion",
            )
        elif event_type == "rate_limit_event":
            info = event.get("rate_limit_info")
            if not isinstance(info, dict) or info.get("status") not in {
                "allowed",
                "allowed_warning",
                "rejected",
            }:
                _fail(
                    "EVENT_FIELD_INVALID",
                    "rate_limit_event.rate_limit_info is malformed",
                )
            if info.get("status") == "rejected":
                self._reject_adverse("provider rate limit rejected the turn")
        elif event_type in {"conversation_reset", "mirror_error"}:
            self._reject_adverse(
                f"{event_type} cannot precede proof completion"
            )
        elif event_type == "auth_status" and event.get("error"):
            self._reject_adverse("authentication status reported an error")

        self._require_session(event, event_type)
        if event_type in _PARENT_ATTRIBUTED_TYPES or event_type in {
            "assistant",
            "user",
        }:
            if "parent_tool_use_id" not in event:
                _fail(
                    "ATTRIBUTION_MISSING",
                    f"{event_type} lacks parent_tool_use_id",
                )
            parent = event["parent_tool_use_id"]
            if parent is None:
                self._root_count += 1
            elif isinstance(parent, str) and parent:
                self._subagent_count += 1
            else:
                _fail(
                    "ATTRIBUTION_INVALID",
                    "parent_tool_use_id must be null or a non-empty string",
                )
        elif "parent_tool_use_id" in event:
            parent = event["parent_tool_use_id"]
            if parent is None:
                self._root_count += 1
            elif isinstance(parent, str) and parent:
                self._subagent_count += 1
            else:
                _fail(
                    "ATTRIBUTION_INVALID",
                    "parent_tool_use_id must be null or a non-empty string",
                )
        else:
            self._unattributed_count += 1

        if event_type in {"assistant", "user"}:
            message = event.get("message")
            if not isinstance(message, dict):
                _fail("EVENT_FIELD_INVALID", f"{event_type}.message must be an object")
            expected_role = event_type
            if message.get("role") != expected_role:
                _fail(
                    "EVENT_FIELD_INVALID",
                    f"{event_type}.message.role must be {expected_role!r}",
                )
            content = message.get("content")
            if (
                event_type == "assistant"
                and not isinstance(content, list)
            ) or (
                event_type == "user"
                and not isinstance(content, (str, list))
            ):
                _fail(
                    "EVENT_FIELD_INVALID",
                    f"{event_type}.message.content has an invalid shape",
                )
            if event_type == "assistant":
                for field in ("id", "model"):
                    _nonempty_string(
                        message.get(field),
                        f"assistant.message.{field}",
                    )
                if (
                    self._expected_init_contract is not None
                    and message.get("model")
                    not in self._expected_init_contract["accepted_models"]
                ):
                    _fail(
                        "MODEL_DENOMINATOR_MISMATCH",
                        "assistant.message.model is outside the explicitly "
                        "armed model denominator",
                    )
                if message.get("type") != "message":
                    _fail(
                        "EVENT_FIELD_INVALID",
                        "assistant.message.type must be 'message'",
                    )
                if not isinstance(message.get("usage"), dict):
                    _fail(
                        "EVENT_FIELD_INVALID",
                        "assistant.message.usage must be an object",
                    )
                error = event.get("error")
                if error is not None:
                    _fail(
                        "ASSISTANT_ERROR",
                        "assistant error envelopes cannot support completion",
                    )
                stop_reason = message.get("stop_reason")
                if stop_reason is not None and not isinstance(stop_reason, str):
                    _fail(
                        "EVENT_FIELD_INVALID",
                        "assistant.message.stop_reason must be string or null",
                    )
                if stop_reason == "end_turn":
                    self._assistant_end_turn_count += 1
                    if event["parent_tool_use_id"] is None:
                        self._root_assistant_end_turn_count += 1
                if event["parent_tool_use_id"] is None:
                    self._last_root_assistant_stop_reason = stop_reason
                    self._pinned_null_stop_terminal_candidate = (
                        "stop_reason" in message
                        and stop_reason is None
                        and len(content) == 1
                        and isinstance(content[0], dict)
                        and content[0].get("type") == "text"
                        and isinstance(content[0].get("text"), str)
                        and bool(content[0]["text"].strip())
                    )
            elif event["parent_tool_use_id"] is None:
                # A later root user/query event starts a new turn.  A preceding
                # assistant end_turn can no longer authorize the eventual
                # result for this new root input.
                self._last_root_assistant_stop_reason = None
            if self._restricted_web_analysis:
                self._validate_restricted_web_message(
                    event_type=event_type,
                    event=event,
                    message=message,
                    content=content,
                )

    def _validate_restricted_web_message(
        self,
        *,
        event_type: str,
        event: Mapping[str, Any],
        message: Mapping[str, Any],
        content: str | list[Any],
    ) -> None:
        """Enforce the reviewed search-result-later-fetch stream sequence."""

        if not isinstance(content, list):
            return
        if event_type == "user":
            for block in content:
                if not isinstance(block, Mapping) or block.get("type") != "tool_result":
                    continue
                tool_use_id = block.get("tool_use_id")
                if tool_use_id in self._web_search_messages:
                    if block.get("is_error") is True:
                        continue
                    self._web_search_results.add(str(tool_use_id))
            return

        web_blocks = [
            block for block in content
            if isinstance(block, Mapping)
            and block.get("type") == "tool_use"
            and block.get("name") in {"WebSearch", "WebFetch"}
        ]
        if not web_blocks:
            return
        if event.get("parent_tool_use_id") is not None:
            _fail(
                "WEB_TOOL_SEQUENCE_INVALID",
                "restricted web tools must be invoked by the root assistant",
            )
        message_id = _nonempty_string(
            message.get("id"), "restricted_web.assistant.message.id",
        )
        if message_id in self._web_assistant_message_ids:
            _fail(
                "WEB_TOOL_SEQUENCE_INVALID",
                "restricted web assistant message ID is duplicated",
            )
        self._web_assistant_message_ids.add(message_id)
        names = {str(block["name"]) for block in web_blocks}
        if names == {"WebSearch", "WebFetch"}:
            _fail(
                "WEB_TOOL_SEQUENCE_INVALID",
                "WebSearch and WebFetch cannot share an assistant message",
            )
        if names == {"WebSearch"}:
            if len(web_blocks) != 1:
                _fail(
                    "WEB_TOOL_SEQUENCE_INVALID",
                    "one assistant message may issue only one WebSearch",
                )
            tool_use_id = _nonempty_string(
                web_blocks[0].get("id"), "restricted_web.WebSearch.id",
            )
            if tool_use_id in self._web_search_messages:
                _fail(
                    "WEB_TOOL_SEQUENCE_INVALID",
                    "WebSearch tool-use ID is duplicated",
                )
            self._web_search_messages[tool_use_id] = message_id
            return
        if not self._web_search_results:
            _fail(
                "WEB_TOOL_SEQUENCE_INVALID",
                "WebFetch precedes a successful WebSearch tool result",
            )
        if len(web_blocks) != 1:
            _fail(
                "WEB_TOOL_SEQUENCE_INVALID",
                "one assistant message may issue only one WebFetch",
            )
        if message_id in set(self._web_search_messages.values()):
            _fail(
                "WEB_TOOL_SEQUENCE_INVALID",
                "WebFetch must occur in a later assistant message",
            )
        for block in web_blocks:
            _nonempty_string(
                block.get("id"), "restricted_web.WebFetch.id",
            )

    def _reject_adverse(self, detail: str) -> None:
        self._protocol_adverse_event_count += 1
        _fail("PROVIDER_ADVERSE_EVENT", detail)

    def _validate_api_retry(self, event: dict[str, Any]) -> None:
        attempt = _nonnegative_int(event.get("attempt"), "api_retry.attempt")
        max_retries = _nonnegative_int(
            event.get("max_retries"), "api_retry.max_retries"
        )
        if attempt < 1 or max_retries < 1 or attempt > max_retries:
            _fail(
                "EVENT_FIELD_INVALID",
                "api_retry attempt must be within 1..max_retries",
            )
        _nonnegative_int(
            event.get("retry_delay_ms"), "api_retry.retry_delay_ms"
        )
        error_status = event.get("error_status")
        if error_status is not None and (
            not isinstance(error_status, int)
            or isinstance(error_status, bool)
            or error_status < 100
            or error_status > 599
        ):
            _fail(
                "EVENT_FIELD_INVALID",
                "api_retry.error_status must be null or an HTTP status integer",
            )
        error = event.get("error")
        if error not in {
            "authentication_failed",
            "oauth_org_not_allowed",
            "billing_error",
            "rate_limit",
            "overloaded",
            "invalid_request",
            "model_not_found",
            "server_error",
            "max_output_tokens",
            "unknown",
        }:
            _fail(
                "EVENT_FIELD_INVALID",
                "api_retry.error is not a documented category",
            )

    def _accept_result(self, event: dict[str, Any]) -> None:
        if self._result_event is not None:
            _fail("ORDER_MULTIPLE_RESULT", "more than one result row")
        if "parent_tool_use_id" in event:
            _fail("RESULT_NOT_ROOT", "result cannot be attributed to a subagent")
        self._require_session(event, "result")
        if event.get("subtype") != "success":
            _fail(
                "RESULT_SUBTYPE_REJECTED",
                f"result subtype {event.get('subtype')!r} is not success",
            )
        if event.get("is_error") is not False:
            _fail("RESULT_IS_ERROR", "result.is_error must be exactly false")
        if event.get("stop_reason") == "refusal":
            _fail(
                "RESULT_CYBER_REFUSAL",
                "Claude refused the cybersecurity request; no audit artifact "
                "was accepted. Legitimate security teams should review the "
                "Anthropic Cyber Verification Program before retrying; Plamen "
                "will not silently switch models.",
            )
        if event.get("stop_reason") != "end_turn":
            _fail(
                "RESULT_STOP_REASON_REJECTED",
                "result.stop_reason must be end_turn",
            )
        if event.get("terminal_reason") not in {None, "completed"}:
            _fail(
                "RESULT_TERMINAL_REASON_REJECTED",
                "optional result.terminal_reason is adverse",
            )
        if not isinstance(event.get("result"), str):
            _fail("EVENT_FIELD_INVALID", "result.result must be a string")
        _nonnegative_int(event.get("duration_ms"), "result.duration_ms")
        _nonnegative_int(event.get("duration_api_ms"), "result.duration_api_ms")
        _nonnegative_int(event.get("num_turns"), "result.num_turns")
        _finite_nonnegative_number(
            event.get("total_cost_usd"), "result.total_cost_usd"
        )
        if not isinstance(event.get("usage"), dict):
            _fail("EVENT_FIELD_INVALID", "result.usage must be an object")
        model_usage = event.get("modelUsage")
        if not isinstance(model_usage, dict):
            _fail("EVENT_FIELD_INVALID", "result.modelUsage must be an object")
        if self._expected_init_contract is not None:
            allowed_usage_models = set(
                self._expected_init_contract["accepted_models"]
            )
            if self._restricted_web_analysis:
                # Locked Claude 2.1.252 reports this exact internal model in
                # aggregate result telemetry even when init and every
                # assistant message remain on the explicitly armed model.
                # It is not admitted anywhere else in the stream grammar.
                allowed_usage_models.update(
                    REVIEWED_RESTRICTED_WEB_AUXILIARY_USAGE_MODELS
                )
                selected_model = (
                    self._init_event.get("model")
                    if self._init_event is not None
                    else None
                )
                if selected_model not in model_usage:
                    _fail(
                        "MODEL_DENOMINATOR_MISMATCH",
                        "restricted web result telemetry omits the selected model",
                    )
            unarmed_models = sorted(
                str(model)
                for model in model_usage
                if model not in allowed_usage_models
            )
            if unarmed_models:
                _fail(
                    "MODEL_DENOMINATOR_MISMATCH",
                    "result.modelUsage contains models outside the explicitly "
                    "armed model denominator",
                )
        permission_denials = event.get("permission_denials")
        if not isinstance(permission_denials, list):
            _fail(
                "EVENT_FIELD_INVALID",
                "result.permission_denials must be an array",
            )
        if permission_denials:
            _fail(
                "RESULT_PERMISSION_DENIED",
                "successful result contains permission denials",
            )
        if event.get("api_error_status") is not None:
            _fail(
                "RESULT_CONTRADICTION",
                "successful result contains an API error status",
            )
        if event.get("errors"):
            _fail(
                "RESULT_CONTRADICTION",
                "successful result contains provider errors",
            )
        if event.get("deferred_tool_use") is not None:
            _fail(
                "RESULT_CONTRADICTION",
                "successful result contains deferred tool authority",
            )
        origin = event.get("origin")
        if origin is not None and origin != {"kind": "human"}:
            _fail(
                "RESULT_ORIGIN_REJECTED",
                "only the armed human-origin query may produce the final result",
            )
        if self._last_root_assistant_stop_reason == "end_turn":
            self._terminal_basis = (
                "FINAL_ROOT_ASSISTANT_END_TURN_AND_RESULT_SUCCESS"
            )
        elif (
            self._init_event is not None
            and self._init_event.get("claude_code_version")
            == REVIEWED_RESTRICTED_INIT_VERSION
            and self._expected_init_contract is not None
            and self._expected_init_contract.get("schema")
            == EXPECTED_INIT_SECURITY_SCHEMA
            and _REVIEWED_RESTRICTED_CAPABILITIES
            & set(self._expected_init_contract.get("required_capabilities", []))
            and self._pinned_null_stop_terminal_candidate
        ):
            self._terminal_basis = (
                "FINAL_ROOT_ASSISTANT_TEXT_NULL_STOP_AND_RESULT_SUCCESS_2_1_252"
            )
        else:
            _fail(
                "ROOT_END_TURN_REQUIRED",
                "result success lacks an accepted final root assistant envelope",
            )
        if self._protocol_adverse_event_count:
            _fail(
                "PROVIDER_ADVERSE_EVENT",
                "successful result follows an adverse provider event",
            )
        self._result_event = event
        self._unattributed_count += 1

    def finish(self) -> ClaudeStreamJsonEvidence:
        """Require exact EOF and return immutable evidence."""

        if self._failed:
            _fail("PARSER_FAILED", "parser cannot finish after a rejected stream")
        if self._finished is not None:
            return self._finished
        try:
            if self._line_buffer:
                _fail(
                    "NDJSON_PARTIAL_FINAL_LINE",
                    "provider stream ended with an unterminated JSONL row",
                )
            if self._init_event is None:
                _fail("ORDER_INIT_REQUIRED", "provider stream has no system/init")
            if self._result_event is None:
                _fail("ORDER_RESULT_REQUIRED", "provider stream has no final result")

            init = self._init_event
            result = self._result_event
            evidence = ClaudeStreamJsonEvidence(
                raw_sha256=self._raw_hasher.hexdigest(),
                raw_byte_count=self._raw_byte_count,
                line_count=self._line_count,
                session_id=self._session_id or "",
                init_uuid=str(init["uuid"]),
                result_uuid=str(result["uuid"]),
                claude_code_version=str(init["claude_code_version"]),
                event_counts=tuple(sorted(self._event_counts.items())),
                root_attributed_event_count=self._root_count,
                subagent_attributed_event_count=self._subagent_count,
                unattributed_event_count=self._unattributed_count,
                post_result_event_count=self._post_result_event_count,
                protocol_adverse_event_count=(
                    self._protocol_adverse_event_count
                ),
                assistant_end_turn_count=self._assistant_end_turn_count,
                root_assistant_end_turn_count=(
                    self._root_assistant_end_turn_count
                ),
                result_text_sha256=hashlib.sha256(
                    result["result"].encode("utf-8")
                ).hexdigest(),
                init_event_sha256=hashlib.sha256(_canonical_json(init)).hexdigest(),
                init_applicability=(
                    "MATCHED"
                    if self._expected_init_contract is not None
                    else "UNBOUND"
                ),
                expected_init_contract_sha256=(
                    hashlib.sha256(
                        _canonical_json(self._expected_init_contract)
                    ).hexdigest()
                    if self._expected_init_contract is not None
                    else None
                ),
                result_event_sha256=hashlib.sha256(
                    _canonical_json(result)
                ).hexdigest(),
                result_subtype="success",
                result_stop_reason_observed=result.get("stop_reason"),
                result_terminal_reason_observed=result.get("terminal_reason"),
                terminal_basis=self._terminal_basis or "",
            )
            self._finished = evidence
            return evidence
        except ClaudeStreamJsonEvidenceError:
            self._failed = True
            raise


def validate_claude_stream_json(
    raw: bytes,
    *,
    expected_session_id: str | None = None,
    expected_init_contract: Mapping[str, Any] | None = None,
    max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
    max_stream_bytes: int = DEFAULT_MAX_STREAM_BYTES,
) -> dict[str, Any]:
    """Validate one complete raw stream and return its canonical summary."""

    if not isinstance(raw, bytes):
        _fail("STREAM_INVALID", "raw provider stream must be bytes")
    parser = ClaudeStreamJsonEvidenceParser(
        expected_session_id=expected_session_id,
        expected_init_contract=expected_init_contract,
        max_line_bytes=max_line_bytes,
        max_stream_bytes=max_stream_bytes,
    )
    parser.feed(raw)
    return parser.finish().canonical_summary()


def normalize_expected_init_contract(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate and canonicalize the provider-init applicability contract."""

    return _normalize_expected_init_contract(value)


def replay_claude_stream_json(
    raw: bytes,
    expected_summary: Mapping[str, Any],
    *,
    expected_session_id: str | None = None,
    expected_init_contract: Mapping[str, Any] | None = None,
    max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
    max_stream_bytes: int = DEFAULT_MAX_STREAM_BYTES,
) -> dict[str, Any]:
    """Reparse exact raw evidence and require the canonical summary to match."""

    if not isinstance(expected_summary, Mapping):
        _fail("REPLAY_SUMMARY_INVALID", "expected summary must be a mapping")
    observed = validate_claude_stream_json(
        raw,
        expected_session_id=expected_session_id,
        expected_init_contract=expected_init_contract,
        max_line_bytes=max_line_bytes,
        max_stream_bytes=max_stream_bytes,
    )
    if _canonical_json(observed) != _canonical_json(dict(expected_summary)):
        _fail("REPLAY_MISMATCH", "provider stream evidence summary changed")
    return observed


def implementation_files() -> tuple[Path, ...]:
    """Return the exact local implementation closure for receipt binding."""

    return (Path(__file__).resolve(strict=True),)


__all__ = [
    "ClaudeStreamJsonEvidence",
    "ClaudeStreamJsonEvidenceError",
    "ClaudeStreamJsonEvidenceParser",
    "DEFAULT_MAX_LINE_BYTES",
    "DEFAULT_MAX_STREAM_BYTES",
    "EVIDENCE_SCHEMA",
    "EXPECTED_INIT_SCHEMA",
    "EXPECTED_INIT_SECURITY_SCHEMA",
    "PRODUCER_EXCLUSIVITY",
    "PROVIDER_PROTOCOL",
    "RESTRICTED_ANALYSIS_CAPABILITY",
    "RESTRICTED_WEB_ANALYSIS_CAPABILITY",
    "REVIEWED_RESTRICTED_INIT_AGENTS",
    "REVIEWED_RESTRICTED_INIT_CAPABILITIES",
    "REVIEWED_RESTRICTED_INIT_TOOLS",
    "REVIEWED_RESTRICTED_INIT_VERSION",
    "REVIEWED_RESTRICTED_WEB_INIT_TOOLS",
    "REVIEWED_RESTRICTED_WEB_AUXILIARY_USAGE_MODELS",
    "implementation_files",
    "normalize_expected_init_contract",
    "replay_claude_stream_json",
    "validate_claude_stream_json",
]
