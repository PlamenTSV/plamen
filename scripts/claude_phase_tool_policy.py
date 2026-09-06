"""Fail-closed Claude tool policy for exact-input consumer phases.

The artifact ledger proves which inputs a model *should* consume.  This module
enforces the corresponding runtime capability boundary for the small set of
consumer phases where reading a raw producer artifact would bypass a neutral
driver projection.  It is stdlib-only so Claude Code can invoke it directly as
a ``PreToolUse`` command hook on every supported host.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import inspect
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import sys
import time
import unicodedata
from typing import Any, Iterable, Mapping
from urllib.parse import SplitResult, urlsplit, urlunsplit


POLICY_SCHEMA = "plamen.claude_phase_tool_policy.v1"
RECEIPT_SCHEMA = "plamen.claude_phase_tool_receipt.v1"
WEB_AUTHORITY_SCHEMA = "plamen.claude_bounded_web_authority.v3"
WEB_RECEIPT_SCHEMA = "plamen.claude_bounded_web_receipt.v4"
MODEL_VISIBLE_PROJECTION_SCHEMA = (
    "plamen.claude_model_visible_tool_projection.v1"
)
MAX_POLICY_BYTES = 2_000_000
DEFAULT_MAX_HOOK_INPUT_BYTES = 131_072
DEFAULT_MAX_WEB_HOOK_INPUT_BYTES = 2_000_000
DEFAULT_MAX_WEB_RESPONSE_BYTES = 1_500_000
DEFAULT_MAX_WEB_SOURCE_URLS = 100
DEPENDENCY_SEARCH_BUDGET = 1
DEPENDENCY_FETCH_BUDGET = 2
MAX_PROVIDER_SEARCHES_PER_TOOL_CALL = 3
PINNED_CLAUDE_WEB_HOOK_VERSION = "2.1.252"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_READ_TOOLS = frozenset({"Read"})
_WRITE_TOOLS = frozenset({"Write", "Edit"})
_SEARCH_TOOLS = frozenset({"Grep", "Glob"})
_RESTRICTED_READ_ALLOW_RULES = frozenset({"Glob", "Grep", "Read"})
_ALWAYS_DENIED = frozenset({"Bash", "PowerShell", "Task", "Agent"})
_WEB_TOOLS = frozenset({"WebFetch", "WebSearch"})
_FETCH_SELECTOR_RE = re.compile(r"^PLAMEN-FETCH-v1-[0-9a-f]{64}$")
_REVIEWED_CROSS_HOST_REDIRECTS = ((
    "docs.uniswap.org", "developers.uniswap.org",
),)
_DEPENDENCY_OBLIGATION_FIELDS = frozenset({
    "obligation_id", "dependency", "kind", "source_location",
    "declaration_evidence", "research_question",
})
_OBLIGATION_ID_RE = re.compile(r"^DEP-[0-9A-F]{12}$")
_URL_BAD_TEXT_RE = re.compile(r"[\x00-\x20\x7f\\]")
_VALID_PERCENT_RE = re.compile(r"%(?:[0-9A-Fa-f]{2})")


class ClaudePhaseToolPolicyError(RuntimeError):
    """Raised when policy construction or integrity validation fails."""


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _digest_unsigned(payload: Mapping[str, Any], digest_field: str) -> str:
    unsigned = {key: value for key, value in payload.items() if key != digest_field}
    return hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _norm(path: Path) -> str:
    return os.path.normcase(str(path))


def _is_within(path: Path, root: Path) -> bool:
    try:
        return os.path.commonpath((_norm(path), _norm(root))) == _norm(root)
    except ValueError:
        return False


def _has_unsafe_path_text(value: str) -> bool:
    if not value or _CONTROL_RE.search(value):
        return True
    drive, tail = os.path.splitdrive(value)
    del drive
    # A colon outside the drive designator is a Windows alternate-data-stream
    # spelling.  Reject it on every OS so a policy built on POSIX remains safe
    # when replayed on Windows.
    return ":" in tail


def _resolve_read_path(value: Any, cwd: Path) -> tuple[Path | None, str]:
    raw = str(value or "")
    if _has_unsafe_path_text(raw):
        return None, "PATH_TEXT_INVALID"
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = cwd / candidate
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError):
        return None, "READ_PATH_UNRESOLVABLE"
    if not resolved.is_file():
        return None, "READ_PATH_NOT_REGULAR_FILE"
    return resolved, ""


def _resolve_search_path(value: Any, cwd: Path) -> tuple[Path | None, str]:
    raw = str(value or "")
    if _has_unsafe_path_text(raw):
        return None, "PATH_TEXT_INVALID"
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = cwd / candidate
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError):
        return None, "SEARCH_PATH_UNRESOLVABLE"
    if not (resolved.is_file() or resolved.is_dir()):
        return None, "SEARCH_PATH_NOT_REGULAR"
    return resolved, ""


def _resolve_write_path(value: Any, cwd: Path) -> tuple[Path | None, str]:
    raw = str(value or "")
    if _has_unsafe_path_text(raw):
        return None, "PATH_TEXT_INVALID"
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = cwd / candidate
    try:
        if candidate.exists():
            resolved = candidate.resolve(strict=True)
            if not resolved.is_file():
                return None, "WRITE_PATH_NOT_REGULAR_FILE"
            return resolved, ""
        parent = candidate.parent.resolve(strict=True)
    except (OSError, RuntimeError):
        return None, "WRITE_PARENT_UNRESOLVABLE"
    return parent / candidate.name, ""


def _canonical_existing_file(path: Path) -> dict[str, Any]:
    resolved = Path(path).resolve(strict=True)
    if not resolved.is_file():
        raise ClaudePhaseToolPolicyError(f"not a regular input file: {resolved}")
    stat = resolved.stat()
    return {
        "path": resolved.as_posix(),
        "size": stat.st_size,
        "sha256": _file_sha256(resolved),
    }


def _canonical_write_file(path: Path) -> str:
    candidate = Path(path)
    if candidate.exists():
        resolved = candidate.resolve(strict=True)
        if not resolved.is_file():
            raise ClaudePhaseToolPolicyError(
                f"output path is not a regular file: {resolved}"
            )
        return resolved.as_posix()
    if not candidate.is_absolute():
        candidate = Path(os.path.abspath(candidate))
    missing: list[str] = []
    anchor = candidate.parent
    while not anchor.exists():
        if anchor.name in {"", ".", ".."}:
            raise ClaudePhaseToolPolicyError(
                f"output parent is unavailable: {candidate.parent}"
            )
        missing.append(anchor.name)
        parent = anchor.parent
        if parent == anchor:
            raise ClaudePhaseToolPolicyError(
                f"output parent is unavailable: {candidate.parent}"
            )
        anchor = parent
    try:
        resolved = anchor.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ClaudePhaseToolPolicyError(
            f"output parent is unavailable: {candidate.parent}"
        ) from exc
    if not resolved.is_dir():
        raise ClaudePhaseToolPolicyError(
            f"output parent is not a directory: {anchor}"
        )
    for component in reversed(missing):
        resolved /= component
    return (resolved / candidate.name).as_posix()


def _canonical_root(path: Path) -> str:
    resolved = Path(path).resolve(strict=True)
    if not resolved.is_dir():
        raise ClaudePhaseToolPolicyError(f"policy root is not a directory: {resolved}")
    return resolved.as_posix()


def _claude_absolute_edit_rule(path: str) -> str:
    """Render one exact absolute file using Claude permission-rule syntax."""

    value = str(path)
    if re.fullmatch(r"[A-Za-z]:/.*", value):
        specifier = f"//{value[0].lower()}{value[2:]}"
    elif value.startswith("/"):
        specifier = "/" + value
    else:
        raise ClaudePhaseToolPolicyError(
            "exact write permission path is not absolute"
        )
    return f"Edit({specifier})"


def exact_edit_permission_rules(paths: Iterable[str | Path]) -> list[str]:
    """Return the canonical exact-file allow denominator for Claude settings."""

    return sorted({
        _claude_absolute_edit_rule(Path(value).as_posix())
        for value in paths
    })


def validate_settings_overlay(
    payload: Mapping[str, Any],
    *,
    restricted_analysis: bool,
    bounded_web: bool = False,
) -> dict[str, Any]:
    """Validate one exact Claude settings capability denominator.

    Restricted analysis owns the explicit allow/defaultMode contract emitted
    by this module.  Other bound-settings lanes retain the legacy deny-only
    contract.  Callers must select the lane from authenticated launch policy;
    the two schemas are deliberately not union-accepted without context.
    """

    if not isinstance(payload, Mapping):
        raise ClaudePhaseToolPolicyError("settings root must be an object")
    settings = dict(payload)
    if set(settings) != {
        "enabledPlugins", "hooks", "mcpServers", "permissions",
    }:
        raise ClaudePhaseToolPolicyError("settings field denominator mismatch")
    if settings.get("enabledPlugins") != {} or settings.get("mcpServers") != {}:
        raise ClaudePhaseToolPolicyError(
            "settings may not grant plugins or MCP servers"
        )

    permissions = settings.get("permissions")
    expected_permission_fields = (
        {"allow", "deny", "defaultMode"}
        if restricted_analysis
        else {"deny"}
    )
    if (
        not isinstance(permissions, dict)
        or set(permissions) != expected_permission_fields
    ):
        raise ClaudePhaseToolPolicyError(
            "settings permissions denominator mismatch"
        )
    if restricted_analysis and permissions.get("defaultMode") != "default":
        raise ClaudePhaseToolPolicyError(
            "restricted settings defaultMode must be default"
        )
    list_fields = ("allow", "deny") if restricted_analysis else ("deny",)
    for field in list_fields:
        values = permissions.get(field)
        if (
            not isinstance(values, list)
            or any(not isinstance(value, str) or not value for value in values)
            or values != sorted(set(values))
        ):
            raise ClaudePhaseToolPolicyError(
                f"settings {field} denominator is not canonical"
            )
    if restricted_analysis:
        allow = permissions["allow"]
        reviewed_rules = set(_RESTRICTED_READ_ALLOW_RULES)
        if bounded_web:
            reviewed_rules.update(_WEB_TOOLS)
        if not _RESTRICTED_READ_ALLOW_RULES.issubset(allow) or any(
            rule not in reviewed_rules
            and not rule.startswith("Edit(")
            for rule in allow
        ):
            raise ClaudePhaseToolPolicyError(
                "restricted settings allow rules exceed the reviewed denominator"
            )
        if bounded_web and not _WEB_TOOLS.isdisjoint(allow):
            raise ClaudePhaseToolPolicyError(
                "bounded web tools may not be statically permission-allowed"
            )

    hooks = settings.get("hooks")
    expected_hook_events = (
        {"PreToolUse", "PostToolUse", "PostToolUseFailure"}
        if bounded_web else {"PreToolUse"}
    )
    if not isinstance(hooks, dict) or set(hooks) not in (set(), expected_hook_events):
        raise ClaudePhaseToolPolicyError("settings hook denominator mismatch")
    if restricted_analysis and set(hooks) != expected_hook_events:
        raise ClaudePhaseToolPolicyError(
            "restricted settings require the exact reviewed hook set"
        )
    if not hooks:
        return settings
    expected_identity: tuple[str, tuple[str, ...], int] | None = None
    for event_name in sorted(expected_hook_events):
        groups = hooks.get(event_name)
        if not isinstance(groups, list) or len(groups) != 1:
            raise ClaudePhaseToolPolicyError(
                f"settings require one {event_name} hook group"
            )
        group = groups[0]
        expected_matcher = ".*" if event_name == "PreToolUse" else "WebFetch|WebSearch"
        if (
            not isinstance(group, dict)
            or set(group) != {"matcher", "hooks"}
            or group.get("matcher") != expected_matcher
            or not isinstance(group.get("hooks"), list)
            or len(group["hooks"]) != 1
        ):
            raise ClaudePhaseToolPolicyError(
                f"settings {event_name} hook group is malformed"
            )
        hook = group["hooks"][0]
        if (
            not isinstance(hook, dict)
            or set(hook) != {"type", "command", "args", "timeout"}
            or hook.get("type") != "command"
            or not isinstance(hook.get("command"), str)
            or not hook["command"]
            or isinstance(hook.get("timeout"), bool)
            or not isinstance(hook.get("timeout"), int)
            or hook["timeout"] != (30 if bounded_web else 10)
        ):
            raise ClaudePhaseToolPolicyError(
                "settings command hook is malformed"
            )
        arguments = hook.get("args")
        if (
            not isinstance(arguments, list)
            or len(arguments) != 3
            or any(not isinstance(value, str) or not value for value in arguments)
            or arguments[1] != "--policy"
        ):
            raise ClaudePhaseToolPolicyError(
                "settings hook arguments are malformed"
            )
        identity = (hook["command"], tuple(arguments), hook["timeout"])
        if expected_identity is None:
            expected_identity = identity
        elif identity != expected_identity:
            raise ClaudePhaseToolPolicyError(
                "settings hook commands do not share one policy authority"
            )
    return settings


def _safe_search_roots(project_root: Path, scratchpad_root: Path) -> list[str]:
    project = project_root.resolve(strict=True)
    scratchpad = scratchpad_root.resolve(strict=True)
    roots: set[str] = set()
    for child in sorted(project.iterdir(), key=lambda item: item.name.casefold()):
        try:
            resolved = child.resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        # A lexical project child may be a symlink/junction into a host path.
        # Search authority is granted to the resolved object, so require that
        # object to remain strictly below the project and outside every path
        # that could expose the scratchpad through an ancestor search.
        if resolved == project or not _is_within(resolved, project):
            continue
        if _is_within(resolved, scratchpad) or _is_within(scratchpad, resolved):
            continue
        if resolved.is_dir():
            roots.add(resolved.as_posix())
    return sorted(roots)


def _bounded_untrusted_text(
    value: Any, *, field: str, max_characters: int, max_bytes: int,
) -> str:
    """Admit one canonical single-line string before policy/model exposure."""

    if not isinstance(value, str) or not value:
        raise ClaudePhaseToolPolicyError(f"{field} must be a nonempty string")
    if unicodedata.normalize("NFC", value) != value:
        raise ClaudePhaseToolPolicyError(f"{field} is not NFC-canonical")
    if (
        "`" in value
        or len(value) > max_characters
        or len(value.encode("utf-8", errors="strict")) > max_bytes
        or any(
            unicodedata.category(character).startswith("C")
            or unicodedata.category(character) in {"Zl", "Zp"}
            for character in value
        )
    ):
        raise ClaudePhaseToolPolicyError(f"{field} contains unsafe text")
    return value


def _dependency_rows(
    obligations: Iterable[Mapping[str, Any]] | Mapping[str, Any],
) -> list[dict[str, str]]:
    if isinstance(obligations, Mapping):
        envelope = dict(obligations)
        if set(envelope) != {
            "schema", "provider", "obligations", "observed_count",
            "retained_count", "truncated", "overflow_ids",
        }:
            raise ClaudePhaseToolPolicyError(
                "dependency obligation envelope denominator mismatch"
            )
        if envelope.get("schema") != "plamen.external-dependency-obligations.v1":
            raise ClaudePhaseToolPolicyError("dependency obligation schema mismatch")
        if envelope.get("provider") != "deterministic-direct-nonlocal-referenced-v1":
            raise ClaudePhaseToolPolicyError("dependency obligation provider mismatch")
        raw_rows = envelope.get("obligations")
        if (
            not isinstance(raw_rows, list)
            or isinstance(envelope.get("truncated"), bool) is False
            or not isinstance(envelope.get("observed_count"), int)
            or not isinstance(envelope.get("retained_count"), int)
            or envelope["retained_count"] != len(raw_rows)
            or envelope["observed_count"] < envelope["retained_count"]
            or envelope["truncated"]
            != (envelope["observed_count"] > envelope["retained_count"])
            or not isinstance(envelope.get("overflow_ids"), list)
        ):
            raise ClaudePhaseToolPolicyError(
                "dependency obligation envelope counts are invalid"
            )
        overflow_ids = envelope["overflow_ids"]
        if (
            len(overflow_ids) != envelope["observed_count"] - envelope["retained_count"]
            or len(overflow_ids) > 50_000
            or any(
                not isinstance(value, str) or not _OBLIGATION_ID_RE.fullmatch(value)
                for value in overflow_ids
            )
            or overflow_ids != sorted(set(overflow_ids))
        ):
            raise ClaudePhaseToolPolicyError(
                "dependency obligation overflow denominator is invalid"
            )
    else:
        raw_rows = list(obligations)
    if not isinstance(raw_rows, list) or len(raw_rows) > 100:
        raise ClaudePhaseToolPolicyError("dependency obligation bound exceeded")
    checked: list[dict[str, str]] = []
    seen: set[str] = set()
    for raw in raw_rows:
        if not isinstance(raw, Mapping) or set(raw) != _DEPENDENCY_OBLIGATION_FIELDS:
            raise ClaudePhaseToolPolicyError(
                "dependency obligation row denominator mismatch"
            )
        row = dict(raw)
        obligation_id = str(row.get("obligation_id") or "")
        if not _OBLIGATION_ID_RE.fullmatch(obligation_id) or obligation_id in seen:
            raise ClaudePhaseToolPolicyError("dependency obligation ID is invalid")
        seen.add(obligation_id)
        admitted = {"obligation_id": obligation_id}
        for field, char_cap, byte_cap in (
            ("dependency", 300, 1_200),
            ("kind", 80, 320),
            ("source_location", 600, 2_400),
            ("declaration_evidence", 500, 2_000),
            ("research_question", 500, 2_000),
        ):
            admitted[field] = _bounded_untrusted_text(
                row.get(field), field=field,
                max_characters=char_cap, max_bytes=byte_cap,
            )
        expected_id = "DEP-" + hashlib.sha256(
            (
                admitted["kind"] + "\0"
                + admitted["dependency"].casefold() + "\0"
                + admitted["source_location"].casefold()
            ).encode("utf-8")
        ).hexdigest()[:12].upper()
        if obligation_id != expected_id:
            raise ClaudePhaseToolPolicyError(
                "dependency obligation ID does not match its semantic row"
            )
        checked.append(admitted)
    if [row["obligation_id"] for row in checked] != sorted(seen):
        raise ClaudePhaseToolPolicyError(
            "dependency obligation rows are not canonically ordered"
        )
    return checked


def build_dependency_research_network_authority(
    obligations: Iterable[Mapping[str, Any]] | Mapping[str, Any],
) -> dict[str, Any]:
    """Compile raw dependency obligations into exact bounded web requests.

    Source locations and declaration evidence are authenticated on admission
    but intentionally omitted from model-visible queries.
    """

    rows: list[dict[str, Any]] = []
    for row in _dependency_rows(obligations):
        query = " ".join((
            row["dependency"], row["kind"], row["research_question"],
            "official documentation temporal guarantees failure behavior",
        ))
        query = _bounded_untrusted_text(
            query, field="derived dependency query",
            max_characters=1_500, max_bytes=6_000,
        )
        fetch_prompt = (
            "Extract externally defined semantics, temporal guarantees, failure "
            "behavior, and integration assumptions for dependency "
            f"{row['dependency']} ({row['kind']})."
        )
        rows.append({
            "obligation_id": row["obligation_id"],
            "query": query,
            "fetch_prompt": fetch_prompt,
            "search_budget": DEPENDENCY_SEARCH_BUDGET,
            "fetch_budget": DEPENDENCY_FETCH_BUDGET,
            "obligation_digest": hashlib.sha256(
                canonical_json_bytes(row)
            ).hexdigest(),
        })
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(str(row["query"]), []).append(row)
    for query, members in grouped.items():
        selector_payload = {
            "query": query,
            "fetch_prompt": members[0]["fetch_prompt"],
            "obligation_ids": sorted(row["obligation_id"] for row in members),
        }
        selector = "PLAMEN-FETCH-v1-" + hashlib.sha256(
            canonical_json_bytes(selector_payload)
        ).hexdigest()
        for row in members:
            row["fetch_selector"] = selector

    authority: dict[str, Any] = {
        "schema_version": WEB_AUTHORITY_SCHEMA,
        "mode": "BOUNDED_RECEIPTS",
        "provider_version": PINNED_CLAUDE_WEB_HOOK_VERSION,
        "permission_mode": "default",
        "obligations": rows,
        "max_event_bytes": DEFAULT_MAX_WEB_HOOK_INPUT_BYTES,
        "max_response_bytes": DEFAULT_MAX_WEB_RESPONSE_BYTES,
        "max_source_urls": DEFAULT_MAX_WEB_SOURCE_URLS,
        "redirect_host_pairs": [list(pair) for pair in _REVIEWED_CROSS_HOST_REDIRECTS],
    }
    authority["authority_digest"] = _digest_unsigned(
        authority, "authority_digest"
    )
    return validate_dependency_research_network_authority(authority)


def validate_dependency_research_network_authority(
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        raise ClaudePhaseToolPolicyError("web authority root must be an object")
    authority = dict(payload)
    if set(authority) != {
        "schema_version", "mode", "provider_version", "permission_mode",
        "obligations", "max_event_bytes",
        "max_response_bytes", "max_source_urls", "redirect_host_pairs",
        "authority_digest",
    }:
        raise ClaudePhaseToolPolicyError("web authority denominator mismatch")
    if (
        authority.get("schema_version") != WEB_AUTHORITY_SCHEMA
        or authority.get("mode") != "BOUNDED_RECEIPTS"
        or authority.get("provider_version") != PINNED_CLAUDE_WEB_HOOK_VERSION
        or authority.get("permission_mode") != "default"
        or authority.get("authority_digest")
        != _digest_unsigned(authority, "authority_digest")
    ):
        raise ClaudePhaseToolPolicyError("web authority integrity mismatch")
    for field, minimum, maximum in (
        ("max_event_bytes", 131_072, 4_000_000),
        ("max_response_bytes", 65_536, 3_000_000),
        ("max_source_urls", 1, 500),
    ):
        value = authority.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
            raise ClaudePhaseToolPolicyError(f"web authority {field} is invalid")
    if authority.get("redirect_host_pairs") != [
        list(pair) for pair in _REVIEWED_CROSS_HOST_REDIRECTS
    ]:
        raise ClaudePhaseToolPolicyError("web authority redirect denominator is invalid")
    rows = authority.get("obligations")
    if not isinstance(rows, list) or len(rows) > 100:
        raise ClaudePhaseToolPolicyError("web authority obligation bound exceeded")
    ids: list[str] = []
    query_prompts: dict[str, str] = {}
    for row in rows:
        if not isinstance(row, dict) or set(row) != {
            "obligation_id", "query", "fetch_prompt", "fetch_selector",
            "search_budget", "fetch_budget",
            "obligation_digest",
        }:
            raise ClaudePhaseToolPolicyError("web authority row is malformed")
        obligation_id = str(row.get("obligation_id") or "")
        query = _bounded_untrusted_text(
            row.get("query"), field="web query",
            max_characters=1_500, max_bytes=6_000,
        )
        _bounded_untrusted_text(
            row.get("fetch_prompt"), field="web fetch prompt",
            max_characters=500, max_bytes=2_000,
        )
        if (
            not _OBLIGATION_ID_RE.fullmatch(obligation_id)
            or row.get("search_budget") != DEPENDENCY_SEARCH_BUDGET
            or row.get("fetch_budget") != DEPENDENCY_FETCH_BUDGET
            or not _SHA256_RE.fullmatch(str(row.get("obligation_digest") or ""))
        ):
            raise ClaudePhaseToolPolicyError("web authority row is invalid")
        prompt = str(row["fetch_prompt"])
        selector = str(row.get("fetch_selector") or "")
        if _FETCH_SELECTOR_RE.fullmatch(selector) is None:
            raise ClaudePhaseToolPolicyError("web authority fetch selector is invalid")
        if query in query_prompts and query_prompts[query] != prompt:
            raise ClaudePhaseToolPolicyError(
                "web authority query group has ambiguous fetch prompts"
            )
        ids.append(obligation_id)
        query_prompts[query] = prompt
    if ids != sorted(set(ids)):
        raise ClaudePhaseToolPolicyError("web authority rows are not canonical")
    _web_query_groups(authority)
    return authority


def _web_query_groups(authority: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Return canonical exact-query groups without exposing private row data."""

    groups: dict[str, dict[str, Any]] = {}
    for row in authority["obligations"]:
        query = str(row["query"])
        current = groups.setdefault(query, {
            "obligation_ids": [],
            "query": query,
            "fetch_prompt": row["fetch_prompt"],
            "fetch_selector": row["fetch_selector"],
            "search_budget": row["search_budget"],
            "fetch_budget": row["fetch_budget"],
        })
        if (
            current["fetch_prompt"] != row["fetch_prompt"]
            or current["fetch_selector"] != row["fetch_selector"]
            or current["search_budget"] != row["search_budget"]
            or current["fetch_budget"] != row["fetch_budget"]
        ):
            raise ClaudePhaseToolPolicyError(
                "web authority query group is internally inconsistent"
            )
        current["obligation_ids"].append(row["obligation_id"])
    result = []
    for query in sorted(groups):
        group = {**groups[query], "obligation_ids": sorted(groups[query]["obligation_ids"])}
        expected = "PLAMEN-FETCH-v1-" + hashlib.sha256(canonical_json_bytes({
            "query": group["query"],
            "fetch_prompt": group["fetch_prompt"],
            "obligation_ids": group["obligation_ids"],
        })).hexdigest()
        if group["fetch_selector"] != expected:
            raise ClaudePhaseToolPolicyError("web authority fetch selector differs")
        result.append(group)
    return result


def build_policy_manifest(
    *,
    run_id: str,
    phase: str,
    attempt: int,
    expected_cwd: Path,
    project_root: Path,
    scratchpad_root: Path,
    methodology_read_roots: Iterable[Path],
    exact_read_files: Iterable[Path],
    exact_write_files: Iterable[Path],
    forbidden_read_files: Iterable[Path],
    receipt_directory: Path,
    network_authority: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a canonical, hash-bound capability manifest."""

    run = str(run_id or "").strip()
    phase_name = str(phase or "").strip()
    if not run or not phase_name or not isinstance(attempt, int) or attempt < 1:
        raise ClaudePhaseToolPolicyError("run_id, phase, and positive attempt are required")
    cwd = Path(expected_cwd).resolve(strict=True)
    project = Path(project_root).resolve(strict=True)
    scratchpad = Path(scratchpad_root).resolve(strict=True)
    receipts = Path(receipt_directory)
    receipts.mkdir(parents=True, exist_ok=True)
    receipts = receipts.resolve(strict=True)

    reads_by_path: dict[str, dict[str, Any]] = {}
    for item in exact_read_files:
        row = _canonical_existing_file(Path(item))
        reads_by_path[row["path"]] = row
    writes = sorted({_canonical_write_file(Path(item)) for item in exact_write_files})
    forbidden: list[str] = []
    for item in forbidden_read_files:
        candidate = Path(item)
        if candidate.exists():
            forbidden.append(candidate.resolve(strict=True).as_posix())
        else:
            try:
                forbidden.append(
                    (candidate.parent.resolve(strict=True) / candidate.name).as_posix()
                )
            except (OSError, RuntimeError) as exc:
                raise ClaudePhaseToolPolicyError(
                    f"forbidden path parent is unavailable: {candidate}"
                ) from exc

    manifest: dict[str, Any] = {
        "schema_version": POLICY_SCHEMA,
        "policy_id": f"{run}:{phase_name}:{attempt}",
        "run_id": run,
        "phase": phase_name,
        "attempt": attempt,
        "backend": "claude",
        "expected_cwd": cwd.as_posix(),
        "project_root": project.as_posix(),
        "scratchpad_root": scratchpad.as_posix(),
        "methodology_read_roots": sorted({
            _canonical_root(Path(item)) for item in methodology_read_roots
        }),
        "exact_read_files": [reads_by_path[key] for key in sorted(reads_by_path)],
        "exact_write_files": writes,
        "forbidden_read_files": sorted(set(forbidden)),
        "source_read_root": project.as_posix(),
        "source_excluded_roots": [scratchpad.as_posix()],
        "safe_search_roots": _safe_search_roots(project, scratchpad),
        "allowed_tools": ["Edit", "Glob", "Grep", "Read", "Write"],
        "denied_tools": [
            "Agent", "Bash", "Task", "WebFetch", "WebSearch", "mcp__*",
        ],
        "external_network_policy": "DENY",
        "bash_policy": "DENY",
        "unknown_tool_policy": "DENY",
        "max_hook_input_bytes": DEFAULT_MAX_HOOK_INPUT_BYTES,
        "receipt_directory": receipts.as_posix(),
    }
    if network_authority is not None:
        authority = validate_dependency_research_network_authority(
            network_authority
        )
        manifest["network_authority"] = authority
        manifest["allowed_tools"] = sorted(
            set(manifest["allowed_tools"]) | _WEB_TOOLS
        )
        manifest["denied_tools"] = [
            value for value in manifest["denied_tools"]
            if value not in _WEB_TOOLS
        ]
        manifest["external_network_policy"] = "BOUNDED_RECEIPTS"
        manifest["max_hook_input_bytes"] = authority["max_event_bytes"]
    manifest["manifest_digest"] = _digest_unsigned(manifest, "manifest_digest")
    return manifest


def validate_policy_manifest(payload: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        raise ClaudePhaseToolPolicyError("policy root must be an object")
    policy = dict(payload)
    required = {
        "schema_version", "policy_id", "manifest_digest", "run_id", "phase",
        "attempt", "backend", "expected_cwd", "project_root", "scratchpad_root",
        "methodology_read_roots", "exact_read_files", "exact_write_files",
        "forbidden_read_files", "source_read_root", "source_excluded_roots",
        "safe_search_roots", "allowed_tools", "denied_tools",
        "external_network_policy", "bash_policy", "unknown_tool_policy",
        "max_hook_input_bytes", "receipt_directory",
    }
    has_web = "network_authority" in policy
    if set(policy) != required | ({"network_authority"} if has_web else set()):
        raise ClaudePhaseToolPolicyError("policy field denominator mismatch")
    if policy.get("schema_version") != POLICY_SCHEMA:
        raise ClaudePhaseToolPolicyError("policy schema mismatch")
    digest = str(policy.get("manifest_digest") or "")
    if not _SHA256_RE.fullmatch(digest) or digest != _digest_unsigned(
        policy, "manifest_digest"
    ):
        raise ClaudePhaseToolPolicyError("policy digest mismatch")
    expected_network = "BOUNDED_RECEIPTS" if has_web else "DENY"
    if policy.get("external_network_policy") != expected_network or (
        policy.get("bash_policy") != "DENY"
        or policy.get("unknown_tool_policy") != "DENY"
    ):
        raise ClaudePhaseToolPolicyError("policy is not fail closed")
    expected_tools = ["Edit", "Glob", "Grep", "Read", "Write"]
    if has_web:
        validate_dependency_research_network_authority(
            policy["network_authority"]
        )
        expected_tools = sorted(set(expected_tools) | _WEB_TOOLS)
    if policy.get("allowed_tools") != expected_tools:
        raise ClaudePhaseToolPolicyError("allowed tool set mismatch")
    expected_denies = [
        "Agent", "Bash", "Task", "WebFetch", "WebSearch", "mcp__*",
    ]
    if has_web:
        expected_denies = [
            value for value in expected_denies if value not in _WEB_TOOLS
        ]
    if policy.get("denied_tools") != expected_denies:
        raise ClaudePhaseToolPolicyError("denied tool set mismatch")
    max_hook_cap = 4_000_000 if has_web else 1_000_000
    if not isinstance(policy.get("max_hook_input_bytes"), int) or not (
        1024 <= int(policy["max_hook_input_bytes"]) <= max_hook_cap
    ):
        raise ClaudePhaseToolPolicyError("hook input bound is invalid")
    if has_web and policy["max_hook_input_bytes"] != policy["network_authority"]["max_event_bytes"]:
        raise ClaudePhaseToolPolicyError("web hook input bound drift")
    for field in (
        "methodology_read_roots", "exact_read_files", "exact_write_files",
        "forbidden_read_files", "source_excluded_roots", "safe_search_roots",
        "denied_tools",
    ):
        if not isinstance(policy.get(field), list):
            raise ClaudePhaseToolPolicyError(f"{field} must be a list")
    for row in policy["exact_read_files"]:
        if (
            not isinstance(row, dict)
            or set(row) != {"path", "size", "sha256"}
            or not isinstance(row["size"], int)
            or row["size"] < 0
            or not _SHA256_RE.fullmatch(str(row["sha256"]))
        ):
            raise ClaudePhaseToolPolicyError("exact read row is malformed")
    return policy


def _validated_project_relative_path(value: Any, *, field: str) -> str:
    raw = str(value or "")
    if (
        _has_unsafe_path_text(raw)
        or "`" in raw
        or any(
            unicodedata.category(character).startswith("C")
            or unicodedata.category(character) in {"Zl", "Zp"}
            for character in raw
        )
    ):
        raise ClaudePhaseToolPolicyError(f"{field} contains invalid path text")
    candidate = Path(raw)
    if candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
        raise ClaudePhaseToolPolicyError(
            f"{field} must contain strict project-relative paths"
        )
    rendered = candidate.as_posix()
    if rendered.startswith("/") or rendered == ".":
        raise ClaudePhaseToolPolicyError(
            f"{field} must contain strict project-relative paths"
        )
    return rendered


def validate_model_visible_projection(
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate the content-minimal tool contract shown to the model."""

    if not isinstance(payload, Mapping):
        raise ClaudePhaseToolPolicyError(
            "model-visible projection root must be an object"
        )
    projection = dict(payload)
    base_fields = {
        "schema_version", "safe_search_roots", "exact_input_paths",
    }
    has_web = "web_research" in projection
    if set(projection) != base_fields | ({"web_research"} if has_web else set()):
        raise ClaudePhaseToolPolicyError(
            "model-visible projection field denominator mismatch"
        )
    if projection.get("schema_version") != MODEL_VISIBLE_PROJECTION_SCHEMA:
        raise ClaudePhaseToolPolicyError(
            "model-visible projection schema mismatch"
        )
    for field in ("safe_search_roots", "exact_input_paths"):
        values = projection.get(field)
        if (
            not isinstance(values, list)
            or any(not isinstance(value, str) for value in values)
            or values != sorted(set(values))
        ):
            raise ClaudePhaseToolPolicyError(
                f"model-visible {field} denominator is not canonical"
            )
        projection[field] = [
            _validated_project_relative_path(value, field=field)
            for value in values
        ]
    if has_web:
        rows = projection.get("web_research")
        if not isinstance(rows, list) or len(rows) > 100:
            raise ClaudePhaseToolPolicyError(
                "model-visible web denominator is invalid"
            )
        ids: list[str] = []
        queries: list[str] = []
        for row in rows:
            if not isinstance(row, dict) or set(row) != {
                "obligation_ids", "query", "fetch_selector",
                "search_budget", "fetch_budget",
            }:
                raise ClaudePhaseToolPolicyError(
                    "model-visible web row is malformed"
                )
            obligation_ids = row.get("obligation_ids")
            if (
                not isinstance(obligation_ids, list)
                or not obligation_ids
                or obligation_ids != sorted(set(obligation_ids))
                or any(
                    not isinstance(value, str)
                    or not _OBLIGATION_ID_RE.fullmatch(value)
                    for value in obligation_ids
                )
                or row.get("search_budget") != DEPENDENCY_SEARCH_BUDGET
                or row.get("fetch_budget") != DEPENDENCY_FETCH_BUDGET
            ):
                raise ClaudePhaseToolPolicyError(
                    "model-visible web row is invalid"
                )
            query = _bounded_untrusted_text(
                row.get("query"), field="model-visible web query",
                max_characters=1_500, max_bytes=6_000,
            )
            if _FETCH_SELECTOR_RE.fullmatch(str(row.get("fetch_selector") or "")) is None:
                raise ClaudePhaseToolPolicyError(
                    "model-visible web fetch selector is invalid"
                )
            ids.extend(obligation_ids)
            queries.append(query)
        if len(ids) != len(set(ids)) or queries != sorted(set(queries)):
            raise ClaudePhaseToolPolicyError(
                "model-visible web rows are not canonical"
            )
    return projection


def build_model_visible_projection(
    policy: Mapping[str, Any],
    *,
    phase_io_input_paths: Iterable[Path],
    private_exact_read_paths: Iterable[Path] = (),
) -> dict[str, Any]:
    """Project the written policy into a deterministic, non-sensitive prompt.

    The caller supplies the PhaseIO denominator and the private exact reads
    (currently the original prompt snapshot).  Both sets must account for the
    exact-read rows in the already-written policy.  This prevents a prompt
    projection from advertising guessed inputs or silently omitting an extra
    policy-visible control file.
    """

    checked = validate_policy_manifest(policy)
    project = Path(str(checked["project_root"])).resolve(strict=True)
    scratchpad = Path(str(checked["scratchpad_root"])).resolve(strict=True)
    receipt_root = Path(str(checked["receipt_directory"])).resolve(strict=True)

    def _existing(value: Path, *, field: str) -> Path:
        try:
            return Path(value).resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise ClaudePhaseToolPolicyError(
                f"model-visible {field} path is unavailable"
            ) from exc

    phase_inputs: dict[str, Path] = {}
    for value in phase_io_input_paths:
        resolved = _existing(Path(value), field="PhaseIO input")
        phase_inputs[_norm(resolved)] = resolved
    private_reads: dict[str, Path] = {}
    for value in private_exact_read_paths:
        resolved = _existing(Path(value), field="private read")
        private_reads[_norm(resolved)] = resolved
    if set(phase_inputs) & set(private_reads):
        raise ClaudePhaseToolPolicyError(
            "PhaseIO and private exact-read denominators overlap"
        )
    try:
        actual_reads = {
            _norm(Path(str(row["path"])).resolve(strict=True))
            for row in checked["exact_read_files"]
        }
    except (OSError, RuntimeError) as exc:
        raise ClaudePhaseToolPolicyError(
            "written policy exact-read path is unavailable"
        ) from exc
    if actual_reads != set(phase_inputs) | set(private_reads):
        raise ClaudePhaseToolPolicyError(
            "model-visible exact-read denominator differs from written policy"
        )

    forbidden = {
        _norm(Path(str(value)).resolve(strict=False))
        for value in checked["forbidden_read_files"]
    }
    methodology_roots = [
        Path(str(value)).resolve(strict=True)
        for value in checked["methodology_read_roots"]
    ]
    exact_relative: list[str] = []
    for key, path in phase_inputs.items():
        if (
            key in forbidden
            or _is_within(path, receipt_root)
            or any(_is_within(path, root) for root in methodology_roots)
            or not _is_within(path, project)
        ):
            raise ClaudePhaseToolPolicyError(
                "model-visible PhaseIO input crosses a private policy boundary"
            )
        exact_relative.append(path.relative_to(project).as_posix())

    safe_relative: list[str] = []
    for raw in checked["safe_search_roots"]:
        path = Path(str(raw)).resolve(strict=True)
        if (
            not path.is_dir()
            or path == project
            or not _is_within(path, project)
            or _is_within(path, scratchpad)
            or _is_within(scratchpad, path)
        ):
            raise ClaudePhaseToolPolicyError(
                "model-visible safe search root crosses its policy boundary"
            )
        safe_relative.append(path.relative_to(project).as_posix())

    projection: dict[str, Any] = {
        "schema_version": MODEL_VISIBLE_PROJECTION_SCHEMA,
        "safe_search_roots": sorted(set(safe_relative)),
        "exact_input_paths": sorted(set(exact_relative)),
    }
    authority = checked.get("network_authority")
    if isinstance(authority, Mapping):
        web = validate_dependency_research_network_authority(authority)
        projection["web_research"] = [
            {
                key: row[key]
                for key in (
                    "obligation_ids", "query", "fetch_selector",
                    "search_budget", "fetch_budget",
                )
            }
            for row in _web_query_groups(web)
        ]
    return validate_model_visible_projection(projection)


def render_model_visible_supervisor_block(
    projection: Mapping[str, Any],
) -> str:
    """Render the exact restricted-Claude file-tool instructions."""

    checked = validate_model_visible_projection(projection)

    def _rows(values: list[str]) -> str:
        if not values:
            return "- (none)"
        return "\n".join(f"- `{value}`" for value in values)

    web_block = ""
    if "web_research" in checked:
        web_rows = "\n".join(
            "- " + json.dumps(
                {
                    "obligation_ids": row["obligation_ids"],
                    "query": row["query"],
                    "fetch_selector": row["fetch_selector"],
                    "search_budget": row["search_budget"],
                    "fetch_budget": row["fetch_budget"],
                },
                sort_keys=True, ensure_ascii=True, separators=(",", ":"),
            )
            for row in checked["web_research"]
        ) or "- (none)"
        web_block = """

Bounded dependency web research (canonical JSON rows):
{web_rows}

- WebSearch may use only an exact listed `query`, with no domain filters or
  extra fields. Each query may run once. Issue one WebSearch and WAIT until
  its result has been received and processed before issuing WebFetch. Do not
  issue WebFetch in the same assistant message; only in a later assistant
  turn. Never batch or parallelize WebSearch with WebFetch.
- WebFetch may fetch only an HTTPS URL returned by a successful WebSearch in
  this same session, or the exact related-host redirect URL returned by a
  successful WebFetch receipt in this same session. Describe the evidence to
  extract normally in its `prompt` field. The authenticated pre-tool hook
  resolves the unique unconsumed URL-parent lineage and replaces the whole
  input with the bound canonical URL and research prompt before execution. If
  more than one eligible group returned the same URL, use the corresponding
  opaque `fetch_selector` alone to disambiguate. At most one redirect may be followed,
  and only when returned from a directly search-returned URL; never follow a
  redirect returned by that successor. Unregistered cross-host redirects,
  guessed URLs, direct URLs, and previously failed URLs are forbidden.
- Use one source-acquisition chain per canonical row: one exact WebSearch,
  then one selected WebFetch, plus its single admitted redirect successor if
  present. Do not fetch multiple candidates. If a selector is needed for
  disambiguation, copy it exactly and never add prose. If any web call is denied, or a
  redirect successor returns another redirect, stop all web calls immediately
  and record the affected obligations as not researched.
- Do not retry failed or timed-out web calls. Every source URL claimed in the
  output must have a successful WebFetch receipt for its obligation.
""".format(web_rows=web_rows)

    return """## Restricted Claude Supervisor Tool Contract

This driver-owned block is derived from the actual tool policy written for
this attempt. Paths below are relative to PROJECT_ROOT.

Safe source search roots for Glob/Grep:
{safe_roots}

Exact PhaseIO input files:
{exact_inputs}
{web_block}

- Every Glob or Grep call MUST set `path` explicitly. Glob MUST use exactly one
  listed safe source search root. Grep MUST use either one listed safe source
  search root, one exact PhaseIO input file listed above, or, after it has been
  written, one exact attempt-owned output path listed by the final Runtime
  output routing block. Grep admission for an exact PhaseIO input revalidates
  its bound byte length and SHA-256 immediately before the call. Never search
  PROJECT_ROOT, the scratchpad root, `.`, an omitted path, or a guessed path.
- A root-level config name such as `foundry.toml` is not permission to probe
  PROJECT_ROOT. Never call Glob/Grep with `path: "."` to locate it. If a needed
  config is not an exact PhaseIO input and is not below a listed safe search
  root, report that evidence unavailable instead of probing; a denial makes
  the whole attempt unusable.
- Read only an exact PhaseIO input listed above, an existing regular source
  file returned by an allowed Glob/Grep call, or an exact attempt-owned output
  after writing it. Never use Read for existence checks, directory probes, or
  guessed paths.
- Use commands only when the runtime exposes an execution tool.
  Restricted Claude exposes no shell/execution tool: consume the bound evidence and
  report `NOT_ATTEMPTED` when command execution evidence is unavailable.
- Any tool-policy DENY invalidates this attempt. Do not retry a denied call.
""".format(
        safe_roots=_rows(checked["safe_search_roots"]),
        exact_inputs=_rows(checked["exact_input_paths"]),
        web_block=web_block,
    )


def provider_builtin_tools(policy: Mapping[str, Any]) -> tuple[str, ...]:
    """Return the exact provider tool denominator from a validated policy."""

    checked = validate_policy_manifest(policy)
    return tuple(checked["allowed_tools"])


def load_policy(path: Path) -> dict[str, Any]:
    target = Path(path)
    try:
        raw = target.read_bytes()
    except OSError as exc:
        raise ClaudePhaseToolPolicyError(f"policy is unreadable: {exc}") from exc
    if len(raw) > MAX_POLICY_BYTES:
        raise ClaudePhaseToolPolicyError("policy exceeds byte bound")
    try:
        payload = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ClaudePhaseToolPolicyError("policy JSON is invalid") from exc
    return validate_policy_manifest(payload)


def build_settings_overlay(
    *, policy: Mapping[str, Any], policy_path: Path, hook_script: Path,
) -> dict[str, Any]:
    checked = validate_policy_manifest(policy)
    hook = Path(hook_script).resolve(strict=True)
    policy_file = Path(policy_path).resolve(strict=True)
    bounded_web = checked["external_network_policy"] == "BOUNDED_RECEIPTS"
    deny_rules: list[str] = []
    cwd = Path(str(checked["expected_cwd"]))
    for raw in checked["forbidden_read_files"]:
        absolute = Path(str(raw)).as_posix()
        deny_rules.append(f"Read({absolute})")
        try:
            relative = Path(absolute).relative_to(cwd).as_posix()
        except ValueError:
            continue
        deny_rules.extend((f"Read({relative})", f"Read(./{relative})"))
    allow_rules = [
        *_RESTRICTED_READ_ALLOW_RULES,
        *exact_edit_permission_rules(checked["exact_write_files"]),
    ]
    # Web tools are made available through the provider's `--tools` surface,
    # but are deliberately not statically permission-allowed here. The
    # PreToolUse hook must return ALLOW for every bounded request; if the
    # command hook times out, Claude falls through to the scrubbed default
    # denial instead of gaining network access.
    hook_entry = {
        "matcher": ".*",
        "hooks": [
            {
                "type": "command",
                "command": Path(sys.executable).resolve().as_posix(),
                "args": [
                    hook.as_posix(),
                    "--policy",
                    policy_file.as_posix(),
                ],
                "timeout": 30 if bounded_web else 10,
            }
        ],
    }
    settings = {
        "enabledPlugins": {},
        "mcpServers": {},
        "permissions": {
            "allow": sorted(set(allow_rules)),
            "deny": sorted(set(deny_rules)),
            "defaultMode": "default",
        },
        "hooks": {
            "PreToolUse": [hook_entry],
        },
    }
    if bounded_web:
        for event_name in ("PostToolUse", "PostToolUseFailure"):
            settings["hooks"][event_name] = [{
                **hook_entry,
                "matcher": "WebFetch|WebSearch",
            }]
    return validate_settings_overlay(
        settings, restricted_analysis=True, bounded_web=bounded_web,
    )


def write_policy_bundle(
    *, policy_path: Path, settings_path: Path, hook_script: Path, **manifest_kwargs: Any,
) -> tuple[dict[str, Any], dict[str, Any]]:
    policy = build_policy_manifest(**manifest_kwargs)
    policy_target = Path(policy_path)
    settings_target = Path(settings_path)
    policy_target.parent.mkdir(parents=True, exist_ok=True)
    settings_target.parent.mkdir(parents=True, exist_ok=True)
    policy_target.write_bytes(canonical_json_bytes(policy))
    # Resolve only after the policy exists; the settings hook binds its exact
    # absolute path and does not depend on the worker cwd.
    settings = build_settings_overlay(
        policy=policy, policy_path=policy_target, hook_script=hook_script
    )
    settings_target.write_bytes(canonical_json_bytes(settings))
    return policy, settings


def write_dependency_research_policy_bundle(
    *, obligations: Iterable[Mapping[str, Any]] | Mapping[str, Any],
    policy_path: Path, settings_path: Path, hook_script: Path,
    **manifest_kwargs: Any,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Write one filesystem policy extended by bounded dependency web access."""

    if "network_authority" in manifest_kwargs:
        raise ClaudePhaseToolPolicyError(
            "dependency bundle owns the network_authority argument"
        )
    return write_policy_bundle(
        policy_path=policy_path,
        settings_path=settings_path,
        hook_script=hook_script,
        network_authority=build_dependency_research_network_authority(
            obligations
        ),
        **manifest_kwargs,
    )


def _path_rows(policy: Mapping[str, Any], field: str) -> list[Path]:
    return [Path(str(value)) for value in policy.get(field, [])]


def _read_index(policy: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    return {
        _norm(Path(str(row["path"]))): row
        for row in policy.get("exact_read_files", [])
        if isinstance(row, Mapping)
    }


def _source_read_allowed(path: Path, policy: Mapping[str, Any]) -> bool:
    root = Path(str(policy["source_read_root"]))
    if not _is_within(path, root):
        return False
    return not any(
        _is_within(path, excluded)
        for excluded in _path_rows(policy, "source_excluded_roots")
    )


def _normalize_https_url(value: Any) -> str:
    def _legacy_numeric_host(host: str) -> bool:
        parts = host.split(".")
        return bool(parts) and all(
            re.fullmatch(r"(?:0[xX][0-9A-Fa-f]+|[0-9]+)", part)
            for part in parts
        )

    if not isinstance(value, str) or not value or len(value) > 4096:
        raise ClaudePhaseToolPolicyError("web URL is invalid")
    if (
        unicodedata.normalize("NFC", value) != value
        or _URL_BAD_TEXT_RE.search(value)
        or any(
            unicodedata.category(character).startswith(("C", "Z"))
            for character in value
        )
    ):
        raise ClaudePhaseToolPolicyError("web URL contains unsafe text")
    invalid_percent = _VALID_PERCENT_RE.sub("", value)
    if "%" in invalid_percent:
        raise ClaudePhaseToolPolicyError("web URL has malformed percent encoding")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ClaudePhaseToolPolicyError("web URL authority is malformed") from exc
    if (
        parsed.scheme.casefold() != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or port not in (None, 443)
    ):
        raise ClaudePhaseToolPolicyError("web URL authority is unsafe")
    hostname = parsed.hostname
    if not hostname or hostname.endswith("."):
        raise ClaudePhaseToolPolicyError("web URL hostname is malformed")
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        # WHATWG/browser URL parsers may accept legacy dotted, octal, or
        # hexadecimal IPv4 spellings that Python intentionally treats as DNS.
        # Reject the entire numeric-looking legacy grammar before IDNA so a
        # loopback literal cannot be laundered through provider-side parsing.
        if _legacy_numeric_host(hostname):
            raise ClaudePhaseToolPolicyError("web URL IP literal is non-canonical")
        # Do not guess whether Claude's fetch service uses IDNA2003 or modern
        # UTS-46 semantics. Callers must supply an already-canonical ASCII
        # hostname (including explicit xn-- labels where appropriate).
        if not hostname.isascii():
            raise ClaudePhaseToolPolicyError("web URL hostname must be canonical ASCII")
        ascii_host = hostname.casefold()
        if _legacy_numeric_host(ascii_host):
            raise ClaudePhaseToolPolicyError("web URL IP literal is non-canonical")
        unsafe_exact_hosts = {
            "localhost", "localhost.localdomain", "test", "invalid", "example", "onion",
        }
        if len(ascii_host) > 253 or ascii_host in unsafe_exact_hosts:
            raise ClaudePhaseToolPolicyError("web URL hostname is unsafe")
        labels = ascii_host.split(".")
        if len(labels) < 2 or any(
            not label
            or len(label) > 63
            or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
            for label in labels
        ):
            raise ClaudePhaseToolPolicyError("web URL hostname is malformed")
        if ascii_host.endswith((
            ".localhost", ".local", ".internal", ".home",
            ".test", ".invalid", ".example", ".onion",
        )):
            raise ClaudePhaseToolPolicyError("web URL hostname is unsafe")
        rendered_host = ascii_host
    else:
        if (
            not ip.is_global
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_private
        ):
            raise ClaudePhaseToolPolicyError("web URL IP literal is not global")
        rendered_host = f"[{ip.compressed}]" if ip.version == 6 else ip.compressed
    netloc = rendered_host + (":443" if port == 443 else "")
    path = parsed.path or "/"
    # Canonicalize only percent hex case. Decoding can change URL semantics.
    path = _VALID_PERCENT_RE.sub(lambda match: match.group(0).upper(), path)
    query = _VALID_PERCENT_RE.sub(lambda match: match.group(0).upper(), parsed.query)
    return urlunsplit(SplitResult("https", netloc, path, query, ""))


def _web_authority(policy: Mapping[str, Any]) -> dict[str, Any]:
    if policy.get("external_network_policy") != "BOUNDED_RECEIPTS":
        raise ClaudePhaseToolPolicyError("bounded web authority is unavailable")
    return validate_dependency_research_network_authority(
        policy.get("network_authority", {})
    )


def _validate_web_event_context(
    event: Mapping[str, Any], policy: Mapping[str, Any],
) -> None:
    """Bind web receipts to the exact reviewed Claude launch context."""

    authority = _web_authority(policy)
    if event.get("permission_mode") != authority["permission_mode"]:
        raise ClaudePhaseToolPolicyError("web hook permission mode is invalid")
    cwd = event.get("cwd")
    if not isinstance(cwd, str) or not cwd:
        raise ClaudePhaseToolPolicyError("web hook cwd is invalid")
    try:
        live_cwd = Path(cwd).resolve(strict=True)
        expected_cwd = Path(str(policy["expected_cwd"])).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ClaudePhaseToolPolicyError("web hook cwd is unresolvable") from exc
    if _norm(live_cwd) != _norm(expected_cwd):
        raise ClaudePhaseToolPolicyError("web hook cwd does not match policy")


def _identity_digest(value: Any, *, field: str) -> str:
    admitted = _bounded_untrusted_text(
        value, field=field, max_characters=256, max_bytes=1_024,
    )
    return hashlib.sha256(admitted.encode("utf-8")).hexdigest()


def _web_request(event: Mapping[str, Any]) -> tuple[str, str]:
    tool = str(event.get("tool_name") or "")
    tool_input = event.get("tool_input")
    if not isinstance(tool_input, dict):
        raise ClaudePhaseToolPolicyError("web tool input is malformed")
    if tool == "WebSearch":
        if set(tool_input) != {"query"}:
            raise ClaudePhaseToolPolicyError("WebSearch input denominator mismatch")
        target = _bounded_untrusted_text(
            tool_input.get("query"), field="WebSearch query",
            max_characters=1_500, max_bytes=6_000,
        )
    elif tool == "WebFetch":
        if set(tool_input) != {"url", "prompt"}:
            raise ClaudePhaseToolPolicyError("WebFetch input denominator mismatch")
        target = _normalize_https_url(tool_input.get("url"))
        _bounded_untrusted_text(
            tool_input.get("prompt"), field="WebFetch prompt",
            max_characters=500, max_bytes=2_000,
        )
    else:
        raise ClaudePhaseToolPolicyError("unsupported web tool")
    request_digest = hashlib.sha256(canonical_json_bytes(tool_input)).hexdigest()
    return target, request_digest


def _web_receipt_payload(
    *, event_kind: str, event: Mapping[str, Any], policy: Mapping[str, Any],
    obligations: Iterable[str], normalized_target: str, outcome: str,
    response_digest: str = "", source_urls: Iterable[str] = (),
    redirect_targets: Iterable[str] = (),
    reason_code: str = "",
    request_role: str = "DENIED",
    parent_receipt_digest: str = "",
    proposed_tool_input: Mapping[str, Any] | None = None,
    effective_tool_input: Mapping[str, Any] | None = None,
    rewrite_kind: str = "NONE",
    group_selector: str = "",
    lineage_parent_receipt_digest: str = "",
    proposed_request_digest: str | None = None,
    proposed_authority_digest: str | None = None,
) -> dict[str, Any]:
    authority = _web_authority(policy)
    proposed = dict(
        event.get("tool_input", {})
        if proposed_tool_input is None else proposed_tool_input
    )
    effective = dict(proposed if effective_tool_input is None else effective_tool_input)
    proposed_event = dict(event); proposed_event["tool_input"] = proposed
    effective_event = dict(event); effective_event["tool_input"] = effective
    proposed_target, derived_proposed_digest = _web_request(proposed_event)
    _, effective_request_digest = _web_request(effective_event)
    normalized_proposed = (
        {"query": proposed_target}
        if event.get("tool_name") == "WebSearch"
        else {"url": proposed_target, "prompt": proposed.get("prompt")}
    )
    payload: dict[str, Any] = {
        "schema_version": WEB_RECEIPT_SCHEMA,
        "event_kind": event_kind,
        "policy_id": policy["policy_id"],
        "manifest_digest": policy["manifest_digest"],
        "authority_digest": authority["authority_digest"],
        "session_digest": _identity_digest(event.get("session_id"), field="session_id"),
        "tool_use_digest": _identity_digest(event.get("tool_use_id"), field="tool_use_id"),
        "proposed_request_digest": (
            proposed_request_digest
            if proposed_request_digest is not None
            else derived_proposed_digest
        ),
        "proposed_authority_digest": (
            proposed_authority_digest
            if proposed_authority_digest is not None
            else hashlib.sha256(
                canonical_json_bytes(normalized_proposed)
            ).hexdigest()
        ),
        "effective_request_digest": effective_request_digest,
        "tool_name": str(event.get("tool_name") or ""),
        "obligation_ids": sorted(set(obligations)),
        "normalized_target": normalized_target,
        "outcome": outcome,
        "response_digest": response_digest,
        "source_urls": sorted(set(source_urls)),
        "redirect_targets": sorted(set(redirect_targets)),
        "reason_code": reason_code,
        "request_role": request_role,
        "parent_receipt_digest": parent_receipt_digest,
        "lineage_parent_receipt_digest": lineage_parent_receipt_digest,
        "rewrite_kind": rewrite_kind,
        "group_selector": group_selector,
    }
    payload["receipt_digest"] = _digest_unsigned(payload, "receipt_digest")
    return payload


def _validated_web_receipt(
    value: Mapping[str, Any], policy: Mapping[str, Any],
) -> dict[str, Any]:
    receipt = dict(value)
    if set(receipt) != {
        "schema_version", "event_kind", "policy_id", "manifest_digest",
        "authority_digest", "session_digest", "tool_use_digest",
        "proposed_request_digest", "proposed_authority_digest",
        "effective_request_digest", "tool_name",
        "obligation_ids", "normalized_target",
        "outcome", "response_digest", "source_urls", "redirect_targets",
        "reason_code", "request_role", "parent_receipt_digest",
        "lineage_parent_receipt_digest", "rewrite_kind", "group_selector",
        "receipt_digest",
    }:
        raise ClaudePhaseToolPolicyError("web receipt denominator mismatch")
    authority = _web_authority(policy)
    if (
        receipt.get("schema_version") != WEB_RECEIPT_SCHEMA
        or receipt.get("policy_id") != policy["policy_id"]
        or receipt.get("manifest_digest") != policy["manifest_digest"]
        or receipt.get("authority_digest") != authority["authority_digest"]
        or receipt.get("receipt_digest") != _digest_unsigned(receipt, "receipt_digest")
        or receipt.get("event_kind") not in {
            "PRE", "PRE_DENY", "POST_SUCCESS", "POST_REDIRECT",
            "POST_FAILURE",
        }
        or receipt.get("tool_name") not in _WEB_TOOLS
        or (receipt.get("event_kind"), receipt.get("outcome")) not in {
            ("PRE", "ALLOW"),
            ("PRE_DENY", "DENY"),
            ("POST_SUCCESS", "SUCCESS"),
            ("POST_REDIRECT", "REDIRECT"),
            ("POST_FAILURE", "FAILURE"),
        }
    ):
        raise ClaudePhaseToolPolicyError("web receipt authority mismatch")
    for field in (
        "session_digest", "tool_use_digest", "proposed_request_digest",
        "proposed_authority_digest",
        "effective_request_digest", "receipt_digest",
    ):
        if not _SHA256_RE.fullmatch(str(receipt.get(field) or "")):
            raise ClaudePhaseToolPolicyError("web receipt digest is malformed")
    if receipt["response_digest"] and not _SHA256_RE.fullmatch(receipt["response_digest"]):
        raise ClaudePhaseToolPolicyError("web response digest is malformed")
    parent_digest = receipt.get("parent_receipt_digest")
    if parent_digest and not _SHA256_RE.fullmatch(str(parent_digest)):
        raise ClaudePhaseToolPolicyError("web receipt parent digest is malformed")
    lineage_digest = receipt.get("lineage_parent_receipt_digest")
    if lineage_digest and not _SHA256_RE.fullmatch(str(lineage_digest)):
        raise ClaudePhaseToolPolicyError("web receipt lineage digest is malformed")
    if not re.fullmatch(r"[A-Z][A-Z0-9_]{2,63}", str(receipt.get("reason_code") or "")):
        raise ClaudePhaseToolPolicyError("web receipt reason code is malformed")
    expected_reasons = {
        "PRE": {"BOUNDED_WEB"},
        "PRE_DENY": {
            "WEB_BUDGET_EXHAUSTED", "WEB_FETCH_CHAIN_EXHAUSTED",
            "WEB_FETCH_SELECTOR_MISMATCH", "WEB_FETCH_AMBIGUOUS_LINEAGE",
            "WEB_FETCH_UNSEARCHED", "WEB_PRIOR_DENIAL",
            "WEB_QUERY_UNREGISTERED", "WEB_REQUEST_REPLAY",
        },
        "POST_SUCCESS": {"WEB_POST_SUCCESS"},
        "POST_REDIRECT": {"WEB_POST_REDIRECT"},
        "POST_FAILURE": {"WEB_POST_FAILURE", "WEB_RESPONSE_REJECTED"},
    }
    if receipt["reason_code"] not in expected_reasons[receipt["event_kind"]]:
        raise ClaudePhaseToolPolicyError("web receipt reason authority is malformed")
    role = receipt.get("request_role")
    rewrite = receipt.get("rewrite_kind")
    selector = str(receipt.get("group_selector") or "")
    if (
        role not in {"DENIED", "SEARCH_ROOT", "FETCH_ROOT", "FETCH_REDIRECT"}
        or (receipt["event_kind"] == "PRE_DENY") != (role == "DENIED")
        or (receipt["event_kind"].startswith("POST_")) != bool(parent_digest)
        or (receipt["event_kind"].startswith("PRE")) and bool(parent_digest)
        or receipt["tool_name"] == "WebSearch" and role not in {"DENIED", "SEARCH_ROOT"}
        or receipt["tool_name"] == "WebFetch" and role == "SEARCH_ROOT"
        or rewrite not in {"NONE", "FETCH_INPUT_CANONICALIZED"}
        or (rewrite == "FETCH_INPUT_CANONICALIZED")
        != (receipt["tool_name"] == "WebFetch" and role != "DENIED")
        or (role != "DENIED") != bool(selector)
        or (selector and _FETCH_SELECTOR_RE.fullmatch(selector) is None)
        or (role in {"FETCH_ROOT", "FETCH_REDIRECT"}) != bool(lineage_digest)
        or role == "SEARCH_ROOT" and bool(lineage_digest)
    ):
        raise ClaudePhaseToolPolicyError("web receipt request role is malformed")
    valid_ids = {row["obligation_id"] for row in authority["obligations"]}
    ids = receipt.get("obligation_ids")
    sources = receipt.get("source_urls")
    redirects = receipt.get("redirect_targets")
    if (
        not isinstance(ids, list) or ids != sorted(set(ids))
        or not set(ids).issubset(valid_ids)
        or not isinstance(sources, list) or sources != sorted(set(sources))
        or any(_normalize_https_url(url) != url for url in sources)
        or not isinstance(redirects, list)
        or redirects != sorted(set(redirects))
        or any(_normalize_https_url(url) != url for url in redirects)
    ):
        raise ClaudePhaseToolPolicyError("web receipt source authority is malformed")
    if selector:
        matching_groups = [
            group for group in _web_query_groups(authority)
            if group["fetch_selector"] == selector
        ]
        if (
            len(matching_groups) != 1
            or ids != matching_groups[0]["obligation_ids"]
        ):
            raise ClaudePhaseToolPolicyError(
                "web receipt group selector authority differs"
            )
    if redirects and (
        receipt["event_kind"] != "POST_REDIRECT"
        or receipt["tool_name"] != "WebFetch"
        or sources
        or len(redirects) != 1
        or not _related_redirect_hosts(
            receipt["normalized_target"], redirects[0], authority,
        )
    ):
        raise ClaudePhaseToolPolicyError("web receipt redirect authority is malformed")
    if receipt["tool_name"] != "WebFetch" and redirects:
        raise ClaudePhaseToolPolicyError("web receipt redirect authority is malformed")
    return receipt


def _web_receipts(policy: Mapping[str, Any]) -> list[dict[str, Any]]:
    root = Path(str(policy["receipt_directory"])).resolve(strict=True)
    receipts: list[dict[str, Any]] = []
    seen: set[str] = set()
    all_paths = sorted(root.glob("*.json"), key=lambda item: item.name)
    for path in all_paths:
        if re.fullmatch(r"[0-9a-f]{32}\.json", path.name):
            continue
        if not path.name.startswith("web-"):
            raise ClaudePhaseToolPolicyError(
                f"receipt directory contains an unexpected file: {path.name}"
            )
        raw = path.read_bytes()
        if len(raw) > 131_072:
            raise ClaudePhaseToolPolicyError("web receipt exceeds byte bound")
        try:
            value = json.loads(raw.decode("utf-8", errors="strict"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ClaudePhaseToolPolicyError("web receipt JSON is invalid") from exc
        if not isinstance(value, dict):
            raise ClaudePhaseToolPolicyError("web receipt root is not an object")
        receipt = _validated_web_receipt(value, policy)
        digest = receipt["receipt_digest"]
        if digest in seen:
            raise ClaudePhaseToolPolicyError("web receipt is duplicated")
        seen.add(digest)
        receipts.append(receipt)
    return receipts


def _web_receipt_state_issues(
    receipts: Iterable[Mapping[str, Any]],
    authority: Mapping[str, Any] | None = None,
) -> list[str]:
    """Require every admitted call to close once and preserve denial debt."""

    rows = [dict(row) for row in receipts]
    issues: list[str] = []

    def key(row: Mapping[str, Any]) -> tuple[str, str, str, str]:
        return (
            str(row["session_digest"]), str(row["tool_use_digest"]),
            str(row["effective_request_digest"]), str(row["tool_name"]),
        )

    admitted = [row for row in rows if row["event_kind"] == "PRE"]
    denied = [row for row in rows if row["event_kind"] == "PRE_DENY"]
    closers = [
        row for row in rows
        if row["event_kind"] in {
            "POST_SUCCESS", "POST_REDIRECT", "POST_FAILURE",
        }
    ]
    for row in admitted:
        matches = [closer for closer in closers if key(closer) == key(row)]
        if len(matches) != 1:
            issues.append(
                "dependency web PRE closure cardinality mismatch: "
                + row["tool_use_digest"]
            )
        elif (
            matches[0]["obligation_ids"] != row["obligation_ids"]
            or matches[0]["request_role"] != row["request_role"]
            or matches[0]["parent_receipt_digest"] != row["receipt_digest"]
            or matches[0]["proposed_request_digest"]
            != row["proposed_request_digest"]
            or matches[0]["proposed_authority_digest"]
            != row["proposed_authority_digest"]
            or matches[0]["rewrite_kind"] != row["rewrite_kind"]
            or matches[0]["group_selector"] != row["group_selector"]
            or matches[0]["lineage_parent_receipt_digest"]
            != row["lineage_parent_receipt_digest"]
        ):
            issues.append(
                "dependency web PRE/POST obligation mismatch: "
                + row["tool_use_digest"]
            )
    admitted_keys = {key(row) for row in admitted}
    for row in closers:
        if key(row) not in admitted_keys:
            issues.append(
                "dependency web POST lacks admitted PRE: "
                + row["tool_use_digest"]
            )
        if (
            row["event_kind"] == "POST_SUCCESS"
            and row["tool_name"] == "WebFetch"
            and (
                row["source_urls"] != [row["normalized_target"]]
                or row["redirect_targets"]
            )
        ):
            issues.append(
                "dependency successful WebFetch response shape differs: "
                + row["tool_use_digest"]
            )
    for redirect in (
        row for row in closers if row["event_kind"] == "POST_REDIRECT"
    ):
        children = [
            row for row in admitted
            if row["tool_name"] == "WebFetch"
            and row["request_role"] == "FETCH_REDIRECT"
            and row["lineage_parent_receipt_digest"]
            == redirect["receipt_digest"]
            and row["session_digest"] == redirect["session_digest"]
            and row["group_selector"] == redirect["group_selector"]
            and row["obligation_ids"] == redirect["obligation_ids"]
        ]
        terminal_children = [
            closer for child in children for closer in closers
            if key(closer) == key(child)
            and closer["event_kind"] in {"POST_SUCCESS", "POST_FAILURE"}
        ]
        if len(children) != 1 or len(terminal_children) != 1:
            issues.append(
                "dependency web redirect successor closure cardinality mismatch: "
                + redirect["tool_use_digest"]
            )
    for row in denied:
        issues.append(
            "dependency web request was denied: "
            + row["reason_code"] + " " + row["tool_use_digest"]
        )
    for row in closers:
        if (
            row["tool_name"] == "WebSearch"
            and row["event_kind"] == "POST_FAILURE"
        ):
            issues.append(
                "dependency web search failed: "
                + row["tool_use_digest"]
            )
    if authority is not None:
        groups = {
            group["fetch_selector"]: group
            for group in _web_query_groups(authority)
        }
        by_digest = {row["receipt_digest"]: row for row in rows}
        for row in rows:
            if row["event_kind"] not in {"PRE", "PRE_DENY"}:
                continue
            if row["event_kind"] == "PRE_DENY":
                continue
            group = groups.get(row["group_selector"])
            if group is None:
                issues.append("dependency web receipt selector is unknown")
                continue
            if row["tool_name"] == "WebSearch":
                expected = hashlib.sha256(canonical_json_bytes({
                    "query": group["query"],
                })).hexdigest()
                if (
                    row["normalized_target"] != group["query"]
                    or row["proposed_authority_digest"] != expected
                    or row["effective_request_digest"] != expected
                ):
                    issues.append("dependency web search request identity differs")
                continue
            expected = hashlib.sha256(canonical_json_bytes({
                "url": row["normalized_target"],
                "prompt": group["fetch_prompt"],
            })).hexdigest()
            if row["effective_request_digest"] != expected:
                issues.append("dependency web effective fetch identity differs")
            expected_proposed = hashlib.sha256(canonical_json_bytes({
                "url": row["normalized_target"],
                "group_selector": row["group_selector"],
                "lineage_parent_receipt_digest": row[
                    "lineage_parent_receipt_digest"
                ],
            })).hexdigest()
            if row["proposed_authority_digest"] != expected_proposed:
                issues.append("dependency web proposed fetch identity differs")
            parent = by_digest.get(row["lineage_parent_receipt_digest"])
            if (
                parent is None
                or parent["session_digest"] != row["session_digest"]
                or parent["group_selector"] != row["group_selector"]
                or parent["obligation_ids"] != row["obligation_ids"]
                or (
                    row["request_role"] == "FETCH_ROOT"
                    and not (
                        parent["event_kind"] == "POST_SUCCESS"
                        and parent["tool_name"] == "WebSearch"
                        and row["normalized_target"] in parent["source_urls"]
                    )
                )
                or (
                    row["request_role"] == "FETCH_REDIRECT"
                    and not (
                        parent["event_kind"] == "POST_REDIRECT"
                        and parent["tool_name"] == "WebFetch"
                        and parent["request_role"] == "FETCH_ROOT"
                        and row["normalized_target"] in parent["redirect_targets"]
                    )
                )
            ):
                issues.append("dependency web fetch lineage differs")
    return sorted(set(issues))


def bounded_web_receipt_lifecycle_projection(
    policy: Mapping[str, Any], *, expected_session_id: str,
) -> dict[str, Any]:
    """Return a replayable terminal projection or fail on receipt debt."""

    checked = validate_policy_manifest(policy)
    authority = _web_authority(checked)
    receipts = _web_receipts(checked)
    expected_session_digest = _identity_digest(
        expected_session_id, field="expected_session_id",
    )
    if any(
        row["session_digest"] != expected_session_digest
        for row in receipts
    ):
        raise ClaudePhaseToolPolicyError(
            "bounded web receipt belongs to a foreign provider session"
        )
    issues = _web_receipt_state_issues(receipts, authority)
    if issues:
        raise ClaudePhaseToolPolicyError("; ".join(issues))
    receipt_digests = sorted(row["receipt_digest"] for row in receipts)
    return {
        "schema": "plamen.bounded_web_receipt_lifecycle.v1",
        "manifest_digest": checked["manifest_digest"],
        "authority_digest": authority["authority_digest"],
        "expected_session_digest": expected_session_digest,
        "receipt_count": len(receipt_digests),
        "receipt_set_sha256": hashlib.sha256(
            canonical_json_bytes(receipt_digests)
        ).hexdigest(),
    }


def _persist_new_web_receipt(
    policy: Mapping[str, Any], receipt: Mapping[str, Any],
) -> None:
    root = Path(str(policy["receipt_directory"])).resolve(strict=True)
    identity = "\0".join((
        str(receipt["event_kind"]), str(receipt["session_digest"]),
        str(receipt["tool_use_digest"]),
        str(receipt["effective_request_digest"]),
    )).encode("ascii")
    target = root / ("web-" + hashlib.sha256(identity).hexdigest() + ".json")
    encoded = canonical_json_bytes(receipt)
    try:
        with target.open("xb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError as exc:
        raise ClaudePhaseToolPolicyError("web receipt replay or collision") from exc
    except OSError as exc:
        raise ClaudePhaseToolPolicyError("web receipt persistence failed") from exc


@contextmanager
def _web_receipt_lock(policy: Mapping[str, Any]):
    """Serialize budget admission and receipt publication across hook processes."""

    root = Path(str(policy["receipt_directory"])).resolve(strict=True)
    lock = root / (".web-receipts-" + str(policy["manifest_digest"])[:16] + ".lock")
    acquired = False
    for _ in range(1_000):
        try:
            lock.mkdir()
            acquired = True
            break
        except FileExistsError:
            time.sleep(0.01)
        except OSError as exc:
            raise ClaudePhaseToolPolicyError("web receipt lock failed") from exc
    if not acquired:
        raise ClaudePhaseToolPolicyError("web receipt lock is unavailable")
    try:
        yield
    finally:
        try:
            lock.rmdir()
        except OSError:
            # A retained lock fails later calls closed. Do not mask a primary
            # policy error with cleanup debt in a non-blocking post hook.
            pass


def _evaluate_web_pre(
    event: Mapping[str, Any], policy: Mapping[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    authority = _web_authority(policy)
    target, proposed_digest = _web_request(event)
    session_digest = _identity_digest(event.get("session_id"), field="session_id")
    receipts = _web_receipts(policy)
    if any(
        row["event_kind"] == "PRE_DENY"
        and row["session_digest"] == session_digest
        for row in receipts
    ):
        return {
            "decision": "DENY", "reason_code": "WEB_PRIOR_DENIAL", "target": target,
        }, []
    replayed = any(
        row["event_kind"] == "PRE"
        and row["session_digest"] == session_digest
        and row["tool_name"] == event.get("tool_name")
        and row["proposed_request_digest"] == proposed_digest
        for row in receipts
    )
    tool = str(event["tool_name"])
    by_id = {row["obligation_id"]: row for row in authority["obligations"]}
    groups = _web_query_groups(authority)
    if tool == "WebSearch":
        if replayed:
            return {"decision": "DENY", "reason_code": "WEB_REQUEST_REPLAY", "target": target}, []
        matching_groups = [
            row for row in groups
            if row["query"] == target
        ]
        if len(matching_groups) != 1:
            return {"decision": "DENY", "reason_code": "WEB_QUERY_UNREGISTERED", "target": target}, []
        obligations = list(matching_groups[0]["obligation_ids"])
        request_role = "SEARCH_ROOT"
        group = matching_groups[0]
        lineage_parent = ""
        effective_input = dict(event["tool_input"])
        rewrite_kind = "NONE"
    else:
        proposed_prompt = str(event["tool_input"].get("prompt") or "")
        selector_groups = [
            group for group in groups
            if group["fetch_selector"] == proposed_prompt
        ]
        canonical_prompt_groups = [
            group for group in groups
            if group["fetch_prompt"] == proposed_prompt
        ]
        successful_searches = [
            row for row in receipts
            if row["event_kind"] == "POST_SUCCESS"
            and row["tool_name"] == "WebSearch"
            and row["session_digest"] == session_digest
            and target in row["source_urls"]
        ]
        direct_redirects = [
            row for row in receipts
            if row["event_kind"] == "POST_REDIRECT"
            and row["tool_name"] == "WebFetch"
            and row["request_role"] == "FETCH_ROOT"
            and row["session_digest"] == session_digest
            and target in row["redirect_targets"]
        ]
        url_parents = successful_searches + direct_redirects
        if replayed:
            return {
                "decision": "DENY",
                "reason_code": "WEB_REQUEST_REPLAY",
                "target": target,
            }, []
        if not url_parents:
            return {
                "decision": "DENY",
                "reason_code": "WEB_FETCH_UNSEARCHED",
                "target": target,
            }, []
        unconsumed_parents = [
            row for row in url_parents
            if not any(
                prior["event_kind"] == "PRE"
                and prior["tool_name"] == "WebFetch"
                and prior["session_digest"] == session_digest
                and prior["lineage_parent_receipt_digest"] == row["receipt_digest"]
                for prior in receipts
            )
        ]
        if selector_groups:
            candidate_groups = selector_groups
            parent_pool = unconsumed_parents
        elif canonical_prompt_groups:
            candidate_groups = canonical_prompt_groups
            parent_pool = [
                parent for parent in unconsumed_parents
                if parent in direct_redirects
            ]
        else:
            # Claude 2.1.252 constructs a natural extraction prompt even when
            # shown an opaque selector.  The authenticated request identity is
            # therefore the unique unconsumed same-session URL parent; the raw
            # prompt remains evidence only and is replaced wholesale.
            selectors = sorted({
                str(parent["group_selector"])
                for parent in unconsumed_parents
            })
            candidate_groups = [
                group for group in groups
                if group["fetch_selector"] in selectors
            ]
            parent_pool = unconsumed_parents
        matching = [
            (group, parent)
            for group in candidate_groups
            for parent in parent_pool
            if parent["group_selector"] == group["fetch_selector"]
            and parent["obligation_ids"] == group["obligation_ids"]
        ]
        if len(matching) > 1:
            return {
                "decision": "DENY",
                "reason_code": "WEB_FETCH_AMBIGUOUS_LINEAGE",
                "target": target,
            }, []
        if not matching:
            return {
                "decision": "DENY",
                "reason_code": (
                    "WEB_FETCH_CHAIN_EXHAUSTED"
                    if not unconsumed_parents else "WEB_FETCH_SELECTOR_MISMATCH"
                ),
                "target": target,
            }, []
        group, parent = matching[0]
        obligations = list(group["obligation_ids"])
        request_role = (
            "FETCH_REDIRECT"
            if parent["event_kind"] == "POST_REDIRECT" else "FETCH_ROOT"
        )
        lineage_parent = str(parent["receipt_digest"])
        effective_input = {"url": target, "prompt": group["fetch_prompt"]}
        rewrite_kind = "FETCH_INPUT_CANONICALIZED"
    available: list[str] = []
    for obligation_id in obligations:
        budget_field = "search_budget" if tool == "WebSearch" else "fetch_budget"
        consumed = sum(
            1 for row in receipts
            if row["event_kind"] == "PRE"
            and row["tool_name"] == tool
            and obligation_id in row["obligation_ids"]
        )
        if consumed < int(by_id[obligation_id][budget_field]):
            available.append(obligation_id)
    if len(available) != len(obligations):
        return {"decision": "DENY", "reason_code": "WEB_BUDGET_EXHAUSTED", "target": target}, []
    return {
        "decision": "ALLOW", "reason_code": "BOUNDED_WEB", "target": target,
        "request_role": request_role,
        "group_selector": group["fetch_selector"],
        "lineage_parent_receipt_digest": lineage_parent,
        "proposed_authority_digest": hashlib.sha256(canonical_json_bytes({
            "url": target,
            "group_selector": group["fetch_selector"],
            "lineage_parent_receipt_digest": lineage_parent,
        })).hexdigest(),
        "effective_tool_input": effective_input,
        "rewrite_kind": rewrite_kind,
    }, obligations


def evaluate_tool_call(
    *, tool_name: str, tool_input: Mapping[str, Any], cwd: Path,
    policy: Mapping[str, Any],
) -> dict[str, Any]:
    """Return a content-free ALLOW/DENY decision for one tool call."""

    checked = validate_policy_manifest(policy)
    tool = str(tool_name or "")
    expected_cwd = Path(str(checked["expected_cwd"]))
    try:
        live_cwd = Path(cwd).resolve(strict=True)
    except (OSError, RuntimeError):
        return {"decision": "DENY", "reason_code": "CWD_UNRESOLVABLE", "target": ""}
    if _norm(live_cwd) != _norm(expected_cwd):
        return {"decision": "DENY", "reason_code": "CWD_MISMATCH", "target": ""}
    if (
        tool.startswith("mcp__")
        or tool in _ALWAYS_DENIED
        or (tool in _WEB_TOOLS and checked["external_network_policy"] == "DENY")
    ):
        return {"decision": "DENY", "reason_code": "TOOL_DENIED", "target": ""}
    if tool not in set(checked["allowed_tools"]):
        return {"decision": "DENY", "reason_code": "UNKNOWN_TOOL", "target": ""}

    if tool in _WEB_TOOLS:
        try:
            decision, _ = _evaluate_web_pre(
                {
                    "session_id": "evaluation-only",
                    "tool_use_id": "evaluation-only",
                    "tool_name": tool,
                    "tool_input": dict(tool_input),
                },
                checked,
            )
            return decision
        except ClaudePhaseToolPolicyError:
            return {"decision": "DENY", "reason_code": "WEB_POLICY_ERROR", "target": ""}

    if tool in _READ_TOOLS:
        path, issue = _resolve_read_path(
            tool_input.get("file_path", tool_input.get("path")), live_cwd
        )
        if path is None:
            return {"decision": "DENY", "reason_code": issue, "target": ""}
        target = path.as_posix()
        if _norm(path) in {_norm(item) for item in _path_rows(checked, "forbidden_read_files")}:
            return {"decision": "DENY", "reason_code": "FORBIDDEN_READ", "target": target}
        if _norm(path) in {
            _norm(item) for item in _path_rows(checked, "exact_write_files")
        }:
            # The worker may perform a post-write self-check of its one exact
            # attempt-owned artifact.  This never expands scratchpad read
            # authority: the path is the frozen write denominator and must
            # already resolve to a regular file.
            return {
                "decision": "ALLOW",
                "reason_code": "ASSIGNED_OUTPUT_READ",
                "target": target,
            }
        read_row = _read_index(checked).get(_norm(path))
        if read_row is not None:
            stat = path.stat()
            if stat.st_size != read_row["size"] or _file_sha256(path) != read_row["sha256"]:
                return {"decision": "DENY", "reason_code": "EXACT_READ_DRIFT", "target": target}
            return {"decision": "ALLOW", "reason_code": "EXACT_READ", "target": target}
        if any(_is_within(path, root) for root in _path_rows(checked, "methodology_read_roots")):
            return {"decision": "ALLOW", "reason_code": "METHODOLOGY_READ", "target": target}
        if _source_read_allowed(path, checked):
            return {"decision": "ALLOW", "reason_code": "SOURCE_READ", "target": target}
        return {"decision": "DENY", "reason_code": "UNREGISTERED_READ", "target": target}

    if tool in _WRITE_TOOLS:
        path, issue = _resolve_write_path(tool_input.get("file_path"), live_cwd)
        if path is None:
            return {"decision": "DENY", "reason_code": issue, "target": ""}
        target = path.as_posix()
        allowed = {_norm(item) for item in _path_rows(checked, "exact_write_files")}
        if _norm(path) not in allowed:
            return {"decision": "DENY", "reason_code": "UNREGISTERED_WRITE", "target": target}
        return {"decision": "ALLOW", "reason_code": "EXACT_WRITE", "target": target}

    if tool in _SEARCH_TOOLS:
        path, issue = _resolve_search_path(tool_input.get("path"), live_cwd)
        if path is None:
            return {"decision": "DENY", "reason_code": issue, "target": ""}
        target = path.as_posix()
        if _norm(path) in {
            _norm(item) for item in _path_rows(checked, "forbidden_read_files")
        }:
            return {
                "decision": "DENY",
                "reason_code": "FORBIDDEN_SEARCH",
                "target": target,
            }
        if tool == "Grep":
            read_row = _read_index(checked).get(_norm(path))
            if read_row is not None:
                try:
                    stat = path.stat()
                    current_sha256 = _file_sha256(path)
                except (OSError, RuntimeError):
                    return {
                        "decision": "DENY",
                        "reason_code": "EXACT_READ_SEARCH_UNAVAILABLE",
                        "target": target,
                    }
                if (
                    not path.is_file()
                    or stat.st_size != read_row["size"]
                    or current_sha256 != read_row["sha256"]
                ):
                    return {
                        "decision": "DENY",
                        "reason_code": "EXACT_READ_SEARCH_DRIFT",
                        "target": target,
                    }
                return {
                    "decision": "ALLOW",
                    "reason_code": "EXACT_READ_SEARCH",
                    "target": target,
                }
        if tool == "Grep" and _norm(path) in {
            _norm(item) for item in _path_rows(checked, "exact_write_files")
        }:
            return {
                "decision": "ALLOW",
                "reason_code": "ASSIGNED_OUTPUT_SEARCH",
                "target": target,
            }
        if any(_is_within(path, root) for root in _path_rows(checked, "source_excluded_roots")):
            return {"decision": "DENY", "reason_code": "SEARCH_EXCLUDED_ROOT", "target": target}
        safe = _path_rows(checked, "safe_search_roots")
        if path.is_file() and _source_read_allowed(path, checked):
            return {"decision": "ALLOW", "reason_code": "SOURCE_FILE_SEARCH", "target": target}
        if any(_is_within(path, root) for root in safe):
            return {"decision": "ALLOW", "reason_code": "SAFE_SOURCE_SEARCH", "target": target}
        return {"decision": "DENY", "reason_code": "UNSAFE_SEARCH_ROOT", "target": target}

    return {"decision": "DENY", "reason_code": "UNKNOWN_TOOL", "target": ""}


def _receipt_payload(
    *, event: Mapping[str, Any], policy: Mapping[str, Any], decision: Mapping[str, Any],
) -> dict[str, Any]:
    tool_input = event.get("tool_input")
    input_digest = hashlib.sha256(canonical_json_bytes(tool_input)).hexdigest()
    payload: dict[str, Any] = {
        "schema_version": RECEIPT_SCHEMA,
        "policy_id": policy["policy_id"],
        "manifest_digest": policy["manifest_digest"],
        "run_id": policy["run_id"],
        "phase": policy["phase"],
        "attempt": policy["attempt"],
        "session_id": str(event.get("session_id") or ""),
        "tool_use_id": str(event.get("tool_use_id") or ""),
        "tool_name": str(event.get("tool_name") or ""),
        "tool_input_digest": input_digest,
        "normalized_target": str(decision.get("target") or ""),
        "decision": str(decision.get("decision") or "DENY"),
        "reason_code": str(decision.get("reason_code") or "POLICY_ERROR"),
    }
    payload["receipt_digest"] = _digest_unsigned(payload, "receipt_digest")
    return payload


def _persist_receipt(policy: Mapping[str, Any], receipt: Mapping[str, Any]) -> None:
    root = Path(str(policy["receipt_directory"])).resolve(strict=True)
    if not root.is_dir():
        raise ClaudePhaseToolPolicyError("receipt directory is not a directory")
    name_key = "\0".join((
        str(receipt.get("session_id") or ""),
        str(receipt.get("tool_use_id") or ""),
        str(receipt.get("tool_input_digest") or ""),
    )).encode("utf-8")
    target = root / (hashlib.sha256(name_key).hexdigest()[:32] + ".json")
    encoded = canonical_json_bytes(receipt)
    try:
        with target.open("xb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError:
        if target.read_bytes() != encoded:
            raise ClaudePhaseToolPolicyError("receipt identity collision")
    except OSError as exc:
        raise ClaudePhaseToolPolicyError(f"receipt persistence failed: {exc}") from exc


def validate_write_receipt_coverage(policy: Mapping[str, Any]) -> list[str]:
    """Require one valid allowed Write/Edit receipt per exact model output."""

    try:
        checked = validate_policy_manifest(policy)
        root = Path(str(checked["receipt_directory"])).resolve(strict=True)
    except (ClaudePhaseToolPolicyError, OSError, RuntimeError) as exc:
        return [f"tool receipt authority is unavailable: {exc}"]
    expected = {_norm(Path(value)): str(value) for value in checked["exact_write_files"]}
    covered: set[str] = set()
    seen_receipts: set[str] = set()
    try:
        paths = sorted(root.glob("*.json"), key=lambda item: item.name)
    except OSError as exc:
        return [f"tool receipt directory is unreadable: {exc}"]
    if any(path.name.startswith("web-") for path in paths):
        try:
            _web_receipts(checked)
        except (ClaudePhaseToolPolicyError, OSError, RuntimeError) as exc:
            return [f"web tool receipt is invalid: {exc}"]
    for path in paths:
        if path.name.startswith("web-"):
            continue
        if not re.fullmatch(r"[0-9a-f]{32}\.json", path.name):
            return [f"tool receipt directory contains an unexpected file: {path.name}"]
        try:
            raw = path.read_bytes()
            if len(raw) > 131_072:
                raise ClaudePhaseToolPolicyError("receipt exceeds byte bound")
            receipt = json.loads(raw.decode("utf-8", errors="strict"))
        except (OSError, UnicodeError, json.JSONDecodeError, ClaudePhaseToolPolicyError) as exc:
            return [f"tool receipt is invalid ({path.name}): {type(exc).__name__}"]
        if not isinstance(receipt, dict):
            return [f"tool receipt is invalid ({path.name}): root is not an object"]
        required = {
            "schema_version", "policy_id", "manifest_digest", "run_id", "phase",
            "attempt", "session_id", "tool_use_id", "tool_name",
            "tool_input_digest", "normalized_target", "decision", "reason_code",
            "receipt_digest",
        }
        if (
            set(receipt) != required
            or receipt.get("schema_version") != RECEIPT_SCHEMA
            or receipt.get("policy_id") != checked["policy_id"]
            or receipt.get("manifest_digest") != checked["manifest_digest"]
            or receipt.get("run_id") != checked["run_id"]
            or receipt.get("phase") != checked["phase"]
            or receipt.get("attempt") != checked["attempt"]
            or receipt.get("receipt_digest")
            != _digest_unsigned(receipt, "receipt_digest")
        ):
            return [f"tool receipt authority mismatch: {path.name}"]
        digest = str(receipt["receipt_digest"])
        if digest in seen_receipts:
            return [f"tool receipt digest is duplicated: {path.name}"]
        seen_receipts.add(digest)
        if (
            receipt.get("decision") == "ALLOW"
            and receipt.get("tool_name") in _WRITE_TOOLS
            and receipt.get("reason_code") == "EXACT_WRITE"
        ):
            normalized = _norm(Path(str(receipt.get("normalized_target") or "")))
            if normalized in expected:
                covered.add(normalized)
    missing = [expected[key] for key in sorted(set(expected) - covered)]
    return [f"exact model output lacks allowed Write/Edit receipt: {item}" for item in missing]


def staged_exact_output_receipt_validator(
    staged_outputs: Mapping[str, bytes],
    context: Mapping[str, Any],
) -> list[str]:
    """Gate transactional exact-consumer bytes before canonical incorporation.

    The Claude hook observes tool calls, while the worker transaction owns the
    disposable output directory.  This validator joins those two authorities:
    every staged member must be in the frozen denominator, the policy must
    authorize precisely those attempt-owned paths, and every path must have an
    allowed Write/Edit receipt.  A model process exit or a file appearing in
    staging is therefore insufficient by itself.
    """

    required = {
        "schema",
        "policy_path",
        "manifest_digest",
        "output_directory",
        "expected_outputs",
    }
    permitted = (required, required | {"selection_signal"})
    if (
        not isinstance(context, Mapping)
        or set(context) not in permitted
        or context.get("schema") != "plamen.claude_exact_staged_gate.v1"
    ):
        return ["staged exact-output gate context is invalid"]
    expected_raw = context.get("expected_outputs")
    if (
        not isinstance(expected_raw, list)
        or not expected_raw
        or any(not isinstance(value, str) for value in expected_raw)
    ):
        return ["staged exact-output denominator is invalid"]
    expected = sorted(set(expected_raw))
    direct_keys = set(expected)
    identity_keys = {f"scratchpad:{value}" for value in expected}
    actual_keys = set(staged_outputs)
    if actual_keys == direct_keys:
        normalized_staged = dict(staged_outputs)
    elif actual_keys == identity_keys:
        # WorkerTransaction deliberately keys staged bytes by their canonical
        # PhaseIO identities.  The tool policy, by contrast, exposes only the
        # attempt-local relative filenames to Claude.  Join those two frozen
        # denominators here without accepting mixed or foreign identities.
        normalized_staged = {
            key.removeprefix("scratchpad:"): value
            for key, value in staged_outputs.items()
        }
    else:
        return ["staged exact-output denominator mismatch"]
    try:
        output_root = Path(str(context["output_directory"])).resolve(strict=True)
        policy = load_policy(Path(str(context["policy_path"])))
    except (OSError, RuntimeError, ClaudePhaseToolPolicyError) as exc:
        return [f"staged exact-output policy is invalid: {exc}"]
    if policy.get("manifest_digest") != context.get("manifest_digest"):
        return ["staged exact-output policy manifest drift"]
    expected_paths: set[str] = set()
    for relative in expected:
        candidate = Path(relative)
        if (
            not relative
            or candidate.is_absolute()
            or ".." in candidate.parts
            or _has_unsafe_path_text(relative)
        ):
            return ["staged exact-output denominator is invalid"]
        expected_paths.add(_norm(output_root / candidate))
    policy_paths = {
        _norm(Path(str(value)))
        for value in policy.get("exact_write_files", [])
    }
    if policy_paths != expected_paths:
        return ["staged exact-output write policy denominator mismatch"]
    if sorted(normalized_staged) != expected:
        return ["staged exact-output denominator mismatch"]
    receipt_issues = validate_write_receipt_coverage(policy)
    if receipt_issues:
        return receipt_issues
    selection_context = context.get("selection_signal")
    if selection_context is None:
        return []
    return staged_recon_selection_signal_validator(
        dict(staged_outputs), selection_context
    )


def recon_selection_signal_staged_context(
    *,
    output: str,
    allowed_rows: Iterable[Mapping[str, Any] | str],
) -> dict[str, Any]:
    """Freeze one recon selection shard's closed skill-ID denominator."""

    from skill_selection_authority import (  # pylint: disable=import-outside-toplevel
        selection_signal_issues,
    )

    output_name = str(output or "")
    candidate = Path(output_name)
    if (
        not output_name
        or candidate.is_absolute()
        or ".." in candidate.parts
        or _has_unsafe_path_text(output_name)
    ):
        raise ClaudePhaseToolPolicyError(
            "recon selection staged output is invalid"
        )
    allowed: set[str] = set()
    for row in allowed_rows:
        value = row.get("skill_id") if isinstance(row, Mapping) else row
        skill_id = str(value or "").strip()
        if not re.fullmatch(r"[A-Z0-9]+(?:_[A-Z0-9]+)*", skill_id):
            raise ClaudePhaseToolPolicyError(
                "recon selection skill-ID denominator is non-canonical"
            )
        allowed.add(skill_id)
    if not allowed:
        raise ClaudePhaseToolPolicyError(
            "recon selection skill-ID denominator is empty"
        )
    source = Path(inspect.getsourcefile(selection_signal_issues) or "")
    try:
        source = source.resolve(strict=True)
        source_digest = hashlib.sha256(source.read_bytes()).hexdigest()
    except (OSError, RuntimeError) as exc:
        raise ClaudePhaseToolPolicyError(
            "recon selection validator source is unavailable"
        ) from exc
    return {
        "schema": "plamen.recon_selection_signal_staged_gate.v1",
        "output": output_name,
        "allowed_skill_ids": sorted(allowed),
        "selection_validator_sha256": source_digest,
    }


def staged_recon_selection_signal_validator(
    staged_outputs: Mapping[str, bytes],
    context: Mapping[str, Any],
) -> list[str]:
    """Reject malformed or invented recon skill IDs before incorporation."""

    from skill_selection_authority import (  # pylint: disable=import-outside-toplevel
        selection_signal_issues,
    )

    required = {
        "schema",
        "output",
        "allowed_skill_ids",
        "selection_validator_sha256",
    }
    if (
        not isinstance(context, Mapping)
        or set(context) != required
        or context.get("schema")
        != "plamen.recon_selection_signal_staged_gate.v1"
    ):
        return ["staged recon selection-signal gate context is invalid"]
    output = context.get("output")
    allowed = context.get("allowed_skill_ids")
    if (
        not isinstance(output, str)
        or not output
        or not isinstance(allowed, list)
        or not allowed
        or allowed != sorted(set(allowed))
        or any(
            not isinstance(value, str)
            or re.fullmatch(r"[A-Z0-9]+(?:_[A-Z0-9]+)*", value) is None
            for value in allowed
        )
    ):
        return ["staged recon selection-signal denominator is invalid"]
    try:
        source = Path(inspect.getsourcefile(selection_signal_issues) or "")
        actual_source_digest = hashlib.sha256(
            source.resolve(strict=True).read_bytes()
        ).hexdigest()
    except (OSError, RuntimeError):
        return ["staged recon selection validator source is unavailable"]
    if actual_source_digest != context.get("selection_validator_sha256"):
        return ["staged recon selection validator implementation drift"]
    direct = output
    identity = f"scratchpad:{output}"
    if set(staged_outputs) == {direct}:
        raw = staged_outputs[direct]
    elif set(staged_outputs) == {identity}:
        raw = staged_outputs[identity]
    else:
        return ["staged recon selection-signal denominator mismatch"]
    if not isinstance(raw, bytes):
        return ["staged recon selection output is not bytes"]
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return ["staged recon selection output is not strict UTF-8"]
    return [
        "recon selection signal: "
        + json.dumps(issue, sort_keys=True, separators=(",", ":"))
        for issue in selection_signal_issues(text, allowed, required=True)
    ]


def _related_redirect_hosts(
    original: str, successor: str, authority: Mapping[str, Any],
) -> bool:
    """Admit same-host or an exact source-reviewed cross-host redirect."""

    original_host = str(urlsplit(_normalize_https_url(original)).hostname or "").casefold()
    successor_host = str(urlsplit(_normalize_https_url(successor)).hostname or "").casefold()
    if original_host == successor_host:
        return True
    return [original_host, successor_host] in authority["redirect_host_pairs"]


def _redirect_successor(
    response: Mapping[str, Any], target: str, fetch_prompt: str,
    authority: Mapping[str, Any],
) -> str:
    result = str(response["result"])
    lines = result.splitlines()
    header = (
        "REDIRECT DETECTED: The URL redirects to a location that was not fetched automatically."
    )
    redirect_prefix = (
        "Redirect URL (from the server's Location header — server-supplied, not verified): "
    )
    if (
        len(lines) != 9
        or lines[0] != header
        or lines[1] != ""
        or not lines[2].startswith("Original URL: ")
        or not lines[3].startswith(redirect_prefix)
        or lines[5] != ""
    ):
        raise ClaudePhaseToolPolicyError("WebFetch redirect envelope is malformed")
    original = _normalize_https_url(lines[2].removeprefix("Original URL: "))
    successor = _normalize_https_url(lines[3].removeprefix(redirect_prefix))
    code = int(response["code"])
    expected_result = "\n".join((
        header,
        "",
        f"Original URL: {target}",
        f"{redirect_prefix}{successor}",
        f"Status: {code} {response['codeText']}",
        "",
        (
            "To complete your request, I need to fetch content from the redirected URL. "
            "Please use WebFetch again with these parameters:"
        ),
        f'- url: "{successor}"',
        f'- prompt: "{fetch_prompt}"',
    ))
    if (
        result != expected_result
        or response["bytes"] != len(result.encode("utf-8"))
        or original != target
        or successor == target
        or not _related_redirect_hosts(target, successor, authority)
    ):
        raise ClaudePhaseToolPolicyError("WebFetch redirect authority is invalid")
    return successor


def _web_response_sources(
    event: Mapping[str, Any], policy: Mapping[str, Any],
) -> tuple[list[str], list[str], str]:
    authority = _web_authority(policy)
    response = event.get("tool_response")
    if not isinstance(response, dict):
        raise ClaudePhaseToolPolicyError("web tool response shape is unknown")
    encoded = canonical_json_bytes(response)
    if len(encoded) > int(authority["max_response_bytes"]):
        raise ClaudePhaseToolPolicyError("web tool response exceeds byte bound")
    tool = str(event.get("tool_name") or "")
    target, _ = _web_request(event)
    urls: list[str] = []
    redirects: list[str] = []
    if tool == "WebSearch":
        if (
            authority["provider_version"] != PINNED_CLAUDE_WEB_HOOK_VERSION
            or set(response) != {"query", "results", "durationSeconds", "searchCount"}
            or response.get("query") != target
        ):
            raise ClaudePhaseToolPolicyError("WebSearch response shape is unknown")
        results = response.get("results")
        duration = response.get("durationSeconds")
        count = response.get("searchCount")
        if (
            not isinstance(results, list)
            or isinstance(duration, bool) or not isinstance(duration, (int, float))
            or not math.isfinite(float(duration)) or duration < 0
            or isinstance(count, bool) or not isinstance(count, int)
            or not 1 <= count <= MAX_PROVIDER_SEARCHES_PER_TOOL_CALL
            or len(results) != count + 1
        ):
            raise ClaudePhaseToolPolicyError("WebSearch response is malformed")
        summary = results[count]
        if (
            not isinstance(summary, str) or not summary
            or len(summary.encode("utf-8")) > int(authority["max_response_bytes"])
        ):
            raise ClaudePhaseToolPolicyError("WebSearch result shape is unknown")
        for block in results[:count]:
            if (
                not isinstance(block, dict)
                or set(block) != {"tool_use_id", "content"}
                or not isinstance(block["tool_use_id"], str)
                or not block["tool_use_id"]
                or not isinstance(block["content"], list)
            ):
                raise ClaudePhaseToolPolicyError("WebSearch result shape is unknown")
            for row in block["content"]:
                if (
                    not isinstance(row, dict) or set(row) != {"title", "url"}
                    or not isinstance(row.get("title"), str)
                ):
                    raise ClaudePhaseToolPolicyError("WebSearch result shape is unknown")
                urls.append(_normalize_https_url(row.get("url")))
    elif tool == "WebFetch":
        if (
            authority["provider_version"] != PINNED_CLAUDE_WEB_HOOK_VERSION
            or set(response) != {"bytes", "code", "codeText", "durationMs", "result", "url"}
        ):
            raise ClaudePhaseToolPolicyError("WebFetch response shape is unknown")
        byte_count = response.get("bytes")
        code = response.get("code")
        duration = response.get("durationMs")
        if (
            isinstance(byte_count, bool) or not isinstance(byte_count, int)
            or not 0 <= byte_count <= int(authority["max_response_bytes"])
            or isinstance(code, bool) or not isinstance(code, int) or not 200 <= code < 400
            or not isinstance(response.get("codeText"), str)
            or len(response["codeText"]) > 100
            or isinstance(duration, bool) or not isinstance(duration, int) or duration < 0
            or not isinstance(response.get("result"), str) or not response["result"]
            or _normalize_https_url(response.get("url")) != target
        ):
            raise ClaudePhaseToolPolicyError("WebFetch response is malformed")
        if code < 300:
            urls.append(target)
        else:
            redirects.append(_redirect_successor(
                response, target, str(event["tool_input"]["prompt"]), authority,
            ))
    else:
        raise ClaudePhaseToolPolicyError("unsupported web response tool")
    urls = sorted(set(urls))
    if len(urls) > int(authority["max_source_urls"]):
        raise ClaudePhaseToolPolicyError("web response source URL bound exceeded")
    return urls, sorted(set(redirects)), hashlib.sha256(encoded).hexdigest()


def _matching_web_pre(
    event: Mapping[str, Any], policy: Mapping[str, Any],
) -> dict[str, Any]:
    _, effective_request_digest = _web_request(event)
    session_digest = _identity_digest(event.get("session_id"), field="session_id")
    tool_use_digest = _identity_digest(event.get("tool_use_id"), field="tool_use_id")
    matches = [
        row for row in _web_receipts(policy)
        if row["event_kind"] == "PRE"
        and row["session_digest"] == session_digest
        and row["tool_use_digest"] == tool_use_digest
        and row["effective_request_digest"] == effective_request_digest
        and row["tool_name"] == event.get("tool_name")
        and row["outcome"] == "ALLOW"
    ]
    if len(matches) != 1:
        raise ClaudePhaseToolPolicyError("web post event lacks one matching pre receipt")
    return matches[0]


def _record_web_post(
    event: Mapping[str, Any], policy: Mapping[str, Any], *, success: bool,
) -> None:
    pre = _matching_web_pre(event, policy)
    target, _ = _web_request(event)
    if success:
        try:
            urls, redirects, response_digest = _web_response_sources(event, policy)
            if redirects and any(
                row["event_kind"] == "POST_REDIRECT"
                and row["session_digest"] == pre["session_digest"]
                and pre["normalized_target"] in row["redirect_targets"]
                for row in _web_receipts(policy)
            ):
                raise ClaudePhaseToolPolicyError(
                    "redirect successor returned a forbidden second redirect"
                )
        except ClaudePhaseToolPolicyError:
            rejected_digest = hashlib.sha256(
                canonical_json_bytes(event.get("tool_response"))
            ).hexdigest()
            rejected = _web_receipt_payload(
                event_kind="POST_FAILURE", event=event, policy=policy,
                obligations=pre["obligation_ids"], normalized_target=target,
                outcome="FAILURE", response_digest=rejected_digest,
                reason_code="WEB_RESPONSE_REJECTED",
                request_role=pre["request_role"],
                parent_receipt_digest=pre["receipt_digest"],
                proposed_request_digest=pre["proposed_request_digest"],
                proposed_authority_digest=pre["proposed_authority_digest"],
                rewrite_kind=pre["rewrite_kind"],
                group_selector=pre["group_selector"],
                lineage_parent_receipt_digest=pre[
                    "lineage_parent_receipt_digest"
                ],
            )
            _persist_new_web_receipt(policy, rejected)
            raise
        kind, outcome = (
            ("POST_REDIRECT", "REDIRECT")
            if redirects
            else ("POST_SUCCESS", "SUCCESS")
        )
        reason_code = (
            "WEB_POST_REDIRECT" if redirects else "WEB_POST_SUCCESS"
        )
    else:
        if "tool_response" in event:
            raise ClaudePhaseToolPolicyError(
                "failed web event may not contain a tool response"
            )
        error = event.get("error")
        if (
            not isinstance(error, str) or not error
            or len(error.encode("utf-8")) > 131_072
            or not isinstance(event.get("is_interrupt", False), bool)
        ):
            raise ClaudePhaseToolPolicyError("web failure event is malformed")
        urls = []
        redirects = []
        response_digest = hashlib.sha256(
            canonical_json_bytes({
                "error": error,
                "is_interrupt": bool(event.get("is_interrupt", False)),
            })
        ).hexdigest()
        kind, outcome = "POST_FAILURE", "FAILURE"
        reason_code = "WEB_POST_FAILURE"
    receipt = _web_receipt_payload(
        event_kind=kind, event=event, policy=policy,
        obligations=pre["obligation_ids"], normalized_target=target,
        outcome=outcome, response_digest=response_digest, source_urls=urls,
        redirect_targets=redirects, reason_code=reason_code,
        request_role=pre["request_role"],
        parent_receipt_digest=pre["receipt_digest"],
        proposed_request_digest=pre["proposed_request_digest"],
        proposed_authority_digest=pre["proposed_authority_digest"],
        rewrite_kind=pre["rewrite_kind"],
        group_selector=pre["group_selector"],
        lineage_parent_receipt_digest=pre["lineage_parent_receipt_digest"],
    )
    _persist_new_web_receipt(policy, receipt)


def _dependency_markdown_row_cells(line: str) -> list[str]:
    """Split one bounded table row without treating inline-code pipes as columns."""

    stripped = line.strip()
    if not stripped.startswith("|") or not stripped.endswith("|"):
        raise ClaudePhaseToolPolicyError("dependency report table row is invalid")
    body = stripped[1:-1]
    cells: list[str] = []
    cell: list[str] = []
    code_fence = 0
    index = 0
    while index < len(body):
        character = body[index]
        if character == "\\" and index + 1 < len(body) and body[index + 1] == "|":
            cell.append("|")
            index += 2
            continue
        if character == "`":
            end = index + 1
            while end < len(body) and body[end] == "`":
                end += 1
            fence = end - index
            if code_fence == 0:
                code_fence = fence
            elif code_fence == fence:
                code_fence = 0
            cell.append(body[index:end])
            index = end
            continue
        if character == "|" and code_fence == 0:
            cells.append("".join(cell).strip())
            cell = []
        else:
            cell.append(character)
        index += 1
    if code_fence:
        raise ClaudePhaseToolPolicyError(
            "dependency report table row has unterminated inline code"
        )
    cells.append("".join(cell).strip())
    return cells


def _claimed_sources_from_report(
    raw: bytes, expected_ids: set[str],
) -> tuple[list[tuple[str, str]], dict[str, str]]:
    if len(raw) > 2_000_000:
        raise ClaudePhaseToolPolicyError("dependency report exceeds byte bound")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise ClaudePhaseToolPolicyError("dependency report is not UTF-8") from exc
    expected_header = (
        "Obligation ID", "Dependency", "Integration Surface", "Assumed Behavior",
        "Real Behavior", "Source", "Conformance", "Fetch Status",
    )
    claims: set[tuple[str, str]] = set()
    statuses: dict[str, str] = {}
    seen_ids: set[str] = set()
    url_re = re.compile(r"https://[^\s|<>()\[\]`]+")
    header_seen = False
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|") or not stripped.endswith("|"):
            continue
        cells = _dependency_markdown_row_cells(stripped)
        if tuple(cells) == expected_header:
            if header_seen:
                raise ClaudePhaseToolPolicyError("dependency report repeats its header")
            header_seen = True
            continue
        if all(re.fullmatch(r":?-{3,}:?", cell) for cell in cells):
            continue
        if not header_seen:
            continue
        if len(cells) != len(expected_header):
            raise ClaudePhaseToolPolicyError("dependency report row width is invalid")
        row = dict(zip(expected_header, cells))
        obligation_id = row["Obligation ID"].upper()
        if not _OBLIGATION_ID_RE.fullmatch(obligation_id):
            raise ClaudePhaseToolPolicyError("dependency report obligation ID is invalid")
        if obligation_id not in expected_ids or obligation_id in seen_ids:
            raise ClaudePhaseToolPolicyError("dependency report obligation row is unexpected")
        seen_ids.add(obligation_id)
        urls = [
            _normalize_https_url(match.rstrip(".,;:"))
            for match in url_re.findall(row["Source"])
        ]
        status = row["Fetch Status"].upper()
        if status == "RESEARCHED" and not urls:
            raise ClaudePhaseToolPolicyError(
                f"researched dependency has no HTTPS source: {obligation_id}"
            )
        if status not in {"RESEARCHED", "FETCH_FAILED", "NEEDS_DEPENDENCY_RESEARCH"}:
            raise ClaudePhaseToolPolicyError("dependency report fetch status is invalid")
        if status != "RESEARCHED" and urls:
            raise ClaudePhaseToolPolicyError(
                f"unresearched dependency may not claim a source: {obligation_id}"
            )
        statuses[obligation_id] = status
        for url in urls:
            claims.add((obligation_id, url))
    if not header_seen:
        raise ClaudePhaseToolPolicyError("dependency report header is missing")
    missing_rows = expected_ids - seen_ids
    if missing_rows:
        raise ClaudePhaseToolPolicyError(
            "dependency report omits obligation rows: " + ",".join(sorted(missing_rows))
        )
    return sorted(claims), statuses


def validate_dependency_source_receipt_coverage(
    policy: Mapping[str, Any], *, report_bytes: bytes | None = None,
    claimed_sources: Iterable[tuple[str, str]] | None = None,
) -> list[str]:
    """Join claimed dependency sources to successful same-policy fetches."""

    try:
        checked = validate_policy_manifest(policy)
        authority = _web_authority(checked)
        expected_ids = {row["obligation_id"] for row in authority["obligations"]}
        if (report_bytes is None) == (claimed_sources is None):
            raise ClaudePhaseToolPolicyError(
                "supply exactly one source-claim representation"
            )
        if report_bytes is not None:
            claims, statuses = _claimed_sources_from_report(
                report_bytes, expected_ids,
            )
        else:
            claims = []
            statuses = None
            assert claimed_sources is not None
            for raw_id, raw_url in claimed_sources:
                obligation_id = str(raw_id)
                if obligation_id not in expected_ids:
                    raise ClaudePhaseToolPolicyError("source claim has unknown obligation")
                claims.append((obligation_id, _normalize_https_url(raw_url)))
            if claims != sorted(set(claims)):
                raise ClaudePhaseToolPolicyError("source claims are not canonical")
        receipts = _web_receipts(checked)
        state_issues = _web_receipt_state_issues(receipts, authority)
        if state_issues:
            return state_issues
        fetched = {
            (obligation_id, url)
            for row in receipts
            if row["event_kind"] == "POST_SUCCESS"
            and row["tool_name"] == "WebFetch"
            and row["outcome"] == "SUCCESS"
            for obligation_id in row["obligation_ids"]
            for url in row["source_urls"]
        }
        errors: list[str] = []
        failed_obligations = {
            obligation_id
            for row in receipts
            if row["event_kind"] == "POST_FAILURE"
            and row["tool_name"] == "WebFetch"
            and row["reason_code"] in {
                "WEB_POST_FAILURE", "WEB_RESPONSE_REJECTED",
            }
            for obligation_id in row["obligation_ids"]
        }
        successful_obligations = {
            obligation_id for obligation_id, _url in fetched
        }
        if statuses is not None:
            overlap = failed_obligations & successful_obligations
            if overlap:
                errors.append(
                    "dependency has conflicting fetch outcomes: "
                    + ",".join(sorted(overlap))
                )
            claimed_sources_by_id = {
                obligation_id: {
                    url for claimed_id, url in claims
                    if claimed_id == obligation_id
                }
                for obligation_id in expected_ids
            }
            fetched_sources_by_id = {
                obligation_id: {
                    url for fetched_id, url in fetched
                    if fetched_id == obligation_id
                }
                for obligation_id in expected_ids
            }
            for obligation_id in sorted(expected_ids):
                if obligation_id in failed_obligations:
                    expected_status = "FETCH_FAILED"
                elif obligation_id in successful_obligations:
                    expected_status = "RESEARCHED"
                else:
                    expected_status = "NEEDS_DEPENDENCY_RESEARCH"
                if statuses.get(obligation_id) != expected_status:
                    errors.append(
                        "dependency fetch status differs from receipts: "
                        + obligation_id + " expected " + expected_status
                    )
                if (
                    expected_status == "RESEARCHED"
                    and claimed_sources_by_id[obligation_id]
                    != fetched_sources_by_id[obligation_id]
                ):
                    errors.append(
                        "dependency successful WebFetch claim set differs from "
                        "receipts: " + obligation_id
                    )
        for obligation_id, url in claims:
            if (
                (obligation_id, url) not in fetched
                and (statuses is None or obligation_id not in successful_obligations)
            ):
                errors.append(
                    f"dependency source lacks successful WebFetch receipt: {obligation_id} {url}"
                )
        return errors
    except (ClaudePhaseToolPolicyError, OSError, RuntimeError, TypeError, ValueError) as exc:
        return [f"dependency web receipt authority is invalid: {exc}"]


def staged_dependency_research_receipt_validator(
    staged_outputs: Mapping[str, bytes], context: Mapping[str, Any],
) -> list[str]:
    """Gate dependency research bytes on exact writes and receipted sources."""

    required = {
        "schema", "policy_path", "manifest_digest", "output_directory",
        "expected_outputs", "research_output",
    }
    if (
        not isinstance(context, Mapping)
        or set(context) != required
        or context.get("schema") != "plamen.claude_dependency_research_staged_gate.v1"
    ):
        return ["staged dependency-research gate context is invalid"]
    expected_outputs = context.get("expected_outputs")
    if (
        not isinstance(expected_outputs, list)
        or not expected_outputs
        or any(not isinstance(value, str) or not value for value in expected_outputs)
    ):
        return ["staged dependency-research output denominator is invalid"]
    direct_keys = set(expected_outputs)
    identity_keys = {f"scratchpad:{value}" for value in expected_outputs}
    actual_keys = set(staged_outputs)
    if actual_keys == direct_keys:
        normalized_staged = dict(staged_outputs)
    elif actual_keys == identity_keys:
        normalized_staged = {
            key.removeprefix("scratchpad:"): value
            for key, value in staged_outputs.items()
        }
    else:
        return ["staged dependency-research canonical identity denominator mismatch"]
    base = {
        "schema": "plamen.claude_exact_staged_gate.v1",
        "policy_path": context["policy_path"],
        "manifest_digest": context["manifest_digest"],
        "output_directory": context["output_directory"],
        "expected_outputs": expected_outputs,
    }
    errors = staged_exact_output_receipt_validator(normalized_staged, base)
    if errors:
        return errors
    research_output = context.get("research_output")
    if not isinstance(research_output, str) or research_output not in normalized_staged:
        return ["staged dependency research output is unavailable"]
    try:
        policy = load_policy(Path(str(context["policy_path"])))
    except (ClaudePhaseToolPolicyError, OSError, RuntimeError) as exc:
        return [f"staged dependency-research policy is invalid: {exc}"]
    return validate_dependency_source_receipt_coverage(
        policy, report_bytes=normalized_staged[research_output],
    )


def _hook_output(
    decision: str, reason: str, *, updated_input: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    result = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow" if decision == "ALLOW" else "deny",
            "permissionDecisionReason": reason,
        }
    }
    if decision == "ALLOW" and updated_input is not None:
        result["hookSpecificOutput"]["updatedInput"] = dict(updated_input)
    return result


def run_hook(policy_path: Path, raw_event: bytes) -> tuple[int, dict[str, Any]]:
    try:
        policy = load_policy(policy_path)
        if len(raw_event) > int(policy["max_hook_input_bytes"]):
            raise ClaudePhaseToolPolicyError("hook event exceeds byte bound")
        event = json.loads(raw_event.decode("utf-8", errors="strict"))
        if not isinstance(event, dict) or not isinstance(event.get("tool_input"), dict):
            raise ClaudePhaseToolPolicyError("hook event is malformed")
        event_name = event.get("hook_event_name")
        if not isinstance(event_name, str) or event_name not in {
            "PreToolUse", "PostToolUse", "PostToolUseFailure",
        }:
            raise ClaudePhaseToolPolicyError("hook event name is unsupported")
        tool_name = str(event.get("tool_name") or "")
        if tool_name in _WEB_TOOLS:
            _validate_web_event_context(event, policy)
        if event_name in {"PostToolUse", "PostToolUseFailure"}:
            if tool_name not in _WEB_TOOLS:
                raise ClaudePhaseToolPolicyError("post hook received a non-web tool")
            with _web_receipt_lock(policy):
                _record_web_post(
                    event, policy, success=event_name == "PostToolUse",
                )
            return 0, {}
        if tool_name in _WEB_TOOLS:
            with _web_receipt_lock(policy):
                decision, obligations = _evaluate_web_pre(event, policy)
                allowed = decision["decision"] == "ALLOW"
                effective_input = (
                    dict(decision["effective_tool_input"])
                    if allowed else dict(event["tool_input"])
                )
                receipt = _web_receipt_payload(
                    event_kind="PRE" if allowed else "PRE_DENY",
                    event=event, policy=policy,
                    obligations=obligations,
                    normalized_target=str(decision["target"]),
                    outcome="ALLOW" if allowed else "DENY",
                    reason_code=str(decision["reason_code"]),
                    request_role=(
                        str(decision["request_role"]) if allowed else "DENIED"
                    ),
                    proposed_tool_input=event["tool_input"],
                    effective_tool_input=effective_input,
                    rewrite_kind=(
                        str(decision["rewrite_kind"]) if allowed else "NONE"
                    ),
                    group_selector=(
                        str(decision["group_selector"]) if allowed else ""
                    ),
                    lineage_parent_receipt_digest=(
                        str(decision["lineage_parent_receipt_digest"])
                        if allowed else ""
                    ),
                    proposed_authority_digest=(
                        str(decision["proposed_authority_digest"])
                        if allowed and tool_name == "WebFetch" else None
                    ),
                )
                _persist_new_web_receipt(policy, receipt)
            return 0, _hook_output(
                str(decision["decision"]), str(decision["reason_code"]),
                updated_input=(
                    effective_input
                    if allowed and decision["rewrite_kind"] != "NONE" else None
                ),
            )
        decision = evaluate_tool_call(
            tool_name=tool_name,
            tool_input=event["tool_input"],
            cwd=Path(str(event.get("cwd") or "")),
            policy=policy,
        )
        receipt = _receipt_payload(event=event, policy=policy, decision=decision)
        try:
            _persist_receipt(policy, receipt)
        except ClaudePhaseToolPolicyError:
            decision = {
                "decision": "DENY",
                "reason_code": "RECEIPT_PERSISTENCE_FAILED",
                "target": str(decision.get("target") or ""),
            }
        return 0, _hook_output(
            str(decision["decision"]), str(decision["reason_code"])
        )
    except Exception as exc:
        # Exit 2 is Claude Code's fail-closed blocking hook signal.  Keep the
        # message content-free: the driver can inspect its own policy files.
        return 2, {"error": f"PLAMEN_TOOL_POLICY_DENY:{type(exc).__name__}"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", required=True)
    args = parser.parse_args(argv)
    raw = sys.stdin.buffer.read(MAX_POLICY_BYTES + 1)
    code, output = run_hook(Path(args.policy), raw)
    stream = sys.stdout if code == 0 else sys.stderr
    stream.write(json.dumps(output, sort_keys=True, separators=(",", ":")) + "\n")
    stream.flush()
    return code


if __name__ == "__main__":  # pragma: no cover - exercised as a subprocess
    raise SystemExit(main())
