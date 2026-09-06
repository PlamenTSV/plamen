"""Compile one attempt-independent Claude launch-security authority.

This record is the semantic policy frozen by a Worker WorkPlan.  It contains
no credential value, profile path, lease path, attempt identity, or other
attempt-local material.  WorkerTransaction/WER later materialize those
resources and must prove that the concrete launch is an exact realization of
this policy.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping, Sequence

from claude_auth_route import (
    ClaudeAuthRouteError,
    compile_claude_endpoint_policy,
    expected_init_api_key_sources,
    replay_claude_endpoint_policy,
)
from claude_executable_observation import (
    ClaudeExecutableObservationError,
    replay_claude_executable_observation,
)
from claude_headless_profile import (
    TYPED_PROFILE_SCHEMA,
    ClaudeHeadlessProfileError,
    replay_claude_headless_profile,
)
from claude_child_environment import (
    ClaudeChildEnvironmentError,
    normalize_claude_functional_controls,
    normalize_claude_phase_environment_policies,
)


CLAUDE_LAUNCH_SECURITY_SCHEMA = "plamen.claude_launch_security.v1"
CLAUDE_AUTH_ROUTE_POLICY_SCHEMA = "plamen.claude_auth_route_policy.v1"
CLAUDE_SETTINGS_AUTHORITY_SCHEMA = "plamen.claude_settings_authority.v1"
CLAUDE_MCP_AUTHORITY_SCHEMA = "plamen.claude_mcp_authority.v1"
CLAUDE_MCP_AUTHORITY_SELECTION_SCHEMA = "plamen.claude_mcp_authority.v2"
MCP_CURRENT_SELECTION_SCHEMA = "plamen.mcp_current_selection.v1"
CLAUDE_LAUNCH_SECURITY_REQUEST_SCHEMA = (
    "plamen.claude_launch_security_request.v1"
)

_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_HOME_POLICIES = {"PRIVATE_HOME", "PRESERVE_TOOLCHAIN_HOME"}
_SETTINGS_MODES = {"SAFE_MODE", "BOUND_SETTINGS"}
_MCP_SELECTION_KEYS = {
    "schema",
    "store_root",
    "generation_id",
    "receipt_sha256",
    "census_sha256",
    "request_sha256",
    "generation_policy_sha256",
    "receipt_key_id",
    "receipt_public_key",
    "install_transaction_id",
    "install_receipt_sha256",
    "install_source_manifest_sha256",
    "install_runtime_manifest_sha256",
    "install_adapter_manifest_sha256",
    "server_launches",
    "backend_launches",
    "signature",
}
_MCP_SERVER_LAUNCH_KEYS = {
    "entrypoint",
    "node_args",
    "cwd",
    "environment_names",
}
_BACKEND_LAUNCH_KEYS = {
    "execution_kind",
    "relative_path",
    "version",
    "size",
    "sha256",
    "member_authority",
}
_MCP_MEMBER_AUTHORITY_KEYS = {
    "schema", "generation_id", "receipt_sha256", "census_sha256",
    "request_sha256", "generation_policy_sha256", "execution_kind",
    "receipt_file_sha256", "relative_path", "size", "sha256", "mode",
    "link_count", "closure_root", "closure_count", "closure_sha256",
    "closure", "ancestors",
}
_MCP_MEMBER_CLOSURE_ROW_KEYS = {
    "path", "kind", "size", "sha256", "mode", "link_count", "reparse",
}
_MCP_MEMBER_ANCESTOR_KEYS = {"path", "mode", "link_count", "reparse"}
_MCP_MEMBER_AUTHENTICATION_KEYS = {"scheme", "key_id", "signature"}
_MCP_MEMBER_AUTHORITY_SCHEMA = "plamen.mcp_native_resource_closure.v2"
_MCP_MAX_NATIVE_RESOURCE_CLOSURE_ROWS = 16
_MCP_MAX_NATIVE_RESOURCE_CLOSURE_BYTES = 2 * 1024 * 1024 * 1024
_CLAUDE_NATIVE_PATH = (
    "node_modules/@anthropic-ai/claude-code/bin/claude.exe"
)
_CODEX_NATIVE_PATH_RE = re.compile(
    r"node_modules/@openai/codex-(darwin|linux|win32)-(arm64|x64)/"
    r"vendor/([^/]+)/bin/(codex(?:\.exe)?)\Z"
)
_CODEX_NATIVE_TARGETS = {
    ("darwin", "arm64"): "aarch64-apple-darwin",
    ("darwin", "x64"): "x86_64-apple-darwin",
    ("linux", "arm64"): "aarch64-unknown-linux-musl",
    ("linux", "x64"): "x86_64-unknown-linux-musl",
    ("win32", "arm64"): "aarch64-pc-windows-msvc",
    ("win32", "x64"): "x86_64-pc-windows-msvc",
}


class ClaudeLaunchSecurityError(RuntimeError):
    """A Claude launch policy has ambiguous or contradictory authority."""


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ClaudeLaunchSecurityError(
            "Claude launch-security policy is not canonical JSON"
        ) from exc


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _sha256(value: Any, *, label: str, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ClaudeLaunchSecurityError(f"{label} must be a lowercase SHA-256")
    return value


def _names(
    value: Sequence[str],
    *,
    label: str,
    require_base: bool = False,
) -> list[str]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ClaudeLaunchSecurityError(f"{label} must be a sequence")
    result = list(value)
    if (
        any(
            not isinstance(item, str)
            or _NAME_RE.fullmatch(item) is None
            for item in result
        )
        or len(result) != len(set(result))
        or (require_base and "base" not in result)
    ):
        raise ClaudeLaunchSecurityError(
            f"{label} is duplicated, malformed, or lacks base"
        )
    return sorted(result)


def _native_backend_roster(relative: str) -> tuple[str, frozenset[str]]:
    """Return the exact native closure published by the installed front."""

    if relative == _CLAUDE_NATIVE_PATH:
        root = relative.rsplit("/", 1)[0]
        return root, frozenset({root, relative})
    matched = _CODEX_NATIVE_PATH_RE.fullmatch(relative)
    if matched is None:
        raise ClaudeLaunchSecurityError(
            "MCP selection backend native path is unsupported"
        )
    platform_name, architecture, target, primary_name = matched.groups()
    expected_target = _CODEX_NATIVE_TARGETS[(platform_name, architecture)]
    expected_primary = "codex.exe" if platform_name == "win32" else "codex"
    if target != expected_target or primary_name != expected_primary:
        raise ClaudeLaunchSecurityError(
            "MCP selection Codex native target topology differs"
        )
    root = relative.rsplit("/bin/", 1)[0]
    suffix = ".exe" if platform_name == "win32" else ""
    members = {
        ".", "bin", "codex-path", "codex-resources", "codex-package.json",
        f"bin/codex{suffix}", f"bin/codex-code-mode-host{suffix}",
        f"codex-path/rg{suffix}",
    }
    if platform_name == "win32":
        members.update({
            "codex-resources/codex-command-runner.exe",
            "codex-resources/codex-windows-sandbox-setup.exe",
        })
    else:
        members.update({
            "codex-resources/zsh", "codex-resources/zsh/bin",
            "codex-resources/zsh/bin/zsh",
        })
        if platform_name == "linux":
            members.add("codex-resources/bwrap")
    return root, frozenset(
        root if member == "." else f"{root}/{member}" for member in members
    )


def _replay_backend_member_authority(
    value: Any,
    *,
    selection: Mapping[str, Any],
    row: Mapping[str, Any],
) -> None:
    """Validate the nested signed closure and bind it to its selection row."""

    if not isinstance(value, dict) or set(value) != {
        "authority", "authentication",
    }:
        raise ClaudeLaunchSecurityError(
            "MCP selection backend member authority fields drifted"
        )
    authority = value.get("authority")
    authentication = value.get("authentication")
    if (
        not isinstance(authority, dict)
        or set(authority) != _MCP_MEMBER_AUTHORITY_KEYS
        or not isinstance(authentication, dict)
        or set(authentication) != _MCP_MEMBER_AUTHENTICATION_KEYS
    ):
        raise ClaudeLaunchSecurityError(
            "MCP selection backend member authority is malformed"
        )
    for field in (
        "receipt_sha256", "census_sha256", "request_sha256",
        "generation_policy_sha256", "receipt_file_sha256", "sha256",
        "closure_sha256",
    ):
        _sha256(authority.get(field), label=f"MCP member authority {field}")
    if (
        authority.get("schema") != _MCP_MEMBER_AUTHORITY_SCHEMA
        or authority.get("generation_id") != selection["generation_id"]
        or authority.get("receipt_sha256") != selection["receipt_sha256"]
        or authority.get("census_sha256") != selection["census_sha256"]
        or authority.get("request_sha256") != selection["request_sha256"]
        or authority.get("generation_policy_sha256")
        != selection["generation_policy_sha256"]
        or authority.get("execution_kind") != row["execution_kind"]
        or authority.get("relative_path") != row["relative_path"]
        or authority.get("size") != row["size"]
        or authority.get("sha256") != row["sha256"]
        or type(authority.get("mode")) is not int
        or not 0 <= authority["mode"] <= 0o7777
        or type(authority.get("link_count")) is not int
        or authority["link_count"] != 1
    ):
        raise ClaudeLaunchSecurityError(
            "MCP selection backend member authority binding differs"
        )

    closure_root, expected_roster = _native_backend_roster(row["relative_path"])
    closure = authority.get("closure")
    if (
        authority.get("closure_root") != closure_root
        or not isinstance(closure, list)
        or not closure
        or len(closure) > _MCP_MAX_NATIVE_RESOURCE_CLOSURE_ROWS
        or type(authority.get("closure_count")) is not int
        or authority["closure_count"] != len(closure)
        or authority["closure_sha256"]
        != hashlib.sha256(_canonical_json(closure)).hexdigest()
    ):
        raise ClaudeLaunchSecurityError(
            "MCP selection backend member closure differs"
        )
    paths: list[str] = []
    total_file_bytes = 0
    primary: Mapping[str, Any] | None = None
    for member in closure:
        if (
            not isinstance(member, dict)
            or set(member) != _MCP_MEMBER_CLOSURE_ROW_KEYS
            or member.get("kind") not in {"file", "directory"}
            or member.get("reparse") is not False
            or not isinstance(member.get("path"), str)
            or type(member.get("size")) is not int
            or member["size"] < 0
            or type(member.get("mode")) is not int
            or not 0 <= member["mode"] <= 0o7777
            or type(member.get("link_count")) is not int
            or member["link_count"] < 1
            or (member["kind"] == "file" and member["link_count"] != 1)
            or _sha256(
                member.get("sha256"), label="MCP member closure digest"
            ) is None
        ):
            raise ClaudeLaunchSecurityError(
                "MCP selection backend member closure row differs"
            )
        paths.append(member["path"])
        if member["kind"] == "file":
            total_file_bytes += member["size"]
        if member["path"] == row["relative_path"]:
            primary = member
    if (
        closure != sorted(closure, key=lambda item: (item["path"].casefold(), item["path"]))
        or len(paths) != len({path.casefold() for path in paths})
        or set(paths) != expected_roster
        or total_file_bytes > _MCP_MAX_NATIVE_RESOURCE_CLOSURE_BYTES
        or primary is None
        or primary.get("kind") != "file"
        or any(
            primary[field] != authority[field]
            for field in ("size", "sha256", "mode", "link_count")
        )
    ):
        raise ClaudeLaunchSecurityError(
            "MCP selection backend member closure topology differs"
        )

    closure_parts = closure_root.split("/")
    parent_parts = closure_parts[:-1]
    expected_ancestor_paths = ["."] + [
        "/".join(parent_parts[:index])
        for index in range(1, len(parent_parts) + 1)
    ]
    ancestors = authority.get("ancestors")
    if not isinstance(ancestors, list) or len(ancestors) != len(
        expected_ancestor_paths
    ):
        raise ClaudeLaunchSecurityError(
            "MCP selection backend member ancestors differ"
        )
    for ancestor, expected_path in zip(ancestors, expected_ancestor_paths):
        if (
            not isinstance(ancestor, dict)
            or set(ancestor) != _MCP_MEMBER_ANCESTOR_KEYS
            or ancestor.get("path") != expected_path
            or type(ancestor.get("mode")) is not int
            or not 0 <= ancestor["mode"] <= 0o7777
            or type(ancestor.get("link_count")) is not int
            or ancestor["link_count"] < 1
            or ancestor.get("reparse") is not False
        ):
            raise ClaudeLaunchSecurityError(
                "MCP selection backend member ancestor differs"
            )

    public = selection["receipt_public_key"]
    expected_key_id = hashlib.sha256(bytes.fromhex(public)).hexdigest()
    if (
        selection["receipt_key_id"] != expected_key_id
        or authentication.get("scheme") != "ed25519"
        or authentication.get("key_id") != expected_key_id
        or not isinstance(authentication.get("signature"), str)
        or re.fullmatch(r"[0-9a-f]{128}", authentication["signature"]) is None
    ):
        raise ClaudeLaunchSecurityError(
            "MCP selection backend member authentication differs"
        )
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )

        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public)).verify(
            bytes.fromhex(authentication["signature"]),
            _canonical_json(authority),
        )
    except Exception as exc:
        raise ClaudeLaunchSecurityError(
            "MCP selection backend member signature differs"
        ) from exc


def replay_mcp_current_selection(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Replay the signed selection emitted by the authenticated install front.

    Signature verification belongs to the installed front.  Consumers retain
    the complete signed record and reject any structural or canonical drift so
    its authenticated identity can be carried through every Claude authority.
    """

    if not isinstance(value, Mapping) or set(value) != _MCP_SELECTION_KEYS:
        raise ClaudeLaunchSecurityError(
            "MCP current-selection fields drifted"
        )
    try:
        clone = json.loads(_canonical_json(dict(value)).decode("utf-8"))
    except (json.JSONDecodeError, UnicodeError, TypeError, ValueError) as exc:
        raise ClaudeLaunchSecurityError(
            "MCP current-selection is not canonical JSON"
        ) from exc
    if clone.get("schema") != MCP_CURRENT_SELECTION_SCHEMA:
        raise ClaudeLaunchSecurityError(
            "MCP current-selection schema is unsupported"
        )
    for name in (
        "receipt_sha256",
        "census_sha256",
        "request_sha256",
        "generation_policy_sha256",
        "install_receipt_sha256",
        "install_source_manifest_sha256",
        "install_runtime_manifest_sha256",
        "install_adapter_manifest_sha256",
        "receipt_key_id",
    ):
        _sha256(clone.get(name), label=f"MCP selection {name}")
    for name in (
        "generation_id",
        "install_transaction_id",
    ):
        raw = clone.get(name)
        if not isinstance(raw, str) or _NAME_RE.fullmatch(raw) is None:
            raise ClaudeLaunchSecurityError(
                f"MCP selection {name} is malformed"
            )
    for name in ("store_root",):
        raw = clone.get(name)
        if (
            not isinstance(raw, str)
            or not raw
            or raw != raw.strip()
            or "\x00" in raw
        ):
            raise ClaudeLaunchSecurityError(
                f"MCP selection {name} is malformed"
            )
    for name, length in (("receipt_public_key", 64), ("signature", 128)):
        raw = clone.get(name)
        if (
            not isinstance(raw, str)
            or len(raw) != length
            or re.fullmatch(r"[0-9a-f]+", raw) is None
        ):
            raise ClaudeLaunchSecurityError(
                f"MCP selection {name} is malformed"
            )
    launches = clone.get("server_launches")
    if not isinstance(launches, dict) or not launches:
        raise ClaudeLaunchSecurityError(
            "MCP selection server launches are absent"
        )
    normalized_launches: dict[str, dict[str, Any]] = {}
    for server_name, launch in launches.items():
        if (
            not isinstance(server_name, str)
            or _NAME_RE.fullmatch(server_name) is None
            or not isinstance(launch, dict)
            or set(launch) != _MCP_SERVER_LAUNCH_KEYS
        ):
            raise ClaudeLaunchSecurityError(
                "MCP selection server launch is malformed"
            )
        raw = launch.get("entrypoint")
        if (
            not isinstance(raw, str)
            or not raw
            or raw != raw.strip()
            or "\x00" in raw
        ):
            raise ClaudeLaunchSecurityError(
                "MCP selection server launch path is malformed"
            )
        cwd = launch.get("cwd")
        if cwd is not None and (
            not isinstance(cwd, str)
            or not cwd
            or cwd != cwd.strip()
            or "\x00" in cwd
        ):
            raise ClaudeLaunchSecurityError(
                "MCP selection server launch cwd is malformed"
            )
        normalized: dict[str, Any] = {
            "entrypoint": launch["entrypoint"],
            "cwd": cwd,
        }
        for sequence_name in ("node_args", "environment_names"):
            sequence = launch.get(sequence_name)
            if (
                not isinstance(sequence, list)
                or any(
                    not isinstance(item, str)
                    or not item
                    or "\x00" in item
                    for item in sequence
                )
                or (
                    sequence_name == "environment_names"
                    and sequence != sorted(set(sequence))
                )
            ):
                raise ClaudeLaunchSecurityError(
                    "MCP selection server launch vector is malformed"
                )
            normalized[sequence_name] = list(sequence)
        normalized_launches[server_name] = {
            key: normalized[key]
            for key in ("entrypoint", "node_args", "cwd", "environment_names")
        }
    if list(launches) != sorted(launches):
        raise ClaudeLaunchSecurityError(
            "MCP selection server launches are not sorted"
        )
    clone["server_launches"] = normalized_launches
    backends = clone.get("backend_launches")
    if not isinstance(backends, dict) or set(backends) != {"claude", "codex"}:
        raise ClaudeLaunchSecurityError(
            "MCP selection backend launches are malformed"
        )
    expected_backend_rows = {
        "claude": ("native", "2.1.252"),
        "codex": ("native", "0.152.0"),
    }
    for backend, (kind, version) in expected_backend_rows.items():
        row = backends.get(backend)
        if (
            not isinstance(row, dict)
            or set(row) != _BACKEND_LAUNCH_KEYS
            or row.get("execution_kind") != kind
            or row.get("version") != version
            or isinstance(row.get("size"), bool)
            or not isinstance(row.get("size"), int)
            or row["size"] < 0
            or _sha256(
                row.get("sha256"),
                label=f"MCP selection {backend} backend digest",
            )
            is None
        ):
            raise ClaudeLaunchSecurityError(
                f"MCP selection {backend} backend launch is malformed"
            )
        if backend == "claude" and row.get("relative_path") != _CLAUDE_NATIVE_PATH:
            raise ClaudeLaunchSecurityError(
                "MCP selection Claude backend launch is malformed"
            )
        if backend == "codex":
            _native_backend_roster(row.get("relative_path"))
        _replay_backend_member_authority(
            row["member_authority"], selection=clone, row=row,
        )
    return clone


def mcp_current_selection_sha256(value: Mapping[str, Any]) -> str:
    """Return the full signed selection identity after strict replay."""

    return hashlib.sha256(
        _canonical_json(replay_mcp_current_selection(value))
    ).hexdigest()


def compile_claude_auth_route_policy(
    *,
    claude_code_version: str,
    desired_route: str,
    endpoint_policy: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Compile the route and exact init-source vocabulary without secrets."""

    try:
        expected_sources = list(
            expected_init_api_key_sources(
                claude_code_version=claude_code_version,
                desired_route=desired_route,
            )
        )
        endpoint = (
            compile_claude_endpoint_policy(
                desired_route=desired_route,
                endpoint_mode="OFFICIAL_DEFAULT",
                endpoint_environment={},
            )
            if endpoint_policy is None
            else replay_claude_endpoint_policy(endpoint_policy)
        )
    except ClaudeAuthRouteError as exc:
        raise ClaudeLaunchSecurityError(
            f"Claude auth-route policy is invalid: {exc}"
        ) from exc
    if endpoint["desired_route"] != desired_route:
        raise ClaudeLaunchSecurityError(
            "Claude endpoint and auth-route policies differ"
        )
    core = {
        "schema": CLAUDE_AUTH_ROUTE_POLICY_SCHEMA,
        "claude_code_version": claude_code_version,
        "desired_route": desired_route,
        "expected_init_api_key_sources": expected_sources,
        "endpoint_policy": endpoint,
    }
    return {**core, "policy_sha256": _digest(core)}


def replay_claude_auth_route_policy(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ClaudeLaunchSecurityError("Claude auth-route policy must be an object")
    clone = dict(value)
    if set(clone) != {
        "schema",
        "claude_code_version",
        "desired_route",
        "expected_init_api_key_sources",
        "endpoint_policy",
        "policy_sha256",
    }:
        raise ClaudeLaunchSecurityError("Claude auth-route policy fields drifted")
    digest = clone.pop("policy_sha256")
    try:
        rebuilt = compile_claude_auth_route_policy(
            claude_code_version=clone.get("claude_code_version"),
            desired_route=clone.get("desired_route"),
            endpoint_policy=clone.get("endpoint_policy"),
        )
    except (ClaudeLaunchSecurityError, TypeError) as exc:
        raise ClaudeLaunchSecurityError(
            f"Claude auth-route policy does not replay: {exc}"
        ) from exc
    if (
        clone.get("schema") != CLAUDE_AUTH_ROUTE_POLICY_SCHEMA
        or _sha256(digest, label="Claude auth-route policy digest") is None
        or rebuilt != {**clone, "policy_sha256": digest}
    ):
        raise ClaudeLaunchSecurityError("Claude auth-route policy does not replay")
    return rebuilt


def compile_claude_settings_authority(
    *,
    mode: str,
    settings_sha256: str | None,
    external_policy_sha256: str | None,
) -> dict[str, Any]:
    """Compile a settings policy with an identity even when no file is used."""

    settings_digest = _sha256(
        settings_sha256,
        label="Claude settings digest",
        optional=True,
    )
    policy_digest = _sha256(
        external_policy_sha256,
        label="Claude external settings-policy digest",
        optional=True,
    )
    if (
        mode not in _SETTINGS_MODES
        or (
            mode == "SAFE_MODE"
            and (settings_digest is not None or policy_digest is not None)
        )
        or (
            mode == "BOUND_SETTINGS"
            and (settings_digest is None or policy_digest is None)
        )
    ):
        raise ClaudeLaunchSecurityError(
            "Claude settings authority is contradictory"
        )
    core = {
        "schema": CLAUDE_SETTINGS_AUTHORITY_SCHEMA,
        "mode": mode,
        "settings_sha256": settings_digest,
        "external_policy_sha256": policy_digest,
    }
    return {**core, "authority_sha256": _digest(core)}


def _settings_authority(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "schema",
        "mode",
        "settings_sha256",
        "external_policy_sha256",
        "authority_sha256",
    }:
        raise ClaudeLaunchSecurityError(
            "Claude settings authority fields drifted"
        )
    rebuilt = compile_claude_settings_authority(
        mode=value.get("mode"),
        settings_sha256=value.get("settings_sha256"),
        external_policy_sha256=value.get("external_policy_sha256"),
    )
    if (
        value.get("schema") != CLAUDE_SETTINGS_AUTHORITY_SCHEMA
        or value.get("authority_sha256") != rebuilt["authority_sha256"]
    ):
        raise ClaudeLaunchSecurityError(
            "Claude settings authority does not replay"
        )
    return rebuilt


def compile_claude_mcp_authority(
    *,
    settings_mode: str,
    server_names: Sequence[str],
    source_manifest_sha256: str | None,
    selected_config_sha256: str | None,
    runtime_selection: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Compile the exact MCP policy, including the empty SAFE_MODE policy."""

    servers = _names(server_names, label="Claude MCP servers")
    manifest = _sha256(
        source_manifest_sha256,
        label="Claude MCP source-manifest digest",
        optional=True,
    )
    selected = _sha256(
        selected_config_sha256,
        label="Claude selected MCP-config digest",
        optional=True,
    )
    selection = (
        None
        if runtime_selection is None
        else replay_mcp_current_selection(runtime_selection)
    )
    if selection is not None and any(
        server not in selection["server_launches"] for server in servers
    ):
        raise ClaudeLaunchSecurityError(
            "Claude MCP servers are absent from runtime selection"
        )
    if (
        settings_mode not in _SETTINGS_MODES
        or (
            settings_mode == "SAFE_MODE"
            and (servers or manifest is not None or selected is not None)
        )
        or (
            settings_mode == "BOUND_SETTINGS"
            and (
                selected is None
                or (bool(servers) != (manifest is not None))
            )
        )
    ):
        raise ClaudeLaunchSecurityError(
            "Claude MCP authority is contradictory"
        )
    core = {
        "schema": (
            CLAUDE_MCP_AUTHORITY_SCHEMA
            if selection is None
            else CLAUDE_MCP_AUTHORITY_SELECTION_SCHEMA
        ),
        "server_names": servers,
        "source_manifest_sha256": manifest,
        "selected_config_sha256": selected,
    }
    if selection is not None:
        core["runtime_selection"] = selection
        core["runtime_selection_sha256"] = mcp_current_selection_sha256(
            selection
        )
    return {**core, "authority_sha256": _digest(core)}


def _mcp_authority(value: Mapping[str, Any], *, settings_mode: str) -> dict[str, Any]:
    legacy_fields = {
        "schema",
        "server_names",
        "source_manifest_sha256",
        "selected_config_sha256",
        "authority_sha256",
    }
    selection_fields = legacy_fields | {
        "runtime_selection",
        "runtime_selection_sha256",
    }
    if not isinstance(value, Mapping) or set(value) not in {
        frozenset(legacy_fields),
        frozenset(selection_fields),
    }:
        raise ClaudeLaunchSecurityError("Claude MCP authority fields drifted")
    selection = value.get("runtime_selection")
    rebuilt = compile_claude_mcp_authority(
        settings_mode=settings_mode,
        server_names=value.get("server_names"),
        source_manifest_sha256=value.get("source_manifest_sha256"),
        selected_config_sha256=value.get("selected_config_sha256"),
        runtime_selection=selection,
    )
    if (
        value.get("schema")
        != (
            CLAUDE_MCP_AUTHORITY_SCHEMA
            if selection is None
            else CLAUDE_MCP_AUTHORITY_SELECTION_SCHEMA
        )
        or (
            selection is not None
            and value.get("runtime_selection_sha256")
            != mcp_current_selection_sha256(selection)
        )
        or value.get("authority_sha256") != rebuilt["authority_sha256"]
    ):
        raise ClaudeLaunchSecurityError("Claude MCP authority does not replay")
    return rebuilt


def _functional_controls(value: Mapping[str, str]) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise ClaudeLaunchSecurityError(
            "Claude functional controls must be an object"
        )
    result: dict[str, str] = {}
    for name, raw in value.items():
        if (
            not isinstance(name, str)
            or _NAME_RE.fullmatch(name) is None
            or not isinstance(raw, str)
            or not raw
            or "\x00" in raw
        ):
            raise ClaudeLaunchSecurityError(
                "Claude functional controls are malformed"
            )
        result[name] = raw
    return dict(sorted(result.items()))


def compile_claude_launch_security(
    *,
    headless_profile: Mapping[str, Any],
    auth_route_policy: Mapping[str, Any],
    executable_observation: Mapping[str, Any],
    settings_authority: Mapping[str, Any],
    mcp_authority: Mapping[str, Any],
    home_variable_policy: str,
    phase_environment_policies: Sequence[str],
    functional_controls: Mapping[str, str],
    expected_child_environment_key_set_sha256: str,
) -> dict[str, Any]:
    """Cross-check every attempt-independent Claude launch denominator."""

    try:
        profile = replay_claude_headless_profile(headless_profile)
        auth = replay_claude_auth_route_policy(auth_route_policy)
        executable = replay_claude_executable_observation(
            executable_observation
        )
    except (
        ClaudeHeadlessProfileError,
        ClaudeExecutableObservationError,
        ClaudeLaunchSecurityError,
    ) as exc:
        raise ClaudeLaunchSecurityError(
            f"Claude launch-security dependency does not replay: {exc}"
        ) from exc
    settings = _settings_authority(settings_authority)
    mcp = _mcp_authority(
        mcp_authority,
        settings_mode=settings["mode"],
    )
    try:
        environment_policies = (
            normalize_claude_phase_environment_policies(
                phase_environment_policies
            )
        )
        controls = normalize_claude_functional_controls(
            functional_controls,
            claude_code_version=profile["claude_code_version"],
        )
    except ClaudeChildEnvironmentError as exc:
        raise ClaudeLaunchSecurityError(
            f"Claude child-environment policy is invalid: {exc}"
        ) from exc
    expected_keys = _sha256(
        expected_child_environment_key_set_sha256,
        label="Claude expected child environment key-set digest",
    )
    version = profile["claude_code_version"]
    expected_init = profile["expected_init_contract"]
    if (
        profile.get("schema") != TYPED_PROFILE_SCHEMA
        or auth["claude_code_version"] != version
        or executable["claude_code_version"] != version
        or profile["executable_observation_reference"][
            "observation_sha256"
        ]
        != executable["observation_sha256"]
        or profile["auth_route_policy"] != auth
        or profile["settings_authority"] != settings
        or profile["mcp_authority"] != mcp
        or expected_init["accepted_api_key_sources"]
        != auth["expected_init_api_key_sources"]
        or profile["customization_mode"] != settings["mode"]
        or expected_init["allowed_mcp_servers"] != mcp["server_names"]
        or expected_init["required_mcp_servers"] != mcp["server_names"]
        or home_variable_policy not in _HOME_POLICIES
    ):
        raise ClaudeLaunchSecurityError(
            "Claude typed v2 profile embedded authorities disagree with "
            "the exact launch authorities"
        )
    core = {
        "schema": CLAUDE_LAUNCH_SECURITY_SCHEMA,
        "headless_profile": profile,
        "auth_route_policy": auth,
        "claude_code_version": version,
        "executable_observation_sha256": executable["observation_sha256"],
        "settings_authority": settings,
        "mcp_authority": mcp,
        "home_variable_policy": home_variable_policy,
        "phase_environment_policies": environment_policies,
        "functional_controls": controls,
        "expected_child_environment_key_set_sha256": expected_keys,
        "credential_values_recorded": False,
        "credential_content_hashes_recorded": False,
    }
    return {**core, "policy_sha256": _digest(core)}


def replay_claude_launch_security(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Replay a WorkPlan policy without requiring its private runtime request."""

    if not isinstance(value, Mapping):
        raise ClaudeLaunchSecurityError(
            "Claude launch-security policy must be an object"
        )
    clone = dict(value)
    expected_fields = {
        "schema",
        "headless_profile",
        "auth_route_policy",
        "claude_code_version",
        "executable_observation_sha256",
        "settings_authority",
        "mcp_authority",
        "home_variable_policy",
        "phase_environment_policies",
        "functional_controls",
        "expected_child_environment_key_set_sha256",
        "credential_values_recorded",
        "credential_content_hashes_recorded",
        "policy_sha256",
    }
    if set(clone) != expected_fields:
        raise ClaudeLaunchSecurityError(
            "Claude launch-security policy fields drifted"
        )
    digest = clone.pop("policy_sha256")
    try:
        profile = replay_claude_headless_profile(clone.get("headless_profile"))
        auth = replay_claude_auth_route_policy(clone.get("auth_route_policy"))
        settings = _settings_authority(clone.get("settings_authority"))
        mcp = _mcp_authority(
            clone.get("mcp_authority"),
            settings_mode=settings["mode"],
        )
        policies = normalize_claude_phase_environment_policies(
            clone.get("phase_environment_policies")
        )
        controls = normalize_claude_functional_controls(
            clone.get("functional_controls"),
            claude_code_version=profile["claude_code_version"],
        )
        executable_digest = _sha256(
            clone.get("executable_observation_sha256"),
            label="Claude executable observation digest",
        )
        expected_keys = _sha256(
            clone.get("expected_child_environment_key_set_sha256"),
            label="Claude expected child environment key-set digest",
        )
    except (
        ClaudeHeadlessProfileError,
        ClaudeChildEnvironmentError,
        ClaudeLaunchSecurityError,
        TypeError,
    ) as exc:
        raise ClaudeLaunchSecurityError(
            f"Claude launch-security policy does not replay: {exc}"
        ) from exc
    normalized = {
        "schema": CLAUDE_LAUNCH_SECURITY_SCHEMA,
        "headless_profile": profile,
        "auth_route_policy": auth,
        "claude_code_version": profile["claude_code_version"],
        "executable_observation_sha256": executable_digest,
        "settings_authority": settings,
        "mcp_authority": mcp,
        "home_variable_policy": clone.get("home_variable_policy"),
        "phase_environment_policies": policies,
        "functional_controls": controls,
        "expected_child_environment_key_set_sha256": expected_keys,
        "credential_values_recorded": False,
        "credential_content_hashes_recorded": False,
    }
    if (
        clone.get("schema") != CLAUDE_LAUNCH_SECURITY_SCHEMA
        or profile.get("schema") != TYPED_PROFILE_SCHEMA
        or auth["claude_code_version"] != profile["claude_code_version"]
        or clone.get("claude_code_version") != profile["claude_code_version"]
        or profile["executable_observation_reference"][
            "observation_sha256"
        ]
        != executable_digest
        or profile["auth_route_policy"] != auth
        or profile["settings_authority"] != settings
        or profile["mcp_authority"] != mcp
        or profile["expected_init_contract"]["accepted_api_key_sources"]
        != auth["expected_init_api_key_sources"]
        or profile["customization_mode"] != settings["mode"]
        or profile["expected_init_contract"]["allowed_mcp_servers"]
        != mcp["server_names"]
        or profile["expected_init_contract"]["required_mcp_servers"]
        != mcp["server_names"]
        or clone.get("home_variable_policy") not in _HOME_POLICIES
        or clone.get("credential_values_recorded") is not False
        or clone.get("credential_content_hashes_recorded") is not False
        or _sha256(digest, label="Claude launch-security policy digest") is None
        or digest != _digest(normalized)
    ):
        raise ClaudeLaunchSecurityError(
            "Claude launch-security typed v2 embedded authorities do not replay"
        )
    return {**normalized, "policy_sha256": digest}


def reconcile_claude_launch_security_request(
    policy: Mapping[str, Any],
    *,
    executable_observation: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind the full executable observation to its redacted WorkPlan policy."""

    replayed = replay_claude_launch_security(policy)
    try:
        executable = replay_claude_executable_observation(
            executable_observation
        )
    except ClaudeExecutableObservationError as exc:
        raise ClaudeLaunchSecurityError(
            f"Claude executable observation does not replay: {exc}"
        ) from exc
    if (
        executable["observation_sha256"]
        != replayed["executable_observation_sha256"]
        or executable["claude_code_version"]
        != replayed["claude_code_version"]
    ):
        raise ClaudeLaunchSecurityError(
            "Claude executable observation differs from WorkPlan policy"
        )
    return replayed


def compile_claude_launch_security_request(
    *,
    policy: Mapping[str, Any],
    executable_observation: Mapping[str, Any],
) -> dict[str, Any]:
    """Carry full, nonsecret replay material beside the redacted WorkPlan policy."""

    replayed_policy = reconcile_claude_launch_security_request(
        policy,
        executable_observation=executable_observation,
    )
    try:
        executable = replay_claude_executable_observation(
            executable_observation
        )
    except ClaudeExecutableObservationError as exc:
        raise ClaudeLaunchSecurityError(
            f"Claude executable observation does not replay: {exc}"
        ) from exc
    core = {
        "schema": CLAUDE_LAUNCH_SECURITY_REQUEST_SCHEMA,
        "policy": replayed_policy,
        "executable_observation": executable,
    }
    return {**core, "request_sha256": _digest(core)}


def replay_claude_launch_security_request(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ClaudeLaunchSecurityError(
            "Claude launch-security request must be an object"
        )
    clone = dict(value)
    if (
        clone.get("schema")
        == "plamen.test_only_claude_launch_security_request.v1"
        or clone.get("authority_class")
        == "TEST_ONLY_NO_PROVIDER_AUTHORITY"
    ):
        raise ClaudeLaunchSecurityError(
            "test-only request has no provider authority and cannot replay "
            "as a production Claude launch-security request"
        )
    if set(clone) != {
        "schema",
        "policy",
        "executable_observation",
        "request_sha256",
    }:
        raise ClaudeLaunchSecurityError(
            "Claude launch-security request fields drifted"
        )
    digest = clone.pop("request_sha256")
    try:
        rebuilt = compile_claude_launch_security_request(
            policy=clone.get("policy"),
            executable_observation=clone.get("executable_observation"),
        )
    except (ClaudeLaunchSecurityError, TypeError) as exc:
        raise ClaudeLaunchSecurityError(
            f"Claude launch-security request does not replay: {exc}"
        ) from exc
    if (
        clone.get("schema") != CLAUDE_LAUNCH_SECURITY_REQUEST_SCHEMA
        or _sha256(digest, label="Claude launch-security request digest") is None
        or rebuilt != {**clone, "request_sha256": digest}
    ):
        raise ClaudeLaunchSecurityError(
            "Claude launch-security request does not replay"
        )
    return rebuilt


__all__ = [
    "CLAUDE_AUTH_ROUTE_POLICY_SCHEMA",
    "CLAUDE_LAUNCH_SECURITY_SCHEMA",
    "CLAUDE_LAUNCH_SECURITY_REQUEST_SCHEMA",
    "CLAUDE_MCP_AUTHORITY_SCHEMA",
    "CLAUDE_MCP_AUTHORITY_SELECTION_SCHEMA",
    "MCP_CURRENT_SELECTION_SCHEMA",
    "CLAUDE_SETTINGS_AUTHORITY_SCHEMA",
    "ClaudeLaunchSecurityError",
    "compile_claude_auth_route_policy",
    "compile_claude_mcp_authority",
    "compile_claude_launch_security",
    "compile_claude_launch_security_request",
    "compile_claude_settings_authority",
    "mcp_current_selection_sha256",
    "reconcile_claude_launch_security_request",
    "replay_claude_auth_route_policy",
    "replay_claude_launch_security",
    "replay_claude_launch_security_request",
    "replay_mcp_current_selection",
]
