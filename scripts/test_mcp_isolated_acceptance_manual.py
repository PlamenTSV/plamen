"""Manual one-shot isolated acceptance for the immutable npm MCP generation."""

from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
RUNTIME_PATH = Path(__file__).resolve().with_name("plamen_mcp_runtime.py")
RUNTIME_SPEC = importlib.util.spec_from_file_location(
    "plamen_mcp_isolated_acceptance_runtime", RUNTIME_PATH,
)
if RUNTIME_SPEC is None or RUNTIME_SPEC.loader is None:
    raise RuntimeError("isolated acceptance runtime module is unavailable")
runtime = importlib.util.module_from_spec(RUNTIME_SPEC)
sys.modules[RUNTIME_SPEC.name] = runtime
RUNTIME_SPEC.loader.exec_module(runtime)


KEY = b"isolated-acceptance-only-not-production-authority"

_CODEX_TARGETS = {
    ("darwin", "arm64"): "aarch64-apple-darwin",
    ("darwin", "x64"): "x86_64-apple-darwin",
    ("linux", "arm64"): "aarch64-unknown-linux-musl",
    ("linux", "x64"): "x86_64-unknown-linux-musl",
    ("win32", "arm64"): "aarch64-pc-windows-msvc",
    ("win32", "x64"): "x86_64-pc-windows-msvc",
}
_CODEX_PATH_RE = re.compile(
    r"node_modules/@openai/codex-(darwin|linux|win32)-(arm64|x64)/"
    r"vendor/([^/]+)/bin/(codex(?:\.exe)?)\Z"
)
_CLAUDE_PATH = "node_modules/@anthropic-ai/claude-code/bin/claude.exe"


def sign(raw: bytes) -> dict[str, str]:
    return {"scheme": "test-hmac-sha256", "key_id": "isolated-acceptance",
            "signature": hmac.new(KEY, raw, hashlib.sha256).hexdigest()}


def verify(raw: bytes, authentication: dict[str, str]) -> bool:
    return (
        authentication.get("scheme") == "test-hmac-sha256"
        and authentication.get("key_id") == "isolated-acceptance"
        and hmac.compare_digest(
            authentication.get("signature", ""),
            hmac.new(KEY, raw, hashlib.sha256).hexdigest(),
        )
    )


def _assert_exact_version(result, expected: str, label: str) -> str:
    output = ((result.stdout or "") + (result.stderr or "")).strip()
    if result.returncode != 0 or output != expected:
        raise RuntimeError(f"{label} version probe differs: {output[-500:]}")
    return output


def _expected_native_resource_roster(relative: str) -> tuple[str, ...]:
    """Independently enumerate all six reviewed Codex platform layouts."""
    if relative == _CLAUDE_PATH:
        root = relative.rsplit("/", 1)[0]
        return tuple(sorted((root, relative), key=lambda path: (path.casefold(), path)))
    match = _CODEX_PATH_RE.fullmatch(relative)
    if match is None:
        raise RuntimeError("backend native resource path is outside the reviewed roster")
    platform_name, architecture, target, primary = match.groups()
    suffix = ".exe" if platform_name == "win32" else ""
    if (
        target != _CODEX_TARGETS[(platform_name, architecture)]
        or primary != "codex" + suffix
    ):
        raise RuntimeError("Codex native target identity differs")
    root = relative.rsplit("/bin/", 1)[0]
    local = {
        ".", "bin", "codex-path", "codex-resources", "codex-package.json",
        "bin/codex" + suffix,
        "bin/codex-code-mode-host" + suffix,
        "codex-path/rg" + suffix,
    }
    if platform_name == "win32":
        local.update({
            "codex-resources/codex-command-runner.exe",
            "codex-resources/codex-windows-sandbox-setup.exe",
        })
    else:
        local.update({
            "codex-resources/zsh",
            "codex-resources/zsh/bin",
            "codex-resources/zsh/bin/zsh",
        })
        if platform_name == "linux":
            local.add("codex-resources/bwrap")
    absolute = {root if path == "." else root + "/" + path for path in local}
    return tuple(sorted(absolute, key=lambda path: (path.casefold(), path)))


def _poisoned_source_environment(root: Path) -> tuple[dict[str, str], Path]:
    """Return an ambient PATH that fails visibly if command lookup is attempted."""
    poison = root / "ambient-path-poison"
    poison.mkdir()
    marker = poison / "ambient-command-invoked"
    if os.name == "nt":
        body = f'@echo off\r\n>"{marker}" echo invoked\r\nexit /b 97\r\n'
        for name in ("node.cmd", "npm.cmd", "npx.cmd"):
            (poison / name).write_text(body, encoding="utf-8", newline="")
    else:
        body = f"#!/bin/sh\nprintf invoked > {str(marker)!r}\nexit 97\n"
        for name in ("node", "npm", "npx"):
            path = poison / name
            path.write_text(body, encoding="utf-8", newline="\n")
            path.chmod(0o700)
    retained = {
        key: value for key, value in os.environ.items()
        if key.upper() in {"SYSTEMROOT", "COMSPEC", "PATHEXT"}
    }
    retained.update({
        "PATH": str(poison),
        "NODE_OPTIONS": "--require=ambient-node-must-not-run",
        "NODE_PATH": str(poison / "ambient-node-path"),
        "NPM_CONFIG_USERCONFIG": str(poison / "ambient-npmrc-must-not-run"),
    })
    return retained, marker


def main() -> int:
    started = time.monotonic()
    acceptance = Path(tempfile.mkdtemp(prefix="plamen-mcp-isolated-acceptance-"))
    store = acceptance / "store"
    managed_store = acceptance / "managed-node-store"
    retained_env = acceptance / "retained-materialization-environment"
    poisoned_source, ambient_marker = _poisoned_source_environment(acceptance)
    if managed_store.exists():
        raise RuntimeError("managed Node acceptance store is not fresh")
    managed_started = time.monotonic()
    managed = runtime.ensure_managed_node_runtime(
        managed_store, signer=sign, verifier=verify, allow_download=True,
    )
    managed_seconds = time.monotonic() - managed_started
    managed_receipt = runtime._parse_managed_node_receipt(
        (managed.generation_path / runtime.MANAGED_NODE_RECEIPT_NAME).read_bytes(),
        managed.generation_id, verify,
    )
    managed_authority = managed_receipt["authority"]
    if (
        managed_authority["node_version"] != runtime.MANAGED_NODE_VERSION
        or managed_authority["npm_version"] != runtime.MANAGED_NPM_VERSION
        or runtime.MANAGED_NODE_VERSION != "24.20.0"
        or runtime.MANAGED_NPM_VERSION != "11.19.0"
    ):
        raise RuntimeError("managed Node/npm authority versions differ")
    node = str(managed.node_path)
    npm = str(managed.npm_cli_path)
    probe_env = runtime.materialization_environment(
        node, npm, retained_env, source_env=poisoned_source,
    )
    expected_path = []
    for executable in (managed.node_path, managed.npm_cli_path):
        parent = str(executable.parent)
        if os.path.normcase(parent) not in {
            os.path.normcase(item) for item in expected_path
        }:
            expected_path.append(parent)
    actual_path = probe_env.get("PATH", "").split(os.pathsep)
    if (
        len(actual_path) != len(expected_path)
        or [os.path.normcase(item) for item in actual_path]
        != [os.path.normcase(item) for item in expected_path]
    ):
        raise RuntimeError("managed materialization PATH denominator differs")
    if any(
        key.upper() in {"NODE_OPTIONS", "NODE_PATH"}
        or key.upper().startswith(("NPM_CONFIG_", "LD_", "DYLD_"))
        for key in probe_env
    ):
        raise RuntimeError("managed materialization environment retained injection controls")
    node_probe = runtime.run_managed_node(
        managed, ["--version"], verifier=verify, cwd=acceptance,
        environment=probe_env, timeout=60, capture_output=True, text=True,
    )
    node_version_output = _assert_exact_version(
        node_probe, "v24.20.0", "managed Node",
    )
    npm_probe = runtime.run_managed_node(
        managed, [npm, "--version"], verifier=verify, cwd=acceptance,
        environment=probe_env, timeout=60, capture_output=True, text=True,
    )
    npm_version_output = _assert_exact_version(
        npm_probe, "11.19.0", "managed npm",
    )
    npm_version = managed.npm_version
    package_value = json.loads((ROOT / "mcp-packages" / "package.json").read_bytes())
    lock_value = json.loads((ROOT / "mcp-packages" / "package-lock.json").read_bytes())
    if (
        package_value.get("dependencies", {}).get("@anthropic-ai/claude-code")
        != "2.1.252"
        or package_value.get("dependencies", {}).get("@openai/codex")
        != "0.152.0"
    ):
        raise RuntimeError("checked-in backend versions differ")
    package_bytes = runtime._canonical_json(package_value) + b"\n"
    lock_bytes = runtime._canonical_json(lock_value) + b"\n"
    sanitizer_bytes = (ROOT / "mcp-packages" / "schema-sanitizer.js").read_bytes()
    finalizer = {
        "schema": "plamen.mcp_finalizer_policy.v1",
        "output_entrypoint": "schema-sanitizer.js",
        "require_ordinary_file": True,
        "require_single_link": True,
        "post_npm_actions": [{
            "schema": "plamen.claude_native_finalizer.v1",
            "package": "@anthropic-ai/claude-code", "version": "2.1.252",
            "script": "node_modules/@anthropic-ai/claude-code/install.cjs",
            "output": "node_modules/@anthropic-ai/claude-code/bin/claude.exe",
            "probe_args": ["--version"],
        }],
    }
    request = runtime.derive_generation_request(
        expected_package_json_bytes=package_bytes,
        expected_package_lock_bytes=lock_bytes,
        sanitizer_bytes=sanitizer_bytes, sanitizer_relative_path="schema-sanitizer.js",
        node_executable=node, npm_executable=npm, npm_version=npm_version,
        npm_install_flags=runtime.REQUIRED_NPM_INSTALL_FLAGS,
        finalizer_policy=finalizer,
    )

    def materialize(payload: Path) -> None:
        (payload / "package.json").write_bytes(package_bytes)
        (payload / "package-lock.json").write_bytes(lock_bytes)
        (payload / "schema-sanitizer.js").write_bytes(sanitizer_bytes)
        install = runtime.run_managed_npm_ci(
            managed, payload, verifier=verify, environment=probe_env, timeout=900,
        )
        if install.returncode != 0:
            raise RuntimeError("npm ci failed: " + install.stderr[-500:])
        finalizer_evidence.clear()
        finalizer_evidence.update(runtime.finalize_claude_native(
            payload, version="2.1.252", node_executable=node,
            environment=probe_env, managed_node=managed, verifier=verify,
        ))

    finalizer_evidence: dict[str, object] = {}
    stage_started = time.monotonic()
    published = runtime.stage_npm_generation(
        store, request.generation_id, materialize,
        expected_package_json_bytes=package_bytes,
        expected_package_lock_bytes=lock_bytes,
        node_executable=node, npm_executable=npm, npm_version=npm_version,
        npm_install_flags=runtime.REQUIRED_NPM_INSTALL_FLAGS,
        generation_request=request, signer=sign, verifier=verify,
    )
    stage_seconds = time.monotonic() - stage_started
    authorities = dict(
        expected_receipt_sha256=published.receipt_sha256,
        expected_census_sha256=published.census_sha256,
        expected_request_sha256=published.request_sha256,
    )
    member_authorities = {
        **authorities,
        "expected_generation_policy_sha256": runtime.generation_policy_sha256(request),
    }
    admitted = runtime.validate_generation(
        store, request.generation_id, verifier=verify,
    )
    if (
        admitted.receipt_sha256 != published.receipt_sha256
        or admitted.census_sha256 != published.census_sha256
        or admitted.request_sha256 != published.request_sha256
    ):
        raise RuntimeError("full generation authority differs after publication")
    rows = {row["path"]: row for row in admitted.entries}
    codex_candidates = [
        path for path, row in rows.items()
        if row["kind"] == "file" and re.fullmatch(
            r"node_modules/@openai/codex-[^/]+/vendor/[^/]+/bin/codex(?:\.exe)?",
            path,
        )
    ]
    if len(codex_candidates) != 1:
        raise RuntimeError("Codex native binary denominator differs")
    backend_specs = {
        "claude": (
            "native", _CLAUDE_PATH,
            "2.1.252 (Claude Code)",
        ),
        "codex": ("native", codex_candidates[0], "codex-cli 0.152.0"),
    }
    backend_seconds = {}
    backend_outputs = {}
    codex_closure = None
    for backend, (kind, relative, expected_output) in backend_specs.items():
        row = rows[relative]
        member_authority = runtime.sign_generation_member_authority(
            admitted, relative, execution_kind=kind,
            generation_policy_sha256_value=member_authorities[
                "expected_generation_policy_sha256"
            ], signer=sign,
        )
        replayed_member_authority = runtime.sign_generation_member_authority(
            admitted, relative, execution_kind=kind,
            generation_policy_sha256_value=member_authorities[
                "expected_generation_policy_sha256"
            ], signer=sign,
        )
        if replayed_member_authority != member_authority:
            raise RuntimeError(backend + " member authority replay differs")
        if not verify(
            runtime._canonical_json(member_authority["authority"]),
            member_authority["authentication"],
        ):
            raise RuntimeError(backend + " member authority signature differs")
        authority = member_authority["authority"]
        runtime_roster = runtime.native_resource_roster(relative)
        expected_roster = _expected_native_resource_roster(relative)
        if runtime_roster != expected_roster:
            raise RuntimeError(backend + " production native resource roster differs")
        closure_root = min(expected_roster, key=lambda path: path.count("/"))
        expected_closure = [
            {
                key: rows[path][key] for key in (
                    "path", "kind", "size", "sha256", "mode", "link_count",
                    "reparse",
                )
            }
            for path in expected_roster
        ]
        expected_closure.sort(
            key=lambda item: (item["path"].casefold(), item["path"]),
        )
        expected_closure_sha256 = hashlib.sha256(
            runtime._canonical_json(expected_closure)
        ).hexdigest()
        closure_parts = closure_root.split("/")
        parent_parts = closure_parts[:-1]
        ancestor_paths = ["."] + [
            "/".join(parent_parts[:index])
            for index in range(1, len(parent_parts) + 1)
        ]
        expected_ancestors = [
            {
                key: rows[path][key]
                for key in ("path", "mode", "link_count", "reparse")
            }
            for path in ancestor_paths
        ]
        receipt_file_sha256 = hashlib.sha256(
            (admitted.generation_path / runtime.RECEIPT_NAME).read_bytes()
        ).hexdigest()
        expected_authority_keys = {
            "schema", "generation_id", "receipt_sha256", "census_sha256",
            "request_sha256", "generation_policy_sha256", "receipt_file_sha256",
            "execution_kind", "relative_path", "size", "sha256", "mode",
            "link_count", "closure_root", "closure_count", "closure_sha256",
            "closure", "ancestors",
        }
        if (
            set(authority) != expected_authority_keys
            or authority["schema"] != "plamen.mcp_native_resource_closure.v2"
            or authority["closure_root"] != closure_root
            or authority["closure_count"] != len(expected_closure)
            or authority["closure_sha256"] != expected_closure_sha256
            or authority["closure"] != expected_closure
            or authority["ancestors"] != expected_ancestors
            or authority["generation_id"] != admitted.generation_id
            or authority["receipt_sha256"] != admitted.receipt_sha256
            or authority["census_sha256"] != admitted.census_sha256
            or authority["request_sha256"] != admitted.request_sha256
            or authority["generation_policy_sha256"]
            != member_authorities["expected_generation_policy_sha256"]
            or authority["receipt_file_sha256"] != receipt_file_sha256
            or authority["execution_kind"] != "native"
            or authority["relative_path"] != relative
            or authority["size"] != row["size"]
            or authority["sha256"] != row["sha256"]
            or authority["mode"] != row["mode"]
            or authority["link_count"] != row["link_count"]
            or relative not in expected_roster
        ):
            raise RuntimeError(backend + " signed native resource closure differs")
        if backend == "codex":
            codex_closure = {
                "schema": authority["schema"],
                "primary": authority["relative_path"],
                "closure_root": closure_root,
                "closure_count": len(expected_closure),
                "closure_sha256": expected_closure_sha256,
                "closure": expected_closure,
            }
        probe_started = time.monotonic()
        process = runtime.launch_generation_member(
            store, request.generation_id, relative, execution_kind=kind,
            expected_size=row["size"], expected_sha256=row["sha256"],
            node_executable=None, verifier=verify, **member_authorities,
            member_args=("--version",), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            full_census=False,
            authenticated_member_authority=member_authority,
        )
        stdout, stderr = process.communicate(timeout=60)
        output = (stdout + stderr).decode(errors="replace").strip()
        if process.returncode != 0 or output != expected_output:
            raise RuntimeError(backend + " backend probe differs")
        backend_outputs[backend] = output
        backend_seconds[backend] = round(time.monotonic() - probe_started, 3)
    if codex_closure is None:
        raise RuntimeError("Codex signed native resource closure was not observed")
    memory = "node_modules/@modelcontextprotocol/server-memory/dist/index.js"
    messages = b"".join(json.dumps(row, separators=(",", ":")).encode() + b"\n" for row in (
        {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"plamen-acceptance","version":"1"}}},
        {"jsonrpc":"2.0","method":"notifications/initialized","params":{}},
        {"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}},
    ))
    mcp_seconds = {}
    mcp_tools = {}
    launch_env = {
        key: value for key, value in poisoned_source.items()
        if key.upper() in {"PATH", "SYSTEMROOT", "COMSPEC", "PATHEXT"}
    }
    for backend in ("claude", "codex"):
        mcp_started = time.monotonic()
        process = runtime.launch_node_generation(
            store, request.generation_id, "schema-sanitizer.js",
            node_executable=node, verifier=verify, **authorities,
            node_args=("--backend=" + backend, str(admitted.payload_path / memory)),
            base_env=launch_env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        stdout, stderr = process.communicate(messages, timeout=60)
        replies = [json.loads(line) for line in stdout.splitlines()]
        if process.returncode != 0 or {row.get("id") for row in replies} != {1, 2}:
            raise RuntimeError(backend + " memory MCP roundtrip differs: " + stderr.decode()[-500:])
        tools_rows = [row for row in replies if row.get("id") == 2]
        tools = (tools_rows[0].get("result") or {}).get("tools") if len(tools_rows) == 1 else None
        if not isinstance(tools, list) or not tools:
            raise RuntimeError(backend + " sanitized memory MCP tools response differs")
        mcp_tools[backend] = sorted(
            item.get("name") for item in tools
            if isinstance(item, dict) and isinstance(item.get("name"), str)
        )
        if len(mcp_tools[backend]) != len(tools):
            raise RuntimeError(backend + " sanitized memory MCP tool names differ")
        mcp_seconds[backend] = round(time.monotonic() - mcp_started, 3)
    if ambient_marker.exists():
        raise RuntimeError("ambient Node/npm command resolution was invoked")
    print(json.dumps({
        "schema": "plamen.mcp_isolated_acceptance.v1",
        "retained_root": str(acceptance), "generation_id": request.generation_id,
        "receipt_sha256": published.receipt_sha256,
        "census_sha256": published.census_sha256,
        "request_sha256": published.request_sha256,
        "generation_policy_sha256": member_authorities[
            "expected_generation_policy_sha256"
        ],
        "managed_node": {
            "generation_id": managed.generation_id,
            "receipt_sha256": managed.receipt_sha256,
            "census_sha256": managed.census_sha256,
            "archive_sha256": managed.archive_sha256,
            "platform_key": managed.platform_key,
            "node_version": managed_authority["node_version"],
            "npm_version": managed_authority["npm_version"],
            "node_probe": node_version_output,
            "npm_probe": npm_version_output,
            "materialization_seconds": round(managed_seconds, 3),
        },
        "npm_version": npm_version, "entry_count": len(admitted.entries),
        "claude_finalizer": finalizer_evidence,
        "backend_probe_output": backend_outputs,
        "codex_signed_native_resource_closure": codex_closure,
        "sanitized_memory_tools": mcp_tools,
        "ambient_path_marker_absent": True,
        "stage_seconds": round(stage_seconds, 3),
        "backend_probe_seconds": backend_seconds,
        "mcp_roundtrip_seconds": mcp_seconds,
        "elapsed_seconds": round(time.monotonic() - started, 3), "status": "PASS",
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
