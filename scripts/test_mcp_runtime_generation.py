"""Adversarial tests for immutable npm MCP runtime generations."""

from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import time
from typing import Any

import pytest


MODULE_PATH = Path(__file__).with_name("plamen_mcp_runtime.py")
SPEC = importlib.util.spec_from_file_location("plamen_mcp_runtime_test", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
RUNTIME = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNTIME
SPEC.loader.exec_module(RUNTIME)

KEY = b"unit-test-only-mcp-generation-key"
PACKAGE = {
    "private": True,
    "version": "1.2.3",
    "dependencies": {"fixture-mcp": "1.2.3"},
}
LOCK = {
    "lockfileVersion": 3,
    "packages": {
        "": {"dependencies": PACKAGE["dependencies"]},
        "node_modules/fixture-mcp": {
            "version": "1.2.3",
            "integrity": "sha512-fixture",
        },
    },
}
PACKAGE_BYTES = RUNTIME._canonical_json(PACKAGE) + b"\n"
LOCK_BYTES = RUNTIME._canonical_json(LOCK) + b"\n"
SANITIZER_BYTES = b"// exact schema sanitizer fixture\n"
FINALIZER_POLICY = {
    "schema": "plamen.mcp_finalizer_policy.v1",
    "output_entrypoint": "node_modules/fixture-mcp/dist/index.js",
    "require_ordinary_file": True,
    "require_single_link": True,
    "post_npm_actions": [],
}


def _sign(raw: bytes) -> dict[str, str]:
    return {
        "scheme": "test-hmac-sha256",
        "key_id": "fixture-key-v1",
        "signature": hmac.new(KEY, raw, hashlib.sha256).hexdigest(),
    }


def _verify(raw: bytes, authentication: dict[str, str]) -> bool:
    return (
        authentication.get("scheme") == "test-hmac-sha256"
        and authentication.get("key_id") == "fixture-key-v1"
        and hmac.compare_digest(
            authentication.get("signature", ""),
            hmac.new(KEY, raw, hashlib.sha256).hexdigest(),
        )
    )


def _install_authority(
    *,
    node_executable: os.PathLike[str] | str = sys.executable,
    npm_executable: os.PathLike[str] | str = sys.executable,
    npm_version: str = "10.9.2",
    npm_install_flags: tuple[str, ...] = RUNTIME.REQUIRED_NPM_INSTALL_FLAGS,
    finalizer_policy: dict[str, Any] = FINALIZER_POLICY,
) -> dict[str, Any]:
    authority = {
        "expected_package_json_bytes": PACKAGE_BYTES,
        "expected_package_lock_bytes": LOCK_BYTES,
        "node_executable": node_executable,
        "npm_executable": npm_executable,
        "npm_version": npm_version,
        "npm_install_flags": npm_install_flags,
    }
    authority["generation_request"] = RUNTIME.derive_generation_request(
        **authority,
        sanitizer_bytes=SANITIZER_BYTES,
        sanitizer_relative_path="schema-sanitizer.js",
        finalizer_policy=finalizer_policy,
    )
    return authority


def _materialize(payload: Path, *, nested: bool = False) -> None:
    (payload / "package.json").write_bytes(PACKAGE_BYTES)
    (payload / "package-lock.json").write_bytes(LOCK_BYTES)
    (payload / "schema-sanitizer.js").write_bytes(SANITIZER_BYTES)
    package_dir = payload / "node_modules" / "fixture-mcp" / "dist"
    package_dir.mkdir(parents=True)
    (package_dir / "index.js").write_text(
        "process.stdout.write('fixture');\n", encoding="utf-8"
    )
    (payload / "empty-directory").mkdir()
    if nested:
        current = payload / "long"
        current.mkdir()
        for index in range(14):
            current = current / (f"segment-{index:02d}-" + "x" * 12)
            os.mkdir(RUNTIME._fs_path(current))
        RUNTIME._write_exclusive(
            current / "deep.js", b"process.stdout.write('deep-runtime-ok');\n"
        )


DEFAULT_GENERATION_ID = _install_authority()["generation_request"].generation_id


def _launch_authority(published) -> dict[str, str]:
    return {
        "expected_receipt_sha256": published.receipt_sha256,
        "expected_census_sha256": published.census_sha256,
        "expected_request_sha256": published.request_sha256,
    }


def _member_launch_authority(published, request=None) -> dict[str, str]:
    request = request or _install_authority()["generation_request"]
    return {
        **_launch_authority(published),
        "expected_generation_policy_sha256": RUNTIME.generation_policy_sha256(request),
    }


def _stage(tmp_path: Path, generation_id: str = DEFAULT_GENERATION_ID):
    store = tmp_path / "mcp-runtime"
    published = RUNTIME.stage_npm_generation(
        store,
        generation_id,
        _materialize,
        **_install_authority(),
        signer=_sign,
        verifier=_verify,
    )
    return store, published


def _stage_native_directory_closure(tmp_path: Path, *, one_file: bool = False):
    def materialize(payload: Path) -> None:
        _materialize(payload)
        if not one_file:
            (payload / "node_modules" / "fixture-mcp" / "dist" / "codex-code-mode-host.exe").write_bytes(
                b"exact native helper fixture\n"
            )

    store = tmp_path / "native-directory-runtime"
    published = RUNTIME.stage_npm_generation(
        store, DEFAULT_GENERATION_ID, materialize, **_install_authority(),
        signer=_sign, verifier=_verify,
    )
    return store, published


_CODEX_TEST_TARGETS = {
    ("darwin", "arm64"): "aarch64-apple-darwin",
    ("darwin", "x64"): "x86_64-apple-darwin",
    ("linux", "arm64"): "aarch64-unknown-linux-musl",
    ("linux", "x64"): "x86_64-unknown-linux-musl",
    ("win32", "arm64"): "aarch64-pc-windows-msvc",
    ("win32", "x64"): "x86_64-pc-windows-msvc",
}


def _codex_test_primary(platform_name: str, architecture: str) -> str:
    target = _CODEX_TEST_TARGETS[(platform_name, architecture)]
    suffix = ".exe" if platform_name == "win32" else ""
    return (
        f"node_modules/@openai/codex-{platform_name}-{architecture}/"
        f"vendor/{target}/bin/codex{suffix}"
    )


def _stage_codex_resource_closure(
    tmp_path: Path, platform_name: str, architecture: str,
):
    primary = _codex_test_primary(platform_name, architecture)
    target_root = primary.rsplit("/bin/", 1)[0]
    roster = RUNTIME.native_resource_roster(primary)
    directories = {
        path for path in roster
        if path == target_root
        or any(candidate.startswith(path + "/") for candidate in roster)
    }

    def materialize(payload: Path) -> None:
        _materialize(payload)
        for relative in sorted(directories, key=lambda value: (value.count("/"), value)):
            os.makedirs(
                RUNTIME._fs_path(payload.joinpath(*relative.split("/"))),
                exist_ok=True,
            )
        target = _CODEX_TEST_TARGETS[(platform_name, architecture)]
        entrypoint = "bin/codex.exe" if platform_name == "win32" else "bin/codex"
        manifest = {
            "layoutVersion": 1, "version": "0.152.0", "target": target,
            "variant": "codex", "entrypoint": entrypoint,
            "resourcesDir": "codex-resources", "pathDir": "codex-path",
        }
        for relative in sorted(set(roster) - directories):
            path = payload.joinpath(*relative.split("/"))
            os.makedirs(RUNTIME._fs_path(path.parent), exist_ok=True)
            raw = (
                RUNTIME._canonical_json(manifest) + b"\n"
                if relative.endswith("/codex-package.json")
                else ("native fixture: " + relative + "\n").encode("utf-8")
            )
            RUNTIME._write_exclusive(path, raw)

    store = tmp_path / f"codex-{platform_name}-{architecture}-runtime"
    published = RUNTIME.stage_npm_generation(
        store, DEFAULT_GENERATION_ID, materialize, **_install_authority(),
        signer=_sign, verifier=_verify,
    )
    return store, published, primary


def _tree_projection(path: Path) -> tuple[tuple[str, str, int], ...]:
    rows: list[tuple[str, str, int]] = []
    for root, directories, files in os.walk(path):
        directories.sort()
        files.sort()
        root_path = Path(root)
        rows.append((root_path.relative_to(path).as_posix() or ".", "directory", 0))
        for name in files:
            child = root_path / name
            raw = child.read_bytes()
            rows.append((child.relative_to(path).as_posix(), hashlib.sha256(raw).hexdigest(), len(raw)))
    return tuple(rows)


def test_stage_receipt_censuses_every_member_and_launch_revalidates_immediately(
    tmp_path: Path,
) -> None:
    store, published = _stage(tmp_path)
    validated = RUNTIME.validate_generation(store, DEFAULT_GENERATION_ID, verifier=_verify)
    assert validated.receipt_sha256 == published.receipt_sha256
    assert validated.census_sha256 == published.census_sha256
    rows = {row["path"]: row for row in validated.entries}
    assert rows["."]["kind"] == "directory"
    assert rows["node_modules"]["kind"] == "directory"
    assert rows["empty-directory"]["kind"] == "directory"
    assert rows["node_modules/fixture-mcp/dist/index.js"]["kind"] == "file"
    assert all(
        set(row)
        == {"path", "kind", "size", "sha256", "mode", "link_count", "reparse"}
        and row["reparse"] is False
        and len(row["sha256"]) == 64
        for row in validated.entries
    )

    calls: list[tuple[list[str], dict[str, Any]]] = []

    def fake_popen(command, **kwargs):
        # This callback is the very next operation after the final entrypoint
        # replay, and the store lock remains held while it is invoked.
        calls.append((list(command), dict(kwargs)))
        return object()

    result = RUNTIME.launch_node_generation(
        store,
        DEFAULT_GENERATION_ID,
        "node_modules/fixture-mcp/dist/index.js",
        node_executable=sys.executable,
        verifier=_verify,
        **_launch_authority(published),
        node_args=("--stdio",),
        popen_factory=fake_popen,
        cwd=tmp_path,
    )
    assert result is not None
    assert len(calls) == 1
    assert os.path.normcase(RUNTIME._display_path(calls[0][0][0]).resolve()) == (
        os.path.normcase(Path(sys.executable).resolve())
    )
    assert calls[0][0][1].endswith("index.js")
    assert calls[0][0][2:] == ["--stdio"]
    assert calls[0][1]["cwd"] == tmp_path
    assert "env" in calls[0][1]


def test_directory_census_identity_normalizes_windows_size_but_preserves_posix(
    monkeypatch,
) -> None:
    class DirectoryInfo:
        st_dev = 1
        st_ino = 2
        st_mode = stat.S_IFDIR | 0o755
        st_nlink = 1
        st_mtime = 3.0
        st_ctime = 4.0
        st_mtime_ns = 3_000_000_000
        st_ctime_ns = 4_000_000_000

        def __init__(self, size: int):
            self.st_size = size

    first = DirectoryInfo(4096)
    jittered = DirectoryInfo(8192)
    monkeypatch.setattr(RUNTIME.os, "name", "nt")
    assert RUNTIME._directory_census_identity(first) == (
        RUNTIME._directory_census_identity(jittered)
    )
    monkeypatch.setattr(RUNTIME.os, "name", "posix")
    assert RUNTIME._directory_census_identity(first) != (
        RUNTIME._directory_census_identity(jittered)
    )


@pytest.mark.skipif(os.name != "nt", reason="NTFS directory-size jitter regression")
def test_windows_directory_size_jitter_has_deterministic_two_replay_census(
    tmp_path: Path, monkeypatch,
) -> None:
    original = RUNTIME._require_plain_directory
    calls: dict[str, int] = {}

    class JitteredDirectory:
        def __init__(self, value, size):
            self._value = value
            self.st_size = size

        def __getattr__(self, name):
            return getattr(self._value, name)

    def jitter(path, label):
        value = original(path, label)
        key = os.path.normcase(os.path.abspath(os.fspath(path)))
        calls[key] = calls.get(key, 0) + 1
        return JitteredDirectory(value, value.st_size + calls[key] * 4096)

    monkeypatch.setattr(RUNTIME, "_require_plain_directory", jitter)
    store, published = _stage(tmp_path)
    first = RUNTIME.validate_generation(store, DEFAULT_GENERATION_ID, verifier=_verify)
    second = RUNTIME.validate_generation(store, DEFAULT_GENERATION_ID, verifier=_verify)
    assert first.census_sha256 == published.census_sha256 == second.census_sha256
    assert first.entries == second.entries
    assert all(row["size"] == 0 for row in first.entries if row["kind"] == "directory")


@pytest.mark.parametrize("mutation", ("add", "remove", "case", "hardlink"))
def test_second_directory_enumeration_rejects_namespace_race(
    tmp_path: Path, monkeypatch, mutation: str,
) -> None:
    payload = tmp_path / "namespace-race"
    payload.mkdir()
    first = payload / "a.txt"
    second = payload / "b.txt"
    first.write_bytes(b"a\n")
    second.write_bytes(b"b\n")
    original = RUNTIME._require_plain_directory
    root_calls = 0

    def mutate_before_replay(path, label):
        nonlocal root_calls
        value = original(path, label)
        if os.path.normcase(os.path.abspath(os.fspath(path))) == os.path.normcase(
            os.path.abspath(os.fspath(payload))
        ):
            root_calls += 1
            if root_calls == 3:
                if mutation == "add":
                    (payload / "extra.txt").write_bytes(b"extra\n")
                elif mutation == "remove":
                    second.unlink()
                elif mutation == "case":
                    intermediate = payload / "case-intermediate"
                    os.replace(second, intermediate)
                    os.replace(intermediate, payload / "B.TXT")
                else:
                    second.unlink()
                    os.link(first, second)
        return value

    monkeypatch.setattr(RUNTIME, "_require_plain_directory", mutate_before_replay)
    with pytest.raises(RUNTIME.MCPRuntimeSecurityError):
        RUNTIME._census_tree(payload)


@pytest.mark.parametrize("mutation", ("add", "remove", "case", "hardlink", "content"))
def test_full_recursive_census_replay_rejects_late_nested_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str,
) -> None:
    payload = tmp_path / "late-nested-race"
    nested = payload / "parent" / "child"
    nested.mkdir(parents=True)
    first = nested / "a.txt"
    second = nested / "b.txt"
    first.write_bytes(b"aaaa\n")
    second.write_bytes(b"bbbb\n")
    original = RUNTIME._census_tree_once
    calls = 0

    def mutate_after_complete_pass(root, **kwargs):
        nonlocal calls
        calls += 1
        result = original(root, **kwargs)
        if calls == 1:
            if mutation == "add":
                (nested / "extra.txt").write_bytes(b"extra\n")
            elif mutation == "remove":
                second.unlink()
            elif mutation == "case":
                intermediate = nested / "case-intermediate"
                os.replace(second, intermediate)
                os.replace(intermediate, nested / "B.TXT")
            elif mutation == "hardlink":
                second.unlink()
                os.link(first, second)
            else:
                second.write_bytes(b"CCCC\n")
        return result

    monkeypatch.setattr(RUNTIME, "_census_tree_once", mutate_after_complete_pass)
    with pytest.raises(RUNTIME.MCPRuntimeSecurityError):
        RUNTIME._census_tree(payload)
    assert calls == 2


def test_full_recursive_census_replay_reapplies_exact_bounds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = tmp_path / "bounded-replay"
    payload.mkdir()
    observed: list[tuple[int | None, int | None]] = []
    original = RUNTIME._census_tree_once

    def record_bounds(root, *, maximum_rows=None, maximum_file_bytes=None):
        observed.append((maximum_rows, maximum_file_bytes))
        return original(
            root,
            maximum_rows=maximum_rows,
            maximum_file_bytes=maximum_file_bytes,
        )

    monkeypatch.setattr(RUNTIME, "_census_tree_once", record_bounds)
    rows, digest = RUNTIME._census_tree(
        payload, maximum_rows=7, maximum_file_bytes=11,
    )
    assert rows and len(digest) == 64
    assert observed == [(7, 11), (7, 11)]


def test_stage_retains_bounded_preseal_postseal_and_committed_full_replays(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[int | None, int | None]] = []
    original = RUNTIME._census_tree_once

    def count_passes(root, *, maximum_rows=None, maximum_file_bytes=None):
        calls.append((maximum_rows, maximum_file_bytes))
        return original(
            root,
            maximum_rows=maximum_rows,
            maximum_file_bytes=maximum_file_bytes,
        )

    monkeypatch.setattr(RUNTIME, "_census_tree_once", count_passes)
    _stage(tmp_path)
    # Two full passes establish the initial authority, two independently
    # replay the signed staged postimage, and two validate the committed tree.
    assert calls == [(None, None)] * 6


def test_backend_member_launch_is_selection_exact_and_strips_loader_environment(
    tmp_path: Path,
) -> None:
    store, published = _stage(tmp_path)
    validated = RUNTIME.validate_generation(store, DEFAULT_GENERATION_ID, verifier=_verify)
    row = {item["path"]: item for item in validated.entries}[
        "node_modules/fixture-mcp/dist/index.js"
    ]
    calls = []

    class Process:
        pass

    def fake_popen(command, **kwargs):
        calls.append((command, kwargs))
        return Process()

    result = RUNTIME.launch_generation_member(
        store, DEFAULT_GENERATION_ID, row["path"], execution_kind="node",
        expected_size=row["size"], expected_sha256=row["sha256"],
        node_executable=sys.executable, verifier=_verify,
        **_member_launch_authority(published), member_args=("--version",),
        base_env={"PATH": "safe", "NODE_OPTIONS": "--require=evil", "LD_PRELOAD": "evil"},
        popen_factory=fake_popen,
    )
    assert isinstance(result, Process)
    command, kwargs = calls[0]
    assert os.path.normcase(command[0]) == os.path.normcase(str(Path(sys.executable).resolve()))
    assert command[-1] == "--version"
    assert "NODE_OPTIONS" not in kwargs["env"] and "LD_PRELOAD" not in kwargs["env"]
    with pytest.raises(RUNTIME.MCPRuntimeSecurityError, match="selection"):
        RUNTIME.launch_generation_member(
            store, DEFAULT_GENERATION_ID, row["path"], execution_kind="node",
            expected_size=row["size"], expected_sha256="0" * 64,
            node_executable=sys.executable, verifier=_verify,
            **_member_launch_authority(published), popen_factory=fake_popen,
        )


def test_fast_backend_admission_binds_signed_member_but_not_unrelated_payload(
    tmp_path: Path,
) -> None:
    store, published = _stage(tmp_path)
    request = _install_authority()["generation_request"]
    authority = _member_launch_authority(published, request)
    full = RUNTIME.validate_generation(store, DEFAULT_GENERATION_ID, verifier=_verify)
    member_authority = RUNTIME.sign_generation_member_authority(
        full, "node_modules/fixture-mcp/dist/index.js", execution_kind="native",
        generation_policy_sha256_value=authority[
            "expected_generation_policy_sha256"
        ], signer=_sign,
    )
    signed = RUNTIME.validate_generation_authority_fast(
        store, DEFAULT_GENERATION_ID, verifier=_verify, **authority,
    )
    relative = "node_modules/fixture-mcp/dist/index.js"
    row = {item["path"]: item for item in signed.entries}[relative]
    unrelated = signed.payload_path / "empty-directory" / "post-install-drift.txt"
    unrelated.write_bytes(b"unrelated payload drift")
    calls = []
    started = time.monotonic()
    RUNTIME.launch_generation_member(
        store, DEFAULT_GENERATION_ID, relative, execution_kind="native",
        expected_size=row["size"], expected_sha256=row["sha256"],
        node_executable=None, verifier=_verify, **authority,
        full_census=False, popen_factory=lambda command, **kwargs: calls.append(
            (command, kwargs)
        ) or object(),
        authenticated_member_authority=member_authority,
    )
    elapsed = time.monotonic() - started
    assert len(calls) == 1
    assert elapsed < 2.0
    with pytest.raises(RUNTIME.MCPRuntimeSecurityError, match="payload differs"):
        RUNTIME.validate_generation(store, DEFAULT_GENERATION_ID, verifier=_verify)

    member = signed.payload_path.joinpath(*relative.split("/"))
    member.write_bytes(member.read_bytes() + b"// tamper\n")
    with pytest.raises(RUNTIME.MCPRuntimeSecurityError, match="changed before launch"):
        RUNTIME.launch_generation_member(
            store, DEFAULT_GENERATION_ID, relative, execution_kind="native",
            expected_size=row["size"], expected_sha256=row["sha256"],
            node_executable=None, verifier=_verify, **authority,
            full_census=False, popen_factory=lambda *_a, **_k: pytest.fail("spawned"),
            authenticated_member_authority=member_authority,
        )


def test_fast_backend_admission_rejects_pending_policy_receipt_and_case_alias(
    tmp_path: Path,
) -> None:
    store, published = _stage(tmp_path)
    authority = _member_launch_authority(published)
    relative = "node_modules/fixture-mcp/dist/index.js"
    full = RUNTIME.validate_generation(store, DEFAULT_GENERATION_ID, verifier=_verify)
    member_authority = RUNTIME.sign_generation_member_authority(
        full, relative, execution_kind="native",
        generation_policy_sha256_value=authority[
            "expected_generation_policy_sha256"
        ], signer=_sign,
    )
    signed = RUNTIME.validate_generation_authority_fast(
        store, DEFAULT_GENERATION_ID, verifier=_verify, **authority,
    )
    row = {item["path"]: item for item in signed.entries}[relative]
    launch = lambda **overrides: RUNTIME.launch_generation_member(
        store, DEFAULT_GENERATION_ID, relative, execution_kind="native",
        expected_size=row["size"], expected_sha256=row["sha256"],
        node_executable=None, verifier=_verify,
        **{**authority, **overrides}, full_census=False,
        authenticated_member_authority=member_authority,
        popen_factory=lambda *_a, **_k: pytest.fail("spawned"),
    )
    pending = store / ".pending" / "uncommitted.json"
    pending.write_bytes(b"{}\n")
    with pytest.raises(RUNTIME.MCPRuntimeSecurityError, match="incomplete"):
        launch()
    pending.unlink()
    with pytest.raises(RUNTIME.MCPRuntimeSecurityError, match="signed member authority"):
        launch(expected_generation_policy_sha256="0" * 64)

    receipt = signed.generation_path / RUNTIME.RECEIPT_NAME
    raw = receipt.read_bytes()
    receipt.write_bytes(raw[:-2] + (b"0" if raw[-2:-1] != b"0" else b"1") + b"\n")
    with pytest.raises(RUNTIME.MCPRuntimeSecurityError):
        launch()
    receipt.write_bytes(raw)
    if os.name != "nt":
        (signed.payload_path / "NODE_MODULES").mkdir()
        with pytest.raises(RUNTIME.MCPRuntimeSecurityError, match="case alias"):
            launch()


@pytest.mark.parametrize(
    "mutation",
    ("mutated", "missing", "case_alias", "extra", "hardlink"),
)
def test_fast_native_directory_closure_rejects_codex_sidecar_drift_without_spawn(
    tmp_path: Path, mutation: str,
) -> None:
    store, published = _stage_native_directory_closure(tmp_path)
    authority = _member_launch_authority(published)
    relative = "node_modules/fixture-mcp/dist/index.js"
    full = RUNTIME.validate_generation(store, DEFAULT_GENERATION_ID, verifier=_verify)
    closure = RUNTIME.sign_generation_member_authority(
        full, relative, execution_kind="native",
        generation_policy_sha256_value=authority[
            "expected_generation_policy_sha256"
        ], signer=_sign,
    )
    signed = RUNTIME.validate_generation_authority_fast(
        store, DEFAULT_GENERATION_ID, verifier=_verify, **authority,
    )
    row = {item["path"]: item for item in signed.entries}[relative]
    directory = signed.payload_path / "node_modules" / "fixture-mcp" / "dist"
    primary = directory / "index.js"
    sidecar = directory / "codex-code-mode-host.exe"
    if mutation == "mutated":
        with open(RUNTIME._fs_path(sidecar), "wb") as stream:
            stream.write(b"mutated helper\n")
    elif mutation == "missing":
        os.unlink(RUNTIME._fs_path(sidecar))
    elif mutation == "case_alias":
        os.replace(
            RUNTIME._fs_path(sidecar),
            RUNTIME._fs_path(directory / "CODEX-CODE-MODE-HOST.EXE"),
        )
    elif mutation == "extra":
        RUNTIME._write_exclusive(directory / "unselected-helper.exe", b"extra\n")
    else:
        os.unlink(RUNTIME._fs_path(sidecar))
        os.link(RUNTIME._fs_path(primary), RUNTIME._fs_path(sidecar))
    calls = []
    with pytest.raises(RUNTIME.MCPRuntimeSecurityError):
        RUNTIME.launch_generation_member(
            store, DEFAULT_GENERATION_ID, relative, execution_kind="native",
            expected_size=row["size"], expected_sha256=row["sha256"],
            node_executable=None, verifier=_verify, **authority,
            full_census=False,
            authenticated_member_authority=closure,
            popen_factory=lambda *args, **kwargs: calls.append(
                (args, kwargs)
            ) or object(),
        )
    assert calls == []


def test_fast_native_directory_closure_rejects_unsigned_and_resigned_forgery(
    tmp_path: Path,
) -> None:
    store, published = _stage_native_directory_closure(tmp_path)
    authority = _member_launch_authority(published)
    relative = "node_modules/fixture-mcp/dist/index.js"
    full = RUNTIME.validate_generation(store, DEFAULT_GENERATION_ID, verifier=_verify)
    closure = RUNTIME.sign_generation_member_authority(
        full, relative, execution_kind="native",
        generation_policy_sha256_value=authority[
            "expected_generation_policy_sha256"
        ], signer=_sign,
    )
    row = {item["path"]: item for item in full.entries}[relative]

    unsigned_forgery = json.loads(json.dumps(closure))
    helper = next(
        item for item in unsigned_forgery["authority"]["closure"]
        if item["kind"] == "file" and item["path"] != relative
    )
    helper["sha256"] = "0" * 64

    resigned_omission = json.loads(json.dumps(closure))
    resigned_omission["authority"]["closure"] = [
        item for item in resigned_omission["authority"]["closure"]
        if item["path"] == relative
    ]
    resigned_omission["authority"]["closure_count"] = 1
    resigned_omission["authority"]["closure_sha256"] = hashlib.sha256(
        RUNTIME._canonical_json(resigned_omission["authority"]["closure"])
    ).hexdigest()
    resigned_omission["authentication"] = _sign(
        RUNTIME._canonical_json(resigned_omission["authority"])
    )

    oversized_forgery = json.loads(json.dumps(closure))
    oversized_helper = next(
        item for item in oversized_forgery["authority"]["closure"]
        if item["kind"] == "file" and item["path"] != relative
    )
    oversized_helper["size"] = 2 * 1024 * 1024 * 1024 + 1
    oversized_forgery["authority"]["closure_sha256"] = hashlib.sha256(
        RUNTIME._canonical_json(oversized_forgery["authority"]["closure"])
    ).hexdigest()
    oversized_forgery["authentication"] = _sign(
        RUNTIME._canonical_json(oversized_forgery["authority"])
    )

    for forged in (unsigned_forgery, resigned_omission, oversized_forgery):
        calls = []
        with pytest.raises(RUNTIME.MCPRuntimeSecurityError):
            RUNTIME.launch_generation_member(
                store, DEFAULT_GENERATION_ID, relative, execution_kind="native",
                expected_size=row["size"], expected_sha256=row["sha256"],
                node_executable=None, verifier=_verify, **authority,
                full_census=False,
                authenticated_member_authority=forged,
                popen_factory=lambda *args, **kwargs: calls.append(
                    (args, kwargs)
                ) or object(),
            )
        assert calls == []


def test_fast_native_directory_closure_preserves_one_file_claude_compatibility(
    tmp_path: Path,
) -> None:
    store, published = _stage_native_directory_closure(tmp_path, one_file=True)
    authority = _member_launch_authority(published)
    relative = "node_modules/fixture-mcp/dist/index.js"
    full = RUNTIME.validate_generation(store, DEFAULT_GENERATION_ID, verifier=_verify)
    closure = RUNTIME.sign_generation_member_authority(
        full, relative, execution_kind="native",
        generation_policy_sha256_value=authority[
            "expected_generation_policy_sha256"
        ], signer=_sign,
    )
    assert [
        row["path"] for row in closure["authority"]["closure"]
    ] == ["node_modules/fixture-mcp/dist", "node_modules/fixture-mcp/dist/index.js"]
    row = {item["path"]: item for item in full.entries}[relative]
    calls = []
    RUNTIME.launch_generation_member(
        store, DEFAULT_GENERATION_ID, relative, execution_kind="native",
        expected_size=row["size"], expected_sha256=row["sha256"],
        node_executable=None, verifier=_verify, **authority,
        full_census=False, authenticated_member_authority=closure,
        popen_factory=lambda command, **kwargs: calls.append(
            (command, kwargs)
        ) or object(),
    )
    assert len(calls) == 1 and calls[0][0][0].endswith("index.js")


def test_fast_native_resource_closure_preserves_exact_claude_one_file_layout(
    tmp_path: Path,
) -> None:
    relative = "node_modules/@anthropic-ai/claude-code/bin/claude.exe"

    def materialize(payload: Path) -> None:
        _materialize(payload)
        target = payload.joinpath(*relative.split("/"))
        os.makedirs(RUNTIME._fs_path(target.parent), exist_ok=True)
        RUNTIME._write_exclusive(target, b"exact Claude native fixture\n")

    store = tmp_path / "claude-native-runtime"
    published = RUNTIME.stage_npm_generation(
        store, DEFAULT_GENERATION_ID, materialize, **_install_authority(),
        signer=_sign, verifier=_verify,
    )
    authority = _member_launch_authority(published)
    full = RUNTIME.validate_generation(store, DEFAULT_GENERATION_ID, verifier=_verify)
    closure = RUNTIME.sign_generation_member_authority(
        full, relative, execution_kind="native",
        generation_policy_sha256_value=authority["expected_generation_policy_sha256"],
        signer=_sign,
    )
    assert tuple(row["path"] for row in closure["authority"]["closure"]) == (
        RUNTIME.native_resource_roster(relative)
    )
    row = {item["path"]: item for item in full.entries}[relative]
    calls = []
    RUNTIME.launch_generation_member(
        store, DEFAULT_GENERATION_ID, relative, execution_kind="native",
        expected_size=row["size"], expected_sha256=row["sha256"],
        node_executable=None, verifier=_verify, **authority,
        full_census=False, authenticated_member_authority=closure,
        popen_factory=lambda command, **kwargs: calls.append((command, kwargs)) or object(),
    )
    assert len(calls) == 1


@pytest.mark.parametrize("platform_name,architecture", tuple(_CODEX_TEST_TARGETS))
def test_codex_native_resource_closure_matches_locked_cross_platform_roster(
    tmp_path: Path, platform_name: str, architecture: str,
) -> None:
    store, published, relative = _stage_codex_resource_closure(
        tmp_path, platform_name, architecture,
    )
    authority = _member_launch_authority(published)
    full = RUNTIME.validate_generation(store, DEFAULT_GENERATION_ID, verifier=_verify)
    closure = RUNTIME.sign_generation_member_authority(
        full, relative, execution_kind="native",
        generation_policy_sha256_value=authority["expected_generation_policy_sha256"],
        signer=_sign,
    )
    assert closure["authority"]["schema"] == RUNTIME.MEMBER_AUTHORITY_SCHEMA
    assert tuple(row["path"] for row in closure["authority"]["closure"]) == (
        RUNTIME.native_resource_roster(relative)
    )
    assert closure["authority"]["closure_count"] == len(
        closure["authority"]["closure"]
    )
    calls = []
    row = {item["path"]: item for item in full.entries}[relative]
    RUNTIME.launch_generation_member(
        store, DEFAULT_GENERATION_ID, relative, execution_kind="native",
        expected_size=row["size"], expected_sha256=row["sha256"],
        node_executable=None, verifier=_verify, **authority,
        full_census=False, authenticated_member_authority=closure,
        popen_factory=lambda command, **kwargs: calls.append((command, kwargs)) or object(),
    )
    assert len(calls) == 1


@pytest.mark.parametrize(
    "platform_name,architecture,resource_suffix",
    (
        ("win32", "x64", "codex-resources/codex-command-runner.exe"),
        ("win32", "arm64", "codex-resources/codex-windows-sandbox-setup.exe"),
        ("linux", "x64", "codex-resources/bwrap"),
        ("linux", "arm64", "codex-resources/zsh/bin/zsh"),
        ("darwin", "x64", "codex-resources/zsh/bin/zsh"),
        ("darwin", "arm64", "codex-path/rg"),
    ),
)
def test_codex_transitive_resource_mutation_rejects_without_spawn(
    tmp_path: Path, platform_name: str, architecture: str, resource_suffix: str,
) -> None:
    store, published, relative = _stage_codex_resource_closure(
        tmp_path, platform_name, architecture,
    )
    authority = _member_launch_authority(published)
    full = RUNTIME.validate_generation(store, DEFAULT_GENERATION_ID, verifier=_verify)
    closure = RUNTIME.sign_generation_member_authority(
        full, relative, execution_kind="native",
        generation_policy_sha256_value=authority["expected_generation_policy_sha256"],
        signer=_sign,
    )
    row = {item["path"]: item for item in full.entries}[relative]
    target_root = full.payload_path.joinpath(*relative.rsplit("/bin/", 1)[0].split("/"))
    target = target_root.joinpath(*resource_suffix.split("/"))
    with open(RUNTIME._fs_path(target), "ab") as stream:
        stream.write(b"mutated\n")
    calls = []
    with pytest.raises(RUNTIME.MCPRuntimeSecurityError, match="resource closure"):
        RUNTIME.launch_generation_member(
            store, DEFAULT_GENERATION_ID, relative, execution_kind="native",
            expected_size=row["size"], expected_sha256=row["sha256"],
            node_executable=None, verifier=_verify, **authority,
            full_census=False, authenticated_member_authority=closure,
            popen_factory=lambda *args, **kwargs: calls.append((args, kwargs)) or object(),
        )
    assert calls == []


@pytest.mark.parametrize("directory", ("bin", "codex-path", "codex-resources"))
def test_codex_extra_native_resource_in_each_execution_directory_rejects_no_spawn(
    tmp_path: Path, directory: str,
) -> None:
    store, published, relative = _stage_codex_resource_closure(tmp_path, "win32", "x64")
    authority = _member_launch_authority(published)
    full = RUNTIME.validate_generation(store, DEFAULT_GENERATION_ID, verifier=_verify)
    closure = RUNTIME.sign_generation_member_authority(
        full, relative, execution_kind="native",
        generation_policy_sha256_value=authority["expected_generation_policy_sha256"],
        signer=_sign,
    )
    row = {item["path"]: item for item in full.entries}[relative]
    target_root = full.payload_path.joinpath(*relative.rsplit("/bin/", 1)[0].split("/"))
    RUNTIME._write_exclusive(
        target_root / directory / "unsigned-native-resource.exe", b"extra\n",
    )
    calls = []
    with pytest.raises(RUNTIME.MCPRuntimeSecurityError):
        RUNTIME.launch_generation_member(
            store, DEFAULT_GENERATION_ID, relative, execution_kind="native",
            expected_size=row["size"], expected_sha256=row["sha256"],
            node_executable=None, verifier=_verify, **authority,
            full_census=False, authenticated_member_authority=closure,
            popen_factory=lambda *args, **kwargs: calls.append((args, kwargs)) or object(),
        )
    assert calls == []


@pytest.mark.parametrize(
    "mutation", ("missing", "extra", "hardlink", "case", "directory_link", "forgery"),
)
def test_codex_resource_topology_and_authority_forgery_reject_without_spawn(
    tmp_path: Path, mutation: str,
) -> None:
    store, published, relative = _stage_codex_resource_closure(tmp_path, "win32", "x64")
    authority = _member_launch_authority(published)
    full = RUNTIME.validate_generation(store, DEFAULT_GENERATION_ID, verifier=_verify)
    closure = RUNTIME.sign_generation_member_authority(
        full, relative, execution_kind="native",
        generation_policy_sha256_value=authority["expected_generation_policy_sha256"],
        signer=_sign,
    )
    row = {item["path"]: item for item in full.entries}[relative]
    target_root = full.payload_path.joinpath(*relative.rsplit("/bin/", 1)[0].split("/"))
    resources = target_root / "codex-resources"
    command_runner = resources / "codex-command-runner.exe"
    if mutation == "missing":
        os.unlink(RUNTIME._fs_path(command_runner))
    elif mutation == "extra":
        RUNTIME._write_exclusive(resources / "unsigned-helper.exe", b"extra\n")
    elif mutation == "hardlink":
        os.unlink(RUNTIME._fs_path(command_runner))
        os.link(
            RUNTIME._fs_path(target_root / "bin" / "codex.exe"),
            RUNTIME._fs_path(command_runner),
        )
    elif mutation == "case":
        temporary = target_root / "resources-intermediate"
        os.replace(RUNTIME._fs_path(resources), RUNTIME._fs_path(temporary))
        os.replace(RUNTIME._fs_path(temporary), RUNTIME._fs_path(target_root / "CODEX-RESOURCES"))
    elif mutation == "directory_link":
        retained = target_root / "retained-resources"
        os.replace(RUNTIME._fs_path(resources), RUNTIME._fs_path(retained))
        try:
            os.symlink(
                RUNTIME._fs_path(retained), RUNTIME._fs_path(resources),
                target_is_directory=True,
            )
        except OSError as exc:
            pytest.skip("directory symlink creation unavailable: " + str(exc))
    else:
        closure = json.loads(json.dumps(closure))
        closure["authority"]["closure"] = [
            item for item in closure["authority"]["closure"]
            if not item["path"].endswith("codex-command-runner.exe")
        ]
        closure["authority"]["closure_count"] = len(closure["authority"]["closure"])
        closure["authority"]["closure_sha256"] = hashlib.sha256(
            RUNTIME._canonical_json(closure["authority"]["closure"])
        ).hexdigest()
        closure["authentication"] = _sign(RUNTIME._canonical_json(closure["authority"]))
    calls = []
    with pytest.raises(RUNTIME.MCPRuntimeSecurityError):
        RUNTIME.launch_generation_member(
            store, DEFAULT_GENERATION_ID, relative, execution_kind="native",
            expected_size=row["size"], expected_sha256=row["sha256"],
            node_executable=None, verifier=_verify, **authority,
            full_census=False, authenticated_member_authority=closure,
            popen_factory=lambda *args, **kwargs: calls.append((args, kwargs)) or object(),
        )
    assert calls == []


def test_codex_fast_resource_closure_has_bounded_launch_cost(tmp_path: Path) -> None:
    store, published, relative = _stage_codex_resource_closure(tmp_path, "win32", "x64")
    authority = _member_launch_authority(published)
    full = RUNTIME.validate_generation(store, DEFAULT_GENERATION_ID, verifier=_verify)
    closure = RUNTIME.sign_generation_member_authority(
        full, relative, execution_kind="native",
        generation_policy_sha256_value=authority["expected_generation_policy_sha256"],
        signer=_sign,
    )
    row = {item["path"]: item for item in full.entries}[relative]
    calls = []
    started = time.perf_counter()
    for _index in range(10):
        RUNTIME.launch_generation_member(
            store, DEFAULT_GENERATION_ID, relative, execution_kind="native",
            expected_size=row["size"], expected_sha256=row["sha256"],
            node_executable=None, verifier=_verify, **authority,
            full_census=False, authenticated_member_authority=closure,
            popen_factory=lambda command, **kwargs: calls.append((command, kwargs)) or object(),
        )
    elapsed = time.perf_counter() - started
    assert len(calls) == 10
    assert elapsed < 5.0


def test_codex_fast_resource_closure_enforces_bounds_before_hash_or_spawn(
    tmp_path: Path, monkeypatch,
) -> None:
    store, published, relative = _stage_codex_resource_closure(tmp_path, "win32", "x64")
    authority = _member_launch_authority(published)
    full = RUNTIME.validate_generation(store, DEFAULT_GENERATION_ID, verifier=_verify)
    closure = RUNTIME.sign_generation_member_authority(
        full, relative, execution_kind="native",
        generation_policy_sha256_value=authority["expected_generation_policy_sha256"],
        signer=_sign,
    )
    row = {item["path"]: item for item in full.entries}[relative]
    target_root = full.payload_path.joinpath(*relative.rsplit("/bin/", 1)[0].split("/"))
    oversized = target_root / "000-overlarge"
    with open(RUNTIME._fs_path(oversized), "xb") as stream:
        stream.seek(RUNTIME._MAX_NATIVE_RESOURCE_CLOSURE_BYTES)
        stream.write(b"x")
    original_digest = RUNTIME._digest_file_exact

    def bounded_digest(path, *args, **kwargs):
        if Path(path).name == oversized.name:
            pytest.fail("oversized resource was hashed before its bound was enforced")
        return original_digest(path, *args, **kwargs)

    monkeypatch.setattr(RUNTIME, "_digest_file_exact", bounded_digest)
    calls = []
    with pytest.raises(RUNTIME.MCPRuntimeSecurityError, match="byte bound"):
        RUNTIME.launch_generation_member(
            store, DEFAULT_GENERATION_ID, relative, execution_kind="native",
            expected_size=row["size"], expected_sha256=row["sha256"],
            node_executable=None, verifier=_verify, **authority,
            full_census=False, authenticated_member_authority=closure,
            popen_factory=lambda *args, **kwargs: calls.append((args, kwargs)) or object(),
        )
    assert calls == []


def test_codex_fast_resource_closure_bounds_directory_enumeration_before_hash(
    tmp_path: Path, monkeypatch,
) -> None:
    store, published, relative = _stage_codex_resource_closure(tmp_path, "win32", "x64")
    authority = _member_launch_authority(published)
    full = RUNTIME.validate_generation(store, DEFAULT_GENERATION_ID, verifier=_verify)
    closure = RUNTIME.sign_generation_member_authority(
        full, relative, execution_kind="native",
        generation_policy_sha256_value=authority["expected_generation_policy_sha256"],
        signer=_sign,
    )
    row = {item["path"]: item for item in full.entries}[relative]
    target_root = full.payload_path.joinpath(*relative.rsplit("/bin/", 1)[0].split("/"))
    for index in range(RUNTIME._MAX_NATIVE_RESOURCE_CLOSURE_ROWS + 1):
        os.mkdir(RUNTIME._fs_path(target_root / f"extra-{index:02d}"))
    original_digest = RUNTIME._digest_file_exact

    def bounded_digest(path, *args, **kwargs):
        if str(path).startswith(str(target_root)):
            pytest.fail("resource was hashed after row overflow")
        return original_digest(path, *args, **kwargs)

    monkeypatch.setattr(RUNTIME, "_digest_file_exact", bounded_digest)
    calls = []
    with pytest.raises(RUNTIME.MCPRuntimeSecurityError, match="row bound"):
        RUNTIME.launch_generation_member(
            store, DEFAULT_GENERATION_ID, relative, execution_kind="native",
            expected_size=row["size"], expected_sha256=row["sha256"],
            node_executable=None, verifier=_verify, **authority,
            full_census=False, authenticated_member_authority=closure,
            popen_factory=lambda *args, **kwargs: calls.append((args, kwargs)) or object(),
        )
    assert calls == []


def test_materialization_environment_is_closed_and_private(tmp_path: Path) -> None:
    private = tmp_path / "payload"
    private.mkdir()
    env = RUNTIME.materialization_environment(
        sys.executable, sys.executable, private,
        source_env={
            "PATH": "C:/evil", "NODE_OPTIONS": "--require=evil",
            "NPM_CONFIG_USERCONFIG": "evil", "npm_config_registry": "https://evil",
            "LD_PRELOAD": "evil", "DYLD_INSERT_LIBRARIES": "evil",
            "SYSTEMROOT": "C:/Windows",
        },
    )
    assert os.path.normcase(env["PATH"]) == os.path.normcase(
        str(Path(sys.executable).resolve().parent)
    )
    assert env["HOME"].startswith(str(private)) and env["TEMP"].startswith(str(private))
    assert set(env).isdisjoint({
        "NODE_OPTIONS", "NPM_CONFIG_USERCONFIG", "npm_config_registry",
        "LD_PRELOAD", "DYLD_INSERT_LIBRARIES",
    })


@pytest.mark.parametrize("mutation", ("alter", "extra", "missing", "hardlink", "mode"))
def test_exact_replay_rejects_every_payload_drift(
    tmp_path: Path, mutation: str
) -> None:
    store, published = _stage(tmp_path)
    payload = published.payload_path
    entry = payload / "node_modules" / "fixture-mcp" / "dist" / "index.js"
    if mutation == "alter":
        raw = entry.read_bytes()
        entry.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
    elif mutation == "extra":
        (payload / "unreceipted.js").write_text("extra\n", encoding="utf-8")
    elif mutation == "missing":
        entry.unlink()
    elif mutation == "hardlink":
        outside = tmp_path / "hardlink-alias.js"
        try:
            os.link(RUNTIME._fs_path(entry), RUNTIME._fs_path(outside))
        except OSError as exc:
            pytest.skip(f"hardlinks unavailable: {exc}")
        assert entry.stat(follow_symlinks=False).st_nlink > 1
    else:
        before = stat.S_IMODE(entry.stat(follow_symlinks=False).st_mode)
        os.chmod(RUNTIME._fs_path(entry), before ^ stat.S_IWUSR)
        after = stat.S_IMODE(entry.stat(follow_symlinks=False).st_mode)
        if after == before:
            pytest.skip("filesystem does not expose mode mutation")
    with pytest.raises(RUNTIME.MCPRuntimeSecurityError):
        RUNTIME.validate_generation(store, DEFAULT_GENERATION_ID, verifier=_verify)


def test_link_or_reparse_member_is_rejected(tmp_path: Path) -> None:
    store, published = _stage(tmp_path)
    target = published.payload_path / "package.json"
    alias = published.payload_path / "linked-package.json"
    try:
        os.symlink(target, alias, target_is_directory=False)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlinks unavailable: {exc}")
    with pytest.raises(RUNTIME.MCPRuntimeSecurityError, match="link or reparse"):
        RUNTIME.validate_generation(store, DEFAULT_GENERATION_ID, verifier=_verify)


def test_case_alias_detector_is_cross_platform_and_invented_label_is_refused(
    tmp_path: Path,
) -> None:
    with pytest.raises(RUNTIME.MCPRuntimeSecurityError, match="case alias"):
        RUNTIME._reject_case_alias_names(["Readme", "README"], "fixture")
    store, published = _stage(tmp_path)
    before = _tree_projection(published.generation_path)
    with pytest.raises(RUNTIME.MCPRuntimeSecurityError, match="deterministic request"):
        RUNTIME.stage_npm_generation(
            store,
            DEFAULT_GENERATION_ID.upper(),
            _materialize,
            **_install_authority(),
            signer=_sign,
            verifier=_verify,
        )
    assert _tree_projection(published.generation_path) == before


def test_authenticated_receipt_rejects_recomputed_unsigned_tamper(
    tmp_path: Path,
) -> None:
    store, published = _stage(tmp_path)
    receipt_path = published.generation_path / RUNTIME.RECEIPT_NAME
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["authority"]["generation_id"] = "forged-v2"
    unsigned = {
        key: receipt[key]
        for key in ("schema", "authority", "authentication")
    }
    receipt["receipt_sha256"] = hashlib.sha256(
        json.dumps(
            unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    ).hexdigest()
    receipt_path.write_text(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(RUNTIME.MCPRuntimeSecurityError):
        RUNTIME.validate_generation(store, DEFAULT_GENERATION_ID, verifier=_verify)


@pytest.mark.parametrize(
    "surface,marker,duplicate",
    (
        ("top-level", b"{", b'{"schema":"duplicate",'),
        (
            "nested-authority",
            b'"authority":{',
            b'"authority":{"schema":"duplicate",',
        ),
        (
            "nested-authentication",
            b'"authentication":{',
            b'"authentication":{"scheme":"duplicate",',
        ),
    ),
)
def test_receipt_rejects_duplicate_keys_recursively(
    tmp_path: Path, surface: str, marker: bytes, duplicate: bytes
) -> None:
    _store, published = _stage(tmp_path)
    receipt_path = published.generation_path / RUNTIME.RECEIPT_NAME
    canonical = receipt_path.read_bytes()
    forged = canonical.replace(marker, duplicate, 1)
    assert forged != canonical, surface
    with pytest.raises(RUNTIME.MCPRuntimeSecurityError, match="duplicate JSON key"):
        RUNTIME._parse_receipt(forged, DEFAULT_GENERATION_ID, _verify)


@pytest.mark.parametrize("format_kind", ("pretty", "missing-newline", "extra-newline"))
def test_receipt_rejects_every_noncanonical_json_serialization(
    tmp_path: Path, format_kind: str
) -> None:
    _store, published = _stage(tmp_path)
    receipt_path = published.generation_path / RUNTIME.RECEIPT_NAME
    canonical = receipt_path.read_bytes()
    if format_kind == "pretty":
        forged = json.dumps(
            json.loads(canonical), sort_keys=True, indent=2, ensure_ascii=False
        ).encode("utf-8") + b"\n"
    elif format_kind == "missing-newline":
        forged = canonical[:-1]
    else:
        forged = canonical + b"\n"
    with pytest.raises(RUNTIME.MCPRuntimeSecurityError, match="not canonical"):
        RUNTIME._parse_receipt(forged, DEFAULT_GENERATION_ID, _verify)


def test_pending_transaction_blocks_launch_and_postpublish_recovery_is_read_only(
    tmp_path: Path,
) -> None:
    store = tmp_path / "mcp-runtime"

    def crash(event: str) -> None:
        if event == "after_publish":
            raise RuntimeError("simulated process loss after atomic publication")

    with pytest.raises(RuntimeError, match="simulated process loss"):
        RUNTIME.stage_npm_generation(
            store,
            DEFAULT_GENERATION_ID,
            _materialize,
            **_install_authority(),
            signer=_sign,
            verifier=_verify,
            fault_hook=crash,
        )
    generation = store / "generations" / DEFAULT_GENERATION_ID
    before = _tree_projection(generation)
    assert any((store / ".pending").iterdir())
    with pytest.raises(RUNTIME.MCPRuntimeSecurityError, match="incomplete MCP"):
        RUNTIME.validate_generation(store, DEFAULT_GENERATION_ID, verifier=_verify)
    calls: list[list[str]] = []
    with pytest.raises(RUNTIME.MCPRuntimeSecurityError, match="incomplete MCP"):
        RUNTIME.launch_node_generation(
            store,
            DEFAULT_GENERATION_ID,
            "node_modules/fixture-mcp/dist/index.js",
            node_executable=sys.executable,
            verifier=_verify,
            expected_receipt_sha256="0" * 64,
            expected_census_sha256="0" * 64,
            expected_request_sha256="0" * 64,
            popen_factory=lambda command, **_kwargs: calls.append(command),
        )
    assert calls == []
    assert RUNTIME.recover_private_staging(store, verifier=_verify) == (DEFAULT_GENERATION_ID,)
    assert _tree_projection(generation) == before
    assert list((store / ".pending").iterdir()) == []
    RUNTIME.validate_generation(store, DEFAULT_GENERATION_ID, verifier=_verify)


def test_recovery_quarantines_private_staging_and_preserves_committed_generation(
    tmp_path: Path,
) -> None:
    store, published = _stage(tmp_path)
    committed_before = _tree_projection(published.generation_path)
    txn_id = "txn-" + "a" * 64
    pending = RUNTIME._pending_payload(txn_id, "uncommitted-v2")
    RUNTIME._write_exclusive(
        store / ".pending" / f"{txn_id}.json",
        RUNTIME._canonical_json(pending) + b"\n",
    )
    staging = store / ".staging" / txn_id
    staging.mkdir()
    (staging / "partial-download").write_bytes(b"not committed")
    assert RUNTIME.recover_private_staging(store, verifier=_verify) == (
        "uncommitted-v2",
    )
    assert not staging.exists()
    abandoned = store / ".abandoned" / txn_id
    assert (abandoned / "partial-download").read_bytes() == b"not committed"
    assert _tree_projection(published.generation_path) == committed_before
    RUNTIME.validate_generation(store, DEFAULT_GENERATION_ID, verifier=_verify)


def test_crash_after_private_staging_is_recovered_without_publication(
    tmp_path: Path,
) -> None:
    store = tmp_path / "mcp-runtime"

    def crash(event: str) -> None:
        if event == "after_staging":
            raise RuntimeError("simulated loss in private staging")

    with pytest.raises(RuntimeError, match="private staging"):
        RUNTIME.stage_npm_generation(
            store,
            DEFAULT_GENERATION_ID,
            _materialize,
            **_install_authority(),
            signer=_sign,
            verifier=_verify,
            fault_hook=crash,
        )
    assert len(list((store / ".pending").iterdir())) == 1
    assert len(list((store / ".staging").iterdir())) == 1
    assert list((store / "generations").iterdir()) == []
    assert RUNTIME.recover_private_staging(store, verifier=_verify) == (
        DEFAULT_GENERATION_ID,
    )
    assert list((store / ".pending").iterdir()) == []
    assert list((store / ".staging").iterdir()) == []
    assert len(list((store / ".abandoned").iterdir())) == 1
    assert list((store / "generations").iterdir()) == []


def test_orphan_staging_and_malformed_pending_fail_closed(tmp_path: Path) -> None:
    store = tmp_path / "mcp-runtime"
    RUNTIME._ensure_store(store)
    orphan = store / ".staging" / ("txn-" + "b" * 64)
    orphan.mkdir()
    with pytest.raises(RUNTIME.MCPRuntimeSecurityError, match="orphan"):
        RUNTIME.recover_private_staging(store, verifier=_verify)
    assert orphan.is_dir()

    orphan.rmdir()
    malformed = store / ".pending" / ("txn-" + "c" * 64 + ".json")
    malformed.write_bytes(b'{"schema":"forged"}\n')
    with pytest.raises(RUNTIME.MCPRuntimeSecurityError, match="fields are not exact"):
        RUNTIME.recover_private_staging(store, verifier=_verify)
    assert malformed.is_file()


@pytest.mark.parametrize("format_kind", ("pretty", "missing-newline", "extra-newline"))
def test_pending_rejects_every_noncanonical_json_serialization(
    tmp_path: Path, format_kind: str
) -> None:
    store = tmp_path / "mcp-runtime"
    RUNTIME._ensure_store(store)
    txn_id = "txn-" + "e" * 64
    value = RUNTIME._pending_payload(txn_id, "pending-v1")
    canonical = RUNTIME._canonical_json(value) + b"\n"
    if format_kind == "pretty":
        forged = json.dumps(value, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    elif format_kind == "missing-newline":
        forged = canonical[:-1]
    else:
        forged = canonical + b"\n"
    pending_path = store / ".pending" / f"{txn_id}.json"
    RUNTIME._write_exclusive(pending_path, forged)
    with pytest.raises(RUNTIME.MCPRuntimeSecurityError, match="not canonical"):
        RUNTIME._parse_pending(pending_path)
    assert pending_path.read_bytes() == forged


def test_pending_rejects_duplicate_top_level_keys(tmp_path: Path) -> None:
    store = tmp_path / "mcp-runtime"
    RUNTIME._ensure_store(store)
    txn_id = "txn-" + "f" * 64
    canonical = RUNTIME._canonical_json(
        RUNTIME._pending_payload(txn_id, "pending-v1")
    ) + b"\n"
    forged = b'{"schema":"duplicate",' + canonical[1:]
    pending_path = store / ".pending" / f"{txn_id}.json"
    RUNTIME._write_exclusive(pending_path, forged)
    with pytest.raises(RUNTIME.MCPRuntimeSecurityError, match="duplicate JSON key"):
        RUNTIME._parse_pending(pending_path)
    assert pending_path.read_bytes() == forged


def test_exact_generation_reuse_is_idempotent_and_does_not_rematerialize(
    tmp_path: Path,
) -> None:
    store, published = _stage(tmp_path)
    before = _tree_projection(published.generation_path)
    called = False

    def must_not_run(_payload: Path) -> None:
        nonlocal called
        called = True

    reused = RUNTIME.stage_npm_generation(
        store,
        DEFAULT_GENERATION_ID,
        must_not_run,
        **_install_authority(),
        signer=_sign,
        verifier=_verify,
    )
    assert not called
    assert reused.receipt_sha256 == published.receipt_sha256
    assert _tree_projection(published.generation_path) == before


def test_generation_request_derives_exact_content_and_policy_identity(
    tmp_path: Path,
) -> None:
    first = _install_authority()["generation_request"]
    second = _install_authority()["generation_request"]
    assert first == second
    assert first.generation_id == "npm-" + first.request_sha256
    assert hashlib.sha256(first.authority_json).hexdigest() == first.request_sha256
    authority = json.loads(first.authority_json)
    assert authority["schema"] == RUNTIME.GENERATION_REQUEST_SCHEMA
    assert authority["census_schema"] == RUNTIME.CENSUS_SCHEMA
    assert authority["npm_install_policy"]["flags"] == list(
        RUNTIME.REQUIRED_NPM_INSTALL_FLAGS
    )
    assert "--no-bin-links" in authority["npm_install_policy"]["flags"]
    assert authority["sanitizer_sha256"] == hashlib.sha256(SANITIZER_BYTES).hexdigest()
    assert authority["finalizer_policy"] == FINALIZER_POLICY

    changed_sanitizer = RUNTIME.derive_generation_request(
        **{key: value for key, value in _install_authority().items() if key != "generation_request"},
        sanitizer_bytes=SANITIZER_BYTES + b"// changed\n",
        sanitizer_relative_path="schema-sanitizer.js",
        finalizer_policy=FINALIZER_POLICY,
    )
    changed_finalizer = RUNTIME.derive_generation_request(
        **{key: value for key, value in _install_authority().items() if key != "generation_request"},
        sanitizer_bytes=SANITIZER_BYTES,
        sanitizer_relative_path="schema-sanitizer.js",
        finalizer_policy={
            **FINALIZER_POLICY,
            "output_entrypoint": "schema-sanitizer.js",
        },
    )
    assert len({first.generation_id, changed_sanitizer.generation_id, changed_finalizer.generation_id}) == 3

    with pytest.raises(RUNTIME.MCPRuntimeSecurityError, match="flags"):
        RUNTIME.derive_generation_request(
            **{
                **{
                    key: value
                    for key, value in _install_authority().items()
                    if key != "generation_request"
                },
                "npm_install_flags": RUNTIME.REQUIRED_NPM_INSTALL_FLAGS[:-1],
            },
            sanitizer_bytes=SANITIZER_BYTES,
            sanitizer_relative_path="schema-sanitizer.js",
            finalizer_policy=FINALIZER_POLICY,
        )

    store, published = _stage(tmp_path)
    receipt = json.loads(
        (published.generation_path / RUNTIME.RECEIPT_NAME).read_bytes()
    )
    assert receipt["authority"]["request_sha256"] == first.request_sha256
    assert receipt["authority"]["generation_request"] == authority


def test_census_v2_request_cannot_alias_authenticated_legacy_v1_generation(
    tmp_path: Path,
) -> None:
    current_request = _install_authority()["generation_request"]
    current_authority = json.loads(current_request.authority_json)
    legacy_authority = dict(current_authority)
    legacy_authority["schema"] = "plamen.mcp_generation_request.v1"
    legacy_authority.pop("census_schema")
    legacy_request_raw = RUNTIME._canonical_json(legacy_authority)
    legacy_request_sha256 = hashlib.sha256(legacy_request_raw).hexdigest()
    legacy_generation_id = "npm-" + legacy_request_sha256
    assert legacy_generation_id != current_request.generation_id

    seed_parent = tmp_path / "legacy-seed"
    seed_parent.mkdir()
    _seed_store, seed = _stage(seed_parent)
    store = tmp_path / "coexisting-store"
    RUNTIME._ensure_store(store)
    legacy_generation = store / "generations" / legacy_generation_id
    shutil.copytree(seed.generation_path, legacy_generation)
    receipt_path = legacy_generation / RUNTIME.RECEIPT_NAME
    receipt = json.loads(receipt_path.read_bytes())
    receipt["authority"]["generation_id"] = legacy_generation_id
    receipt["authority"]["census_schema"] = "plamen.mcp_recursive_census.v1"
    receipt["authority"]["generation_request"] = legacy_authority
    receipt["authority"]["request_sha256"] = legacy_request_sha256
    authority_raw = RUNTIME._canonical_json(receipt["authority"])
    receipt["authentication"] = _sign(authority_raw)
    unsigned = {
        key: receipt[key]
        for key in ("schema", "authority", "authentication")
    }
    receipt["receipt_sha256"] = hashlib.sha256(
        RUNTIME._canonical_json(unsigned)
    ).hexdigest()
    receipt_path.write_bytes(RUNTIME._canonical_json(receipt) + b"\n")
    assert _verify(authority_raw, receipt["authentication"])
    before = _tree_projection(legacy_generation)

    published = RUNTIME.stage_npm_generation(
        store,
        current_request.generation_id,
        _materialize,
        **_install_authority(),
        signer=_sign,
        verifier=_verify,
    )

    assert published.generation_id == current_request.generation_id
    assert published.generation_path != legacy_generation
    assert _tree_projection(legacy_generation) == before
    assert receipt_path.read_bytes() == RUNTIME._canonical_json(receipt) + b"\n"


@pytest.mark.parametrize("field", ("lifecycle_scripts", "audit", "fund"))
def test_receipt_rejects_bool_int_npm_policy_confusion_even_when_resigned(
    tmp_path: Path, field: str
) -> None:
    _store, published = _stage(tmp_path)
    receipt_path = published.generation_path / RUNTIME.RECEIPT_NAME
    receipt = json.loads(receipt_path.read_bytes())
    receipt["authority"]["npm_install_policy"][field] = 0
    receipt["authority"]["generation_request"]["npm_install_policy"][field] = 0
    authority_raw = RUNTIME._canonical_json(receipt["authority"])
    receipt["authentication"] = _sign(authority_raw)
    unsigned = {
        key: receipt[key]
        for key in ("schema", "authority", "authentication")
    }
    receipt["receipt_sha256"] = hashlib.sha256(
        RUNTIME._canonical_json(unsigned)
    ).hexdigest()
    forged = RUNTIME._canonical_json(receipt) + b"\n"
    with pytest.raises(RUNTIME.MCPRuntimeSecurityError, match="npm install policy"):
        RUNTIME._parse_receipt(forged, published.generation_id, _verify)


@pytest.mark.parametrize(
    "mutation",
    ("wrong-schema", "extra", "traversal", "absolute", "reserved", "typed-bool"),
)
def test_generation_request_rejects_malformed_finalizer_policy(
    mutation: str,
) -> None:
    policy = dict(FINALIZER_POLICY)
    if mutation == "wrong-schema":
        policy["schema"] = "plamen.mcp_finalizer_policy.v0"
    elif mutation == "extra":
        policy["unowned"] = True
    elif mutation == "traversal":
        policy["output_entrypoint"] = "../escape.js"
    elif mutation == "absolute":
        policy["output_entrypoint"] = str(Path(sys.executable).resolve())
    elif mutation == "reserved":
        policy["output_entrypoint"] = "CON.js"
    else:
        policy["require_single_link"] = 1
    authority = {
        key: value
        for key, value in _install_authority().items()
        if key != "generation_request"
    }
    with pytest.raises(RUNTIME.MCPRuntimeSecurityError, match="finalizer|relative|ambiguous"):
        RUNTIME.derive_generation_request(
            **authority,
            sanitizer_bytes=SANITIZER_BYTES,
            sanitizer_relative_path="schema-sanitizer.js",
            finalizer_policy=policy,
        )


def test_stage_requires_exact_receipt_bound_finalizer_output(tmp_path: Path) -> None:
    policy = {
        **FINALIZER_POLICY,
        "output_entrypoint": "node_modules/fixture-mcp/dist/missing.js",
    }
    authority = _install_authority(finalizer_policy=policy)
    request = authority["generation_request"]
    with pytest.raises(RUNTIME.MCPRuntimeSecurityError, match="finalizer output"):
        RUNTIME.stage_npm_generation(
            tmp_path / "mcp-runtime",
            request.generation_id,
            _materialize,
            **authority,
            signer=_sign,
            verifier=_verify,
        )
    assert list((tmp_path / "mcp-runtime" / "generations").iterdir()) == []


def test_stage_and_reuse_replay_reject_forged_nested_policy_types(
    tmp_path: Path,
) -> None:
    authority = _install_authority()
    request = authority["generation_request"]
    forged_value = json.loads(request.authority_json)
    forged_value["npm_install_policy"]["audit"] = 0
    forged_raw = RUNTIME._canonical_json(forged_value)
    forged_sha = hashlib.sha256(forged_raw).hexdigest()
    authority["generation_request"] = RUNTIME.GenerationRequest(
        generation_id="npm-" + forged_sha,
        request_sha256=forged_sha,
        authority_json=forged_raw,
    )
    called = False

    def materialize(_payload: Path) -> None:
        nonlocal called
        called = True

    with pytest.raises(RUNTIME.MCPRuntimeSecurityError, match="npm install policy"):
        RUNTIME.stage_npm_generation(
            tmp_path / "must-not-exist",
            "npm-" + forged_sha,
            materialize,
            **authority,
            signer=_sign,
            verifier=_verify,
        )
    assert not called
    assert not (tmp_path / "must-not-exist").exists()


@pytest.mark.parametrize(
    "field",
    (
        "expected_receipt_sha256",
        "expected_census_sha256",
        "expected_request_sha256",
    ),
)
def test_launcher_requires_exact_external_generation_authority_before_popen(
    tmp_path: Path, field: str
) -> None:
    store, published = _stage(tmp_path)
    expected = _launch_authority(published)
    expected[field] = "0" * 64
    calls: list[list[str]] = []
    with pytest.raises(RUNTIME.MCPRuntimeSecurityError, match="expected launch authority"):
        RUNTIME.launch_node_generation(
            store,
            published.generation_id,
            "node_modules/fixture-mcp/dist/index.js",
            node_executable=sys.executable,
            verifier=_verify,
            **expected,
            popen_factory=lambda command, **_kwargs: calls.append(list(command)),
        )
    assert calls == []


def test_atomic_publication_never_replaces_an_existing_directory(tmp_path: Path) -> None:
    source = tmp_path / "source-generation"
    destination = tmp_path / "committed-generation"
    source.mkdir()
    destination.mkdir()
    (source / "identity").write_text("new\n", encoding="utf-8")
    (destination / "identity").write_text("committed\n", encoding="utf-8")
    with pytest.raises(FileExistsError):
        RUNTIME._atomic_rename_noreplace(source, destination)
    assert (source / "identity").read_text(encoding="utf-8") == "new\n"
    assert (destination / "identity").read_text(encoding="utf-8") == "committed\n"


def test_signed_node_executable_authority_rejects_path_content_and_link_drift(
    tmp_path: Path,
) -> None:
    node_a = tmp_path / "node-a.exe"
    node_b = tmp_path / "node-b.exe"
    original = Path(sys.executable).read_bytes()
    node_a.write_bytes(original)
    node_b.write_bytes(original)
    source_mode = stat.S_IMODE(Path(sys.executable).stat(follow_symlinks=False).st_mode)
    os.chmod(RUNTIME._fs_path(node_a), source_mode)
    os.chmod(RUNTIME._fs_path(node_b), source_mode)
    store = tmp_path / "mcp-runtime"
    authority = _install_authority(node_executable=node_a)
    generation_id = authority["generation_request"].generation_id
    published = RUNTIME.stage_npm_generation(
        store,
        generation_id,
        _materialize,
        **authority,
        signer=_sign,
        verifier=_verify,
    )
    receipt = json.loads(
        (published.generation_path / RUNTIME.RECEIPT_NAME).read_text(encoding="utf-8")
    )
    node_authority = receipt["authority"]["node_executable_authority"]
    assert node_authority["canonical_path"] == os.path.normcase(
        os.path.realpath(os.path.abspath(node_a))
    )
    assert node_authority["sha256"] == hashlib.sha256(original).hexdigest()
    assert node_authority["size"] == len(original)
    assert node_authority["link_count"] >= 1
    assert node_authority["reparse"] is False

    calls: list[list[str]] = []
    RUNTIME.launch_node_generation(
        store,
        generation_id,
        "node_modules/fixture-mcp/dist/index.js",
        node_executable=node_a,
        verifier=_verify,
        **_launch_authority(published),
        popen_factory=lambda command, **_kwargs: calls.append(list(command)),
    )
    assert len(calls) == 1

    calls.clear()
    with pytest.raises(RUNTIME.MCPRuntimeSecurityError, match="differs"):
        RUNTIME.launch_node_generation(
            store,
            generation_id,
            "node_modules/fixture-mcp/dist/index.js",
            node_executable=node_b,
            verifier=_verify,
            **_launch_authority(published),
            popen_factory=lambda command, **_kwargs: calls.append(list(command)),
        )
    assert calls == []

    node_a.write_bytes(bytes([original[0] ^ 1]) + original[1:])
    with pytest.raises(RUNTIME.MCPRuntimeSecurityError, match="differs"):
        RUNTIME.launch_node_generation(
            store,
            generation_id,
            "node_modules/fixture-mcp/dist/index.js",
            node_executable=node_a,
            verifier=_verify,
            **_launch_authority(published),
            popen_factory=lambda command, **_kwargs: calls.append(list(command)),
        )
    assert calls == []

    node_a.write_bytes(original)
    os.chmod(RUNTIME._fs_path(node_a), source_mode)
    alias = tmp_path / "node-hardlink.exe"
    try:
        os.link(RUNTIME._fs_path(node_a), RUNTIME._fs_path(alias))
    except OSError as exc:
        pytest.skip(f"hardlinks unavailable: {exc}")
    with pytest.raises(RUNTIME.MCPRuntimeSecurityError, match="differs"):
        RUNTIME.launch_node_generation(
            store,
            generation_id,
            "node_modules/fixture-mcp/dist/index.js",
            node_executable=node_a,
            verifier=_verify,
            **_launch_authority(published),
            popen_factory=lambda command, **_kwargs: calls.append(list(command)),
        )
    assert calls == []


def test_long_path_generation_census_and_validation(tmp_path: Path) -> None:
    store = tmp_path / "mcp-runtime"
    authority = _install_authority()
    generation_id = authority["generation_request"].generation_id
    published = RUNTIME.stage_npm_generation(
        store,
        generation_id,
        lambda payload: _materialize(payload, nested=True),
        **authority,
        signer=_sign,
        verifier=_verify,
    )
    assert len(str(published.payload_path)) > 0
    validated = RUNTIME.validate_generation(store, generation_id, verifier=_verify)
    deep = [row for row in validated.entries if row["path"].endswith("deep.js")]
    assert len(deep) == 1
    assert len(deep[0]["path"]) > 260


def test_generation_root_extra_and_entrypoint_escape_are_rejected(tmp_path: Path) -> None:
    store, published = _stage(tmp_path)
    (published.generation_path / "unowned-receipt.json").write_text(
        "{}\n", encoding="utf-8"
    )
    with pytest.raises(RUNTIME.MCPRuntimeSecurityError, match="extra or missing"):
        RUNTIME.validate_generation(store, DEFAULT_GENERATION_ID, verifier=_verify)
    (published.generation_path / "unowned-receipt.json").unlink()
    with pytest.raises(RUNTIME.MCPRuntimeSecurityError, match="relative path"):
        RUNTIME.launch_node_generation(
            store,
            DEFAULT_GENERATION_ID,
            "../package.json",
            node_executable=sys.executable,
            verifier=_verify,
            **_launch_authority(published),
        )


def test_signer_and_verifier_are_mandatory_and_callback_shape_is_exact(
    tmp_path: Path,
) -> None:
    store = tmp_path / "mcp-runtime"
    with pytest.raises(RUNTIME.MCPRuntimeSecurityError, match="signer"):
        RUNTIME.stage_npm_generation(
            store,
            "unsigned-v1",
            _materialize,
            **_install_authority(),
            signer=None,
            verifier=_verify,
        )
    assert not store.exists()
    (tmp_path / "signed").mkdir()
    store2, _published = _stage(tmp_path / "signed")
    with pytest.raises(RUNTIME.MCPRuntimeSecurityError, match="verifier"):
        RUNTIME.validate_generation(store2, DEFAULT_GENERATION_ID, verifier=None)


def test_recovery_quarantines_opaque_reparse_root_without_touching_victim(
    tmp_path: Path,
) -> None:
    store = tmp_path / "mcp-runtime"
    RUNTIME._ensure_store(store)
    victim = tmp_path / "victim"
    victim.mkdir()
    secret = victim / "must-survive.txt"
    secret.write_bytes(b"irreplaceable")
    txn_id = "txn-" + "d" * 64
    staging = store / ".staging" / txn_id
    try:
        os.symlink(victim, staging, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"directory symlink/reparse creation unavailable: {exc}")
    pending = RUNTIME._pending_payload(txn_id, "opaque-v1")
    RUNTIME._write_exclusive(
        store / ".pending" / f"{txn_id}.json",
        RUNTIME._canonical_json(pending) + b"\n",
    )
    assert RUNTIME.recover_private_staging(store, verifier=_verify) == ("opaque-v1",)
    assert secret.read_bytes() == b"irreplaceable"
    assert not os.path.lexists(RUNTIME._fs_path(staging))
    quarantined = store / ".abandoned" / txn_id
    assert os.path.lexists(RUNTIME._fs_path(quarantined))
    assert RUNTIME._is_reparse(RUNTIME._lstat(quarantined)) or quarantined.is_symlink()
    assert "_remove_tree_no_follow" not in MODULE_PATH.read_text(encoding="utf-8")


@pytest.mark.parametrize("target_kind", ("payload_file", "payload_dir", "receipt", "node"))
def test_extended_metadata_is_rejected_on_every_authority_surface(
    tmp_path: Path, target_kind: str
) -> None:
    node = tmp_path / "node.exe"
    node.write_bytes(Path(sys.executable).read_bytes())
    store = tmp_path / "mcp-runtime"
    authority = _install_authority(node_executable=node)
    generation_id = authority["generation_request"].generation_id
    published = RUNTIME.stage_npm_generation(
        store,
        generation_id,
        _materialize,
        **authority,
        signer=_sign,
        verifier=_verify,
    )
    targets = {
        "payload_file": published.payload_path / "package.json",
        "payload_dir": published.payload_path / "node_modules",
        "receipt": published.generation_path / RUNTIME.RECEIPT_NAME,
        "node": node,
    }
    target = targets[target_kind]
    if os.name == "nt":
        try:
            with open(RUNTIME._fs_path(str(target) + ":plamen-review"), "wb") as stream:
                stream.write(b"hidden")
        except OSError as exc:
            pytest.skip(f"ADS creation unavailable: {exc}")
    else:
        setter = getattr(os, "setxattr", None)
        if setter is None:
            pytest.skip("xattr creation unavailable")
        try:
            setter(RUNTIME._fs_path(target), "user.plamen-review", b"hidden", follow_symlinks=False)
        except OSError as exc:
            pytest.skip(f"xattr creation unavailable: {exc}")
    if target_kind == "node":
        action = lambda: RUNTIME.launch_node_generation(
            store,
            generation_id,
            "node_modules/fixture-mcp/dist/index.js",
            node_executable=node,
            verifier=_verify,
            **_launch_authority(published),
            popen_factory=lambda *_args, **_kwargs: pytest.fail("Node spawned"),
        )
    else:
        action = lambda: RUNTIME.validate_generation(
            store, generation_id, verifier=_verify
        )
    with pytest.raises(RUNTIME.MCPRuntimeSecurityError, match="streams|attributes"):
        action()


@pytest.mark.skipif(os.name != "nt", reason="Windows ADS enumeration")
def test_windows_stream_enumerator_reuses_one_ctypes_pointer_type(
    tmp_path: Path,
) -> None:
    import ctypes

    target = tmp_path / "ordinary.txt"
    target.write_bytes(b"ordinary payload")
    expected = RUNTIME._windows_stream_names(target)
    assert "::$DATA" in expected

    pointer_cache = getattr(ctypes, "_pointer_type_cache", None)
    if pointer_cache is None:
        pytest.skip("CPython ctypes pointer cache is unavailable")
    pointer_type = RUNTIME._LP_WIN32_FIND_STREAM_DATA
    assert pointer_type is ctypes.POINTER(RUNTIME._WIN32_FIND_STREAM_DATA)
    before = set(pointer_cache)

    for _ in range(2_048):
        assert RUNTIME._windows_stream_names(target) == expected

    assert set(pointer_cache) == before
    assert RUNTIME._LP_WIN32_FIND_STREAM_DATA is pointer_type


@pytest.mark.skipif(os.name != "nt", reason="Windows component ambiguity")
@pytest.mark.parametrize("name", ("CON", "aux.txt", "trailing. ", "ads:name", "bad\x01name"))
def test_windows_ambiguous_components_are_rejected(name: str) -> None:
    with pytest.raises(RUNTIME.MCPRuntimeSecurityError, match="Windows-ambiguous"):
        RUNTIME._reject_windows_ambiguous_component(name, "fixture")


_WINDOWS_RESERVED_GENERATION_IDS = tuple(
    value
    for basename in (
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "CLOCK$",
        *(f"COM{index}" for index in range(1, 10)),
        *(f"LPT{index}" for index in range(1, 10)),
    )
    for value in (basename, basename.lower() + ".runtime")
) + ("trailing.", "trailing ")


@pytest.mark.skipif(os.name != "nt", reason="Windows component ambiguity")
@pytest.mark.parametrize("generation_id", _WINDOWS_RESERVED_GENERATION_IDS)
def test_stage_rejects_windows_ambiguous_generation_before_store_creation(
    tmp_path: Path, generation_id: str
) -> None:
    store = tmp_path / "must-not-exist"
    with pytest.raises(RUNTIME.MCPRuntimeSecurityError, match="Windows-ambiguous"):
        RUNTIME.stage_npm_generation(
            store,
            generation_id,
            _materialize,
            **_install_authority(),
            signer=_sign,
            verifier=_verify,
        )
    assert not os.path.lexists(RUNTIME._fs_path(store))


@pytest.mark.parametrize("override", ("shell", "executable", "preexec_fn", "env"))
def test_launcher_rejects_process_semantic_overrides(
    tmp_path: Path, override: str
) -> None:
    store, published = _stage(tmp_path)
    values: dict[str, Any] = {
        "shell": False,
        "executable": sys.executable,
        "preexec_fn": lambda: None,
        "env": {},
    }
    with pytest.raises(RUNTIME.MCPRuntimeSecurityError, match="overrides"):
        RUNTIME.launch_node_generation(
            store,
            DEFAULT_GENERATION_ID,
            "node_modules/fixture-mcp/dist/index.js",
            node_executable=sys.executable,
            verifier=_verify,
            **_launch_authority(published),
            popen_factory=lambda *_args, **_kwargs: pytest.fail("Node spawned"),
            **{override: values[override]},
        )


def test_launcher_sanitizes_dynamic_loader_and_node_environment(
    tmp_path: Path,
) -> None:
    store, published = _stage(tmp_path)
    captured: dict[str, Any] = {}

    def fake_popen(command, **kwargs):
        captured["command"] = list(command)
        captured.update(kwargs)
        return object()

    base_env = {
        "SAFE": "retained",
        "NODE_OPTIONS": "--require attacker.js",
        "node_path": "attacker-modules",
        "LD_PRELOAD": "/tmp/attacker.so",
        "ld_library_path": "/tmp",
        "DYLD_INSERT_LIBRARIES": "/tmp/attacker.dylib",
    }
    RUNTIME.launch_node_generation(
        store,
        DEFAULT_GENERATION_ID,
        "node_modules/fixture-mcp/dist/index.js",
        node_executable=sys.executable,
        verifier=_verify,
        **_launch_authority(published),
        base_env=base_env,
        popen_factory=fake_popen,
    )
    assert captured["env"] == {"SAFE": "retained"}
    assert not captured["command"][0].startswith("\\\\?\\")
    assert not captured["command"][1].startswith("\\\\?\\")


def test_durability_order_flushes_tree_before_publish_and_pending_retirement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[tuple[str, str]] = []
    monkeypatch.setattr(
        RUNTIME,
        "_durability_event",
        lambda event, path: events.append((event, str(path))),
    )
    _stage(tmp_path)
    rename_index = next(
        index for index, row in enumerate(events) if row[0].startswith("rename-noreplace")
    )
    retire_index = next(
        index for index, row in enumerate(events) if row[0] == "pending-retired"
    )
    payload_flushes = [
        index
        for index, row in enumerate(events)
        if row[0] == "file-fsync"
        and any(name in row[1] for name in ("package.json", "package-lock.json", "index.js", RUNTIME.RECEIPT_NAME))
    ]
    assert payload_flushes and max(payload_flushes) < rename_index < retire_index
    control_events = [
        row for row in events if row[0] in {"directory-fsync", "directory-identity"}
    ]
    assert sum(row[1].endswith(".staging") for row in control_events) >= 2
    assert sum(row[1].endswith("generations") for row in control_events) >= 2
    store = tmp_path / "mcp-runtime"
    assert any(
        os.path.normcase(row[1]) == os.path.normcase(str(store))
        for row in control_events
    )


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory-fsync ordering")
def test_fresh_store_and_parent_are_durable_before_pending_is_observable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[tuple[str, Path]] = []
    monkeypatch.setattr(
        RUNTIME,
        "_durability_event",
        lambda event, path: events.append((event, Path(path))),
    )
    store = tmp_path / "fresh-store"

    def crash(event: str) -> None:
        if event == "after_pending":
            raise RuntimeError("crash after durable pending")

    with pytest.raises(RuntimeError, match="durable pending"):
        RUNTIME.stage_npm_generation(
            store,
            DEFAULT_GENERATION_ID,
            _materialize,
            **_install_authority(),
            signer=_sign,
            verifier=_verify,
            fault_hook=crash,
        )

    pending_index = next(
        index
        for index, (event, path) in enumerate(events)
        if event == "file-fsync" and path.parent.name == ".pending"
    )
    required_barriers = {store.resolve(), tmp_path.resolve()}
    observed_before_pending = {
        path.resolve()
        for event, path in events[:pending_index]
        if event == "directory-fsync"
    }
    assert required_barriers <= observed_before_pending
    assert store.is_dir()
    assert len(list((store / ".pending").iterdir())) == 1


def test_same_generation_id_rejects_every_install_authority_drift(
    tmp_path: Path,
) -> None:
    store, published = _stage(tmp_path)
    before = _tree_projection(published.generation_path)
    called = False

    def must_not_run(_payload: Path) -> None:
        nonlocal called
        called = True

    changed_lock = json.loads(LOCK_BYTES)
    changed_lock["lockfileVersion"] = 2
    changed_lock_bytes = RUNTIME._canonical_json(changed_lock) + b"\n"
    changed = _install_authority()
    changed["expected_package_lock_bytes"] = changed_lock_bytes
    with pytest.raises(RUNTIME.MCPRuntimeSecurityError, match="deterministic"):
        RUNTIME.stage_npm_generation(
            store,
            DEFAULT_GENERATION_ID,
            must_not_run,
            **changed,
            signer=_sign,
            verifier=_verify,
        )
    changed = _install_authority(npm_version="10.9.3")
    with pytest.raises(RUNTIME.MCPRuntimeSecurityError, match="deterministic"):
        RUNTIME.stage_npm_generation(
            store,
            DEFAULT_GENERATION_ID,
            must_not_run,
            **changed,
            signer=_sign,
            verifier=_verify,
        )
    alternate_tool = tmp_path / "byte-identical-tool.exe"
    alternate_tool.write_bytes(Path(sys.executable).read_bytes())
    for field in ("node_executable", "npm_executable"):
        changed = _install_authority()
        changed[field] = alternate_tool
        with pytest.raises(RUNTIME.MCPRuntimeSecurityError, match="deterministic"):
            RUNTIME.stage_npm_generation(
                store,
                DEFAULT_GENERATION_ID,
                must_not_run,
                **changed,
                signer=_sign,
                verifier=_verify,
            )
    with pytest.raises(RUNTIME.MCPRuntimeSecurityError, match="flags"):
        RUNTIME.stage_npm_generation(
            store,
            DEFAULT_GENERATION_ID,
            must_not_run,
            **_install_authority(npm_install_flags=("ci", "--no-audit")),
            signer=_sign,
            verifier=_verify,
        )
    assert not called
    assert _tree_projection(published.generation_path) == before


def test_materialization_must_match_expected_canonical_manifest_bytes(
    tmp_path: Path,
) -> None:
    def drifted(payload: Path) -> None:
        _materialize(payload)
        package = json.loads(PACKAGE_BYTES)
        package["version"] = "9.9.9"
        (payload / "package.json").write_bytes(RUNTIME._canonical_json(package) + b"\n")

    with pytest.raises(RUNTIME.MCPRuntimeSecurityError, match="expected canonical"):
        RUNTIME.stage_npm_generation(
            tmp_path / "mcp-runtime",
            DEFAULT_GENERATION_ID,
            drifted,
            **_install_authority(),
            signer=_sign,
            verifier=_verify,
        )


def test_actual_node_launch_uses_display_paths_for_short_and_long_entries(
    tmp_path: Path,
) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is unavailable")
    node = os.path.abspath(node)
    store = tmp_path / "mcp-runtime"
    authority = _install_authority(node_executable=node)
    generation_id = authority["generation_request"].generation_id
    published = RUNTIME.stage_npm_generation(
        store,
        generation_id,
        lambda payload: _materialize(payload, nested=True),
        **authority,
        signer=_sign,
        verifier=_verify,
    )
    short = RUNTIME.launch_node_generation(
        store,
        generation_id,
        "node_modules/fixture-mcp/dist/index.js",
        node_executable=node,
        verifier=_verify,
        **_launch_authority(published),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    stdout, stderr = short.communicate(timeout=30)
    assert short.returncode == 0, stderr
    assert stdout == "fixture"
    validated = RUNTIME.validate_generation(store, generation_id, verifier=_verify)
    deep = next(row["path"] for row in validated.entries if row["path"].endswith("deep.js"))
    assert len(str(validated.payload_path / Path(deep))) > 260
    with pytest.raises(RUNTIME.MCPRuntimeSecurityError, match="finalizer output"):
        RUNTIME.launch_node_generation(
            store,
            generation_id,
            deep,
            node_executable=node,
            verifier=_verify,
            **_launch_authority(published),
            popen_factory=lambda *_args, **_kwargs: pytest.fail("alternate entry spawned"),
        )
    deep_policy = {
        **FINALIZER_POLICY,
        "output_entrypoint": deep,
    }
    deep_authority = _install_authority(
        node_executable=node, finalizer_policy=deep_policy
    )
    deep_generation_id = deep_authority["generation_request"].generation_id
    deep_published = RUNTIME.stage_npm_generation(
        store,
        deep_generation_id,
        lambda payload: _materialize(payload, nested=True),
        **deep_authority,
        signer=_sign,
        verifier=_verify,
    )
    long_process = RUNTIME.launch_node_generation(
        store,
        deep_generation_id,
        deep,
        node_executable=node,
        verifier=_verify,
        **_launch_authority(deep_published),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    stdout, stderr = long_process.communicate(timeout=30)
    assert long_process.returncode == 0, stderr
    assert stdout == "deep-runtime-ok"
