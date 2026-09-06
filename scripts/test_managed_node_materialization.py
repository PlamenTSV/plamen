"""Adversarial tests for the reviewed official Node/npm materialization root."""

from __future__ import annotations

import hashlib
import hmac
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
from types import SimpleNamespace
import zipfile

import pytest


MODULE_PATH = Path(__file__).with_name("plamen_mcp_runtime.py")
ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("managed_node_runtime_test", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
RUNTIME = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNTIME
SPEC.loader.exec_module(RUNTIME)

KEY = b"managed-node-unit-test-key"


def _sign(raw: bytes):
    return {
        "scheme": "test-hmac-sha256", "key_id": "managed-node-test",
        "signature": hmac.new(KEY, raw, hashlib.sha256).hexdigest(),
    }


def _verify(raw: bytes, authentication) -> bool:
    return (
        authentication.get("scheme") == "test-hmac-sha256"
        and authentication.get("key_id") == "managed-node-test"
        and hmac.compare_digest(
            authentication.get("signature", ""),
            hmac.new(KEY, raw, hashlib.sha256).hexdigest(),
        )
    )


def _zip_bytes(archive) -> bytes:
    npm_root = archive["npm_cli"].rsplit("/bin/npm-cli.js", 1)[0]
    rows = {
        archive["node"]: b"exact managed node fixture\n",
        archive["npm_cli"]: b"require('../lib/cli.js')(process)\n",
        npm_root + "/lib/cli.js": b"module.exports = () => 0\n",
        npm_root + "/node_modules/fixture-dependency/index.js": b"module.exports = 1\n",
        npm_root + "/package.json": json.dumps(
            {"name": "npm", "version": RUNTIME.MANAGED_NPM_VERSION},
            separators=(",", ":"),
        ).encode(),
    }
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive_file:
        for relative, raw in rows.items():
            info = zipfile.ZipInfo(archive["archive_root"] + "/" + relative)
            info.external_attr = (stat.S_IFREG | (0o755 if relative == archive["node"] else 0o644)) << 16
            archive_file.writestr(info, raw)
    return output.getvalue()


def _fake_reviewed_archive(monkeypatch):
    key = RUNTIME._managed_node_platform_key()
    original = dict(RUNTIME.MANAGED_NODE_ARCHIVES[key])
    archive = {
        **original,
        "filename": "node-v24.20.0-reviewed-fixture.zip",
        "format": "zip",
        "archive_root": "node-v24.20.0-reviewed-fixture",
        "node": "node.exe",
        "npm_cli": "node_modules/npm/bin/npm-cli.js",
    }
    raw = _zip_bytes(archive)
    archive["sha256"] = hashlib.sha256(raw).hexdigest()
    monkeypatch.setitem(RUNTIME.MANAGED_NODE_ARCHIVES, key, archive)
    return key, archive, raw


def _stage(tmp_path, monkeypatch):
    _key, archive, raw = _fake_reviewed_archive(monkeypatch)
    downloads = []
    managed = RUNTIME.ensure_managed_node_runtime(
        tmp_path / "node-store", signer=_sign, verifier=_verify,
        downloader=lambda url, maximum: downloads.append((url, maximum)) or raw,
    )
    return managed, archive, raw, downloads


def test_official_node_archive_authorities_are_exact_and_complete() -> None:
    assert RUNTIME.MANAGED_NODE_VERSION == "24.20.0"
    assert RUNTIME.MANAGED_NPM_VERSION == "11.19.0"
    assert set(RUNTIME.MANAGED_NODE_ARCHIVES) == {
        "windows-x64", "windows-arm64", "linux-x64", "linux-arm64",
        "darwin-x64", "darwin-arm64",
    }
    assert {
        key: row["sha256"] for key, row in RUNTIME.MANAGED_NODE_ARCHIVES.items()
    } == {
        "windows-x64": "6cac9ffbca8f6a47091e4b5c772e0606049c3871cb67d900c0cedde630e545ba",
        "windows-arm64": "31c6799744de8a54601643098040c68c3697e56c94e407d61d0e5fa5f34191d7",
        "linux-x64": "2f2c0da162318f0de47665410c7c8c2ed3d36c8f3105de4bbc61176c70a7cbf2",
        "linux-arm64": "5f4ddab610c1ab2016b3c227cebdbf6d9495161487e4739c7b90090595f465f7",
        "darwin-x64": "9e5b2644cf107befb6aefca676b96d3296bc10138096f022ed378d6233ed81f4",
        "darwin-arm64": "40e5607e5ecb3db9192723776da2d75d966260fc74a7a9e731c1bd67dda96bc8",
    }
    assert all(row["filename"].startswith("node-v24.20.0-") for row in RUNTIME.MANAGED_NODE_ARCHIVES.values())


def test_production_materializer_has_no_ambient_npm_or_node_resolution() -> None:
    source = (ROOT / "plamen.py").read_text(encoding="utf-8")
    region = source[
        source.index("def _setup_mcp_immutable_generation"):
        source.index("def _mcp_runtime_has_updater_debris")
    ]
    assert "shutil.which" not in region
    assert "ensure_managed_node_runtime" in region
    assert "run_managed_npm_ci" in region
    assert "[npm" not in region and "npm.cmd" not in region
    legacy_prefix = source[
        source.index("def _setup_mcp_packages_legacy"):
        source.index("import json as _json", source.index("def _setup_mcp_packages_legacy"))
    ]
    assert "permanently disabled" in legacy_prefix


def test_managed_node_download_publish_and_offline_reuse_are_exact(tmp_path, monkeypatch) -> None:
    managed, archive, _raw, downloads = _stage(tmp_path, monkeypatch)
    assert managed.archive_sha256 == archive["sha256"]
    assert managed.npm_version == "11.19.0"
    assert managed.node_path.is_file() and managed.npm_cli_path.is_file()
    assert len(downloads) == 1 and downloads[0][0].startswith(
        "https://nodejs.org/dist/v24.20.0/"
    )
    reused = RUNTIME.ensure_managed_node_runtime(
        managed.store_root, signer=_sign, verifier=_verify, allow_download=False,
        downloader=lambda *_args: pytest.fail("offline reuse downloaded"),
    )
    assert reused == managed


def test_npm_ci_never_executes_path_wrapper_and_uses_exact_managed_cli(
    tmp_path, monkeypatch,
) -> None:
    managed, _archive, _raw, _downloads = _stage(tmp_path, monkeypatch)
    evil = tmp_path / "evil" / "npm.cmd"
    evil.parent.mkdir(); evil.write_text("@echo 11.19.0\r\n", encoding="utf-8")
    private = tmp_path / "private-environment"
    environment = RUNTIME.materialization_environment(
        managed.node_path, managed.npm_cli_path, private,
        source_env={
            "PATH": str(evil.parent), "NODE_OPTIONS": "--require=evil",
            "NPM_CONFIG_USERCONFIG": str(evil), "SYSTEMROOT": "C:/Windows",
        },
    )
    payload = tmp_path / "payload"; payload.mkdir()
    calls = []
    result = RUNTIME.run_managed_npm_ci(
        managed, payload, verifier=_verify, environment=environment,
        runner=lambda command, **kwargs: calls.append((command, kwargs))
        or SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    assert result.returncode == 0 and len(calls) == 1
    command, kwargs = calls[0]
    assert Path(command[0]) == managed.node_path
    assert Path(command[1]) == managed.npm_cli_path
    assert command[2:] == list(RUNTIME.REQUIRED_NPM_INSTALL_FLAGS)
    assert all("npm.cmd" not in item.lower() for item in command)
    assert str(evil.parent) not in kwargs["env"]["PATH"]
    assert "NODE_OPTIONS" not in kwargs["env"]
    assert not any(key.upper().startswith("NPM_CONFIG_") for key in kwargs["env"])


@pytest.mark.parametrize("target_kind", ["npm-cli", "dependency"])
def test_managed_npm_mutation_fails_before_spawn(tmp_path, monkeypatch, target_kind) -> None:
    managed, _archive, _raw, _downloads = _stage(tmp_path, monkeypatch)
    target = managed.npm_cli_path
    if target_kind == "dependency":
        target = managed.npm_cli_path.parent.parent / "node_modules" / "fixture-dependency" / "index.js"
    target.write_bytes(target.read_bytes() + b"// drift\n")
    payload = tmp_path / "payload"; payload.mkdir()
    with pytest.raises(RUNTIME.MCPRuntimeSecurityError, match="implementation closure changed"):
        RUNTIME.run_managed_npm_ci(
            managed, payload, verifier=_verify,
            environment=RUNTIME.materialization_environment(
                managed.node_path, managed.npm_cli_path, tmp_path / "private",
                source_env={},
            ),
            runner=lambda *_args, **_kwargs: pytest.fail("mutated closure spawned"),
        )


def test_managed_npm_revalidates_closure_after_runner_before_unlock(tmp_path, monkeypatch) -> None:
    managed, _archive, _raw, _downloads = _stage(tmp_path, monkeypatch)
    dependency = (
        managed.npm_cli_path.parent.parent / "node_modules"
        / "fixture-dependency" / "index.js"
    )
    payload = tmp_path / "payload"; payload.mkdir()
    def mutate_during_run(_command, **_kwargs):
        dependency.write_bytes(b"mutated while lock held\n")
        return SimpleNamespace(returncode=0, stdout="", stderr="")
    with pytest.raises(RUNTIME.MCPRuntimeSecurityError, match="implementation closure changed"):
        RUNTIME.run_managed_npm_ci(
            managed, payload, verifier=_verify,
            environment=RUNTIME.materialization_environment(
                managed.node_path, managed.npm_cli_path, tmp_path / "private",
                source_env={},
            ), runner=mutate_during_run,
        )


def test_archive_digest_and_link_member_fail_before_publication(tmp_path, monkeypatch) -> None:
    key, archive, raw = _fake_reviewed_archive(monkeypatch)
    with pytest.raises(RUNTIME.MCPRuntimeSecurityError, match="downloaded managed Node"):
        RUNTIME.ensure_managed_node_runtime(
            tmp_path / "bad-digest", signer=_sign, verifier=_verify,
            downloader=lambda *_args: raw + b"drift",
        )
    store = tmp_path / "bad-digest"
    assert not list((store / "generations").iterdir())

    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as bundle:
        node = zipfile.ZipInfo(archive["archive_root"] + "/" + archive["node"])
        node.external_attr = (stat.S_IFREG | 0o755) << 16
        bundle.writestr(node, b"node")
        linked = zipfile.ZipInfo(archive["archive_root"] + "/" + archive["npm_cli"])
        linked.external_attr = (stat.S_IFLNK | 0o777) << 16
        bundle.writestr(linked, b"target")
    linked_raw = output.getvalue()
    linked_archive = {**archive, "sha256": hashlib.sha256(linked_raw).hexdigest()}
    monkeypatch.setitem(RUNTIME.MANAGED_NODE_ARCHIVES, key, linked_archive)
    with pytest.raises(RUNTIME.MCPRuntimeSecurityError, match="contains a link"):
        RUNTIME.ensure_managed_node_runtime(
            tmp_path / "linked", signer=_sign, verifier=_verify,
            downloader=lambda *_args: linked_raw,
        )
    assert not list((tmp_path / "linked" / "generations").iterdir())


def test_committed_generation_recovers_durable_pending_without_download(
    tmp_path, monkeypatch,
) -> None:
    _key, _archive, raw = _fake_reviewed_archive(monkeypatch)
    real_unlink = RUNTIME._durable_unlink
    failed = False
    def fail_pending_retirement(path):
        nonlocal failed
        if not failed and Path(path).parent.name == ".pending":
            failed = True
            raise OSError("crash seam before pending retirement")
        return real_unlink(path)
    monkeypatch.setattr(RUNTIME, "_durable_unlink", fail_pending_retirement)
    store = tmp_path / "node-store"
    with pytest.raises(OSError, match="crash seam"):
        RUNTIME.ensure_managed_node_runtime(
            store, signer=_sign, verifier=_verify,
            downloader=lambda *_args: raw,
        )
    assert len(list((store / "generations").iterdir())) == 1
    assert len(list((store / ".pending").iterdir())) == 1
    monkeypatch.setattr(RUNTIME, "_durable_unlink", real_unlink)
    recovered = RUNTIME.ensure_managed_node_runtime(
        store, signer=_sign, verifier=_verify, allow_download=False,
        downloader=lambda *_args: pytest.fail("recovery downloaded"),
    )
    assert recovered.node_path.is_file()
    assert not list((store / ".pending").iterdir())
