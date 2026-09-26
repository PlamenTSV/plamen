from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

import runtime_source_projection as projection


COMMIT = "a" * 40


def _closure_document() -> dict[str, object]:
    rows = [
        {
            "digest_mode": "raw-v1",
            "kind": "python-source",
            "path": "entry.py",
            "sha256": "a" * 64,
        },
        {
            "digest_mode": "raw-v1",
            "kind": "runtime-data",
            "path": "payload.json",
            "sha256": "b" * 64,
        },
    ]
    return {
        "assets": rows,
        "derivation": projection.RUNTIME_CLOSURE_DERIVATION,
        "entrypoints": ["entry.py"],
        "files": [
            "entry.py", "payload.json", projection.RUNTIME_CLOSURE_PATH,
        ],
        "manifest_control": {
            "kind": "control", "path": projection.RUNTIME_CLOSURE_PATH,
        },
        "schema": projection.RUNTIME_CLOSURE_SCHEMA,
    }


def test_runtime_closure_decoder_requires_complete_unique_denominator() -> None:
    document = _closure_document()
    assert projection._decode_runtime_closure(
        projection.canonical_json(document)
    ) == document

    missing = json.loads(projection.canonical_json(document))
    missing["assets"].pop()
    with pytest.raises(projection.ProjectionError, match="denominator differs"):
        projection._decode_runtime_closure(projection.canonical_json(missing))

    duplicate_path = json.loads(projection.canonical_json(document))
    duplicate_path["assets"].append(dict(duplicate_path["assets"][0]))
    duplicate_path["files"].append("entry.py")
    with pytest.raises(projection.ProjectionError, match="denominator differs"):
        projection._decode_runtime_closure(
            projection.canonical_json(duplicate_path)
        )


def test_runtime_closure_decoder_rejects_duplicate_json_keys() -> None:
    raw = projection.canonical_json(_closure_document()).replace(
        b'{"assets":', b'{"schema":"decoy","assets":', 1
    )
    with pytest.raises(projection.ProjectionError, match="duplicate/non-string"):
        projection._decode_runtime_closure(raw)


def _write(path: Path, raw: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    path.chmod(mode)


def _fixture(monkeypatch: pytest.MonkeyPatch, root: Path) -> None:
    _write(root / "asset.py", b"asset = 1\n")
    _write(root / "worker.py", b"print('worker')\n", 0o755)
    _write(root / "backend.json", b"{}")
    closure = {
        "assets": [{
            "digest_mode": "raw-v1", "kind": "python-source", "path": "asset.py",
            "sha256": hashlib.sha256(b"asset = 1\n").hexdigest(),
        }]
    }
    _write(root / "closure.json", projection.canonical_json(closure))
    _write(root / "codex-adapter/AGENTS.md", b"agent\n")
    _write(root / "codex-adapter/skills/plamen/SKILL.md", b"skill\n")
    monkeypatch.setattr(projection, "RUNTIME_FIXED", ("closure.json", "backend.json"))
    monkeypatch.setattr(projection, "NATIVE_REQUIRED", ("worker.py",))
    monkeypatch.setattr(projection, "METHOD_ROOTS", ())
    monkeypatch.setattr(projection, "RULE_PROJECTION", {})
    monkeypatch.setattr(projection, "ADAPTER_FIXED", ("AGENTS.md",))
    monkeypatch.setattr(projection, "ADAPTER_TREE_ROOTS", ("skills",))
    monkeypatch.setattr(projection, "BACKEND_POLICY", "backend.json")
    original = projection._release_roster

    def release(root_fd: int):
        # The production function's closure path is fixed authority.  This
        # fixture substitutes the same exact schema at a smaller path.
        raw, _ = projection._read_file(root_fd, "closure.json")
        value = projection._strict_json(raw, "fixture closure")
        runtime = {path: "runtime-fixed" for path in projection.RUNTIME_FIXED}
        for row in value["assets"]:
            runtime[row["path"]] = "runtime-closure-asset"
        for path in projection.NATIVE_REQUIRED:
            runtime[path] = "native-runtime-required"
        adapter = {"codex-adapter/AGENTS.md": "codex-adapter-fixed"}
        for path in projection._walk_files(root_fd, "codex-adapter/skills"):
            adapter[path] = "codex-adapter-tree"
        policy = {
            "adapter_fixed": ["AGENTS.md"], "adapter_tree_roots": ["skills"],
            "closure_authority_complete": True, "closure_mismatch_paths": [],
            "method_tree_roots": [], "native_required": ["worker.py"],
            "rule_projection": {}, "runtime_fixed": ["closure.json", "backend.json"],
            "schema": projection.POLICY_SCHEMA,
            "selection": "governed-runtime-closure-and-rule-projection-v1",
        }
        roster = {path: (role, projection.RUNTIME_ROOT, path) for path, role in runtime.items()}
        roster.update({
            path: (role, projection.ADAPTER_ROOT, path[len("codex-adapter/"):])
            for path, role in adapter.items()
        })
        return policy, roster

    assert original is not None
    monkeypatch.setattr(projection, "_release_roster", release)


def _open(path: Path) -> int:
    return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)


def test_managed_evm_driver_cutover_is_explicit_native_runtime_input() -> None:
    required = {
        "scripts/native_managed_evm_driver_preflight.py",
        "scripts/native_managed_evm_setup_effects.py",
        "scripts/posix_managed_evm_setup_transaction.py",
    }
    assert required <= set(projection.NATIVE_REQUIRED)


def test_candidate_is_exact_but_not_production_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _fixture(monkeypatch, source)
    source_fd = _open(source)
    try:
        raw = projection.generate_candidate(source_fd, source_commit=COMMIT)
        value = projection.validate_manifest(raw, source_fd, require_frozen=False)
        assert value["state"] == "CANDIDATE"
        assert value["counts"] == {"adapter": 2, "runtime": 4, "total": 6}
        with pytest.raises(projection.ProjectionError, match="not frozen"):
            projection.validate_manifest(raw, source_fd)
    finally:
        os.close(source_fd)


def test_frozen_manifest_detects_byte_and_policy_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _fixture(monkeypatch, source)
    source_fd = _open(source)
    try:
        candidate = projection.generate_candidate(source_fd, source_commit=COMMIT)
        frozen = projection.freeze_candidate(candidate, source_fd)
        digest = hashlib.sha256(frozen).hexdigest()
        projection.validate_manifest(
            frozen, source_fd, expected_manifest_sha256=digest
        )
        _write(source / "asset.py", b"asset = 2\n")
        with pytest.raises(
            projection.ProjectionError,
            match="(?:roster_sha256|rows) differs",
        ):
            projection.validate_manifest(
                frozen, source_fd, expected_manifest_sha256=digest
            )
        value = json.loads(frozen)
        value["policy"]["selection"] = "different"
        tampered = projection.canonical_json(value)
        with pytest.raises(projection.ProjectionError, match="policy digest"):
            projection.validate_manifest(tampered, source_fd)
    finally:
        os.close(source_fd)


def test_materialization_is_exclusive_and_returns_recensus(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    runtime = tmp_path / "runtime"
    adapter = tmp_path / "adapter"
    source.mkdir(); runtime.mkdir(mode=0o700); adapter.mkdir(mode=0o700)
    _fixture(monkeypatch, source)
    source_fd = _open(source); runtime_fd = _open(runtime); adapter_fd = _open(adapter)
    try:
        candidate = projection.generate_candidate(source_fd, source_commit=COMMIT)
        frozen = projection.freeze_candidate(candidate, source_fd)
        digest = hashlib.sha256(frozen).hexdigest()
        receipt = projection.materialize_validated(
            frozen, source_fd, runtime_fd, adapter_fd,
            expected_manifest_sha256=digest,
        )
        assert receipt["count"] == 6
        assert receipt["total_bytes"] == sum(
            row["size"] for row in json.loads(frozen)["rows"]
        )
        assert (runtime / "worker.py").stat().st_mode & 0o777 == 0o400
        assert (adapter / "skills/plamen/SKILL.md").read_bytes() == b"skill\n"
        with pytest.raises(projection.ProjectionError, match="not empty"):
            projection.materialize_validated(
                frozen, source_fd, runtime_fd, adapter_fd,
                expected_manifest_sha256=digest,
            )
    finally:
        os.close(adapter_fd); os.close(runtime_fd); os.close(source_fd)


def test_descriptor_reader_rejects_links(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _fixture(monkeypatch, source)
    (source / "asset.py").unlink()
    (source / "asset.py").symlink_to("worker.py")
    source_fd = _open(source)
    try:
        with pytest.raises(projection.ProjectionError, match="opened safely"):
            projection.generate_candidate(source_fd, source_commit=COMMIT)
    finally:
        os.close(source_fd)
