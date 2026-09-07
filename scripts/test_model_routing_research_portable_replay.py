from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "scripts" / "replay_model_routing_research.py"
MANIFEST = ROOT / "docs" / "continuation" / "MODEL_ROUTING_PORTABLE_REPLAY.json"


def _load_tool():
    spec = importlib.util.spec_from_file_location("portable_model_routing_replay", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _copy_public_replay_projection(destination: Path) -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    corpus_path = ROOT / manifest["corpus_manifest_ref"]
    corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
    refs = {
        manifest["corpus_manifest_ref"],
        MANIFEST.relative_to(ROOT).as_posix(),
        TOOL.relative_to(ROOT).as_posix(),
    }
    refs.update(
        row["publication"]["portable_path"]
        for row in corpus["source_inventory"]
        if row["publication"].get("portable_path") is not None
    )
    for requirement in manifest["requirements"].values():
        refs.update(requirement["public_evidence_refs"])
    for validator in manifest["validators"]:
        refs.add(validator["validator_ref"])
        refs.update(validator["package_refs"])
    for relative in refs:
        source = ROOT / Path(*Path(relative).parts)
        target = destination / Path(*Path(relative).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    # Keep the full corpus registry because it is the hash authority, but copy no
    # omitted review_fixtures and no unsanitized aliases.
    assert corpus["source_inventory"]


def test_current_public_projection_is_one_exact_pass_and_eight_explicit_blocks() -> None:
    tool = _load_tool()
    report = tool.evaluate(ROOT)
    assert report["claim"] == "PUBLIC_SAFE_REPLAY_WITH_EXPLICIT_ARCHIVAL_BLOCKS"
    assert report["summary"] == {
        "validator_count": 9,
        "public_corpus_port_count": 127,
        "exact_archival_pass": 1,
        "exact_archival_fail": 0,
        "blocked_nonpublic_prerequisite": 8,
        "public_evidence_integrity": "PASS",
        "archival_complete": False,
    }
    assert report["results"][0]["id"] == "r2_3"
    assert report["results"][0]["status"] == "EXACT_ARCHIVAL_PASS"
    assert all(
        row["status"] == "BLOCKED_NONPUBLIC_PREREQUISITE"
        for row in report["results"][1:]
    )


def test_clean_public_projection_replays_without_private_fixture_tree(tmp_path: Path) -> None:
    checkout = tmp_path / "public-checkout"
    _copy_public_replay_projection(checkout)
    projected_tool = checkout / TOOL.relative_to(ROOT)
    assert projected_tool.is_file()
    assert not (checkout / "review_fixtures").exists()
    assert not any(
        path.name.endswith("independent_review_r1_20260730.md")
        for path in checkout.rglob("*")
    )
    completed = subprocess.run(
        [
            sys.executable,
            str(projected_tool),
            "--root",
            str(checkout),
            "--accept-declared-blocks",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert completed.returncode == 0, completed.stderr + completed.stdout
    report = json.loads(completed.stdout)
    assert report["summary"]["exact_archival_pass"] == 1
    assert report["summary"]["public_corpus_port_count"] == 127
    assert report["summary"]["blocked_nonpublic_prerequisite"] == 8
    assert report["summary"]["archival_complete"] is False


def test_replay_handoff_assets_are_git_tracked() -> None:
    if not (ROOT / ".git").exists():
        pytest.skip("exported source tree has no Git index")
    required = [
        MANIFEST.relative_to(ROOT).as_posix(),
        TOOL.relative_to(ROOT).as_posix(),
        Path(__file__).resolve().relative_to(ROOT).as_posix(),
    ]
    completed = subprocess.run(
        ["git", "ls-files", "--error-unmatch", "--", *required],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    staged = {}
    for entry in subprocess.check_output(
        ["git", "ls-files", "--stage", "-z", "--", *required], cwd=ROOT,
    ).split(b"\0"):
        if not entry:
            continue
        metadata, relative = entry.split(b"\t", 1)
        staged[relative.decode("utf-8")] = metadata.split()[1].decode("ascii")
    for relative in required:
        raw = (ROOT / relative).read_bytes()
        blob = hashlib.sha1(
            b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw,
        ).hexdigest()
        assert staged[relative] == blob


def test_unrelated_public_port_size_drift_fails_full_corpus_replay(tmp_path: Path) -> None:
    checkout = tmp_path / "public-checkout"
    _copy_public_replay_projection(checkout)
    corpus_path = checkout / "docs" / "continuation" / "CORPUS_MANIFEST.json"
    corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
    row = next(
        item for item in corpus["source_inventory"]
        if item["family"] != "backend_routing"
        and item["publication"].get("portable_path") is not None
    )
    row["publication"]["portable_bytes"] += 1
    corpus_path.write_text(json.dumps(corpus), encoding="utf-8")

    tool = _load_tool()
    with pytest.raises(tool.ReplayIntegrityError, match="PUBLIC_REF_SIZE_INVALID|PUBLIC_REF_PORT_ALIAS_MISMATCH"):
        tool.evaluate(checkout)


def test_validator_publication_cannot_be_reclassified_as_sanitized(tmp_path: Path) -> None:
    checkout = tmp_path / "public-checkout"
    _copy_public_replay_projection(checkout)
    corpus_path = checkout / "docs" / "continuation" / "CORPUS_MANIFEST.json"
    corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
    row = next(
        item for item in corpus["source_inventory"]
        if item["source_identity"] == "validate_plamen_model_routing_r2_3.py"
    )
    row["publication"]["mode"] = "SANITIZED"
    row["publication"]["transformation"] = "sanitized"
    corpus_path.write_text(json.dumps(corpus), encoding="utf-8")

    tool = _load_tool()
    with pytest.raises(tool.ReplayIntegrityError, match="VALIDATOR_NOT_EXACT"):
        tool.evaluate(checkout)


def test_validator_dependency_graph_is_bound_to_archived_source(tmp_path: Path) -> None:
    checkout = tmp_path / "public-checkout"
    _copy_public_replay_projection(checkout)
    manifest_path = checkout / MANIFEST.relative_to(ROOT)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    row = next(item for item in manifest["validators"] if item["id"] == "r2_4")
    row["predecessor_ids"] = []
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    tool = _load_tool()
    with pytest.raises(tool.ReplayIntegrityError, match="VALIDATOR_PREDECESSOR_BINDING_MISMATCH"):
        tool.evaluate(checkout)


def test_nonpublic_requirement_hash_is_bound_to_archived_validator(tmp_path: Path) -> None:
    checkout = tmp_path / "public-checkout"
    _copy_public_replay_projection(checkout)
    manifest_path = checkout / MANIFEST.relative_to(ROOT)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["requirements"]["review_r2_4"]["expected_raw_sha256"] = "f" * 64
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    tool = _load_tool()
    with pytest.raises(tool.ReplayIntegrityError, match="VALIDATOR_REQUIREMENT_BINDING_MISMATCH"):
        tool.evaluate(checkout)


def test_validator_failure_output_does_not_expose_machine_paths(monkeypatch) -> None:
    tool = _load_tool()
    private_path = str(Path.home() / "private-runtime" / "secret.txt")

    def failed_validator(*_args, **_kwargs):
        return subprocess.CompletedProcess(
            [], 9, stdout=f"failed at {private_path}\n", stderr=f"trace {private_path}\n",
        )

    monkeypatch.setattr(tool.subprocess, "run", failed_validator)
    report = tool.evaluate(ROOT)
    encoded = json.dumps(report)
    assert private_path not in encoded
    failure = report["results"][0]
    assert failure["status"] == "EXACT_ARCHIVAL_FAIL"
    assert "stderr" not in failure
    assert failure["stderr_line_count"] == 1


def test_default_cli_is_nonzero_while_archival_replay_is_incomplete() -> None:
    completed = subprocess.run(
        [sys.executable, str(TOOL), "--root", str(ROOT)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert completed.returncode == 2
    report = json.loads(completed.stdout)
    assert report["summary"]["archival_complete"] is False
