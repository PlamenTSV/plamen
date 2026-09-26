from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import opengrep_rule_authority as authority


def _source_fixture(tmp_path: Path, monkeypatch) -> tuple[Path, dict[str, tuple[str, str]]]:
    sources = {
        "a-rules": ("https://github.com/example/a-rules.git", "a" * 40),
        "b-rules": ("https://github.com/example/b-rules.git", "b" * 40),
        "c-rules": ("https://github.com/example/c-rules.git", "c" * 40),
    }
    monkeypatch.setattr(authority, "OPENGREP_RULE_SOURCES", sources)
    monkeypatch.setattr(
        authority,
        "OPENGREP_RULE_REVISIONS",
        {name: revision for name, (_source, revision) in sources.items()},
    )
    base = tmp_path / "opengrep-rules"
    tracked: dict[str, tuple[str, ...]] = {}
    for index, name in enumerate(sorted(sources)):
        root = base / name
        (root / ".git").mkdir(parents=True)
        (root / "nested").mkdir()
        (root / "nested" / f"rule-{index}.yaml").write_text(
            f"rules:\n  - id: rule-{index}\n", encoding="utf-8"
        )
        (root / "LICENSE").write_text("fixture license\n", encoding="utf-8")
        tracked[name] = ("LICENSE", f"nested/rule-{index}.yaml")

    def fake_git(root: Path, *args: str) -> bytes:
        source, revision = sources[root.name]
        if args == ("rev-parse", "HEAD"):
            return (revision + "\n").encode("ascii")
        if args == ("config", "--get", "remote.origin.url"):
            return (source + "\n").encode("utf-8")
        if args == ("status", "--porcelain", "--untracked-files=all"):
            return b""
        if args == ("ls-files", "-z"):
            return ("\0".join(tracked[root.name]) + "\0").encode("utf-8")
        raise AssertionError(args)

    monkeypatch.setattr(authority, "_git", fake_git)
    return base, sources


def _publish_source_manifest(base: Path, monkeypatch) -> bytes:
    raw = authority.build_source_rule_authority(base)
    (base / authority.RULE_AUTHORITY_FILENAME).write_bytes(raw)
    monkeypatch.setattr(
        authority,
        "EXPECTED_RULE_AUTHORITY_SHA256",
        json.loads(raw)["authority_sha256"],
    )
    return raw


def _strip_source_git(base: Path, sources: dict[str, tuple[str, str]]) -> None:
    for name in sources:
        (base / name / ".git").rmdir()


def _select_fixture_projection(
    base: Path,
    sources: dict[str, tuple[str, str]],
    monkeypatch,
) -> None:
    projection = {name: ("nested",) for name in sources}
    expected = {}
    for name in sources:
        captured = authority._capture_rule_tree(
            base / name / "nested", source_checkout=False
        )
        expected[name] = {
            "nested": (
                captured["file_count"],
                captured["byte_count"],
                captured["content_sha256"],
                captured["tree_sha256"],
            )
        }
    monkeypatch.setattr(authority, "OPENGREP_RULE_PROJECTION", projection)
    monkeypatch.setattr(authority, "EXPECTED_RULE_PROJECTION", expected)


def test_source_build_is_deterministic_and_runtime_replay_needs_no_git(
    tmp_path: Path, monkeypatch
) -> None:
    base, sources = _source_fixture(tmp_path, monkeypatch)
    first = authority.build_source_rule_authority(base)
    second = authority.build_source_rule_authority(base)
    assert first == second
    assert b'"timestamp"' not in first
    assert str(tmp_path).encode() not in first
    manifest = json.loads(first)
    unsigned = dict(manifest)
    claimed = unsigned.pop("authority_sha256")
    assert claimed == hashlib.sha256(authority._canonical_json(unsigned)).hexdigest()
    assert {row["revision"] for row in manifest["trees"]} == {
        revision for _source, revision in sources.values()
    }

    _publish_source_manifest(base, monkeypatch)
    assert set(authority.validate_source_rule_authority(base)) == set(sources)
    _strip_source_git(base, sources)

    def forbid_subprocess(*_args, **_kwargs):
        raise AssertionError("runtime rule replay must not invoke Git or subprocesses")

    monkeypatch.setattr(authority.subprocess, "run", forbid_subprocess)
    assert set(authority.validate_installed_rule_authority(base)) == set(sources)


def test_projection_roster_is_release_pinned_and_installed_layout_is_exact(
    tmp_path: Path, monkeypatch
) -> None:
    base, sources = _source_fixture(tmp_path, monkeypatch)
    _publish_source_manifest(base, monkeypatch)
    _select_fixture_projection(base, sources, monkeypatch)

    census = authority.source_rule_projection_census(base)
    roster = tuple(row[0] for row in census)
    assert roster == (
        "a-rules/nested/rule-0.yaml",
        "b-rules/nested/rule-1.yaml",
        "c-rules/nested/rule-2.yaml",
        authority.RULE_AUTHORITY_FILENAME,
    )
    for relative, size, digest in census:
        raw = (base / relative).read_bytes()
        assert size == len(raw)
        assert digest == hashlib.sha256(raw).hexdigest()

    _strip_source_git(base, sources)
    for name in sources:
        (base / name / "LICENSE").unlink()
    assert set(authority.validate_installed_rule_authority(base)) == set(sources)
    assert authority.installed_rule_projection_roster(base) == roster

    (base / "a-rules" / "README.md").write_text("not projected\n")
    with pytest.raises(
        authority.OpenGrepRuleAuthorityError,
        match="matches neither admitted layout",
    ):
        authority.validate_installed_rule_authority(base)


def test_projection_rejects_selected_subtree_drift(
    tmp_path: Path, monkeypatch
) -> None:
    base, sources = _source_fixture(tmp_path, monkeypatch)
    _publish_source_manifest(base, monkeypatch)
    _select_fixture_projection(base, sources, monkeypatch)
    _strip_source_git(base, sources)
    for name in sources:
        (base / name / "LICENSE").unlink()
    (base / "b-rules" / "nested" / "rule-1.yaml").write_text(
        "rules: []\n", encoding="utf-8"
    )
    with pytest.raises(
        authority.OpenGrepRuleAuthorityError,
        match="projection content differs",
    ):
        authority.validate_installed_rule_authority(base)


@pytest.mark.parametrize("tamper", ["content", "extra", "missing", "git"])
def test_runtime_replay_fails_closed_on_exact_tree_tamper(
    tmp_path: Path, monkeypatch, tamper: str
) -> None:
    base, sources = _source_fixture(tmp_path, monkeypatch)
    _publish_source_manifest(base, monkeypatch)
    _strip_source_git(base, sources)
    target = base / "a-rules" / "nested" / "rule-0.yaml"
    if tamper == "content":
        target.write_text("rules: []\n", encoding="utf-8")
    elif tamper == "extra":
        (base / "a-rules" / "extra.yaml").write_text("rules: []\n", encoding="utf-8")
    elif tamper == "missing":
        target.unlink()
    else:
        (base / "a-rules" / ".git").write_text("forbidden\n", encoding="utf-8")
    with pytest.raises(authority.OpenGrepRuleAuthorityError):
        authority.validate_installed_rule_authority(base)


def test_runtime_rejects_resigned_manifest_that_changes_public_governance(
    tmp_path: Path, monkeypatch
) -> None:
    base, sources = _source_fixture(tmp_path, monkeypatch)
    raw = _publish_source_manifest(base, monkeypatch)
    _strip_source_git(base, sources)
    manifest = json.loads(raw)
    manifest["trees"][0]["source"] = "https://github.com/example/hostile.git"
    unsigned = dict(manifest)
    unsigned.pop("authority_sha256")
    manifest["authority_sha256"] = hashlib.sha256(
        authority._canonical_json(unsigned)
    ).hexdigest()
    (base / authority.RULE_AUTHORITY_FILENAME).write_bytes(
        authority._canonical_json(manifest)
    )
    with pytest.raises(
        authority.OpenGrepRuleAuthorityError,
        match="authority digest is invalid",
    ):
        authority.validate_installed_rule_authority(base)


def test_source_builder_rejects_dirty_or_wrong_upstream(
    tmp_path: Path, monkeypatch
) -> None:
    base, sources = _source_fixture(tmp_path, monkeypatch)
    clean_git = authority._git

    def dirty_git(root: Path, *args: str) -> bytes:
        if root.name == "a-rules" and args == (
            "status", "--porcelain", "--untracked-files=all"
        ):
            return b" M nested/rule-0.yaml\n"
        return clean_git(root, *args)

    monkeypatch.setattr(authority, "_git", dirty_git)
    with pytest.raises(authority.OpenGrepRuleAuthorityError, match="dirty"):
        authority.build_source_rule_authority(base)

    def wrong_origin(root: Path, *args: str) -> bytes:
        if root.name == "a-rules" and args == (
            "config", "--get", "remote.origin.url"
        ):
            return b"https://github.com/example/hostile.git\n"
        return clean_git(root, *args)

    monkeypatch.setattr(authority, "_git", wrong_origin)
    with pytest.raises(authority.OpenGrepRuleAuthorityError, match="upstream"):
        authority.build_source_rule_authority(base)
