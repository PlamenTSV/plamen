from __future__ import annotations

from dataclasses import FrozenInstanceError
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import copy
import hashlib
import json
import os
import pickle

import pytest

import program_facts_source_manifest as manifest_module
from audit_snapshot import build_audit_snapshot
from program_facts_source_manifest import (
    ParsedProgramFactsSourceManifest,
    ProgramFactsSourceManifestError,
    build_program_facts_source_manifest,
    parse_program_facts_source_manifest_shape,
    replay_program_facts_source_manifest,
)
from program_facts_types import canonical_file_bytes


def _implementation_tree(root: Path) -> Path:
    for directory in ("scripts", "prompts", "rules", "agents"):
        (root / directory).mkdir(parents=True, exist_ok=True)
    (root / "scripts" / "plamen_driver.py").write_text(
        "VERSION = 1\n", encoding="utf-8"
    )
    (root / "prompts" / "phase.md").write_text(
        "method v1\n", encoding="utf-8"
    )
    (root / "rules" / "rule.md").write_text("rule v1\n", encoding="utf-8")
    return root


def _fixture(tmp_path: Path, *, language: str = "evm", pipeline: str = "sc"):
    project = tmp_path / "project"
    source = project / "src" / "Vault.sol"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"contract Vault {\r\n    uint256 x;\n}\n")
    if language == "evm":
        (project / "foundry.toml").write_text(
            "[profile.default]\n", encoding="utf-8"
        )
    config = {
        "project_root": str(project),
        "scratchpad": str(project / ".scratchpad"),
        "mode": "thorough",
        "pipeline": pipeline,
        "language": language,
        "cli_backend": "codex",
        "scope_notes": "production contracts",
    }
    snapshot = build_audit_snapshot(
        config, _implementation_tree(tmp_path / "plamen")
    )
    return project, source, config, snapshot


def _record(authority) -> dict[str, object]:
    return json.loads(authority.canonical_bytes)


def _resign(record: dict[str, object]) -> bytes:
    unsigned = dict(record)
    unsigned.pop("authority_digest", None)
    record["authority_digest"] = hashlib.sha256(
        manifest_module.canonical_json_bytes(unsigned)
    ).hexdigest()
    return canonical_file_bytes(record)


def test_fixture_build_is_deterministic_portable_and_replayable(tmp_path):
    project, source, config, snapshot = _fixture(tmp_path)

    first = build_program_facts_source_manifest(
        config, snapshot, compiled_source_paths=["src/Vault.sol"]
    )
    second = build_program_facts_source_manifest(
        config, snapshot, compiled_source_paths=["src/Vault.sol"]
    )

    assert first.canonical_bytes == second.canonical_bytes
    assert first.authority_digest == second.authority_digest
    assert first.file_sha256 == hashlib.sha256(first.canonical_bytes).hexdigest()
    assert first.canonical_bytes.endswith(b"\n")
    assert not first.canonical_bytes.startswith(b"\xef\xbb\xbf")
    assert str(project).encode() not in first.canonical_bytes
    assert b'"timestamp"' not in first.canonical_bytes
    assert b'"pid"' not in first.canonical_bytes

    record = _record(first)
    assert (
        first.manifest_digest
        == record["source_manifest"]["manifest_digest"]
    )
    assert record["schema_version"] == (
        "plamen.program-facts-source-manifest-authority.v1"
    )
    row = record["source_manifest"]["eligible_files"][0]
    raw = source.read_bytes()
    assert row["path"] == "src/Vault.sol"
    assert row["path_casefold_key"] == "src/vault.sol"
    assert row["source_sha256"] == hashlib.sha256(raw).hexdigest()
    assert row["size_bytes"] == len(raw)
    assert row["language"] == "solidity"
    assert row["scope_class"] == "PRODUCTION"
    assert record["line_replay_inputs"] == [
        {
            "source_file_id": row["source_file_id"],
            "line_start_byte_offsets": [0, 18, 33, 35],
        }
    ]
    assert record["tree_identity"]["stable"] is True
    assert (
        record["tree_identity"]["pre_digest"]
        == record["tree_identity"]["post_digest"]
    )
    assert record["compiled_denominator"]["status"] == "UNKNOWN"
    assert record["compiled_denominator"]["compiled_source_file_ids"] == []
    assert {row["code"] for row in record["debts"]} == {
        "COMPILED_DENOMINATOR_UNTRUSTED"
    }

    parsed = parse_program_facts_source_manifest_shape(first.canonical_bytes)
    assert parsed.parent_authority_established is False
    replayed = replay_program_facts_source_manifest(
        parsed,
        expected_snapshot_digest=snapshot["snapshot_digest"],
        expected_source_scope_digest=snapshot["components"]["source_scope"][
            "digest"
        ],
        source_bytes_by_id=first.source_bytes_by_id,
        excluded_source_bytes_by_identity=(
            first.excluded_source_bytes_by_identity
        ),
        capture_capability=first.capture_capability,
    )
    assert replayed.parent_authority_established is True
    replayed_from_tree = replay_program_facts_source_manifest(
        parsed,
        expected_snapshot_digest=snapshot["snapshot_digest"],
        expected_source_scope_digest=snapshot["components"]["source_scope"][
            "digest"
        ],
        project_root=project,
        config=config,
    )
    assert replayed_from_tree.parent_authority_established is True


def test_mapping_replay_cannot_self_establish_parent_authority(tmp_path):
    _project, _source, config, snapshot = _fixture(tmp_path)
    authority = build_program_facts_source_manifest(config, snapshot)
    parsed = parse_program_facts_source_manifest_shape(
        authority.canonical_bytes
    )

    with pytest.raises(
        ProgramFactsSourceManifestError,
        match="capture capability|project.tree",
    ):
        replay_program_facts_source_manifest(
            parsed,
            expected_snapshot_digest=snapshot["snapshot_digest"],
            expected_source_scope_digest=snapshot["components"][
                "source_scope"
            ]["digest"],
            source_bytes_by_id=authority.source_bytes_by_id,
        )

    with pytest.raises(TypeError):
        ParsedProgramFactsSourceManifest(
            record=parsed.record,
            canonical_bytes=parsed.canonical_bytes,
            authority_digest=parsed.authority_digest,
            file_sha256=parsed.file_sha256,
            parent_authority_established=True,
        )


def test_one_shot_builder_capture_capability_cannot_be_replayed_twice(tmp_path):
    _project, _source, config, snapshot = _fixture(tmp_path)
    authority = build_program_facts_source_manifest(config, snapshot)

    replayed = replay_program_facts_source_manifest(
        authority.canonical_bytes,
        expected_snapshot_digest=snapshot["snapshot_digest"],
        expected_source_scope_digest=snapshot["components"]["source_scope"][
            "digest"
        ],
        source_bytes_by_id=authority.source_bytes_by_id,
        excluded_source_bytes_by_identity=(
            authority.excluded_source_bytes_by_identity
        ),
        capture_capability=authority.capture_capability,
    )
    assert replayed.parent_authority_established is True

    with pytest.raises(
        ProgramFactsSourceManifestError, match="consumed|one-shot"
    ):
        replay_program_facts_source_manifest(
            authority.canonical_bytes,
            expected_snapshot_digest=snapshot["snapshot_digest"],
            expected_source_scope_digest=snapshot["components"][
                "source_scope"
            ]["digest"],
            source_bytes_by_id=authority.source_bytes_by_id,
            excluded_source_bytes_by_identity=(
                authority.excluded_source_bytes_by_identity
            ),
            capture_capability=authority.capture_capability,
        )


def test_one_shot_capture_capability_has_exactly_one_concurrent_winner(
    tmp_path,
):
    _project, _source, config, snapshot = _fixture(tmp_path)
    authority = build_program_facts_source_manifest(config, snapshot)

    def attempt(_index):
        try:
            replay_program_facts_source_manifest(
                authority.canonical_bytes,
                expected_snapshot_digest=snapshot["snapshot_digest"],
                expected_source_scope_digest=snapshot["components"][
                    "source_scope"
                ]["digest"],
                source_bytes_by_id=authority.source_bytes_by_id,
                excluded_source_bytes_by_identity=(
                    authority.excluded_source_bytes_by_identity
                ),
                capture_capability=authority.capture_capability,
            )
            return "ESTABLISHED"
        except ProgramFactsSourceManifestError as exc:
            assert "consumed" in str(exc)
            return "REJECTED"

    with ThreadPoolExecutor(max_workers=16) as pool:
        outcomes = list(pool.map(attempt, range(32)))
    assert outcomes.count("ESTABLISHED") == 1
    assert outcomes.count("REJECTED") == 31


def test_capture_capability_is_not_copyable_serializable_or_transferable(
    tmp_path,
    monkeypatch,
):
    _project, _source, config, snapshot = _fixture(tmp_path)
    authority = build_program_facts_source_manifest(config, snapshot)
    capability = authority.capture_capability

    with pytest.raises(TypeError, match="cannot be copied"):
        copy.copy(capability)
    with pytest.raises(TypeError, match="cannot be copied"):
        copy.deepcopy(capability)
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(capability)
    with pytest.raises(TypeError, match="immutable"):
        capability._consumed = False
    real_pid = os.getpid()
    with monkeypatch.context() as isolated:
        isolated.setattr(
            manifest_module.os, "getpid", lambda: real_pid + 1
        )
        with pytest.raises(
            ProgramFactsSourceManifestError,
            match="process-bound|fork|transfer",
        ):
            replay_program_facts_source_manifest(
                authority.canonical_bytes,
                expected_snapshot_digest=snapshot["snapshot_digest"],
                expected_source_scope_digest=snapshot["components"][
                    "source_scope"
                ]["digest"],
                source_bytes_by_id=authority.source_bytes_by_id,
                excluded_source_bytes_by_identity=(
                    authority.excluded_source_bytes_by_identity
                ),
                capture_capability=capability,
            )


def test_tree_replay_rejects_added_source_outside_frozen_denominator(tmp_path):
    project, _source, config, snapshot = _fixture(tmp_path)
    authority = build_program_facts_source_manifest(config, snapshot)
    parsed = parse_program_facts_source_manifest_shape(
        authority.canonical_bytes
    )
    added = project / "src" / "Added.sol"
    added.write_text(
        "pragma solidity ^0.8.0;\ncontract Added {}\n",
        encoding="utf-8",
    )

    with pytest.raises(
        ProgramFactsSourceManifestError,
        match="denominator|selection|tree",
    ):
        replay_program_facts_source_manifest(
            parsed,
            expected_snapshot_digest=snapshot["snapshot_digest"],
            expected_source_scope_digest=snapshot["components"][
                "source_scope"
            ]["digest"],
            project_root=project,
            config=config,
        )


def test_tree_replay_requires_shared_selector_config(tmp_path):
    project, _source, config, snapshot = _fixture(tmp_path)
    authority = build_program_facts_source_manifest(config, snapshot)

    with pytest.raises(
        ProgramFactsSourceManifestError,
        match="config",
    ):
        replay_program_facts_source_manifest(
            authority.canonical_bytes,
            expected_snapshot_digest=snapshot["snapshot_digest"],
            expected_source_scope_digest=snapshot["components"][
                "source_scope"
            ]["digest"],
            project_root=project,
        )


def test_shape_parser_is_immutable_and_not_parent_authority(tmp_path):
    _project, _source, config, snapshot = _fixture(tmp_path)
    authority = build_program_facts_source_manifest(config, snapshot)
    parsed = parse_program_facts_source_manifest_shape(authority.canonical_bytes)

    with pytest.raises(TypeError):
        parsed.record["schema_version"] = "tampered"
    with pytest.raises(FrozenInstanceError):
        parsed.parent_authority_established = True
    assert parsed.parent_authority_established is False
    assert parsed.canonical_bytes == authority.canonical_bytes


def test_parent_replay_rejects_wrong_snapshot_or_scope(tmp_path):
    _project, _source, config, snapshot = _fixture(tmp_path)
    authority = build_program_facts_source_manifest(config, snapshot)

    with pytest.raises(ProgramFactsSourceManifestError, match="snapshot"):
        replay_program_facts_source_manifest(
            authority.canonical_bytes,
            expected_snapshot_digest="f" * 64,
            expected_source_scope_digest=snapshot["components"]["source_scope"][
                "digest"
            ],
            source_bytes_by_id=authority.source_bytes_by_id,
        )
    with pytest.raises(ProgramFactsSourceManifestError, match="source scope"):
        replay_program_facts_source_manifest(
            authority.canonical_bytes,
            expected_snapshot_digest=snapshot["snapshot_digest"],
            expected_source_scope_digest="e" * 64,
            source_bytes_by_id=authority.source_bytes_by_id,
        )


def test_builder_rejects_tampered_snapshot_and_config_parent_mismatch(tmp_path):
    _project, _source, config, snapshot = _fixture(tmp_path)
    tampered = json.loads(json.dumps(snapshot))
    tampered["components"]["source_scope"]["digest"] = "f" * 64

    with pytest.raises(
        ProgramFactsSourceManifestError, match="intact canonical snapshot"
    ):
        build_program_facts_source_manifest(config, tampered)

    wrong_config = dict(config)
    wrong_config["language"] = "solana"
    with pytest.raises(ProgramFactsSourceManifestError, match="language"):
        build_program_facts_source_manifest(wrong_config, snapshot)


def test_parent_replay_rejects_selector_identity_drift(tmp_path):
    _project, _source, config, snapshot = _fixture(tmp_path)
    authority = build_program_facts_source_manifest(config, snapshot)
    record = _record(authority)
    record["selection_policy"]["selector_bridge_digest"] = "f" * 64
    policy = record["selection_policy"]
    policy["policy_digest"] = hashlib.sha256(
        manifest_module.canonical_json_bytes(
            {
                key: value
                for key, value in policy.items()
                if key != "policy_digest"
            }
        )
    ).hexdigest()
    raw = _resign(record)

    with pytest.raises(
        ProgramFactsSourceManifestError, match="selector identity mismatch"
    ):
        replay_program_facts_source_manifest(
            raw,
            expected_snapshot_digest=snapshot["snapshot_digest"],
            expected_source_scope_digest=snapshot["components"][
                "source_scope"
            ]["digest"],
            source_bytes_by_id=authority.source_bytes_by_id,
        )


def test_selector_authority_binds_every_file_selection_input(tmp_path):
    project, _source, config, snapshot = _fixture(tmp_path)
    scope_file = project / "scope-a.txt"
    scope_file.write_text("src/Vault.sol\n", encoding="utf-8")
    build_source = project / "src" / "Vault.sol"
    dependency_root = project / "lib"
    dependency_root.mkdir()
    bound_config = {
        **config,
        "scope_file": str(scope_file),
        "scope_match_mode": "legacy",
        "allow_external_scope_targets": False,
        "_resolved_build_root": str(project),
        "_resolved_build_source_files": [str(build_source)],
        "_resolved_compiled_dependency_roots": [str(dependency_root)],
    }
    bound_snapshot = build_audit_snapshot(
        bound_config, _implementation_tree(tmp_path / "plamen")
    )

    record = _record(
        build_program_facts_source_manifest(bound_config, bound_snapshot)
    )
    selector = record["selector_authority"]

    assert selector["pipeline"] == "sc"
    assert selector["ecosystem"] == "evm"
    assert selector["scope_match_mode"] == "legacy"
    assert selector["scope_file_input"] == "scope-a.txt"
    assert selector["allow_external_scope_targets"] is False
    assert selector["build_root_input"] == "."
    assert selector["build_source_inputs"] == ["src/Vault.sol"]
    assert selector["dependency_root_inputs"] == ["lib"]
    assert selector["project_root_input_digest"] == hashlib.sha256(
        str(project).encode("utf-8")
    ).hexdigest()
    assert selector["project_root_identity_digest"]
    assert selector["source_config_inputs"] == [
        {
            "identity": "foundry.toml",
            "source_sha256": hashlib.sha256(
                (project / "foundry.toml").read_bytes()
            ).hexdigest(),
        },
        {
            "identity": "scope-a.txt",
            "source_sha256": hashlib.sha256(
                scope_file.read_bytes()
            ).hexdigest(),
        },
    ]
    assert selector["selector_inputs_digest"] == hashlib.sha256(
        manifest_module.canonical_json_bytes(
            {
                key: value
                for key, value in selector.items()
                if key != "selector_inputs_digest"
            }
        )
    ).hexdigest()


def test_tree_replay_rejects_scope_config_drift_with_same_selected_bytes(
    tmp_path,
):
    project, _source, config, _snapshot = _fixture(tmp_path)
    scope_a = project / "scope-a.txt"
    scope_b = project / "scope-b.txt"
    scope_a.write_text("src/Vault.sol\n", encoding="utf-8")
    scope_b.write_text("src/Vault.sol\n", encoding="utf-8")
    config_a = {**config, "scope_file": str(scope_a)}
    config_b = {**config, "scope_file": str(scope_b)}
    snapshot_a = build_audit_snapshot(
        config_a, _implementation_tree(tmp_path / "plamen")
    )
    authority = build_program_facts_source_manifest(config_a, snapshot_a)

    with pytest.raises(
        ProgramFactsSourceManifestError,
        match="selector input|selector authority|config",
    ):
        replay_program_facts_source_manifest(
            authority.canonical_bytes,
            expected_snapshot_digest=snapshot_a["snapshot_digest"],
            expected_source_scope_digest=snapshot_a["components"][
                "source_scope"
            ]["digest"],
            project_root=project,
            config=config_b,
        )


def test_tree_replay_rejects_every_bound_selector_dimension_drift(tmp_path):
    project, source, config, _snapshot = _fixture(tmp_path)
    scope_a = project / "scope-a.txt"
    scope_b = project / "scope-b.txt"
    scope_a.write_text("src/Vault.sol\n", encoding="utf-8")
    scope_b.write_text("src/Vault.sol\n", encoding="utf-8")
    dependency = project / "lib"
    dependency.mkdir()
    base = {
        **config,
        "scope_file": str(scope_a),
        "scope_match_mode": "legacy",
        "allow_external_scope_targets": False,
        "_resolved_build_root": str(project),
        "_resolved_build_source_files": [],
        "_resolved_compiled_dependency_roots": [str(dependency)],
    }
    snapshot = build_audit_snapshot(
        base, _implementation_tree(tmp_path / "plamen")
    )
    authority = build_program_facts_source_manifest(base, snapshot)
    variants = [
        {**base, "pipeline": "l1"},
        {**base, "language": "solana"},
        {**base, "scope_match_mode": "exact"},
        {**base, "scope_file": str(scope_b)},
        {**base, "allow_external_scope_targets": True},
        {
            key: value
            for key, value in base.items()
            if key != "_resolved_build_root"
        },
        {**base, "_resolved_build_source_files": [str(source)]},
        {**base, "_resolved_compiled_dependency_roots": []},
    ]

    for drifted in variants:
        with pytest.raises(
            ProgramFactsSourceManifestError,
            match="selector authority|config input",
        ):
            replay_program_facts_source_manifest(
                authority.canonical_bytes,
                expected_snapshot_digest=snapshot["snapshot_digest"],
                expected_source_scope_digest=snapshot["components"][
                    "source_scope"
                ]["digest"],
                project_root=project,
                config=drifted,
            )

    foundry = project / "foundry.toml"
    foundry.write_text(
        "[profile.default]\nlibs = []\n", encoding="utf-8"
    )
    with pytest.raises(
        ProgramFactsSourceManifestError,
        match="selector authority|config input",
    ):
        replay_program_facts_source_manifest(
            authority.canonical_bytes,
            expected_snapshot_digest=snapshot["snapshot_digest"],
            expected_source_scope_digest=snapshot["components"][
                "source_scope"
            ]["digest"],
            project_root=project,
            config=base,
        )


def test_shape_parser_rejects_noncanonical_tampered_and_open_records(tmp_path):
    _project, _source, config, snapshot = _fixture(tmp_path)
    authority = build_program_facts_source_manifest(config, snapshot)
    record = _record(authority)

    with pytest.raises(ProgramFactsSourceManifestError, match="canonical"):
        parse_program_facts_source_manifest_shape(
            json.dumps(record, indent=2).encode("utf-8")
        )

    record["authority_digest"] = "f" * 64
    with pytest.raises(ProgramFactsSourceManifestError, match="digest"):
        parse_program_facts_source_manifest_shape(canonical_file_bytes(record))

    record = _record(authority)
    record["host_path"] = r"C:\secret\project"
    with pytest.raises(ProgramFactsSourceManifestError, match="unexpected"):
        parse_program_facts_source_manifest_shape(_resign(record))


def test_portable_parser_rejects_casefold_collision(tmp_path):
    _project, _source, config, snapshot = _fixture(tmp_path)
    authority = build_program_facts_source_manifest(config, snapshot)
    record = _record(authority)
    first = record["source_manifest"]["eligible_files"][0]
    duplicate = dict(first)
    duplicate["path"] = "src/vault.sol"
    duplicate["source_file_id"] = manifest_module.derive_stable_id(
        "PFS",
        {
            "source_scope_digest": snapshot["components"]["source_scope"][
                "digest"
            ],
            "path": duplicate["path"],
            "source_sha256": duplicate["source_sha256"],
            "scope_class": duplicate["scope_class"],
        },
    )
    record["source_manifest"]["eligible_files"].append(duplicate)
    record["source_manifest"]["eligible_files"].sort(
        key=lambda row: row["source_file_id"]
    )
    record["source_manifest"]["file_count"] = 2
    record["source_manifest"]["byte_count"] *= 2
    record["source_manifest"]["manifest_digest"] = (
        manifest_module.derive_source_manifest_digest(record["source_manifest"])
    )
    replay = dict(record["line_replay_inputs"][0])
    replay["source_file_id"] = duplicate["source_file_id"]
    record["line_replay_inputs"].append(replay)
    record["line_replay_inputs"].sort(key=lambda row: row["source_file_id"])
    compiled = record["compiled_denominator"]
    compiled["eligible_source_file_ids"].append(duplicate["source_file_id"])
    compiled["eligible_source_file_ids"].sort()
    compiled["uncompiled_source_file_ids"].append(duplicate["source_file_id"])
    compiled["uncompiled_source_file_ids"].sort()
    compiled["status"] = "PARTIAL"
    compiled["denominator_digest"] = manifest_module.digest_compiled_denominator(
        compiled
    )

    with pytest.raises(ProgramFactsSourceManifestError, match="case-fold"):
        parse_program_facts_source_manifest_shape(_resign(record))


def test_compiled_denominator_smaller_and_larger_are_explicit_debt(tmp_path):
    project, _source, config, snapshot = _fixture(tmp_path)
    other = project / "src" / "Other.sol"
    other.write_bytes(b"contract Other {}\n")
    snapshot = build_audit_snapshot(
        config, _implementation_tree(tmp_path / "plamen")
    )

    smaller = build_program_facts_source_manifest(
        config, snapshot, compiled_source_paths=["src/Vault.sol"]
    )
    smaller_record = _record(smaller)
    assert smaller_record["compiled_denominator"]["status"] == "UNKNOWN"
    assert len(
        smaller_record["compiled_denominator"]["uncompiled_source_file_ids"]
    ) == 2
    assert "COMPILED_DENOMINATOR_UNTRUSTED" in {
        row["code"] for row in smaller_record["debts"]
    }

    larger = build_program_facts_source_manifest(
        config,
        snapshot,
        compiled_source_paths=["src/Vault.sol", "src/Missing.sol"],
    )
    larger_record = _record(larger)
    assert larger_record["compiled_denominator"]["status"] == "UNKNOWN"
    assert larger_record["compiled_denominator"]["unexpected_compiled_paths"] == [
        "src/Missing.sol"
    ]
    assert "COMPILED_SOURCE_OUTSIDE_ELIGIBLE_DENOMINATOR" in {
        row["code"] for row in larger_record["debts"]
    }
    assert "COMPILED_DENOMINATOR_UNTRUSTED" in {
        row["code"] for row in larger_record["debts"]
    }


def test_compiled_denominator_rejects_casefold_aliases(tmp_path):
    _project, _source, config, snapshot = _fixture(tmp_path)

    with pytest.raises(ProgramFactsSourceManifestError, match="case-fold"):
        build_program_facts_source_manifest(
            config,
            snapshot,
            compiled_source_paths=["src/Vault.sol", "src/vault.sol"],
        )


def test_missing_compiled_denominator_is_unknown_not_implicitly_full(tmp_path):
    _project, _source, config, snapshot = _fixture(tmp_path)
    record = _record(build_program_facts_source_manifest(config, snapshot))

    assert record["compiled_denominator"]["status"] == "UNKNOWN"
    assert record["compiled_denominator"]["compiled_source_file_ids"] == []
    assert {row["code"] for row in record["debts"]} == {
        "COMPILED_DENOMINATOR_UNAVAILABLE"
    }


def test_unknown_ecosystem_is_included_with_typed_unsupported_debt(tmp_path):
    _project, _source, config, snapshot = _fixture(
        tmp_path, language="unknown-chain"
    )
    record = _record(
        build_program_facts_source_manifest(
            config, snapshot, compiled_source_paths=["src/Vault.sol"]
        )
    )

    assert len(record["source_manifest"]["eligible_files"]) == 1
    assert record["compiled_denominator"]["status"] == "UNSUPPORTED"
    assert "UNSUPPORTED_ECOSYSTEM" in {
        row["code"] for row in record["debts"]
    }


def test_generated_source_is_excluded_unless_build_bound(tmp_path):
    project, _source, config, _snapshot = _fixture(tmp_path)
    generated = project / "src" / "Vault.t.sol"
    generated.write_bytes(b"contract GeneratedBound {}\n")
    helper = project / "tests" / "Helper.sol"
    helper.parent.mkdir()
    helper.write_bytes(b"contract Helper {}\n")
    snapshot = build_audit_snapshot(
        config, _implementation_tree(tmp_path / "plamen")
    )
    ordinary_authority = build_program_facts_source_manifest(
        config, snapshot, compiled_source_paths=["src/Vault.sol"]
    )
    ordinary = _record(ordinary_authority)
    assert [
        row["path"] for row in ordinary["source_manifest"]["eligible_files"]
    ] == ["src/Vault.sol"]
    assert ordinary["source_manifest"]["excluded_files"] == [
        {
            "identity": "src/Vault.t.sol",
            "reason": "GENERATED_SOURCE_NOT_BOUND",
            "source_sha256": hashlib.sha256(
                generated.read_bytes()
            ).hexdigest(),
        },
        {
            "identity": "tests/Helper.sol",
            "reason": "NON_PRODUCTION_SOURCE",
            "source_sha256": hashlib.sha256(
                helper.read_bytes()
            ).hexdigest(),
        }
    ]
    replayed = replay_program_facts_source_manifest(
        ordinary_authority.canonical_bytes,
        expected_snapshot_digest=snapshot["snapshot_digest"],
        expected_source_scope_digest=snapshot["components"][
            "source_scope"
        ]["digest"],
        source_bytes_by_id=ordinary_authority.source_bytes_by_id,
        excluded_source_bytes_by_identity=(
            ordinary_authority.excluded_source_bytes_by_identity
        ),
        capture_capability=ordinary_authority.capture_capability,
    )
    assert replayed.parent_authority_established is True

    bound_config = {
        **config,
        "_resolved_build_source_files": [str(generated)],
    }
    bound_snapshot = build_audit_snapshot(
        bound_config, _implementation_tree(tmp_path / "plamen")
    )
    bound = _record(
        build_program_facts_source_manifest(
            bound_config,
            bound_snapshot,
            compiled_source_paths=["src/Vault.sol", "src/Vault.t.sol"],
        )
    )
    by_path = {
        row["path"]: row["scope_class"]
        for row in bound["source_manifest"]["eligible_files"]
    }
    assert by_path == {
        "src/Vault.sol": "PRODUCTION",
        "src/Vault.t.sol": "GENERATED_BOUND",
    }


def test_shared_context_inventory_makes_policy_exclusions_explicit(tmp_path):
    project, _source, config, _snapshot = _fixture(tmp_path)
    dependency = project / "lib" / "Dependency.sol"
    dependency.parent.mkdir()
    dependency.write_bytes(b"contract Dependency {}\n")
    other_ecosystem = project / "src" / "side.rs"
    other_ecosystem.write_bytes(b"pub fn side() {}\n")
    mock = project / "src" / "MockVault.sol"
    mock.write_bytes(b"contract MockVault {}\n")
    snapshot = build_audit_snapshot(
        config, _implementation_tree(tmp_path / "plamen")
    )

    record = _record(
        build_program_facts_source_manifest(
            config, snapshot, compiled_source_paths=["src/Vault.sol"]
        )
    )
    reasons = {
        row["identity"]: row["reason"]
        for row in record["source_manifest"]["excluded_files"]
    }
    assert reasons == {
        "lib/Dependency.sol": "BOUND_DEPENDENCY_NOT_SELECTED",
        "src/MockVault.sol": "NON_PRODUCTION_SOURCE",
        "src/side.rs": "SOURCE_SUFFIX_OUTSIDE_ECOSYSTEM_POLICY",
    }


def test_selector_order_is_canonicalized(tmp_path, monkeypatch):
    project, _source, config, snapshot = _fixture(tmp_path)
    (project / "src" / "Alpha.sol").write_bytes(b"contract Alpha {}\n")
    snapshot = build_audit_snapshot(
        config, _implementation_tree(tmp_path / "plamen")
    )
    expected = build_program_facts_source_manifest(
        config,
        snapshot,
        compiled_source_paths=["src/Alpha.sol", "src/Vault.sol"],
    )
    original = manifest_module._shared_production_source_files

    def reverse(*args, **kwargs):
        return list(reversed(original(*args, **kwargs)))

    monkeypatch.setattr(
        manifest_module, "_shared_production_source_files", reverse
    )
    actual = build_program_facts_source_manifest(
        config,
        snapshot,
        compiled_source_paths=["src/Vault.sol", "src/Alpha.sol"],
    )
    assert actual.canonical_bytes == expected.canonical_bytes


def test_shared_selector_unavailable_has_no_fallback_walk(tmp_path, monkeypatch):
    _project, _source, config, snapshot = _fixture(tmp_path)

    def unavailable(*_args, **_kwargs):
        raise manifest_module.SharedSourceSelectionUnavailable(
            "snapshot selector unavailable"
        )

    monkeypatch.setattr(
        manifest_module, "_shared_production_source_files", unavailable
    )
    with pytest.raises(
        ProgramFactsSourceManifestError,
        match="shared source selection unavailable",
    ):
        build_program_facts_source_manifest(config, snapshot)


def test_bounded_reads_reject_file_and_total_limits(tmp_path):
    _project, source, config, snapshot = _fixture(tmp_path)

    with pytest.raises(ProgramFactsSourceManifestError, match="per-file"):
        build_program_facts_source_manifest(
            config, snapshot, max_file_bytes=source.stat().st_size - 1
        )
    with pytest.raises(ProgramFactsSourceManifestError, match="total"):
        build_program_facts_source_manifest(
            config, snapshot, max_total_bytes=source.stat().st_size - 1
        )
    with pytest.raises(ProgramFactsSourceManifestError, match="file-count"):
        build_program_facts_source_manifest(config, snapshot, max_files=0)
    with pytest.raises(ProgramFactsSourceManifestError, match="line-replay"):
        build_program_facts_source_manifest(
            config, snapshot, max_line_starts=2
        )
    with pytest.raises(ProgramFactsSourceManifestError, match="canonical-byte"):
        build_program_facts_source_manifest(
            config, snapshot, max_manifest_bytes=1
        )


def test_replay_rejects_wrong_raw_bytes_or_line_offsets(tmp_path):
    project, _source, config, snapshot = _fixture(tmp_path)
    authority = build_program_facts_source_manifest(config, snapshot)
    source_id = next(iter(authority.source_bytes_by_id))

    with pytest.raises(ProgramFactsSourceManifestError, match="raw bytes"):
        replay_program_facts_source_manifest(
            authority.canonical_bytes,
            expected_snapshot_digest=snapshot["snapshot_digest"],
            expected_source_scope_digest=snapshot["components"]["source_scope"][
                "digest"
            ],
            source_bytes_by_id={source_id: b"different\n"},
            capture_capability=authority.capture_capability,
        )

    record = _record(authority)
    record["line_replay_inputs"][0]["line_start_byte_offsets"] = [0, 1]
    with pytest.raises(ProgramFactsSourceManifestError, match="line replay"):
        replay_program_facts_source_manifest(
            _resign(record),
            expected_snapshot_digest=snapshot["snapshot_digest"],
            expected_source_scope_digest=snapshot["components"]["source_scope"][
                "digest"
            ],
            project_root=project,
            config=config,
        )


def test_source_mutation_during_capture_is_rejected(tmp_path, monkeypatch):
    _project, source, config, snapshot = _fixture(tmp_path)
    original = manifest_module._read_regular_file_stably
    mutated = False

    def mutate_after_read(path, **kwargs):
        nonlocal mutated
        result = original(path, **kwargs)
        if not mutated and Path(path) == source:
            mutated = True
            source.write_bytes(source.read_bytes() + b"// changed\n")
        return result

    monkeypatch.setattr(
        manifest_module, "_read_regular_file_stably", mutate_after_read
    )
    with pytest.raises(ProgramFactsSourceManifestError, match="changed"):
        build_program_facts_source_manifest(config, snapshot)


def test_hardlink_duplicate_is_rejected(tmp_path):
    project, source, config, _snapshot = _fixture(tmp_path)
    alias = project / "src" / "Alias.sol"
    try:
        os.link(source, alias)
    except OSError as exc:
        pytest.skip(f"hard links unavailable for fixture: {exc}")
    snapshot = build_audit_snapshot(
        config, _implementation_tree(tmp_path / "plamen")
    )

    with pytest.raises(
        ProgramFactsSourceManifestError, match="physical-identity alias"
    ):
        build_program_facts_source_manifest(config, snapshot)


def test_tree_replay_rejects_excluded_physical_replacement_and_cross_alias(
    tmp_path,
):
    project, source, config, _snapshot = _fixture(tmp_path)
    excluded = project / "tests" / "Helper.sol"
    excluded.parent.mkdir()
    excluded.write_bytes(source.read_bytes())
    snapshot = build_audit_snapshot(
        config, _implementation_tree(tmp_path / "plamen")
    )
    authority = build_program_facts_source_manifest(config, snapshot)

    excluded.unlink()
    excluded.write_bytes(source.read_bytes())
    with pytest.raises(
        ProgramFactsSourceManifestError,
        match="excluded.*physical identity|physical.identity",
    ):
        replay_program_facts_source_manifest(
            authority.canonical_bytes,
            expected_snapshot_digest=snapshot["snapshot_digest"],
            expected_source_scope_digest=snapshot["components"][
                "source_scope"
            ]["digest"],
            project_root=project,
            config=config,
        )

    replacement = build_program_facts_source_manifest(config, snapshot)
    excluded.unlink()
    try:
        os.link(source, excluded)
    except OSError as exc:
        pytest.skip(f"hard links unavailable for fixture: {exc}")
    with pytest.raises(
        ProgramFactsSourceManifestError,
        match="physical.identity alias|physical identity",
    ):
        replay_program_facts_source_manifest(
            replacement.canonical_bytes,
            expected_snapshot_digest=snapshot["snapshot_digest"],
            expected_source_scope_digest=snapshot["components"][
                "source_scope"
            ]["digest"],
            project_root=project,
            config=config,
        )


def test_shape_rejects_cross_denominator_physical_identity_alias(tmp_path):
    project, _source, config, _snapshot = _fixture(tmp_path)
    excluded = project / "tests" / "Helper.sol"
    excluded.parent.mkdir()
    excluded.write_bytes(b"contract Helper {}\n")
    snapshot = build_audit_snapshot(
        config, _implementation_tree(tmp_path / "plamen")
    )
    authority = build_program_facts_source_manifest(config, snapshot)
    record = _record(authority)
    inventory = record["physical_identity_inventory"]
    eligible_digest = next(
        row["physical_identity_digest"]
        for row in inventory
        if row["kind"] == "ELIGIBLE"
    )
    next(
        row for row in inventory if row["kind"] == "EXCLUDED"
    )["physical_identity_digest"] = eligible_digest

    with pytest.raises(
        ProgramFactsSourceManifestError,
        match="physical-identity alias",
    ):
        parse_program_facts_source_manifest_shape(_resign(record))


def test_symlink_source_is_rejected_when_platform_can_create_it(tmp_path):
    project, source, config, _snapshot = _fixture(tmp_path)
    link = project / "src" / "Link.sol"
    try:
        link.symlink_to(source)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable for fixture: {exc}")
    snapshot = build_audit_snapshot(
        config, _implementation_tree(tmp_path / "plamen")
    )

    with pytest.raises(ProgramFactsSourceManifestError, match="symbolic link"):
        build_program_facts_source_manifest(config, snapshot)


def test_project_root_rejects_symlink_in_full_ancestor_chain(tmp_path):
    real_parent = tmp_path / "real-parent"
    project, _source, config, snapshot = _fixture(real_parent)
    alias_parent = tmp_path / "alias-parent"
    try:
        alias_parent.symlink_to(real_parent, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlinks unavailable for fixture: {exc}")
    alias_config = {
        **config,
        "project_root": str(alias_parent / "project"),
        "scratchpad": str(alias_parent / "project" / ".scratchpad"),
    }

    with pytest.raises(
        ProgramFactsSourceManifestError,
        match="project_root.*symbolic link|project_root.*reparse",
    ):
        build_program_facts_source_manifest(alias_config, snapshot)


def test_tree_replay_rejects_config_root_ancestor_alias(tmp_path):
    real_parent = tmp_path / "real-parent"
    project, _source, config, snapshot = _fixture(real_parent)
    authority = build_program_facts_source_manifest(config, snapshot)
    alias_parent = tmp_path / "alias-parent"
    try:
        alias_parent.symlink_to(real_parent, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlinks unavailable for fixture: {exc}")
    alias_config = {
        **config,
        "project_root": str(alias_parent / "project"),
    }

    with pytest.raises(
        ProgramFactsSourceManifestError,
        match="project_root.*symbolic link|project_root.*reparse|project_root input",
    ):
        replay_program_facts_source_manifest(
            authority.canonical_bytes,
            expected_snapshot_digest=snapshot["snapshot_digest"],
            expected_source_scope_digest=snapshot["components"][
                "source_scope"
            ]["digest"],
            project_root=project,
            config=alias_config,
        )


@pytest.mark.skipif(os.name != "nt", reason="case aliases are Windows-specific")
def test_project_root_rejects_case_alias_in_full_ancestor_chain(tmp_path):
    project, _source, config, snapshot = _fixture(tmp_path)
    parts = list(project.parts)
    mutable_index = next(
        index
        for index, part in enumerate(parts)
        if part and part.lower() != part.upper()
    )
    part = parts[mutable_index]
    parts[mutable_index] = (
        part.swapcase()
        if part.swapcase() != part
        else part.upper()
    )
    alias_root = Path(*parts)
    if str(alias_root) == str(project):
        pytest.skip("fixture path has no case-variant component")
    alias_config = {**config, "project_root": str(alias_root)}

    with pytest.raises(
        ProgramFactsSourceManifestError,
        match="project_root.*spelling|project_root.*case",
    ):
        build_program_facts_source_manifest(alias_config, snapshot)


def test_external_source_language_is_bound_to_closed_suffix_policy(tmp_path):
    project, _source, config, _snapshot = _fixture(tmp_path)
    external = tmp_path / "external" / "Outside.sol"
    external.parent.mkdir()
    external.write_bytes(b"contract Outside {}\n")
    scope = project / "scope.txt"
    scope.write_text(str(external), encoding="utf-8")
    external_config = {
        **config,
        "scope_file": str(scope),
        "allow_external_scope_targets": True,
    }
    snapshot = build_audit_snapshot(
        external_config, _implementation_tree(tmp_path / "plamen")
    )
    authority = build_program_facts_source_manifest(
        external_config, snapshot
    )
    record = _record(authority)
    external_row = next(
        row
        for row in record["source_manifest"]["eligible_files"]
        if row["path"].startswith("@outside/")
    )
    external_row["language"] = "rust"
    record["source_manifest"]["manifest_digest"] = (
        manifest_module.derive_source_manifest_digest(
            record["source_manifest"]
        )
    )

    with pytest.raises(
        ProgramFactsSourceManifestError, match="language.*suffix|suffix.*language"
    ):
        parse_program_facts_source_manifest_shape(_resign(record))

    jointly_forged = _record(authority)
    forged_row = next(
        row
        for row in jointly_forged["source_manifest"]["eligible_files"]
        if row["path"].startswith("@outside/")
    )
    forged_row["language"] = "rust"
    jointly_forged["source_manifest"]["manifest_digest"] = (
        manifest_module.derive_source_manifest_digest(
            jointly_forged["source_manifest"]
        )
    )
    next(
        row
        for row in jointly_forged["source_suffix_bindings"]
        if row["source_file_id"] == forged_row["source_file_id"]
    )["suffix"] = ".rs"
    forged_raw = _resign(jointly_forged)
    parsed = parse_program_facts_source_manifest_shape(forged_raw)
    assert parsed.parent_authority_established is False
    with pytest.raises(
        ProgramFactsSourceManifestError, match="suffix/language"
    ):
        replay_program_facts_source_manifest(
            parsed,
            expected_snapshot_digest=snapshot["snapshot_digest"],
            expected_source_scope_digest=snapshot["components"][
                "source_scope"
            ]["digest"],
            project_root=project,
            config=external_config,
        )


@pytest.mark.parametrize(
    "path",
    [
        "../Vault.sol",
        "/src/Vault.sol",
        r"src\Vault.sol",
        "C:/src/Vault.sol",
        "src/Vault.sol:stream",
        "src/\u0065\u0301.sol",
    ],
)
def test_portable_shape_contract_rejects_unsafe_paths(tmp_path, path):
    _project, _source, config, snapshot = _fixture(tmp_path)
    authority = build_program_facts_source_manifest(config, snapshot)
    record = _record(authority)
    row = record["source_manifest"]["eligible_files"][0]
    row["path"] = path
    row["path_casefold_key"] = path.casefold()

    if path == "src/\u0065\u0301.sol":
        raw = (
            json.dumps(
                record,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
        )
    else:
        raw = _resign(record)
    with pytest.raises(ProgramFactsSourceManifestError):
        parse_program_facts_source_manifest_shape(raw)
