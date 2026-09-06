from __future__ import annotations

from pathlib import Path
import copy
import hashlib
import json
import os

import pytest

import program_facts_source_manifest as manifest_module
from audit_snapshot import build_audit_snapshot
from program_facts_source_manifest import (
    ProgramFactsSourceManifestError,
    ReplayedProgramFactsSourceManifest,
    build_program_facts_source_manifest,
    parse_program_facts_source_manifest_shape,
    replay_program_facts_source_manifest,
)
from test_program_facts_source_manifest import (
    _fixture,
    _implementation_tree,
    _resign,
)


def _record(authority) -> dict[str, object]:
    return json.loads(authority.canonical_bytes)


def _closure_values(function) -> dict[str, object]:
    return dict(zip(
        function.__code__.co_freevars,
        (cell.cell_contents for cell in function.__closure__),
    ))


def _unissued_replayed(parsed):
    forged = object.__new__(ReplayedProgramFactsSourceManifest)
    object.__setattr__(forged, "record", parsed.record)
    object.__setattr__(
        forged, "canonical_bytes", parsed.canonical_bytes
    )
    object.__setattr__(
        forged, "authority_digest", parsed.authority_digest
    )
    object.__setattr__(forged, "file_sha256", parsed.file_sha256)
    return forged


def test_production_replay_rejects_closure_injected_issuance_after_mutation(
    tmp_path,
):
    project, source, config, snapshot = _fixture(tmp_path)
    authority = build_program_facts_source_manifest(config, snapshot)
    parsed = parse_program_facts_source_manifest_shape(
        authority.canonical_bytes
    )
    forged = _unissued_replayed(parsed)
    closure = _closure_values(
        manifest_module._manifest_authority_is_issued
    )
    with closure["lock"]:
        closure["authorities"][id(forged)] = (
            forged,
            closure["authority_signature"](forged),
        )
    assert forged.parent_authority_established is True
    source.write_bytes(b"contract Vault { uint256 changed; }\n")

    with pytest.raises(
        ProgramFactsSourceManifestError,
        match="stale|source|selection|replay|physical|bytes",
    ):
        manifest_module.replay_program_facts_source_authority(
            forged,
            expected_snapshot_digest=snapshot["snapshot_digest"],
            expected_source_scope_digest=snapshot["components"][
                "source_scope"
            ]["digest"],
            project_root=project,
            config=config,
        )


def test_production_replay_uses_live_semantics_not_issuance_metadata(
    tmp_path,
):
    project, _source, config, snapshot = _fixture(tmp_path)
    authority = build_program_facts_source_manifest(config, snapshot)
    parsed = parse_program_facts_source_manifest_shape(
        authority.canonical_bytes
    )
    unissued = _unissued_replayed(parsed)
    assert unissued.parent_authority_established is False

    replayed = manifest_module.replay_program_facts_source_authority(
        unissued,
        expected_snapshot_digest=snapshot["snapshot_digest"],
        expected_source_scope_digest=snapshot["components"][
            "source_scope"
        ]["digest"],
        project_root=project,
        config=config,
    )
    assert replayed.parent_authority_established is True
    with pytest.raises(
        ProgramFactsSourceManifestError,
        match="ledger binding",
    ):
        manifest_module.replay_program_facts_source_authority(
            authority,
            expected_snapshot_digest=snapshot["snapshot_digest"],
            expected_source_scope_digest=snapshot["components"][
                "source_scope"
            ]["digest"],
            project_root=project,
            config=config,
            expected_ledger_binding={"self_asserted": True},
        )


def test_production_replay_does_not_trust_forged_raw_mapping_capability(
    tmp_path,
):
    project, source, config, snapshot = _fixture(tmp_path)
    authority = build_program_facts_source_manifest(config, snapshot)
    forged_capability = object.__new__(
        manifest_module.SourceManifestCaptureCapability
    )
    object.__setattr__(
        forged_capability, "_opaque_nonce", object()
    )
    closure = _closure_values(
        manifest_module._consume_capture_capability
    )
    binding = (
        authority.authority_digest,
        snapshot["snapshot_digest"],
        snapshot["components"]["source_scope"]["digest"],
        manifest_module._capture_bytes_digest(
            authority.source_bytes_by_id,
            authority.excluded_source_bytes_by_identity,
        ),
    )
    with closure["lock"]:
        closure["capabilities"][id(forged_capability)] = (
            forged_capability,
            binding,
            os.getpid(),
            False,
        )
    forged_replay = replay_program_facts_source_manifest(
        authority.canonical_bytes,
        expected_snapshot_digest=snapshot["snapshot_digest"],
        expected_source_scope_digest=snapshot["components"][
            "source_scope"
        ]["digest"],
        source_bytes_by_id=authority.source_bytes_by_id,
        excluded_source_bytes_by_identity=(
            authority.excluded_source_bytes_by_identity
        ),
        capture_capability=forged_capability,
    )
    assert forged_replay.parent_authority_established is True
    source.write_bytes(b"contract Vault { uint256 changed; }\n")

    with pytest.raises(
        ProgramFactsSourceManifestError,
        match="stale|source|selection|replay|physical|bytes",
    ):
        manifest_module.replay_program_facts_source_authority(
            forged_replay,
            expected_snapshot_digest=snapshot["snapshot_digest"],
            expected_source_scope_digest=snapshot["components"][
                "source_scope"
            ]["digest"],
            project_root=project,
            config=config,
        )


def test_compiled_paths_reject_stateful_or_unbounded_inputs(tmp_path):
    _project, _source, config, snapshot = _fixture(tmp_path)

    class StatefulPaths:
        def __iter__(self):
            yield "src/Vault.sol"

    with pytest.raises(
        ProgramFactsSourceManifestError,
        match="exact list or tuple",
    ):
        build_program_facts_source_manifest(
            config,
            snapshot,
            compiled_source_paths=StatefulPaths(),
        )
    with pytest.raises(
        ProgramFactsSourceManifestError,
        match="count limit",
    ):
        build_program_facts_source_manifest(
            config,
            snapshot,
            compiled_source_paths=[
                "src/Vault.sol",
                "src/Second.sol",
            ],
            max_compiled_source_paths=1,
        )
    with pytest.raises(
        ProgramFactsSourceManifestError,
        match="byte limit",
    ):
        build_program_facts_source_manifest(
            config,
            snapshot,
            compiled_source_paths=["src/Vault.sol"],
            max_compiled_source_path_bytes=4,
        )


def test_source_changed_after_snapshot_before_manifest_is_stale(tmp_path):
    _project, source, config, snapshot = _fixture(tmp_path)
    source.write_bytes(b"contract Vault { uint256 changedAfterSnapshot; }\n")

    with pytest.raises(
        ProgramFactsSourceManifestError,
        match="stale|snapshot|source.scope",
    ):
        build_program_facts_source_manifest(config, snapshot)


def test_non_source_snapshot_input_changed_during_capture_is_stale(
    tmp_path,
    monkeypatch,
):
    project, _source, config, _snapshot = _fixture(tmp_path)
    readme = project / "README.md"
    readme.write_text("before\n", encoding="utf-8")
    snapshot = build_audit_snapshot(
        config, _implementation_tree(tmp_path / "plamen")
    )
    original = manifest_module._read_regular_file_stably
    changed = False

    def mutate_context_after_source_read(path, **kwargs):
        nonlocal changed
        result = original(path, **kwargs)
        if not changed and Path(path).suffix.casefold() == ".sol":
            changed = True
            readme.write_text("after\n", encoding="utf-8")
        return result

    monkeypatch.setattr(
        manifest_module,
        "_read_regular_file_stably",
        mutate_context_after_source_read,
    )
    with pytest.raises(
        ProgramFactsSourceManifestError,
        match="stale|snapshot|source.scope|changed",
    ):
        build_program_facts_source_manifest(config, snapshot)


def test_replayed_authority_has_no_importable_seal_or_public_constructor(
    tmp_path,
):
    _project, _source, config, snapshot = _fixture(tmp_path)
    authority = build_program_facts_source_manifest(config, snapshot)
    parsed = parse_program_facts_source_manifest_shape(
        authority.canonical_bytes
    )

    assert not hasattr(manifest_module, "_PARENT_AUTHORITY_PROOF")
    with pytest.raises(TypeError, match="issued|replay|constructor"):
        ReplayedProgramFactsSourceManifest(
            record=parsed.record,
            canonical_bytes=parsed.canonical_bytes,
            authority_digest=parsed.authority_digest,
            file_sha256=parsed.file_sha256,
        )

    forged = object.__new__(ReplayedProgramFactsSourceManifest)
    object.__setattr__(forged, "record", parsed.record)
    object.__setattr__(forged, "canonical_bytes", parsed.canonical_bytes)
    object.__setattr__(forged, "authority_digest", parsed.authority_digest)
    object.__setattr__(forged, "file_sha256", parsed.file_sha256)
    assert forged.parent_authority_established is False

    with pytest.raises(TypeError, match="issuance|internal|validated"):
        manifest_module._issue_manifest_authority(
            ReplayedProgramFactsSourceManifest,
            record=parsed.record,
            canonical_bytes=parsed.canonical_bytes,
            authority_digest=parsed.authority_digest,
            file_sha256=parsed.file_sha256,
        )
    with pytest.raises(TypeError, match="issuance|internal|validated"):
        manifest_module._issue_capture_capability(
            authority_digest=parsed.authority_digest,
            snapshot_digest=snapshot["snapshot_digest"],
            source_scope_digest=snapshot["components"]["source_scope"][
                "digest"
            ],
            capture_digest="0" * 64,
        )


def test_capture_consumption_is_external_to_mutable_instance_slots(tmp_path):
    _project, _source, config, snapshot = _fixture(tmp_path)
    authority = build_program_facts_source_manifest(config, snapshot)
    capability = authority.capture_capability
    kwargs = {
        "expected_snapshot_digest": snapshot["snapshot_digest"],
        "expected_source_scope_digest": snapshot["components"][
            "source_scope"
        ]["digest"],
        "source_bytes_by_id": authority.source_bytes_by_id,
        "excluded_source_bytes_by_identity": (
            authority.excluded_source_bytes_by_identity
        ),
        "capture_capability": capability,
    }
    replay_program_facts_source_manifest(authority.canonical_bytes, **kwargs)

    mutations = (
        lambda: object.__setattr__(capability, "_consumed", False),
        lambda: object.__delattr__(capability, "_opaque_nonce"),
        lambda: object.__setattr__(capability, "_opaque_nonce", object()),
    )
    for mutation in mutations:
        try:
            mutation()
        except (AttributeError, TypeError):
            pass
        with pytest.raises(
            ProgramFactsSourceManifestError,
            match="consumed|one-shot|issued|binding",
        ):
            replay_program_facts_source_manifest(
                authority.canonical_bytes,
                **kwargs,
            )
    with pytest.raises(TypeError, match="copied"):
        copy.copy(capability)


def test_raw_compiled_paths_are_untrusted_and_cannot_mint_full(tmp_path):
    _project, _source, config, snapshot = _fixture(tmp_path)
    record = _record(
        build_program_facts_source_manifest(
            config,
            snapshot,
            compiled_source_paths=["src/Vault.sol"],
        )
    )

    assert record["compiled_denominator"]["status"] == "UNKNOWN"
    assert record["compiled_denominator"]["compiled_source_file_ids"] == []
    assert {
        row["code"] for row in record["debts"]
    } >= {"COMPILED_DENOMINATOR_UNTRUSTED"}


def test_self_signed_shape_cannot_upgrade_raw_paths_to_full(tmp_path):
    _project, _source, config, snapshot = _fixture(tmp_path)
    record = _record(
        build_program_facts_source_manifest(
            config,
            snapshot,
            compiled_source_paths=["src/Vault.sol"],
        )
    )
    source_ids = record["compiled_denominator"][
        "eligible_source_file_ids"
    ]
    record["debts"] = []
    denominator = record["compiled_denominator"]
    denominator["status"] = "FULL"
    denominator["compiled_source_file_ids"] = list(source_ids)
    denominator["uncompiled_source_file_ids"] = []
    denominator["unexpected_compiled_paths"] = []
    denominator["unresolved_debt_ids"] = []
    denominator["denominator_digest"] = (
        manifest_module.digest_compiled_denominator(denominator)
    )

    with pytest.raises(
        ProgramFactsSourceManifestError,
        match="compiled denominator.*authority|substantiate|evidence debt",
    ):
        parse_program_facts_source_manifest_shape(_resign(record))


def test_generated_test_and_harness_sources_are_total_exclusions(tmp_path):
    project, _source, config, _snapshot = _fixture(tmp_path)
    sources = {
        "src/Vault.t.sol": b"contract GeneratedTest {}\n",
        "tests/poc_Attack.sol": b"contract GeneratedPoc {}\n",
        "generated/Bindings.sol": b"contract GeneratedBindings {}\n",
        "harness/ExploitHarness.sol": b"contract ExploitHarness {}\n",
    }
    for relative, raw in sources.items():
        path = project / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    snapshot = build_audit_snapshot(
        config, _implementation_tree(tmp_path / "plamen")
    )

    record = _record(build_program_facts_source_manifest(config, snapshot))
    excluded = {
        row["identity"]: row
        for row in record["source_manifest"]["excluded_files"]
    }
    assert set(sources) <= set(excluded)
    for relative, raw in sources.items():
        assert excluded[relative]["reason"] == "GENERATED_SOURCE_NOT_BOUND"
        assert excluded[relative]["source_sha256"] == hashlib.sha256(
            raw
        ).hexdigest()
    source_excluded_debts = [
        row for row in record["debts"] if row["code"] == "SOURCE_EXCLUDED"
    ]
    assert len(source_excluded_debts) == 1
    assert set(sources) <= set(
        source_excluded_debts[0]["affected_paths"]
    )


def test_self_signed_shape_cannot_drop_source_exclusion_debt(tmp_path):
    project, _source, config, _snapshot = _fixture(tmp_path)
    generated = project / "src" / "Vault.t.sol"
    generated.write_bytes(b"contract GeneratedTest {}\n")
    snapshot = build_audit_snapshot(
        config, _implementation_tree(tmp_path / "plamen")
    )
    record = _record(build_program_facts_source_manifest(config, snapshot))
    removed_ids = {
        row["debt_id"]
        for row in record["debts"]
        if row["code"] == "SOURCE_EXCLUDED"
    }
    record["debts"] = [
        row
        for row in record["debts"]
        if row["debt_id"] not in removed_ids
    ]
    denominator = record["compiled_denominator"]
    denominator["unresolved_debt_ids"] = [
        debt_id
        for debt_id in denominator["unresolved_debt_ids"]
        if debt_id not in removed_ids
    ]
    denominator["denominator_digest"] = (
        manifest_module.digest_compiled_denominator(denominator)
    )

    with pytest.raises(
        ProgramFactsSourceManifestError,
        match="excluded source denominator|SOURCE_EXCLUDED",
    ):
        parse_program_facts_source_manifest_shape(_resign(record))


def test_decomposed_unicode_disk_name_is_rejected(tmp_path):
    project, _source, config, _snapshot = _fixture(tmp_path)
    decomposed = project / "src" / "e\u0301.sol"
    decomposed.write_bytes(b"contract UnicodeName {}\n")
    snapshot = build_audit_snapshot(
        config, _implementation_tree(tmp_path / "plamen")
    )

    with pytest.raises(
        ProgramFactsSourceManifestError,
        match="NFC|Unicode|collision|spelling",
    ):
        build_program_facts_source_manifest(config, snapshot)


def test_generated_exclusion_hardlink_to_eligible_is_rejected(tmp_path):
    project, source, config, _snapshot = _fixture(tmp_path)
    generated = project / "generated" / "Alias.sol"
    generated.parent.mkdir(parents=True)
    try:
        generated.hardlink_to(source)
    except OSError as exc:
        pytest.skip(f"hard links unavailable for fixture: {exc}")
    snapshot = build_audit_snapshot(
        config, _implementation_tree(tmp_path / "plamen")
    )

    with pytest.raises(
        ProgramFactsSourceManifestError,
        match="physical-identity alias",
    ):
        build_program_facts_source_manifest(config, snapshot)


def test_reparse_attribute_is_rejected_even_without_symlink_mode():
    class FakeStat:
        st_mode = 0o100644
        st_file_attributes = 0x0400

    with pytest.raises(
        ProgramFactsSourceManifestError,
        match="junction|reparse",
    ):
        manifest_module._check_regular_file(
            Path("fixture.sol"),
            FakeStat(),
            context="fixture",
        )
