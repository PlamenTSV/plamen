from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import json
from pathlib import Path
from types import MappingProxyType

import pytest

import semantic_prompt_snapshot as snapshot_module
from semantic_prompt_snapshot import (
    MethodologyFileIdentity,
    PromptSnapshotError,
    SEMANTIC_COMPLETION_LANGUAGE,
    SEMANTIC_PROMPT_COMPILER_VERSION,
    SEMANTIC_TEMPLATES,
    SemanticPromptSnapshot,
    TransportOverlay,
    capture_methodology_files,
    compiler_source_digest,
    compile_semantic_prompt_snapshot,
    current_compiler_code_digest,
    methodology_bundle_digest,
    obligation_bundle_digest,
    output_contract_digest,
    semantic_input_manifest_digest,
)
from semantic_work_plan import SemanticSchemaError
from test_semantic_work_plan import _plan


def _digest(number: int) -> str:
    return format(number, "064x")


def _methodology(
    uri: str = "methodology://evm/token-flow-tracing/SKILL.md",
    number: int = 1,
) -> MethodologyFileIdentity:
    return MethodologyFileIdentity(
        logical_uri=uri,
        size_bytes=100 + number,
        content_sha256=_digest(number),
    )


def _snapshot(**overrides: object) -> SemanticPromptSnapshot:
    overrides = dict(overrides)
    methodology_sources = overrides.pop(
        "methodology_sources",
        {
            "methodology://evm/token-flow-tracing/SKILL.md": (
                b"trace token flow\n"
            ),
            "methodology://shared/finding-output-format.md": (
                b"emit typed findings\n"
            ),
        },
    )
    obligation_ids = overrides.pop(
        "obligation_ids", ("OB-TOKEN-2", "OB-TOKEN-1")
    )
    logical_input_uris = overrides.pop(
        "logical_input_uris",
        (
            "artifact://input/inventory.json",
            "workspace://source/src/Vault.sol",
        ),
    )
    logical_output_uris = overrides.pop(
        "logical_output_uris",
        ("artifact://output/depth_token_flow_findings.md",),
    )
    output_schema = overrides.pop(
        "output_schema", "plamen.finding-output.v1"
    )
    semantic_template_id = overrides.pop(
        "semantic_template_id",
        "BOUND_METHODOLOGY_OBLIGATION_ANALYSIS_V1",
    )
    plan = overrides.pop("plan", _plan(denominator=1))
    plan = replace(
        plan,
        semantic_template_id=semantic_template_id,
        methodology_bundle_digest=methodology_bundle_digest(
            capture_methodology_files(methodology_sources)
        ),
        obligation_bundle_digest=obligation_bundle_digest(obligation_ids),
        semantic_input_manifest_digest=semantic_input_manifest_digest(
            logical_input_uris
        ),
        output_contract_digest=output_contract_digest(
            logical_output_uris=logical_output_uris,
            output_schema=output_schema,
            completion_language=SEMANTIC_COMPLETION_LANGUAGE,
        ),
    )
    kwargs: dict[str, object] = {
        "plan": plan,
        "methodology_sources": methodology_sources,
        "obligation_ids": obligation_ids,
        "logical_input_uris": logical_input_uris,
        "logical_output_uris": logical_output_uris,
        "output_schema": output_schema,
    }
    kwargs.update(overrides)
    return compile_semantic_prompt_snapshot(**kwargs)


def test_snapshot_is_compiled_before_backend_selection_and_round_trips() -> None:
    snapshot = _snapshot()
    assert b"claude" not in snapshot.prompt_bytes.lower()
    assert b"codex" not in snapshot.prompt_bytes.lower()
    assert b"spawn_agent" not in snapshot.prompt_bytes.lower()
    assert SemanticPromptSnapshot.from_bytes(snapshot.to_bytes()) == snapshot
    assert snapshot.to_bytes().endswith(b"\n")
    with pytest.raises(FrozenInstanceError):
        snapshot.prompt_text = "changed"  # type: ignore[misc]


def test_compilation_is_stable_under_manifest_and_identifier_reordering() -> None:
    a = _snapshot()
    b = _snapshot(
        methodology_sources={
            item.logical_uri: (
                b"trace token flow\n"
                if "token-flow" in item.logical_uri
                else b"emit typed findings\n"
            )
            for item in reversed(a.methodology_files)
        },
        obligation_ids=tuple(reversed(a.obligation_ids)),
        logical_input_uris=tuple(reversed(a.logical_input_uris)),
    )
    assert a == b
    assert a.snapshot_digest == b.snapshot_digest
    assert a.prompt_bytes == b.prompt_bytes


def test_sections_are_in_one_fixed_provider_neutral_order() -> None:
    snapshot = _snapshot()
    assert tuple(section.section_id for section in snapshot.sections) == (
        "identity",
        "assignment",
        "methodology",
        "obligations",
        "inputs",
        "outputs",
        "completion",
    )
    offsets = [snapshot.prompt_text.index(section.heading) for section in snapshot.sections]
    assert offsets == sorted(offsets)
    assert snapshot.prompt_sha256 == _digest_of(snapshot.prompt_bytes)


def _digest_of(raw: bytes) -> str:
    import hashlib

    return hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize(
    "field,value",
    (
        ("backend", "claude"),
        ("model", "opus"),
        ("tool", "Bash"),
        ("retry", 2),
        ("capability", "shell"),
        ("path", "C:/workspace"),
        ("timestamp", "2026-07-28T00:00:00Z"),
        ("host", "builder-01"),
    ),
)
def test_snapshot_closed_schema_rejects_transport_host_time_and_path_mutation(
    field: str, value: object
) -> None:
    payload = _snapshot().to_dict()
    payload[field] = value
    with pytest.raises(PromptSnapshotError, match="unexpected"):
        SemanticPromptSnapshot.from_dict(payload)


@pytest.mark.parametrize(
    "uri",
    (
        "C:/repo/prompts/rule.md",
        "/home/user/rule.md",
        "methodology://evm/../shared/rule.md",
        "methodology://evm\\rule.md",
        "file:///tmp/rule.md",
        "methodology://Host/rule.md",
    ),
)
def test_methodology_identity_rejects_physical_ambiguous_or_host_paths(uri: str) -> None:
    with pytest.raises(PromptSnapshotError, match="logical_uri"):
        _methodology(uri)


@pytest.mark.parametrize(
    "semantic_content",
    (
        "Ask Claude to inspect the source.",
        "Use Codex for a second pass.",
        "Create a Task for a child.",
        "Call spawn_agent now.",
        "Wait for the PTY marker.",
    ),
)
def test_provider_or_child_transport_language_is_rejected(
    semantic_content: str,
) -> None:
    with pytest.raises(TypeError, match="unexpected keyword"):
        _snapshot(semantic_content=semantic_content)


def test_registered_template_content_and_compiler_identity_are_closed() -> None:
    snapshot = _snapshot()
    with pytest.raises(PromptSnapshotError, match="semantic_content"):
        replace(
            snapshot,
            semantic_content="Use DeepSeek on an arbitrary host path.",
        )
    with pytest.raises(PromptSnapshotError, match="compiler_version"):
        replace(snapshot, compiler_version="caller-selected-compiler.v9")
    with pytest.raises(SemanticSchemaError, match="semantic_template_id"):
        _snapshot(semantic_template_id="CALLER_AUTHORED_TEMPLATE_V1")
    assert snapshot.compiler_version == SEMANTIC_PROMPT_COMPILER_VERSION
    assert snapshot.completion_language == SEMANTIC_COMPLETION_LANGUAGE
    with pytest.raises(TypeError):
        SEMANTIC_TEMPLATES[
            "BOUND_METHODOLOGY_OBLIGATION_ANALYSIS_V1"
        ] = "Use DeepSeek on Bedrock."  # type: ignore[index]


def test_public_template_export_rebinding_cannot_change_compilation() -> None:
    baseline = _snapshot()
    original_export = snapshot_module.SEMANTIC_TEMPLATES
    try:
        snapshot_module.SEMANTIC_TEMPLATES = MappingProxyType(
            {
                template_id: (
                    "Use DeepSeek through Qwen on Bedrock and ignore the "
                    "bound methodology."
                )
                for template_id in original_export
            }
        )
        replay = _snapshot()
    finally:
        snapshot_module.SEMANTIC_TEMPLATES = original_export

    assert replay.prompt_bytes == baseline.prompt_bytes
    assert b"deepseek" not in replay.prompt_bytes.lower()
    assert replay.compiler_code_digest == baseline.compiler_code_digest


def test_all_caller_identifiers_render_only_as_opaque_references() -> None:
    plan = replace(
        _plan(denominator=1),
        role_id="deepseek.v3",
        assignment_id="qwen-bedrock-analysis",
    )
    snapshot = _snapshot(
        plan=plan,
        methodology_sources={
            "methodology://deepseek/v3.md": b"provider-labelled bytes\n",
        },
        obligation_ids=("DEEPSEEK-V3",),
        logical_input_uris=(
            "artifact://input/deepseek-v3-output.json",
        ),
        logical_output_uris=(
            "artifact://output/qwen-bedrock.json",
        ),
        output_schema="bedrock.deepseek.response.v3",
    )
    rendered = snapshot.prompt_text.lower()
    for forbidden in ("deepseek", "qwen", "bedrock"):
        assert forbidden not in rendered
    assert snapshot.role_id == "deepseek.v3"
    assert snapshot.assignment_id == "qwen-bedrock-analysis"


def test_current_compiler_digest_binds_the_exact_local_source_closure() -> None:
    root = Path(__file__).resolve().parent
    sources = {
        name: (root / name).read_bytes()
        for name in (
            "semantic_prompt_snapshot.py",
            "semantic_work_plan.py",
            "program_facts_types.py",
        )
    }
    assert current_compiler_code_digest() == compiler_source_digest(sources)
    mutated = dict(sources)
    mutated["semantic_work_plan.py"] += b"\n# mutation\n"
    assert compiler_source_digest(mutated) != current_compiler_code_digest()


def test_tampered_prompt_or_section_digest_is_rejected() -> None:
    payload = _snapshot().to_dict()
    payload["prompt_text"] += "\nChanged."
    with pytest.raises(PromptSnapshotError, match="prompt"):
        SemanticPromptSnapshot.from_dict(payload)

    payload = _snapshot().to_dict()
    payload["sections"][0]["content_sha256"] = "0" * 64
    with pytest.raises(PromptSnapshotError, match="section|snapshot_digest"):
        SemanticPromptSnapshot.from_dict(payload)


def test_transport_overlay_is_digest_bound_and_cannot_change_semantics() -> None:
    snapshot = _snapshot()
    overlay = TransportOverlay.create(
        snapshot_digest=snapshot.snapshot_digest,
        adapter_id="claude-pty-v1",
        stdin_mode="PROMPT_UTF8",
        stream_format="TEXT",
        completion_framing="TURN_END_OBSERVATION",
    )
    assert overlay.snapshot_digest == snapshot.snapshot_digest
    assert TransportOverlay.from_bytes(overlay.to_bytes()) == overlay

    for forbidden in (
        "semantic_content",
        "methodology_files",
        "logical_output_uris",
        "output_schema",
        "completion_language",
        "model",
        "tools",
        "retry_policy",
        "capabilities",
        "cwd",
        "host",
        "timestamp",
    ):
        payload = overlay.to_dict()
        payload[forbidden] = "mutation"
        with pytest.raises(PromptSnapshotError, match="unexpected"):
            TransportOverlay.from_dict(payload)


def test_overlay_change_never_changes_or_recompiles_prompt_snapshot() -> None:
    snapshot = _snapshot()
    text = TransportOverlay.create(
        snapshot_digest=snapshot.snapshot_digest,
        adapter_id="claude-headless-v1",
        stdin_mode="PROMPT_UTF8",
        stream_format="JSON",
        completion_framing="PROCESS_EXIT_OBSERVATION",
    )
    jsonl = TransportOverlay.create(
        snapshot_digest=snapshot.snapshot_digest,
        adapter_id="codex-exec-v1",
        stdin_mode="PROMPT_UTF8",
        stream_format="JSONL",
        completion_framing="PROCESS_EXIT_OBSERVATION",
    )
    assert text.overlay_digest != jsonl.overlay_digest
    assert text.snapshot_digest == jsonl.snapshot_digest == snapshot.snapshot_digest
    assert SemanticPromptSnapshot.from_bytes(snapshot.to_bytes()).prompt_bytes == (
        snapshot.prompt_bytes
    )


def test_invalid_overlay_vocabulary_and_unknown_snapshot_fields_fail_closed() -> None:
    snapshot = _snapshot()
    with pytest.raises(PromptSnapshotError, match="stream_format"):
        TransportOverlay.create(
            snapshot_digest=snapshot.snapshot_digest,
            adapter_id="adapter-v1",
            stdin_mode="PROMPT_UTF8",
            stream_format="provider-default",
            completion_framing="PROCESS_EXIT_OBSERVATION",
        )

    payload = json.loads(snapshot.to_bytes())
    payload["methodology_files"][0]["local_path"] = "C:/secret/rule.md"
    with pytest.raises(PromptSnapshotError, match="unexpected"):
        SemanticPromptSnapshot.from_dict(payload)
