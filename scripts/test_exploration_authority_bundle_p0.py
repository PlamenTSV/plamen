from __future__ import annotations

from dataclasses import replace
import base64
import hashlib
import json
from pathlib import Path

import pytest

from depth_self_exclusion_publication import (
    DepthSelfExclusionPublicationError,
    build_depth_self_exclusion_publication,
    render_depth_self_exclusion_reemit,
    validate_depth_self_exclusion_publication,
)
from exploration_authority_bundle import (
    EXPLORATION_CLEAR_STAGED_GATE_SCHEMA,
    ExplorationAuthorityError,
    PRIOR_ALIAS_NAME,
    PRIOR_SNAPSHOT_NAME,
    RepairProviderOutcome,
    build_immutable_prior_bundle,
    build_repair_terminal_companion,
    compile_repair_provider_outcome,
    load_immutable_prior_bundle,
    load_immutable_prior_bundle_bytes,
    staged_exploration_clear_response_validator,
    validate_repair_terminal_companion,
)


def test_staged_exploration_clear_gate_requires_exact_plan_denominator() -> None:
    identity = "scratchpad:exploration_clear_repair_response.md"
    plan_id = "ECRP-0123456789ABCDEF01234567"
    plan_hash = "a" * 64
    context = {
        "schema": EXPLORATION_CLEAR_STAGED_GATE_SCHEMA,
        "output_identity": identity,
        "plan_id": plan_id,
        "plan_hash": plan_hash,
        "obligation_ids": ["ECLR-ONE", "ECLR-TWO"],
    }
    response = (
        "# Exploration Clear Repair\n\n"
        f"**Plan ID**: {plan_id}\n"
        f"**Plan Hash**: {plan_hash}\n\n"
        "## Repair Dispositions\n\n"
        "| Obligation ID | Disposition | Evidence | Action ID | Rationale |\n"
        "|---|---|---|---|---|\n"
        "| ECLR-ONE | CLEAR | contracts/A.sol:10 |  | exact guard |\n"
        "| ECLR-TWO | UNRESOLVED | none |  | needs review |\n"
    ).encode()
    assert staged_exploration_clear_response_validator(
        {identity: response}, context
    ) == ()

    missing = response.replace(
        b"| ECLR-TWO | UNRESOLVED | none |  | needs review |\n", b""
    )
    issues = staged_exploration_clear_response_validator(
        {identity: missing}, context
    )
    assert any("denominator differs" in issue for issue in issues)


def _json_bytes(payload: dict) -> bytes:
    return (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode()


def _identity_map(local_id: str = "OLD-1") -> bytes:
    row = {
        "canonical_id": "CID-0123456789ABCDEF",
        "artifact": "analysis_core_state.md",
        "local_id": local_id,
        "local_id_raw": local_id,
        "offset": 10,
    }
    return _json_bytes({
        "schema_version": "plamen.canonical_finding_ids.v1",
        "record_count": 1,
        "records": [row],
    })


def _plan_arm() -> tuple[bytes, bytes]:
    receipt_hash = "b" * 64
    plan = {
        "schema_version": "plamen.exploration_clear_repair_plan.v1",
        "plan_id": "ECRP-0123456789ABCDEF01234567",
        "attempt": 1,
        "source_receipt_hash": receipt_hash,
        "source_artifact_sha256": "c" * 64,
        "obligation_ids": [],
        "items": [],
    }
    plan["plan_hash"] = hashlib.sha256(
        json.dumps(
            plan,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    arm = {
        "schema_version": "plamen.exploration_clear_repair_attempt.v1",
        "plan_id": plan["plan_id"],
        "plan_hash": plan["plan_hash"],
        "source_receipt_hash": receipt_hash,
        "invocation_id": "ECRA-0123456789ABCDEF01234567",
        "status": "ARMED",
        "phase": "exploration_clear",
        "backend": "codex",
        "model": "gpt-5.6-terra",
        "timeout_s": 3600,
        "return_code": None,
    }
    return _json_bytes(plan), _json_bytes(arm)


def test_depth_reemit_publication_binds_exact_sorted_sources_and_bytes():
    recovered = [
        {"source": "depth_z_findings.md", "own_id": "DZ-1"},
        {"source": "depth_a_findings.md", "own_id": "DA-1"},
        {"source": "depth_z_findings.md", "own_id": "DZ-2"},
    ]
    sources = {
        "depth_z_findings.md": b"z-source\n",
        "depth_a_findings.md": b"a-source\n",
    }
    rendered = (
        b"# Depth Self-Exclusion Re-Emit\n\n"
        b"### Finding [DXRE-1]: retained\n\n"
        b"<!-- PLAMEN_STATUS: COMPLETE -->\n"
    )
    publication = build_depth_self_exclusion_publication(
        recovered=recovered,
        rendered_bytes=rendered,
        source_bytes=sources,
    )
    assert publication.exact_source_names == (
        "depth_a_findings.md", "depth_z_findings.md",
    )
    assert publication.exact_outputs == (
        "depth_selfexcl_reemit_findings.md",
    )
    assert publication.output_vector == {
        "depth_selfexcl_reemit_findings.md": rendered
    }
    validate_depth_self_exclusion_publication(
        publication, source_bytes=sources
    )


def test_depth_renderer_preserves_contentless_single_record_exclusion():
    raw = render_depth_self_exclusion_reemit([{
        "source": "depth_a_findings.md", "own_id": "DA-1",
        "line_text": "absorbed", "content_bearing": False,
    }])
    text = raw.decode()
    assert "### Review Disposition [DXRE-1]" in text
    assert "CONTENT_LESS_HUMAN_REVIEW" in text
    assert "### Finding [DXRE-1]" not in text


def test_depth_reemit_publication_rejects_source_or_output_drift():
    recovered = [{"source": "depth_a_findings.md", "own_id": "DA-1"}]
    rendered = b"# Reemit\n<!-- PLAMEN_STATUS: COMPLETE -->\n"
    publication = build_depth_self_exclusion_publication(
        recovered=recovered,
        rendered_bytes=rendered,
        source_bytes={"depth_a_findings.md": b"before"},
    )
    with pytest.raises(
        DepthSelfExclusionPublicationError,
        match="source bytes changed",
    ):
        validate_depth_self_exclusion_publication(
            publication,
            source_bytes={"depth_a_findings.md": b"after"},
        )
    with pytest.raises(
        DepthSelfExclusionPublicationError,
        match="output bytes changed",
    ):
        validate_depth_self_exclusion_publication(
            replace(publication, output_bytes=rendered + b"tamper"),
            source_bytes={"depth_a_findings.md": b"before"},
        )


def test_depth_reemit_publication_rejects_unbound_or_ambiguous_sources():
    marker = b"<!-- PLAMEN_STATUS: COMPLETE -->"
    with pytest.raises(
        DepthSelfExclusionPublicationError,
        match="source-byte denominator",
    ):
        build_depth_self_exclusion_publication(
            recovered=[{"source": "depth_a_findings.md"}],
            rendered_bytes=marker,
            source_bytes={},
        )
    with pytest.raises(
        DepthSelfExclusionPublicationError,
        match="collide case-insensitively",
    ):
        build_depth_self_exclusion_publication(
            recovered=[
                {"source": "depth_A_findings.md"},
                {"source": "depth_a_findings.md"},
            ],
            rendered_bytes=marker,
            source_bytes={
                "depth_A_findings.md": b"a",
                "depth_a_findings.md": b"b",
            },
        )


def test_prior_alias_replays_from_snapshot_after_live_map_changes(tmp_path: Path):
    original = _identity_map("OLD-1")
    bundle = build_immutable_prior_bundle(original)
    (tmp_path / PRIOR_SNAPSHOT_NAME).write_bytes(bundle.snapshot_bytes)
    (tmp_path / PRIOR_ALIAS_NAME).write_bytes(bundle.alias_bytes)
    # This mutable file is intentionally no longer part of alias replay.
    (tmp_path / "_canonical_finding_ids.json").write_bytes(
        _identity_map("NEW-2")
    )
    loaded = load_immutable_prior_bundle(tmp_path)
    assert loaded.aliases["OLD-1"] == "CID-0123456789ABCDEF"
    assert "NEW-2" not in loaded.aliases


def test_prior_bundle_freezes_an_absent_identity_map():
    bundle = build_immutable_prior_bundle(None)
    loaded = load_immutable_prior_bundle_bytes(
        snapshot_bytes=bundle.snapshot_bytes, alias_bytes=bundle.alias_bytes,
    )
    assert loaded.snapshot_payload["source_present"] is False
    assert loaded.aliases == {}


def test_prior_bundle_rejects_snapshot_or_alias_tampering():
    bundle = build_immutable_prior_bundle(_identity_map())
    snapshot = json.loads(bundle.snapshot_bytes)
    source = json.loads(base64.b64decode(snapshot["source_content_b64"]))
    source["records"][0]["local_id"] = "FORGED-1"
    snapshot["source_content_b64"] = base64.b64encode(
        _json_bytes(source)
    ).decode()
    tampered_snapshot = _json_bytes(snapshot)
    with pytest.raises(ExplorationAuthorityError):
        load_immutable_prior_bundle_bytes(
            snapshot_bytes=tampered_snapshot,
            alias_bytes=bundle.alias_bytes,
        )
    alias = json.loads(bundle.alias_bytes)
    alias["aliases"]["OLD-1"] = "CID-FFFFFFFFFFFFFFFF"
    unsigned = {k: v for k, v in alias.items() if k != "alias_receipt_sha256"}
    alias["alias_receipt_sha256"] = hashlib.sha256(
        json.dumps(
            unsigned,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    with pytest.raises(
        ExplorationAuthorityError,
        match="semantic parity mismatch",
    ):
        load_immutable_prior_bundle_bytes(
            snapshot_bytes=bundle.snapshot_bytes,
            alias_bytes=_json_bytes(alias),
        )


def test_terminal_companion_binds_plan_arm_provider_and_response():
    plan, arm = _plan_arm()
    arm_before = bytes(arm)
    response = b"# Exploration Clear Repair\n"
    provider_outcome = compile_repair_provider_outcome(
        terminal_status="COMPLETED", provider_status="COMPLETED",
        return_code=0, failure_code="",
        outcome_artifact="exploration_clear_repair_response.md",
        outcome_bytes=response,
    )
    provider = provider_outcome.provider_receipt_bytes
    result = build_repair_terminal_companion(
        plan_bytes=plan,
        arm_bytes=arm,
        outcome=provider_outcome,
    )
    assert arm == arm_before
    assert result.payload["terminal_status"] == "COMPLETED"
    assert result.payload["arm_sha256"] == hashlib.sha256(arm).hexdigest()
    validate_repair_terminal_companion(
        result.file_bytes,
        plan_bytes=plan,
        arm_bytes=arm,
        provider_receipt_bytes=provider,
        outcome_bytes=response,
    )


def test_compiled_provider_outcome_binds_exact_outcome_bytes():
    outcome = compile_repair_provider_outcome(
        terminal_status="COMPLETED", provider_status="COMPLETED",
        return_code=0, failure_code="",
        outcome_artifact="exploration_clear_repair_response.md",
        outcome_bytes=b"response", issues=("same", "same"),
    )
    payload = json.loads(outcome.provider_receipt_bytes)
    assert payload["issues"] == ["same"]
    assert payload["outcome_sha256"] == hashlib.sha256(b"response").hexdigest()


@pytest.mark.parametrize("changed", ["plan", "arm", "provider", "outcome"])
def test_terminal_companion_rejects_any_input_drift(changed: str):
    plan, arm = _plan_arm()
    response = b"repair-response"
    provider_outcome = compile_repair_provider_outcome(
        terminal_status="COMPLETED", provider_status="COMPLETED",
        return_code=0, failure_code="",
        outcome_artifact="exploration_clear_repair_response.md",
        outcome_bytes=response,
    )
    provider = provider_outcome.provider_receipt_bytes
    result = build_repair_terminal_companion(
        plan_bytes=plan,
        arm_bytes=arm,
        outcome=provider_outcome,
    )
    inputs = {
        "plan_bytes": plan,
        "arm_bytes": arm,
        "provider_receipt_bytes": provider,
        "outcome_bytes": response,
    }
    inputs[f"{changed}_bytes" if changed != "provider" else "provider_receipt_bytes"] += b"x"
    with pytest.raises(ExplorationAuthorityError):
        validate_repair_terminal_companion(result.file_bytes, **inputs)


def test_completed_terminal_companion_rejects_nonzero_provider_result():
    plan, arm = _plan_arm()
    with pytest.raises(
        ExplorationAuthorityError,
        match="lacks completed provider outcome",
    ):
        build_repair_terminal_companion(
            plan_bytes=plan,
            arm_bytes=arm,
            outcome=RepairProviderOutcome(
                terminal_status="COMPLETED",
                provider_status="STAGED_SEMANTIC_REJECTED",
                return_code=-2,
                failure_code="STAGED_SEMANTIC_REJECTED",
                provider_receipt_artifact="provider.json",
                provider_receipt_bytes=b"provider",
                outcome_artifact="exploration_clear_repair_failure.json",
                outcome_bytes=b"failure",
            ),
        )
