from __future__ import annotations

import hashlib
import json
from pathlib import Path

import jsonschema
import pytest

import application_skeptic as A
import methodology_application_states as S
import skeptic_execution_work as E
from skeptic_assessment_transport import (
    application_skeptic_output_schema,
    application_skeptic_packet_context,
    application_skeptic_stdout_digest,
    compile_application_skeptic_staged_context,
    staged_application_skeptic_assessment_validator,
)


def _plan(tmp_path: Path) -> tuple[dict, Path, Path, Path]:
    root = tmp_path / "scratch"
    root.mkdir()
    home = tmp_path / "home"
    method = home / "agents" / "state" / "SKILL.md"
    method.parent.mkdir(parents=True)
    method.write_text("# exact state methodology\nstep alpha\n", encoding="utf-8")
    project = tmp_path / "project"
    source = project / "src" / "A.sol"
    source.parent.mkdir(parents=True)
    source.write_text(
        "contract A {\n  uint x;\n  function f() external {\n    x = 1;\n  }\n}\n",
        encoding="utf-8",
    )
    row = S.classify_application_row(
        {
            "phase": "breadth",
            "worker_id": "BREADTH_PRODUCER",
            "producer_invocation_id": "producer-call-1",
            "output": "analysis_state.md",
            "output_sha256": "a" * 64,
            "prompt_sha256": "b" * 64,
            "dispatch_contract_sha256": "c" * 64,
            "skill": "STATE_TRANSITIONS",
            "methodology_path": method.as_posix(),
            "methodology_sha256": hashlib.sha256(method.read_bytes()).hexdigest(),
            "step": "alpha",
            "executed": "yes",
            "evidence": "src/A.sol:L4",
            "result": "SAFE: exact transition rejected",
            "delivery_integrity": "CURRENT",
            "trace_state": "VALID",
            "evidence_basis": "IN_SCOPE_SOURCE",
        }
    )
    S.write_application_queues(root, [row], phase="breadth")
    S.write_application_queues(root, [], phase="depth")
    plan = A.write_application_skeptic_work_plan(
        root, queue_phases=("breadth", "depth")
    )
    return plan, home, root, project


def _valid_payload(plan: dict, shard: dict, assessor: str, invocation: str) -> dict:
    return {
        "schema_version": A.ASSESSMENT_SCHEMA,
        "work_plan_digest": plan["work_plan_digest"],
        "shard_id": shard["shard_id"],
        "assessments": [
            {
                "work_item_id": work_id,
                "assessor_id": assessor,
                "assessor_invocation_id": invocation,
                "outcome": "INCONCLUSIVE",
                "evidence_basis": "IN_SCOPE_SOURCE",
                "evidence": "",
                "rationale": "premise remains open",
                "candidate": None,
            }
            for work_id in shard["work_item_ids"]
        ],
    }


def test_schema_binds_wire_denominator_and_assessor(tmp_path: Path) -> None:
    plan, _home, _root, _project = _plan(tmp_path)
    shard = plan["shards"][0]
    schema = application_skeptic_output_schema(
        plan,
        shard,
        assessor_id="ASSESSOR_A",
        assessor_invocation_id="INVOCATION_A",
    )
    payload = _valid_payload(plan, shard, "ASSESSOR_A", "INVOCATION_A")
    jsonschema.Draft202012Validator(schema).validate(payload)
    assert isinstance(schema["properties"]["assessments"]["items"], dict)
    assert "prefixItems" not in schema["properties"]["assessments"]

    payload["assessments"][0]["assessor_id"] = "PRODUCER"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(payload)
    payload["assessments"][0]["assessor_id"] = "ASSESSOR_A"
    payload["assessments"][0]["extra"] = "smuggled"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(payload)


def test_codex_schema_does_not_advertise_forbidden_terminal_negative(
    tmp_path: Path,
) -> None:
    plan, _home, _root, _project = _plan(tmp_path)
    shard = plan["shards"][0]
    schema = application_skeptic_output_schema(
        plan,
        shard,
        assessor_id="ASSESSOR_A",
        assessor_invocation_id="INVOCATION_A",
        allow_agree_negative=False,
    )
    payload = _valid_payload(plan, shard, "ASSESSOR_A", "INVOCATION_A")
    payload["assessments"][0].update({
        "outcome": "AGREE_NEGATIVE",
        "evidence": "src/A.sol:L3",
        "rationale": "negative conclusion",
    })
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(payload)

    payload["assessments"][0].update({
        "outcome": "INCONCLUSIVE",
        "evidence": "",
        "rationale": "terminal-negative authority unavailable",
    })
    jsonschema.Draft202012Validator(schema).validate(payload)


def test_packet_context_contains_exact_plan_source_and_methodology_bytes(
    tmp_path: Path,
) -> None:
    plan, home, root, project = _plan(tmp_path)
    shard = plan["shards"][0]
    context = application_skeptic_packet_context(
        plan,
        shard,
        trusted_methodology_roots=(home,),
        project_root=project,
        scratchpad=root,
    )
    assigned = context["assigned_work_items"][0]
    assert assigned["work_item"] == plan["work_items"][0]
    assert assigned["methodology_bytes_sha256"] == plan["work_items"][0][
        "methodology_sha256"
    ]
    assert assigned["methodology_context_mode"] == "CONTENT_ADDRESSED_BLOB"
    assert len(context["methodology_blobs"]) == 1
    assert context["methodology_blobs"][0]["content_utf8"].encode("utf-8") == Path(
        plan["work_items"][0]["methodology_path"]
    ).read_bytes()
    assert context["source_context_state"] == (
        "COMPLETE_FOR_ALL_RESOLVED_CITATIONS"
    )
    assert context["source_context"][0]["relative_path"] == "src/A.sol"
    assert "contract A" in context["source_context"][0]["content_utf8"]
    assert context["bound_source_queues"][0]["relative_path"] == (
        "methodology_skeptic_queue_breadth.json"
    )
    assert "content_utf8" not in context["bound_source_queues"][0]
    assert context["bound_source_queues"][0]["content_projection"] == (
        "DIGEST_BOUND_ASSIGNED_ROWS_IN_WORK_ITEMS"
    )


def test_bound_queue_change_after_context_capture_is_rejected(tmp_path: Path) -> None:
    plan, home, root, project = _plan(tmp_path)
    shard = plan["shards"][0]
    context = application_skeptic_packet_context(
        plan,
        shard,
        trusted_methodology_roots=[home],
        project_root=project,
        scratchpad=root,
    )
    queue = root / "methodology_skeptic_queue_breadth.json"
    queue.write_bytes(queue.read_bytes() + b" ")
    with pytest.raises(E.SkepticExecutionWorkError, match="changed after context"):
        E.validate_skeptic_context_queue_bindings(root, context)

    rendered = A.build_application_skeptic_shard_prompt(
        plan,
        shard["shard_id"],
        trusted_methodology_roots=(home,),
        output_path=None,
        output_transport="STDOUT",
        context_transport="PACKET",
        assessor_id="ASSESSOR_A",
        assessor_invocation_id="INVOCATION_A",
    )
    assert "raw JSON object on stdout" in rendered["prompt"]
    assert "Write only:" not in rendered["prompt"]
    assert "# exact state methodology" not in rendered["prompt"]
    assert rendered["output_path"] == "PROVIDER_OWNED_STDOUT"


def test_candidate_packet_projects_assigned_rows_without_repeating_large_sources(
    tmp_path: Path,
) -> None:
    plan, _home, root, project = _plan(tmp_path)
    item = plan["work_items"][0]
    methodology = Path(item["methodology_path"])
    methodology.write_text("# bound worklist\n" + ("x" * 600_000), encoding="utf-8")
    item["methodology_sha256"] = hashlib.sha256(
        methodology.read_bytes()
    ).hexdigest()
    item["application_subject"] = "CANDIDATE_NEGATIVE"
    queue_name = item["source_queues"][0]
    queue = root / queue_name
    queue.write_bytes(queue.read_bytes() + (b" " * 3_000_000))
    plan["source_queues"][queue_name]["artifact_sha256"] = hashlib.sha256(
        queue.read_bytes()
    ).hexdigest()
    unsigned = {
        key: value for key, value in plan.items() if key != "work_plan_digest"
    }
    plan["work_plan_digest"] = A._digest(unsigned)

    context = application_skeptic_packet_context(
        plan,
        plan["shards"][0],
        trusted_methodology_roots=[methodology.parent.parent.parent],
        project_root=project,
        scratchpad=root,
        max_context_bytes=256 * 1024,
    )

    assert context["methodology_blobs"] == []
    assert context["assigned_work_items"][0]["methodology_context_mode"] == (
        "CONTENT_ADDRESSED_REFERENCE_WITH_TYPED_WORK_ITEM_PROJECTION"
    )
    assert context["bound_source_queues"][0]["size_bytes"] > 3_000_000
    assert "content_utf8" not in context["bound_source_queues"][0]
    assert context["total_bound_context_bytes"] < 256 * 1024


def test_consumer_parser_rejects_duplicate_keys_and_non_finite_values(
    tmp_path: Path,
) -> None:
    path = tmp_path / "packet.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "plamen.skeptic_execution_packet.v2",
                "plan": {"work_plan_digest": "p" * 64},
                "shard": {"shard_id": "shard-1", "work_item_ids": ["W-1"]},
                "assessor": {"identity": "A-1", "invocation_id": "I-1"},
            }
        ),
        encoding="utf-8",
    )
    payload = {
        "schema_version": A.ASSESSMENT_SCHEMA,
        "work_plan_digest": "p" * 64,
        "shard_id": "shard-1",
        "assessments": [
            {
                "work_item_id": "W-1",
                "assessor_id": "A-1",
                "assessor_invocation_id": "I-1",
                "outcome": "INCONCLUSIVE",
                "evidence_basis": "IN_SCOPE_SOURCE",
                "evidence": "",
                "rationale": "open",
                "candidate": None,
            }
        ],
    }
    valid = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    assert application_skeptic_stdout_digest(path, valid) == hashlib.sha256(
        valid
    ).hexdigest()
    with pytest.raises(A.ApplicationSkepticError, match="duplicate JSON key"):
        application_skeptic_stdout_digest(path, b'{"a":1,"a":2}')
    with pytest.raises(A.ApplicationSkepticError, match="invalid JSON constant"):
        application_skeptic_stdout_digest(path, b'{"a":NaN}')


def test_consumer_parser_enforces_exact_order_before_provider_completion(
    tmp_path: Path,
) -> None:
    path = tmp_path / "packet.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "plamen.skeptic_execution_packet.v2",
                "plan": {"work_plan_digest": "p" * 64},
                "shard": {
                    "shard_id": "shard-1",
                    "work_item_ids": ["W-1", "W-2"],
                },
                "assessor": {"identity": "A-1", "invocation_id": "I-1"},
            }
        ),
        encoding="utf-8",
    )
    rows = [
        {
            "work_item_id": work_id,
            "assessor_id": "A-1",
            "assessor_invocation_id": "I-1",
            "outcome": "INCONCLUSIVE",
            "evidence_basis": "IN_SCOPE_SOURCE",
            "evidence": "",
            "rationale": "open",
            "candidate": None,
        }
        for work_id in ("W-2", "W-1")
    ]
    raw = json.dumps(
        {
            "schema_version": A.ASSESSMENT_SCHEMA,
            "work_plan_digest": "p" * 64,
            "shard_id": "shard-1",
            "assessments": rows,
        }
    ).encode()
    with pytest.raises(A.ApplicationSkepticError, match="exact ordered"):
        application_skeptic_stdout_digest(path, raw)


def test_codex_staged_gate_is_filesystem_free_and_rejects_agree_negative(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    packet = {
        "schema_version": "plamen.skeptic_execution_packet.v2",
        "plan": {"work_plan_digest": "p" * 64},
        "shard": {"shard_id": "shard-1", "work_item_ids": ["W-1"]},
        "assessor": {"identity": "A-1", "invocation_id": "I-1"},
    }
    packet_raw = json.dumps(packet, sort_keys=True, separators=(",", ":")).encode()
    identity = "scratchpad:application_skeptic_assessments_0001.json"
    context = compile_application_skeptic_staged_context(
        packet_raw, identity, reject_agree_negative=True
    )

    def payload(outcome: str) -> bytes:
        return json.dumps(
            {
                "schema_version": A.ASSESSMENT_SCHEMA,
                "work_plan_digest": "p" * 64,
                "shard_id": "shard-1",
                "assessments": [{
                    "work_item_id": "W-1",
                    "assessor_id": "A-1",
                    "assessor_invocation_id": "I-1",
                    "outcome": outcome,
                    "evidence_basis": "IN_SCOPE_SOURCE",
                    "evidence": "src/A.sol:L3" if outcome != "INCONCLUSIVE" else "",
                    "rationale": "independent assessment",
                    "candidate": (
                        {"title": "t", "mechanism": "m", "harm": "h"}
                        if outcome == "DISAGREE_CANDIDATE" else None
                    ),
                }],
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()

    monkeypatch.setattr(
        Path,
        "read_bytes",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("staged validator consulted the filesystem")
        ),
    )
    assert staged_application_skeptic_assessment_validator(
        {identity: payload("DISAGREE_CANDIDATE")}, context
    ) == ()
    reasons = staged_application_skeptic_assessment_validator(
        {identity: payload("AGREE_NEGATIVE")}, context
    )
    assert reasons and "lacks equivalent terminal-negative authority" in reasons[0]


@pytest.mark.parametrize(
    "raw",
    (
        b'{"schema_version":"plamen.application_skeptic_assessments.v1",'
        b'"work_plan_digest":"x","work_plan_digest":"y"}',
        b'{"schema_version":"plamen.application_skeptic_assessments.v1",'
        b'"work_plan_digest":NaN}',
    ),
)
def test_codex_staged_gate_rejects_duplicate_and_nonfinite_json(raw: bytes) -> None:
    packet = {
        "schema_version": "plamen.skeptic_execution_packet.v2",
        "plan": {"work_plan_digest": "p" * 64},
        "shard": {"shard_id": "shard-1", "work_item_ids": ["W-1"]},
        "assessor": {"identity": "A-1", "invocation_id": "I-1"},
    }
    identity = "scratchpad:application_skeptic_assessments_0001.json"
    context = compile_application_skeptic_staged_context(
        json.dumps(packet).encode(), identity, reject_agree_negative=True
    )
    assert staged_application_skeptic_assessment_validator(
        {identity: raw}, context
    )
