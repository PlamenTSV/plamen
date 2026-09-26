from __future__ import annotations

import json

import plamen_driver as D


def test_codex_skeptic_packet_is_shard_local_and_preflight_budgeted() -> None:
    shard = {
        "shard_id": "candidate-negative-0001",
        "work_item_ids": ["ASW-ONE"],
        "shard_digest": "s" * 64,
    }
    plan = {
        "schema_version": "plamen.application_skeptic_work_plan.v1",
        "status": "READY",
        "work_plan_digest": "p" * 64,
        "work_item_count": 2_000,
        "work_items": [{"unrelated_full_plan_payload": "x" * 1_100_000}],
        "shards": [shard],
    }
    packet_raw = D._codex_application_skeptic_packet(
        workflow="candidate_negative",
        run_id="run-1",
        plan=plan,
        shard=shard,
        context={"assigned_work_items": [{"work_item_id": "ASW-ONE"}]},
        output_schema={"type": "object"},
        assessor_id="ASSESSOR",
        assessor_invocation_id="INVOCATION",
        output_name="candidate_negative_skeptic_assessments_0001.json",
    )
    packet = json.loads(packet_raw)
    assert "unrelated_full_plan_payload" not in packet_raw.decode("utf-8")
    assert packet["plan"] == {
        "schema_version": "plamen.application_skeptic_work_plan.v1",
        "status": "READY",
        "work_plan_digest": "p" * 64,
        "work_item_count": 2_000,
        "shard_count": 1,
        "projection_scope": "CURRENT_SHARD_ONLY",
        "projected_shard_id": "candidate-negative-0001",
        "projected_work_item_ids": ["ASW-ONE"],
    }
    prompt = D._codex_application_skeptic_prompt(packet_raw)
    assert D._codex_application_skeptic_prompt_budget_issue(prompt, {}) is None
    assert D._codex_application_skeptic_prompt_budget_issue(
        prompt, {"application_skeptic_codex_prompt_limit_chars": 10}
    ) is not None
