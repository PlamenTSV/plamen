"""Exact Markdown-cell preservation for attention-repair receipts."""

from __future__ import annotations

from pathlib import Path

import attention_repair_shards as shards
from plamen_types import attention_queue_binding_sha256


def test_inline_code_plus_prose_keeps_balanced_ticks_through_aggregation(
    tmp_path: Path,
) -> None:
    target = "contracts/GatewaySend.sol"
    rows = [{
        "row": 1,
        "kind": "uncited-security-file",
        "target": target,
        "reason": "review the callback boundary",
        "source": "scope.md",
        "evidence": target,
    }]
    binding = attention_queue_binding_sha256(rows)
    queue = tmp_path / "attention_repair_queue.md"
    queue.write_text(
        "# Attention Repair Queue\n\n"
        f"QUEUE_BINDING_SHA256: {binding}\n\n"
        "| # | Kind | Target | Reason | Source | Evidence hint |\n"
        "|---|---|---|---|---|---|\n"
        f"| 1 | uncited-security-file | `{target}` | review the callback boundary "
        f"| `scope.md` | `{target}` |\n",
        encoding="utf-8",
    )
    plan = shards.build_plan(queue)
    shard = plan["shards"][0]
    shard_input = tmp_path / str(shard["input_path"])
    shard_input.parent.mkdir(parents=True)
    shard_input.write_bytes(shards.render_shard_input(plan, shard))
    inline_evidence = f"`{target}:L341` gates the callback"
    output = tmp_path / str(shard["output_path"])
    output.write_text(
        "# Attention Repair Shard Receipt\n\n"
        f"PARENT_QUEUE_BINDING_SHA256: {plan['parent_queue_binding_sha256']}\n"
        f"SHARD_BINDING_SHA256: {shard['row_binding_sha256']}\n\n"
        "| Queue # | Kind | Target | Verdict | Evidence | Notes |\n"
        "|---|---|---|---|---|---|\n"
        f"| 1 | uncited-security-file | `{target}` | SAFE | "
        f"{inline_evidence} | exact source review |\n",
        encoding="utf-8",
    )

    parsed, issues = shards.parse_shard_output(
        output.read_text(encoding="utf-8"), plan=plan, shard=shard
    )
    assert issues == []
    assert parsed[0][4] == inline_evidence

    summary, _findings = shards.aggregate_outputs(tmp_path, plan)
    summary_text = summary.decode("utf-8")
    assert inline_evidence in summary_text
    assert f"{target}:L341``" not in summary_text
