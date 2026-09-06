"""Regression for global attention queue identity in sharded findings."""

from pathlib import Path

import pytest

import attention_repair_shards as shards

pytestmark = pytest.mark.integration


def _contract():
    plan = {"parent_queue_binding_sha256": "a" * 64}
    shard = {
        "row_binding_sha256": "b" * 64,
        "rows": [{"row": 5, "kind": "uncited-security-file",
                  "target": "contracts/libraries/AccountEncoder.sol"}],
    }
    table = (
        "PARENT_QUEUE_BINDING_SHA256: " + "a" * 64 + "\n"
        "SHARD_BINDING_SHA256: " + "b" * 64 + "\n\n"
        "| Queue # | Kind | Target | Verdict | Evidence | Notes |\n"
        "|---|---|---|---|---|---|\n"
        "| 5 | uncited-security-file | `contracts/libraries/AccountEncoder.sol` "
        "| CONFIRMED | `contracts/libraries/AccountEncoder.sol:L27` | See {finding}. |\n\n"
    )
    return plan, shard, table


def test_first_confirmed_row_five_cannot_be_renumbered_att_one():
    plan, shard, table = _contract()
    wrong = table.format(finding="ATT-1") + (
        "### Finding [ATT-1]: reproduced p18 identity mismatch\n"
    )
    _rows, issues = shards.parse_shard_output(wrong, plan=plan, shard=shard)
    assert issues == ["worker receipt row 5 is CONFIRMED without ATT-5"]


def test_first_confirmed_row_five_uses_att_five():
    plan, shard, table = _contract()
    correct = table.format(finding="ATT-5") + (
        "### Finding [ATT-5]: global queue identity is preserved\n"
    )
    _rows, issues = shards.parse_shard_output(correct, plan=plan, shard=shard)
    assert issues == []


@pytest.mark.parametrize("heading", [
    "### Finding [ATT-50]: prefix confusion",
    "### Finding [ATT-5x]: suffix confusion",
    "### Finding [ATT-5]suffix confusion",
])
def test_row_five_rejects_non_exact_finding_identity(heading):
    plan, shard, table = _contract()
    text = table.format(finding="ATT-5") + heading + "\n"
    _rows, issues = shards.parse_shard_output(text, plan=plan, shard=shard)
    assert issues == ["worker receipt row 5 is CONFIRMED without ATT-5"]


def test_shared_methodology_states_global_queue_rule():
    prompt = (Path(__file__).resolve().parents[1] / "prompts" / "shared" / "v2"
              / "phase4b4-attention-repair.md").read_text(encoding="utf-8")
    assert "exact **global Queue #**" in prompt
    assert "if queue row 5 is" in prompt
    assert "`ATT-5`, not `ATT-1`" in prompt
