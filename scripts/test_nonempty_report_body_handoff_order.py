"""Fixture handoff ordering only; runtime/ledger authority is substituted here.

The genuine same-run test proves those boundaries. These fast regressions keep
its child helper from requiring final DRIVER projection before returning raw
MODEL bytes to the recovery test.
"""
from pathlib import Path
from types import SimpleNamespace
import os

import pytest

import test_nonempty_low_info_body_child as helper


@pytest.mark.posix_only
@pytest.mark.skipif(os.name != "posix", reason="body fixture requires POSIX")
@pytest.mark.parametrize("raw_issues", [[], ["invalid typed raw body"]])
def test_raw_child_handoff_defers_final_projection_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, raw_issues: list[str],
) -> None:
    project = tmp_path / "project"
    root = project / ".scratchpad"
    root.mkdir(parents=True)
    config = {"_run_id": "fixture-order"}
    checkpoint = SimpleNamespace(run_id="fixture-order")
    phase = SimpleNamespace(name="report_body_writer_low_info")
    contract = SimpleNamespace(
        model_invoked=True,
        outputs=(SimpleNamespace(path="report_low_info.md"),),
    )
    launch = SimpleNamespace(model="fixture-model", timeout_s=10)
    body = "raw typed body awaiting DRIVER projection\n"
    events = []
    monkeypatch.setattr(helper, "_typed_body", lambda _root: body)
    monkeypatch.setattr(helper, "_patch_compat_codex_lookup", lambda *_args: None)
    monkeypatch.setattr(helper.D, "_posix_v2_compat_session_for_launch", lambda: object())
    monkeypatch.setattr(helper.D, "_run_report_index_routing_transaction",
                        lambda *_args: ({"report_low_info": {}}, []))
    monkeypatch.setattr(helper.D, "_ensure_report_evidence_before_body_writer",
                        lambda *_args: [])
    monkeypatch.setattr(helper.D, "_typed_model_phase_contract_and_launch",
                        lambda *_args: (contract, launch))
    monkeypatch.setattr(helper.D, "_bind_typed_model_phase_inputs", lambda *_args: [])

    def raw_child(**kwargs):
        events.append(("child", kwargs["attempt"]))
        assert kwargs["phase_io_contract"] is contract
        raw = body if kwargs["attempt"] == 1 else body.rstrip() + (
            "\n\n<!-- deterministic transport variant: report body attempt 0002 -->\n"
        )
        (root / "report_low_info.md").write_text(raw, encoding="utf-8")
        return 0

    def raw_validator(_root, shard, raw):
        events.append(("raw_validation", shard))
        assert raw.startswith(body.rstrip())
        return raw_issues

    def premature_final_gate(*_args, **_kwargs):
        pytest.fail("raw MODEL body validated before DRIVER projection")

    monkeypatch.setattr(helper.D, "_run_one_codex_exec", raw_child)
    monkeypatch.setattr(helper, "validate_typed_report_evidence_shard_markdown", raw_validator)
    monkeypatch.setattr(helper.D, "_validate_tier_body_against_manifest", premature_final_gate)
    kwargs = dict(root=root, project=project, config=config, checkpoint=checkpoint,
                  phases=[phase], monkeypatch=monkeypatch)
    if raw_issues:
        with pytest.raises(AssertionError):
            helper.run_nonempty_low_info_body_child(**kwargs)
        assert events == [("child", 1), ("raw_validation", "report_low_info")]
        return

    for attempt in (1, 2):
        assert helper.run_nonempty_low_info_body_child(**kwargs, attempt=attempt) == (
            phase, contract, launch,
        )
    assert events == [
        ("child", 1), ("raw_validation", "report_low_info"),
        ("child", 2), ("raw_validation", "report_low_info"),
    ]
