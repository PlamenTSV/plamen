from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import plamen_driver as D


def test_empty_sc_aggregate_runs_mandatory_r10_closure(
    tmp_path: Path, monkeypatch,
) -> None:
    calls = []

    def fake_close(*, scratchpad, config, phase):
        calls.append((Path(scratchpad), config["pipeline"], phase.name))
        return {"outcome": "CLEAN_ZERO"}, []

    monkeypatch.setattr(D, "_write_and_record_r10_phase_io", fake_close)
    phase = SimpleNamespace(name="sc_verify_aggregate")
    issues = D._close_empty_verify_aggregate_r10(
        scratchpad=tmp_path,
        config={"pipeline": "sc"},
        phase=phase,
    )

    assert issues == []
    assert calls == [(tmp_path, "sc", "sc_verify_aggregate")]


def test_empty_r10_closure_is_inapplicable_to_l1_and_propagates_sc_debt(
    tmp_path: Path, monkeypatch,
) -> None:
    calls = []

    def fake_close(**kwargs):
        calls.append(kwargs["phase"].name)
        return {}, ["synthetic R10 debt", "synthetic R10 debt"]

    monkeypatch.setattr(D, "_write_and_record_r10_phase_io", fake_close)
    phase = SimpleNamespace(name="verify_aggregate")
    assert D._close_empty_verify_aggregate_r10(
        scratchpad=tmp_path,
        config={"pipeline": "l1"},
        phase=phase,
    ) == []
    assert calls == []

    assert D._close_empty_verify_aggregate_r10(
        scratchpad=tmp_path,
        config={"pipeline": "sc"},
        phase=phase,
    ) == ["synthetic R10 debt"]
    assert calls == ["verify_aggregate"]


def test_empty_aggregate_placeholder_is_armed_before_write_and_committed(
    tmp_path: Path, monkeypatch,
) -> None:
    root = tmp_path / ".scratchpad"
    root.mkdir()
    for name in (
        "verification_queue.md",
        "verification_queue.work_items.json",
        "verification_queue.work_plan.json",
    ):
        (root / name).write_text("{}\n", encoding="utf-8")
    (root / "verify_core.md").write_text(
        "# Verification Core (Auto-Generated)\n\n"
        "No `verify_*.md` files found. "
        "All verification shards may have been skipped.\n\n"
        "| Finding | Verdict | Evidence | Severity |\n"
        "|---------|---------|----------|----------|\n",
        encoding="utf-8",
    )

    events: list[str] = []

    def fake_arm(**_kwargs):
        events.append("arm")
        assert not (root / "verify_core.md").exists()
        return True, []

    def fake_write(scratchpad, phase_name, reason):
        events.append("write")
        assert phase_name == "sc_verify_aggregate"
        assert reason == "typed zero queue"
        (Path(scratchpad) / "verify_core.md").write_text(
            "# verify_core: N/A\n", encoding="utf-8"
        )

    def fake_commit(**_kwargs):
        events.append("commit")
        assert (root / "verify_core.md").is_file()
        return []

    monkeypatch.setattr(D, "_arm_deterministic_driver_work_unit", fake_arm)
    monkeypatch.setattr(D, "write_empty_verify_placeholders", fake_write)
    monkeypatch.setattr(D, "_commit_deterministic_driver_work_unit", fake_commit)

    issues = D._write_empty_verify_aggregate_projection(
        scratchpad=root,
        config={
            "project_root": str(tmp_path),
            "pipeline": "sc",
            "mode": "light",
            "language": "evm",
            "cli_backend": "codex",
            "_run_id": "empty-aggregate-run",
        },
        phase=SimpleNamespace(
            name="sc_verify_aggregate", base_timeout_s=120
        ),
        reason="typed zero queue",
    )

    assert issues == []
    assert events == ["arm", "write", "commit"]
