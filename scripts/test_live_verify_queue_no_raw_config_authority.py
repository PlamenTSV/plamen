"""The signed live plan, not raw config.json, owns runtime dimensions."""
from __future__ import annotations

from pathlib import Path

import plamen_parsers as P
from verify_queue_transaction import live_verify_queue_base_upstream_roster


def test_live_t0_does_not_require_unowned_raw_user_config() -> None:
    for pipeline in ("sc", "l1"):
        assert "config.json" not in live_verify_queue_base_upstream_roster(
            pipeline
        )


def test_mechanical_queue_writer_accepts_explicit_signed_pipeline(
    tmp_path: Path,
    monkeypatch,
) -> None:
    observed: list[str] = []

    def rows(_root: Path, pipeline: str = ""):
        observed.append(pipeline)
        return [], []

    monkeypatch.setattr(
        P, "_queue_rows_from_inventory_with_exclusions", rows
    )

    assert P._write_mechanical_verification_queue_from_inventory(
        tmp_path, pipeline="l1"
    ) == 0
    assert observed == ["l1"]
