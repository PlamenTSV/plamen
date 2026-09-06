"""Mechanical crash matrix for the chain-tail terminal transaction.

The matrix is derived from the writes actually observed on the success and
failure paths.  It injects once at both sides of every durable temporary write
and atomic replace, then requires deterministic roll-forward with one semantic
application and one terminal journal event.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import chain_tail_authority as CTA


def _row() -> dict[str, object]:
    return {
        "a": "H-1",
        "b": "M-1",
        "a_sev": "High",
        "b_sev": "Medium",
        "signal": "state-graph: exact shared transition",
        "graph_backed": True,
        "score": 9.0,
        "initial_route": "CHAIN_ITER2",
    }


def _write_sources(scratchpad: Path) -> None:
    for name in (
        "composition_coverage.md",
        "chain_hypotheses.md",
        "findings_inventory.md",
    ):
        (scratchpad / name).write_text(f"# {name}\n", encoding="utf-8")


def _write_success_output(path: Path, row: dict[str, object]) -> None:
    path.write_text(
        "# Chain Iteration 2\n\n"
        "## Tail Pair Dispositions\n\n"
        "| Pair ID | Finding A | Finding B | Disposition | Evidence |\n"
        "|---|---|---|---|---|\n"
        f"| {row['pair_id']} | {row['a']} | {row['b']} | EXPLORED | "
        "exact source loci compared |\n",
        encoding="utf-8",
    )


def _fresh_transaction(root: Path, kind: str) -> tuple[Path, dict[str, object]]:
    scratchpad = root / ".scratchpad"
    scratchpad.mkdir(parents=True)
    _write_sources(scratchpad)
    CTA.initialize_chain_tail(
        scratchpad,
        [_row()],
        shard_size=1,
        activate_first_shard=False,
    )
    shard = CTA.prepare_next_chain_tail_shard(scratchpad)
    isolated = CTA.materialize_isolated_chain_tail_shard(
        scratchpad,
        shard,
        source_names=(
            "composition_coverage.md",
            "chain_hypotheses.md",
            "findings_inventory.md",
        ),
    )
    if kind == "success":
        _write_success_output(
            scratchpad / str(isolated["transcript_path"]),
            isolated["rows"][0],
        )
    return scratchpad, isolated


def _run_transaction(
    scratchpad: Path,
    isolated: dict[str, object],
    kind: str,
) -> dict[str, object]:
    if kind == "success":
        return CTA.reconcile_chain_tail_output(
            scratchpad,
            output_name=str(isolated["transcript_path"]),
            disposition_receipt_name=str(
                isolated["disposition_receipt_path"]
            ),
        )
    return CTA.record_isolated_chain_tail_failure(
        scratchpad,
        disposition_receipt_name=str(
            isolated["disposition_receipt_path"]
        ),
        reason="CHAIN_TAIL_WORKER_FAILURE",
    )


def _assert_exactly_once(
    scratchpad: Path,
    isolated: dict[str, object],
    kind: str,
) -> None:
    receipt_path = scratchpad / str(isolated["disposition_receipt_path"])
    plan_path = scratchpad / str(isolated["terminal_plan_path"])
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    assert receipt["receipt_sha256"] == CTA._digest(
        receipt, "receipt_sha256"
    )
    assert plan["plan_sha256"] == CTA._digest(plan, "plan_sha256")
    assert plan["disposition_receipt"] == receipt
    assert len(receipt["pair_results"]) == 1
    expected_terminal = "COMMITTED" if kind == "success" else "DEBT"
    assert receipt["terminal_status"] == expected_terminal

    _manifest, ledger = CTA._load_manifest_ledger(scratchpad)
    assert ledger["active_shard"] is None
    assert len(ledger["pairs"]) == 1
    assert ledger["pairs"][0]["attempts"] == 1
    journal = json.loads(
        (
            scratchpad
            / CTA.CONTROL_DIR
            / CTA.CONTROL_JOURNAL_NAME
        ).read_text(encoding="utf-8")
    )
    terminal_events = [
        row
        for row in journal["events"]
        if row.get("event") == "SHARD_TERMINAL"
    ]
    assert len(terminal_events) == 1
    assert terminal_events[0]["terminal_status"] == expected_terminal


@pytest.mark.parametrize("kind", ("success", "failure"))
def test_terminal_transaction_all_durable_failpoints_success_and_failure(
    tmp_path: Path,
    kind: str,
) -> None:
    baseline_scratchpad, baseline_isolated = _fresh_transaction(
        tmp_path / f"{kind}-baseline",
        kind,
    )
    observed: list[tuple[str, str, str]] = []

    def record(operation: str, edge: str, path: Path) -> None:
        observed.append(
            (
                operation,
                edge,
                path.relative_to(baseline_scratchpad).as_posix(),
            )
        )

    with CTA.observe_chain_tail_durable_transitions(record):
        _run_transaction(baseline_scratchpad, baseline_isolated, kind)
    _assert_exactly_once(baseline_scratchpad, baseline_isolated, kind)
    assert observed
    assert {operation for operation, _edge, _path in observed} == {
        "TEMP_WRITE",
        "ATOMIC_REPLACE",
    }
    assert {edge for _operation, edge, _path in observed} == {
        "BEFORE",
        "AFTER",
    }

    for fail_index, expected in enumerate(observed):
        scratchpad, isolated = _fresh_transaction(
            tmp_path / f"{kind}-{fail_index:03d}",
            kind,
        )
        current_index = {"value": 0}

        def fail_once(operation: str, edge: str, path: Path) -> None:
            index = current_index["value"]
            current_index["value"] += 1
            if index == fail_index:
                relative = path.relative_to(scratchpad).as_posix()
                assert (operation, edge, relative) == expected
                raise OSError(
                    "injected chain-tail durable transition failure: "
                    f"{operation}/{edge}/{relative}"
                )

        with pytest.raises(OSError, match="durable transition failure"):
            with CTA.observe_chain_tail_durable_transitions(fail_once):
                _run_transaction(scratchpad, isolated, kind)

        _run_transaction(scratchpad, isolated, kind)
        _assert_exactly_once(scratchpad, isolated, kind)
