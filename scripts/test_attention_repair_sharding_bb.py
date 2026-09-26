from __future__ import annotations

import json
import inspect
import os
from pathlib import Path
import re
import sys

import pytest

import attention_repair_shards as shards
import plamen_driver as driver
import plamen_mechanical as mechanical
import plamen_validators as validators
import worker_transaction as transaction
from plamen_types import Phase, SC_PHASES
from test_support_startup_permit import FIXTURE_RUN_ID, durable_startup_permit
from test_claude_launch_authority_fixtures import (
    materialize_test_provider_executable,
)


def _queue(root: Path, count: int) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    mechanical._write_attention_repair_queue(
        root,
        [
            {
                "kind": "uncited-security-file",
                "target": f"contracts/Scope{index:02d}.sol",
                "reason": "uncited exact-scope file",
                "source": "scope.md",
                "evidence": f"contracts/Scope{index:02d}.sol",
            }
            for index in range(1, count + 1)
        ],
    )
    return root / "attention_repair_queue.md"


def _materialize_plan(root: Path, count: int) -> dict:
    plan = shards.build_plan(_queue(root, count))
    for shard in plan["shards"]:
        path = root / shard["input_path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(shards.render_shard_input(plan, shard))
    (root / "attention_repair_shard_plan.json").write_text(
        json.dumps(plan, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return plan


def _write_safe_output(root: Path, plan: dict, shard: dict) -> None:
    lines = [
        "# Attention Repair Shard Receipt",
        "",
        "PARENT_QUEUE_BINDING_SHA256: "
        + plan["parent_queue_binding_sha256"],
        "SHARD_BINDING_SHA256: " + shard["row_binding_sha256"],
        "",
        "| Queue # | Kind | Target | Verdict | Evidence | Notes |",
        "|---|---|---|---|---|---|",
    ]
    for row in shard["rows"]:
        lines.append(
            "| {row} | {kind} | `{target}` | SAFE | `{target}:L1` reviewed | "
            "no issue |".format(**row)
        )
    (root / shard["output_path"]).write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )


def test_attention_plan_shards_exact_17_row_union(tmp_path: Path) -> None:
    plan = _materialize_plan(tmp_path, 17)
    assert plan["shard_count"] == 3
    assert [len(shard["rows"]) for shard in plan["shards"]] == [8, 8, 1]
    assert [
        row
        for shard in plan["shards"]
        for row in shard["row_numbers"]
    ] == list(range(1, 18))
    assert shards.validate_plan(tmp_path, plan) == []


def test_attention_plan_covers_more_than_legacy_512_without_truncation(
    tmp_path: Path,
) -> None:
    assert shards.MAX_ROWS > 512
    plan = _materialize_plan(tmp_path, 513)
    assert plan["row_count"] == 513
    assert plan["shard_count"] == 65
    assert [
        row
        for shard in plan["shards"]
        for row in shard["row_numbers"]
    ] == list(range(1, 514))
    assert shards.validate_plan(tmp_path, plan) == []


def test_attention_plan_rejects_queue_beyond_hard_maximum(
    tmp_path: Path,
) -> None:
    queue = _queue(tmp_path, shards.MAX_ROWS + 1)
    with pytest.raises(
        shards.AttentionRepairShardError,
        match="exceeds the hard",
    ):
        shards.build_plan(queue)


def test_attention_plan_debt_never_falls_back_to_monolithic_model() -> None:
    source = inspect.getsource(driver.main)
    assert "retaining monolithic fallback" not in source
    assert "shard plan unavailable; monolithic execution vetoed" in source


def test_attention_plan_rejects_shard_input_tamper(tmp_path: Path) -> None:
    plan = _materialize_plan(tmp_path, 17)
    first = tmp_path / plan["shards"][0]["input_path"]
    first.write_text(
        first.read_text(encoding="utf-8").replace(
            "contracts/Scope01.sol",
            "contracts/Other.sol",
        ),
        encoding="utf-8",
    )
    assert any("input drift" in issue for issue in shards.validate_plan(tmp_path, plan))


def test_attention_receipt_rejects_full_path_alias_for_basename_target(
    tmp_path: Path,
) -> None:
    mechanical._write_attention_repair_queue(
        tmp_path,
        [
            {
                "kind": "uncited-security-file",
                "target": "BytesHelperLib.sol",
                "reason": "strict citation coverage missed the basename target",
                "source": "scip/repo_map.md",
                "evidence": "BytesHelperLib.sol",
            }
        ],
    )
    plan = shards.build_plan(tmp_path / "attention_repair_queue.md")
    shard = plan["shards"][0]
    receipt = "\n".join(
        [
            "PARENT_QUEUE_BINDING_SHA256: "
            + plan["parent_queue_binding_sha256"],
            "SHARD_BINDING_SHA256: " + shard["row_binding_sha256"],
            "",
            "| Queue # | Kind | Target | Verdict | Evidence | Notes |",
            "|---|---|---|---|---|---|",
            "| 1 | uncited-security-file | `BytesHelperLib.sol` | SAFE | "
            "`contracts/libraries/BytesHelperLib.sol:L6` reviewed | no issue |",
        ]
    )

    rows, issues = shards.parse_shard_output(
        receipt,
        plan=plan,
        shard=shard,
    )

    assert issues == [
        "worker receipt row 1 omits exact target evidence",
        "worker receipt row 1 lacks verbatim target:Lline evidence",
    ]
    assert len(rows) == 1


def test_attention_receipt_requires_verbatim_target_colon_l_line(
    tmp_path: Path,
) -> None:
    plan = _materialize_plan(tmp_path, 1)
    shard = plan["shards"][0]
    target = str(shard["rows"][0]["target"])
    base = "\n".join(
        [
            "PARENT_QUEUE_BINDING_SHA256: "
            + plan["parent_queue_binding_sha256"],
            "SHARD_BINDING_SHA256: " + shard["row_binding_sha256"],
            "",
            "| Queue # | Kind | Target | Verdict | Evidence | Notes |",
            "|---|---|---|---|---|---|",
            f"| 1 | uncited-security-file | `{target}` | SAFE | {{evidence}} | ok |",
        ]
    )

    _rows, no_l = shards.parse_shard_output(
        base.format(evidence=f"`{target}:12` reviewed"),
        plan=plan,
        shard=shard,
    )
    _rows, alias = shards.parse_shard_output(
        base.format(evidence="`Scope01.sol:L12` reviewed"),
        plan=plan,
        shard=shard,
    )
    _rows, exact = shards.parse_shard_output(
        base.format(evidence=f"`{target}:L12` reviewed"),
        plan=plan,
        shard=shard,
    )

    assert no_l == [
        "worker receipt row 1 lacks verbatim target:Lline evidence"
    ]
    assert alias == [
        "worker receipt row 1 omits exact target evidence",
        "worker receipt row 1 lacks verbatim target:Lline evidence",
    ]
    assert exact == []
    shard_input = shards.render_shard_input(plan, shard).decode("utf-8")
    assert shards.PATH_RECEIPT_CONTRACT in shard_input


def test_attention_receipt_identity_is_out_of_band_not_model_transcribed(
    tmp_path: Path,
) -> None:
    plan = _materialize_plan(tmp_path, 1)
    shard = plan["shards"][0]
    row = shard["rows"][0]
    target = str(row["target"])
    receipt = "\n".join(
        [
            "# Attention Repair Shard Receipt",
            "",
            # A legacy/foreign presentation hash must have no authority. The
            # trusted plan + launch + route bind this semantic receipt.
            "SHARD_BINDING_SHA256: " + "0" * 64,
            "",
            "| Queue # | Kind | Target | Verdict | Evidence | Notes |",
            "|---|---|---|---|---|---|",
            f"| 1 | {row['kind']} | `{target}` | SAFE | "
            f"`{target}:L1` reviewed | no issue |",
        ]
    )

    parsed, issues = shards.parse_shard_output(
        receipt,
        plan=plan,
        shard=shard,
    )

    assert issues == []
    assert len(parsed) == 1


def test_attention_summary_binding_is_derived_by_driver_not_model(
    tmp_path: Path,
) -> None:
    plan = _materialize_plan(tmp_path, 1)
    _write_safe_output(tmp_path, plan, plan["shards"][0])
    summary, findings = shards.aggregate_outputs(tmp_path, plan)
    summary_text = "\n".join(
        line
        for line in summary.decode("utf-8").splitlines()
        if not line.startswith("QUEUE_BINDING_SHA256:")
    ) + "\n"
    (tmp_path / "attention_repair_summary.md").write_text(
        summary_text,
        encoding="utf-8",
    )
    (tmp_path / "attention_repair_findings.md").write_bytes(findings)
    expected_receipt: list[bytes] = []

    hard, _soft = validators._validate_attention_repair(
        tmp_path,
        "thorough",
        expected_receipt=expected_receipt,
        require_application_receipt=False,
    )

    assert hard == []
    assert len(expected_receipt) == 1
    assert plan["parent_queue_binding_sha256"] in expected_receipt[0].decode(
        "utf-8"
    )


def test_attention_queue_rejects_nonportable_source_target(tmp_path: Path) -> None:
    queue = _queue(tmp_path, 1)
    raw = queue.read_text(encoding="utf-8")
    raw = raw.replace(
        "contracts/Scope01.sol",
        "/contracts/Scope01.sol",
    )
    # Rebinding cannot make a host-specific path portable.
    cells = shards._split_table_row(
        next(line for line in raw.splitlines() if line.startswith("| 1 |"))
    )
    rows = [{
        "row": 1,
        "kind": cells[1],
        "target": cells[2],
        "reason": cells[3],
        "source": cells[4],
        "evidence": cells[5],
    }]
    raw = re.sub(
        r"(?m)^QUEUE_BINDING_SHA256: [a-f0-9]{64}$",
        "QUEUE_BINDING_SHA256: "
        + shards.attention_queue_binding_sha256(rows),
        raw,
    )
    queue.write_text(raw, encoding="utf-8")

    with pytest.raises(
        shards.AttentionRepairShardError,
        match="not a portable relative path",
    ):
        shards.build_plan(queue)


def test_attention_retry_enumerates_only_missing_or_invalid_shards(
    tmp_path: Path,
) -> None:
    plan = _materialize_plan(tmp_path, 17)
    _write_safe_output(tmp_path, plan, plan["shards"][0])
    _write_safe_output(tmp_path, plan, plan["shards"][1])
    third = dict(plan["shards"][2])
    _write_safe_output(tmp_path, plan, third)
    third_path = tmp_path / third["output_path"]
    third_path.write_text(
        third_path.read_text(encoding="utf-8").replace(
            "| SAFE |",
            "| UNSUPPORTED |",
            1,
        ),
        encoding="utf-8",
    )
    assert [
        shard["ordinal"] for shard in shards.open_shards(tmp_path, plan)
    ] == [3]


def test_valid_looking_shards_without_current_run_authority_remain_open(
    tmp_path: Path,
) -> None:
    plan = _materialize_plan(tmp_path, 17)
    for shard in plan["shards"]:
        _write_safe_output(tmp_path, plan, shard)
    config = {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "_run_id": "attention-unowned-fixture",
    }
    assert [
        shard["ordinal"]
        for shard in driver._attention_open_shards(
            scratchpad=tmp_path,
            config=config,
            plan=plan,
        )
    ] == [1, 2, 3]
    assert any(
        "no typed producer authority" in issue
        for issue in driver._aggregate_attention_repair_shards(
            phase=next(
                item for item in SC_PHASES if item.name == "attention_repair"
            ),
            scratchpad=tmp_path,
            config={
                **config,
                "cli_backend": "claude",
                "claude_exec_mode": "headless",
                "project_root": str(tmp_path),
                "scratchpad": str(tmp_path),
            },
            plan=plan,
        )
    )


def test_attention_shard_aggregate_disposes_every_parent_row(
    tmp_path: Path,
) -> None:
    plan = _materialize_plan(tmp_path, 17)
    for shard in plan["shards"]:
        _write_safe_output(tmp_path, plan, shard)
    summary, findings = shards.aggregate_outputs(tmp_path, plan)
    (tmp_path / "attention_repair_summary.md").write_bytes(summary)
    (tmp_path / "attention_repair_findings.md").write_bytes(findings)
    expected_receipt: list[bytes] = []
    hard, soft = validators._validate_attention_repair(
        tmp_path,
        "thorough",
        expected_receipt=expected_receipt,
        require_application_receipt=False,
    )
    assert hard == []
    assert len(expected_receipt) == 1
    assert soft == []
    assert not (tmp_path / "attention_repair_application_receipt.json").exists()
    receipt = json.loads(expected_receipt[0])
    assert len(receipt["rows"]) == 17
    assert len(receipt["accepted_paths"]) == 17


@pytest.mark.parametrize("mutation", ("duplicate", "surplus"))
def test_attention_structured_receipt_requires_exact_row_denominator(
    tmp_path: Path, mutation: str,
) -> None:
    plan = _materialize_plan(tmp_path, 1)
    _write_safe_output(tmp_path, plan, plan["shards"][0])
    summary, findings = shards.aggregate_outputs(tmp_path, plan)
    text = summary.decode("utf-8")
    row = next(
        line for line in text.splitlines()
        if re.match(r"^\|\s*1\s*\|", line)
    )
    injected = (
        row.replace("| SAFE |", "| CONFIRMED |")
        if mutation == "duplicate"
        else row.replace("| 1 |", "| 99 |", 1)
    )
    (tmp_path / "attention_repair_summary.md").write_text(
        text + injected + "\n", encoding="utf-8"
    )
    (tmp_path / "attention_repair_findings.md").write_bytes(findings)
    hard, _soft = validators._validate_attention_repair(
        tmp_path,
        "thorough",
        expected_receipt=[],
        require_application_receipt=False,
    )
    expected = "duplicate structured" if mutation == "duplicate" else "surplus structured"
    assert any(expected in issue for issue in hard)


def test_monolithic_attention_receipt_is_single_publish_and_compare_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    plan = _materialize_plan(scratchpad, 1)
    (scratchpad / "attention_repair_shard_plan.json").unlink()
    phase = next(item for item in SC_PHASES if item.name == "attention_repair")
    config = {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "claude_exec_mode": "pty",
        "project_root": str(project),
        "scratchpad": str(scratchpad),
        "_run_id": "attention-monolithic-fixture",
    }
    _write_safe_output(scratchpad, plan, plan["shards"][0])
    summary, findings = shards.aggregate_outputs(scratchpad, plan)
    (scratchpad / "attention_repair_summary.md").write_bytes(summary)
    (scratchpad / "attention_repair_findings.md").write_bytes(findings)
    # This unit exercises the DRIVER-owned receipt transaction in isolation;
    # MODEL producer binding is covered by the end-to-end shard tests below.
    monkeypatch.setattr(
        driver, "_record_typed_model_phase_artifacts", lambda *_a, **_k: []
    )

    assert driver._run_attention_repair_monolithic_receipt_transaction(
        phase=phase, scratchpad=scratchpad, config=config
    ) == []
    receipt = scratchpad / "attention_repair_application_receipt.json"
    original = receipt.read_bytes()
    inode = receipt.stat().st_ino
    assert driver._run_attention_repair_monolithic_receipt_transaction(
        phase=phase, scratchpad=scratchpad, config=config
    ) == []
    assert receipt.stat().st_ino == inode
    assert receipt.read_bytes() == original

    tampered = original + b"tampered\n"
    receipt.write_bytes(tampered)
    issues = driver._run_attention_repair_monolithic_receipt_transaction(
        phase=phase, scratchpad=scratchpad, config=config
    )
    assert issues and "receipt" in issues[0]
    assert receipt.read_bytes() == tampered


def test_attention_harvest_delivers_all_twenty_four_negative_proposals(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad = tmp_path / "scratch"
    scratchpad.mkdir()
    home = tmp_path / "home"
    methodology = home / "rules" / "finding-output-format.md"
    methodology.parent.mkdir(parents=True)
    methodology.write_text("# finding contract\n", encoding="utf-8")
    monkeypatch.setattr(driver, "plamen_home", lambda: home)
    rows = [
        "| Queue # | Kind | Target | Verdict | Evidence | Notes |",
        "|---|---|---|---|---|---|",
        *[
            f"| {index} | uncited | src/C{index}.sol | SAFE | "
            f"src/C{index}.sol:L1 | reviewed |"
            for index in range(1, 25)
        ],
    ]
    (scratchpad / "attention_repair_summary.md").write_text(
        "\n".join(rows) + "\n", encoding="utf-8"
    )
    phase = Phase(
        "attention_repair",
        ["Attention"],
        ["attention_repair_summary.md"],
        base_timeout_s=60,
        min_artifact_bytes=1,
    )
    config = {
        "project_root": str(tmp_path),
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "_run_id": "attention-negative-24",
    }

    driver._harvest_candidate_negative_phase(phase, config, scratchpad)
    ledger = json.loads(
        (scratchpad / "candidate_negative_proposals_attention_repair.json").read_text()
    )
    assert ledger["event_count"] == 24
    assert len(ledger["events"]) == 24


def test_attention_shard_confirmed_requires_global_row_finding_id(
    tmp_path: Path,
) -> None:
    plan = _materialize_plan(tmp_path, 11)
    for shard in plan["shards"]:
        _write_safe_output(tmp_path, plan, shard)
    first = plan["shards"][0]
    output = tmp_path / first["output_path"]
    text = output.read_text(encoding="utf-8")
    text = text.replace(
        "| SAFE | `contracts/Scope01.sol:L1` reviewed |",
        "| CONFIRMED | `contracts/Scope01.sol:L1` reviewed |",
        1,
    )
    output.write_text(text, encoding="utf-8")
    assert any(
        "CONFIRMED without ATT-1" in issue
        for issue in shards.shard_output_issues(tmp_path, plan, first)
    )


def test_driver_sharded_attention_fanout_is_bound_and_aggregated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    for index in range(1, 18):
        path = project / "contracts" / f"Scope{index:02d}.sol"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("contract Scope {}\n", encoding="utf-8")
    _queue(scratchpad, 17)
    phase = next(item for item in SC_PHASES if item.name == "attention_repair")
    config = {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "claude_exec_mode": "headless",
        "project_root": str(project),
        "scratchpad": str(scratchpad),
        "_run_id": "attention-shard-fixture",
    }
    plan, issues = driver._prepare_attention_repair_shard_plan(
        phase=phase,
        scratchpad=scratchpad,
        config=config,
    )
    assert issues == []
    assert plan is not None
    launched: list[int] = []

    def fake_worker(**kwargs):
        shard = kwargs["shard"]
        contract = kwargs["contract"]
        launch = kwargs["launch"]
        launched.append(int(shard["ordinal"]))
        _write_safe_output(scratchpad, plan, shard)
        if int(shard["ordinal"]) == 3 and int(kwargs["attempt"]) == 1:
            output = scratchpad / shard["output_path"]
            output.unlink()
            return {
                "ordinal": int(shard["ordinal"]),
                "output": str(shard["output_path"]),
                "rc": 2,
                "issues": [
                    "staged semantic validation failed: shard binding drift"
                ],
                "status": "incomplete",
            }
        driver.record_work_unit_artifacts(
            scratchpad,
            project,
            contract,
            launch,
            run_id=config["_run_id"],
            actor="MODEL",
        )
        worker_issues = shards.shard_output_issues(
            scratchpad,
            plan,
            shard,
        )
        return {
            "ordinal": int(shard["ordinal"]),
            "output": str(shard["output_path"]),
            "rc": 0,
            "issues": worker_issues,
            "status": "complete" if not worker_issues else "incomplete",
        }

    monkeypatch.setattr(
        driver,
        "_run_attention_repair_shard_worker",
        fake_worker,
    )

    def fake_execution_authority(*, scratchpad, config, shard):
        output = Path(scratchpad) / str(shard["output_path"])
        if not output.is_file():
            return ["fixture shard output is missing"]
        identity = f"scratchpad:{shard['output_path']}"
        binding = driver.read_artifact_ledger(Path(scratchpad)).get(
            "artifact_bindings", {}
        ).get(identity)
        return (
            []
            if isinstance(binding, dict)
            and binding.get("status") == "ACTIVE"
            else ["fixture shard authority is absent"]
        )

    monkeypatch.setattr(
        driver,
        "_attention_shard_output_authority_issues",
        fake_execution_authority,
    )
    rc = driver._run_attention_repair_sharded_fanout(
        phase=phase,
        scratchpad=scratchpad,
        config=config,
        plan=plan,
        attempt=1,
        timeout=300,
        effective_model=driver.phase_model(phase, "thorough", config),
    )
    assert rc == -2
    assert sorted(launched) == [1, 2, 3]
    assert not (
        scratchpad / "attention_repair_application_receipt.json"
    ).exists()
    ledger_after_reject = driver.read_artifact_ledger(scratchpad)
    rejected_key = (
        "sc/thorough/evm/claude/attention_repair/"
        "worker.attn-0003"
    )
    assert ledger_after_reject["work_units"][rejected_key][
        "semantic_status"
    ] == "INPUTS_BOUND"
    assert ledger_after_reject["work_units"][rejected_key][
        "artifacts"
    ] == {}
    assert not (scratchpad / "attention_repair_rows_0003.md").exists()

    launched.clear()
    rc = driver._run_attention_repair_sharded_fanout(
        phase=phase,
        scratchpad=scratchpad,
        config=config,
        plan=plan,
        attempt=2,
        timeout=300,
        effective_model=driver.phase_model(phase, "thorough", config),
    )
    assert rc == 0
    assert launched == [3]
    receipt = json.loads(
        (
            scratchpad / "attention_repair_application_receipt.json"
        ).read_text(encoding="utf-8")
    )
    assert receipt["status"] == "COMPLETE"
    assert len(receipt["accepted_paths"]) == 17
    retry_key = rejected_key + ".r0002"
    assert driver.read_artifact_ledger(scratchpad)["work_units"][retry_key][
        "semantic_status"
    ] == "ACTIVE"

    launched.clear()
    receipt_path = scratchpad / "attention_repair_application_receipt.json"
    inode_before = receipt_path.stat().st_ino
    receipt_bytes = receipt_path.read_bytes()
    rc = driver._run_attention_repair_sharded_fanout(
        phase=phase,
        scratchpad=scratchpad,
        config=config,
        plan=plan,
        attempt=3,
        timeout=300,
        effective_model=driver.phase_model(phase, "thorough", config),
    )
    assert rc == 0
    assert launched == []
    assert receipt_path.stat().st_ino == inode_before
    assert receipt_path.read_bytes() == receipt_bytes

    tampered = receipt_bytes + b"tampered\n"
    receipt_path.write_bytes(tampered)
    rc = driver._run_attention_repair_sharded_fanout(
        phase=phase,
        scratchpad=scratchpad,
        config=config,
        plan=plan,
        attempt=3,
        timeout=300,
        effective_model=driver.phase_model(phase, "thorough", config),
    )
    assert rc == -2
    assert receipt_path.read_bytes() == tampered


@pytest.mark.parametrize(
    ("backend", "extra"),
    [
        ("codex", {}),
        ("claude", {"claude_exec_mode": "headless"}),
    ],
)
def test_small_headless_attention_queue_still_gets_typed_shard_plan(
    tmp_path: Path,
    backend: str,
    extra: dict,
) -> None:
    project = tmp_path / backend
    scratchpad = project / ".scratchpad"
    for index in range(1, 7):
        path = project / "contracts" / f"Scope{index:02d}.sol"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("contract Scope {}\n", encoding="utf-8")
    _queue(scratchpad, 6)
    phase = next(item for item in SC_PHASES if item.name == "attention_repair")
    config = {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": backend,
        "project_root": str(project),
        "scratchpad": str(scratchpad),
        "_run_id": FIXTURE_RUN_ID,
        "_audit_snapshot": {"snapshot_digest": "a" * 64},
        **extra,
    }
    config["_auxiliary_writable_root_startup_binding"] = durable_startup_permit(
        scratchpad,
        run_id=FIXTURE_RUN_ID,
    )
    plan, issues = driver._prepare_attention_repair_shard_plan(
        phase=phase,
        scratchpad=scratchpad,
        config=config,
    )
    assert issues == []
    assert plan is not None
    assert plan["row_count"] == 6
    assert plan["shard_count"] == 1


def test_real_transactional_shards_reject_before_publish_then_retry_missing_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
) -> None:
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    for index in range(1, 12):
        path = project / "contracts" / f"Scope{index:02d}.sol"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("contract Scope {}\n", encoding="utf-8")
    _queue(scratchpad, 11)
    phase = next(item for item in SC_PHASES if item.name == "attention_repair")
    config = {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "codex",
        "project_root": str(project),
        "scratchpad": str(scratchpad),
        "_run_id": FIXTURE_RUN_ID,
        "_audit_snapshot": {"snapshot_digest": "a" * 64},
    }
    config["_auxiliary_writable_root_startup_binding"] = durable_startup_permit(
        scratchpad,
        run_id=FIXTURE_RUN_ID,
    )
    assert driver._current_auxiliary_writable_root_startup_binding(
        scratchpad, config
    ) == config["_auxiliary_writable_root_startup_binding"]
    plan, issues = driver._prepare_attention_repair_shard_plan(
        phase=phase,
        scratchpad=scratchpad,
        config=config,
    )
    assert issues == []
    assert plan is not None

    provider_callbacks: list[str] = []
    provider_python = Path(sys.executable)
    if os.name == "nt" and int(getattr(provider_python.stat(), "st_nlink", 1)) != 1:
        provider_python = materialize_test_provider_executable(tmp_path)
    monkeypatch.setattr(driver, "CODEX_BIN", str(provider_python))
    monkeypatch.setattr(driver, "_codex_auth_available", lambda: True)
    monkeypatch.setattr(driver, "_codex_prompt_fits", lambda *_args: True)

    child_script = """
from pathlib import Path
import json
import os
import re
import sys

if sys.argv[1:] == ["--version"]:
    print("codex-cli 0.test")
    raise SystemExit(0)

prompt = sys.stdin.buffer.read().decode("utf-8")
if "-o" in sys.argv:
    blocks = re.findall(r"```json\\n(.*?)\\n```", prompt, re.S)
    route = json.loads(blocks[-1])["output_routes"][0]
    output_root = Path(route["path"]).parent
    scratchpad = Path(route["canonical_path"]).parent
    output_path = Path(route["path"])
else:
    output_root = Path(sys.argv[1])
    scratchpad = Path(os.environ["PLAMEN_SCRATCHPAD"])
    output_path = None
plan = json.loads(
    (scratchpad / "attention_repair_shard_plan.json").read_text(
        encoding="utf-8"
    )
)
match = re.search(r"worker\\.attn-(\\d{4})", output_root.as_posix())
if match is None:
    match = re.search(r"attention_repair_rows_(\\d{4})\\.md", prompt)
ordinal = int(match.group(1))
shard = plan["shards"][ordinal - 1]
first_shard_two_attempt = (
    "# PRIOR ATTEMPT DIAGNOSTICS" not in prompt
    if "-o" in sys.argv
    else ".r0002/" not in output_root.as_posix()
)
lines = [
    "# Attention Repair Shard Receipt",
    "",
    "| Queue # | Kind | Target | Verdict | Evidence | Notes |",
    "|---|---|---|---|---|---|",
]
for index, row in enumerate(shard["rows"]):
    verdict = (
        "UNSUPPORTED"
        if ordinal == 2 and first_shard_two_attempt and index == 0
        else "SAFE"
    )
    lines.append(
        f"| {row['row']} | {row['kind']} | `{row['target']}` | {verdict} | "
        f"`{row['target']}:L1` reviewed | no issue |"
    )
destination = output_path or output_root / shard["output_path"]
destination.parent.mkdir(parents=True, exist_ok=True)
destination.write_text("\\n".join(lines) + "\\n", encoding="utf-8")
if "-o" in sys.argv:
    model = sys.argv[sys.argv.index("--model") + 1]
    sys.stderr.write(
        "OpenAI Codex v0.test\\n--------\\nworkdir: /test\\n"
        f"model: {model}\\nprovider: openai\\n--------\\nuser\\n"
    )
    Path(sys.argv[sys.argv.index("-o") + 1]).write_text(
        "done\\n", encoding="utf-8"
    )
    print(json.dumps({"type": "turn.completed"}))
"""

    compat_session = None
    if os.name != "nt":
        import posix_v2_compat_runtime as compat

        provider_dir = tmp_path / "provider-bin"
        provider_dir.mkdir()
        provider_codex = provider_dir / "codex"
        provider_codex.write_text(
            "#!" + sys.executable + "\n" + child_script,
            encoding="utf-8",
        )
        provider_codex.chmod(0o700)
        fake_home = tmp_path / "account-home"
        fake_home.mkdir()
        monkeypatch.setenv(
            "PATH",
            str(provider_dir) + os.pathsep + os.environ.get("PATH", ""),
        )
        monkeypatch.delenv("CODEX_API_KEY", raising=False)
        monkeypatch.setenv("OPENAI_API_KEY", "test-only-compat-authority")
        monkeypatch.setattr(compat, "_account_home", lambda: fake_home)
        compat_session = compat.issue_posix_v2_compat_session_for_installed_front(
            run_id=FIXTURE_RUN_ID,
            project_root=project,
            scratchpad=scratchpad,
        )
        request.addfinalizer(compat_session.close)
        monkeypatch.setattr(
            driver, "_posix_v2_compat_process_active", lambda: True
        )
        monkeypatch.setattr(
            driver,
            "_posix_v2_compat_session_for_launch",
            lambda: compat_session,
        )

    def fake_codex_command(
        _model: str,
        *,
        needs_mcp: bool = False,
        output_last_message: str = "",
        writable_dirs=None,
        live_search: bool = False,
    ) -> list[str]:
        del needs_mcp, output_last_message, live_search
        output_root = str(writable_dirs[0])
        provider_callbacks.append(output_root)
        assert output_root == transaction.ATTEMPT_OUTPUT_DIRECTORY_PLACEHOLDER
        return [
                str(provider_python),
            "-I",
            "-c",
            child_script,
            output_root,
        ]

    monkeypatch.setattr(driver, "_build_codex_cmd", fake_codex_command)

    def persisted_attempt_identities() -> list[tuple[str, str]]:
        identities: list[tuple[str, str]] = []
        transaction_root = scratchpad / ".worker_transactions"
        if compat_session is not None:
            for completion_path in sorted(
                transaction_root.glob(
                    "posix_v2_compat_attention/*/compat-attempt-*/completion.json"
                )
            ):
                completion = json.loads(
                    completion_path.read_text(encoding="utf-8")
                )
                provider_completion = json.loads(
                    (
                        scratchpad
                        / completion["provider_completion_relative_path"]
                    ).read_text(encoding="utf-8")
                )
                assert provider_completion["completion_sha256"] == completion[
                    "provider_completion_digest"
                ]
                compat_receipt = json.loads(
                    (
                        scratchpad
                        / provider_completion[
                            "compatibility_receipt_relative_path"
                        ]
                    ).read_text(encoding="utf-8")
                )
                assert compat_receipt["status"] == "COMPLETED"
                assert compat_receipt["isolation"][
                    "process_group_empty_observed"
                ] is True
                assert compat_receipt["isolation"][
                    "population_zero_proven"
                ] is False
                identities.append(
                    (completion["work_unit_id"], completion["attempt_id"])
                )
            return identities
        for completion_path in sorted(
            transaction_root.glob(
                "attention_repair/*/attempts/attempt-*/completion.json"
            )
        ):
            attempt_dir = completion_path.parent
            arm_payload = json.loads(
                (attempt_dir / "arm.json").read_text(encoding="utf-8")
            )
            arm = transaction._validate_arm(
                arm_payload,
                run_id=FIXTURE_RUN_ID,
                phase_dir=attempt_dir.parents[2],
                unit_dir=attempt_dir.parents[1],
                plan_dir=attempt_dir.parent,
                attempt_dir=attempt_dir,
            )
            completion = transaction._validate_attempt_completion(
                completion_path,
                arm=arm,
            )
            provider_completion = json.loads(
                (
                    scratchpad
                    / completion["provider_completion_relative_path"]
                ).read_text(encoding="utf-8")
            )
            assert provider_completion["completion_sha256"] == completion[
                "provider_completion_digest"
            ]
            assert provider_completion["process_observation"][
                "process_population_zero_proven"
            ] is True
            identities.append(
                (completion["work_unit_id"], completion["attempt_id"])
            )
        return identities

    model = driver.phase_model(phase, "thorough", config)
    first = driver._run_attention_repair_sharded_fanout(
        phase=phase,
        scratchpad=scratchpad,
        config=config,
        plan=plan,
        attempt=1,
        timeout=30,
        effective_model=model,
    )
    assert first == -2
    if compat_session is None:
        assert provider_callbacks == [
            transaction.ATTEMPT_OUTPUT_DIRECTORY_PLACEHOLDER,
            transaction.ATTEMPT_OUTPUT_DIRECTORY_PLACEHOLDER,
        ]
    else:
        first_receipts = [
            json.loads(path.read_text(encoding="utf-8"))
            for path in sorted(
                (scratchpad / ".posix_v2_compat_receipts").glob("*.json")
            )
        ]
        assert sorted(row["status"] for row in first_receipts) == [
            "COMPLETED",
            "STAGED_SEMANTIC_REJECTED",
        ]
    first_attempts = persisted_attempt_identities()
    assert {work_unit for work_unit, _attempt_id in first_attempts} == (
        {"worker.attn-0001"}
        if compat_session is not None
        else {"worker.attn-0001", "worker.attn-0002"}
    )
    if compat_session is None:
        assert all(
            re.fullmatch(r"attempt-[0-9a-f]{24}", attempt_id)
            for _work_unit, attempt_id in first_attempts
        )
        rejected_attempt_completion_path = next(
            path
            for path in (
                scratchpad / ".worker_transactions" / "attention_repair"
            ).glob("*/attempts/attempt-*/completion.json")
            if json.loads(path.read_text(encoding="utf-8"))["work_unit_id"]
            == "worker.attn-0002"
        )
        rejected_attempt_completion = json.loads(
            rejected_attempt_completion_path.read_text(encoding="utf-8")
        )
        rejected_provider_completion_path = (
            scratchpad
            / rejected_attempt_completion["provider_completion_relative_path"]
        )
        rejected_provider_completion_bytes = (
            rejected_provider_completion_path.read_bytes()
        )
        assert json.loads(
            rejected_provider_completion_bytes.decode("utf-8")
        )["completion_sha256"] == (
            rejected_attempt_completion["provider_completion_digest"]
        )
    else:
        assert all(
            re.fullmatch(r"compat-attempt-0001-[0-9a-f]{16}", attempt_id)
            for _work_unit, attempt_id in first_attempts
        )
        rejected_provider_completion_path = next(
            path
            for path in (
                scratchpad / ".posix_v2_compat_receipts"
            ).glob("*.json")
            if json.loads(path.read_text(encoding="utf-8"))["status"]
            == "STAGED_SEMANTIC_REJECTED"
        )
        rejected_provider_completion_bytes = (
            rejected_provider_completion_path.read_bytes()
        )
    assert (scratchpad / "attention_repair_rows_0001.md").is_file()
    assert not (scratchpad / "attention_repair_rows_0002.md").exists()
    rejected = driver.read_artifact_ledger(scratchpad)["work_units"][
        "sc/thorough/evm/codex/attention_repair/worker.attn-0002"
    ]
    assert rejected["semantic_status"] == "INPUTS_BOUND"
    assert rejected["artifacts"] == {}
    assert "execution_authority" not in rejected
    assert driver._attention_shard_output_authority_issues(
        scratchpad=scratchpad,
        config=config,
        shard=plan["shards"][0],
    ) == []

    provider_callbacks.clear()
    second = driver._run_attention_repair_sharded_fanout(
        phase=phase,
        scratchpad=scratchpad,
        config=config,
        plan=plan,
        attempt=2,
        timeout=30,
        effective_model=model,
    )
    assert second == 0
    if compat_session is None:
        assert provider_callbacks == [
            transaction.ATTEMPT_OUTPUT_DIRECTORY_PLACEHOLDER
        ]
    else:
        all_receipts = [
            json.loads(path.read_text(encoding="utf-8"))
            for path in sorted(
                (scratchpad / ".posix_v2_compat_receipts").glob("*.json")
            )
        ]
        assert len(all_receipts) == 3
        assert sum(row["status"] == "COMPLETED" for row in all_receipts) == 2
    second_attempts = persisted_attempt_identities()
    assert {work_unit for work_unit, _attempt_id in second_attempts} == (
        {"worker.attn-0001", "worker.attn-0002.r0002"}
        if compat_session is not None
        else {
            "worker.attn-0001",
            "worker.attn-0002",
            "worker.attn-0002.r0002",
        }
    )
    # A semantic rejection prevents canonical publication, but it does not
    # invalidate its durable provider evidence (a native attempt completion
    # or a compatibility rejection receipt). Retrying the missing shard must
    # never clean up that predecessor evidence.
    assert (
        rejected_provider_completion_path.read_bytes()
        == rejected_provider_completion_bytes
    )
    assert driver._attention_shard_output_authority_issues(
        scratchpad=scratchpad,
        config=config,
        shard=plan["shards"][1],
    ) == []
    receipt = json.loads(
        (
            scratchpad / "attention_repair_application_receipt.json"
        ).read_text(encoding="utf-8")
    )
    assert receipt["status"] == "COMPLETE"
    assert len(receipt["accepted_paths"]) == 11
