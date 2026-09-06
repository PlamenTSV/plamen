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
from plamen_types import SC_PHASES
from test_support_startup_permit import FIXTURE_RUN_ID, durable_startup_permit


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


def test_attention_receipt_accepts_full_path_for_basename_target(
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

    assert issues == []
    assert len(rows) == 1


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
            third["row_binding_sha256"],
            "0" * 64,
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
    hard, soft = validators._validate_attention_repair(tmp_path, "thorough")
    assert hard == []
    assert soft == []
    receipt = json.loads(
        (tmp_path / "attention_repair_application_receipt.json").read_text(
            encoding="utf-8"
        )
    )
    assert len(receipt["rows"]) == 17
    assert len(receipt["accepted_paths"]) == 17


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
        reviewed = Path(r"C:\p27rt\python.exe")
        if reviewed.is_file() and int(getattr(reviewed.stat(), "st_nlink", 1)) == 1:
            provider_python = reviewed
    monkeypatch.setattr(driver, "CODEX_BIN", str(provider_python))
    monkeypatch.setattr(driver, "_codex_auth_available", lambda: True)
    monkeypatch.setattr(driver, "_codex_prompt_fits", lambda *_args: True)

    child_script = """
from pathlib import Path
import json
import os
import re
import sys

output_root = Path(sys.argv[1])
scratchpad = Path(os.environ["PLAMEN_SCRATCHPAD"])
plan = json.loads(
    (scratchpad / "attention_repair_shard_plan.json").read_text(
        encoding="utf-8"
    )
)
match = re.search(r"worker\\.attn-(\\d{4})", output_root.as_posix())
ordinal = int(match.group(1))
shard = plan["shards"][ordinal - 1]
binding = shard["row_binding_sha256"]
if ordinal == 2 and ".r0002/" not in output_root.as_posix():
    binding = "0" * 64
lines = [
    "# Attention Repair Shard Receipt",
    "",
    "PARENT_QUEUE_BINDING_SHA256: "
    + plan["parent_queue_binding_sha256"],
    "SHARD_BINDING_SHA256: " + binding,
    "",
    "| Queue # | Kind | Target | Verdict | Evidence | Notes |",
    "|---|---|---|---|---|---|",
]
for row in shard["rows"]:
    lines.append(
        f"| {row['row']} | {row['kind']} | `{row['target']}` | SAFE | "
        f"`{row['target']}:L1` reviewed | no issue |"
    )
destination = output_root / shard["output_path"]
destination.parent.mkdir(parents=True, exist_ok=True)
destination.write_text("\\n".join(lines) + "\\n", encoding="utf-8")
"""

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
    assert provider_callbacks == [
        transaction.ATTEMPT_OUTPUT_DIRECTORY_PLACEHOLDER,
        transaction.ATTEMPT_OUTPUT_DIRECTORY_PLACEHOLDER,
    ]
    first_attempts = persisted_attempt_identities()
    assert {work_unit for work_unit, _attempt_id in first_attempts} == {
        "worker.attn-0001",
        "worker.attn-0002",
    }
    assert all(
        re.fullmatch(r"attempt-[0-9a-f]{24}", attempt_id)
        for _work_unit, attempt_id in first_attempts
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
    assert provider_callbacks == [
        transaction.ATTEMPT_OUTPUT_DIRECTORY_PLACEHOLDER
    ]
    second_attempts = persisted_attempt_identities()
    assert {work_unit for work_unit, _attempt_id in second_attempts} == {
        "worker.attn-0001",
        "worker.attn-0002",
        "worker.attn-0002.r0002",
    }
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
