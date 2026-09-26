from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import uuid

import pytest

import attention_repair_shards as shards
import plamen_driver as driver
import plamen_mechanical as mechanical
from plamen_types import SC_PHASES


RUN_ID = "attention-posix-compat-fixture"


def _queue(root: Path, count: int) -> None:
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


def _safe_output(root: Path, plan: dict, shard: dict, *, valid: bool) -> bytes:
    lines = [
        "# Attention Repair Shard Receipt",
        "",
        "| Queue # | Kind | Target | Verdict | Evidence | Notes |",
        "|---|---|---|---|---|---|",
    ]
    for index, row in enumerate(shard["rows"]):
        verdict = "SAFE" if valid or index else "UNSUPPORTED"
        lines.append(
            "| {row} | {kind} | `{target}` | {verdict} | "
            "`{target}:L1` reviewed | no issue |".format(
                verdict=verdict, **row
            )
        )
    raw = ("\n".join(lines) + "\n").encode()
    (root / shard["output_path"]).write_bytes(raw)
    return raw


def _runtime_json(value: dict) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _write_compat_receipt(
    *,
    scratchpad: Path,
    project: Path,
    contract,
    launch,
    label: str,
    attempt: int,
    prompt: str,
    output_raw: bytes,
) -> Path:
    ledger = driver.read_artifact_ledger(scratchpad)
    unit = ledger["work_units"][contract.key]
    input_routes = []
    for identity in sorted(
        {*contract.immutable_inputs, *contract.bounded_lookup_inputs}
    ):
        root_name, relative = identity.split(":", 1)
        route_root = scratchpad if root_name == "scratchpad" else project
        binding = unit["input_bindings"][identity]
        input_routes.append(
            {
                "identity": identity,
                "path": os.fspath((route_root / relative).resolve()),
                "class": (
                    "IMMUTABLE"
                    if identity in contract.immutable_inputs
                    else "BOUNDED_LOOKUP"
                ),
                "binding_status": binding["status"],
                "sha256": binding["sha256"],
                "size": binding["size"],
            }
        )
    spec = contract.outputs[0]
    identity = spec.identity
    relative = identity.removeprefix("scratchpad:")
    prestate = unit["output_prestates"][identity]
    invocation = uuid.uuid4().hex
    output_path = (scratchpad / relative).resolve()
    staged_output_path = (
        scratchpad
        / ".posix_v2_compat_private"
        / invocation
        / "staged-output"
        / relative
    ).resolve()
    output_routes = [
        {
            "identity": identity,
            "path": os.fspath(staged_output_path),
            "canonical_path": os.fspath(output_path),
            "write_mode": spec.write_mode,
            "prestate_status": prestate["status"],
            "prestate_existed": prestate["existed"],
            "prestate_sha256": prestate["sha256"],
            "prestate_size": prestate["size"],
        }
    ]
    stdout = b"compat worker complete\n"
    stderr = b""
    (scratchpad / f"_stdio_{label}.attempt{attempt}.log").write_bytes(stdout)
    prompt_sha = hashlib.sha256(prompt.encode()).hexdigest()
    receipt = {
        "schema": driver._POSIX_V2_COMPAT_EXECUTION_RECEIPT_SCHEMA,
        "status": "COMPLETED",
        "failure_code": None,
        "run_id": RUN_ID,
        "phase": "attention_repair",
        "label": label,
        "attempt": attempt,
        "invocation_id": invocation,
        "backend": "codex",
        "requested_model": launch.model,
        "model_binding": "EXPLICIT_CLI_ARGUMENT",
        "observed_model": launch.model,
        "model_observation": "MATCH",
        "methodology_prompt_sha256": prompt_sha,
        "prompt_sha256": prompt_sha,
        "phase_io_contract_digest": contract.digest,
        "phase_io_launch_digest": launch.digest,
        "phase_io_input_set_digest": unit["input_set_digest"],
        "phase_io_output_prestate_digest": unit["output_prestate_digest"],
        "phase_io_input_routes": input_routes,
        "phase_io_output_routes": output_routes,
        "phase_io_input_routes_digest": hashlib.sha256(
            _runtime_json({"routes": input_routes})
        ).hexdigest(),
        "phase_io_output_routes_digest": hashlib.sha256(
            _runtime_json({"routes": output_routes})
        ).hexdigest(),
        "completed_output_evidence": [
            {
                "path": os.fspath(output_path),
                "sha256": hashlib.sha256(output_raw).hexdigest(),
                "size": len(output_raw),
            }
        ],
        "returncode": 0,
        "compatibility_return_value": 0,
        "timed_out": False,
        "overflowed_stream": None,
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "stdout_size": len(stdout),
        "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
        "stderr_size": len(stderr),
    }
    receipt["receipt_sha256"] = hashlib.sha256(
        _runtime_json(receipt)
    ).hexdigest()
    receipt_root = scratchpad / ".posix_v2_compat_receipts"
    receipt_root.mkdir(exist_ok=True)
    path = receipt_root / (
        f"attention_repair.{label}.attempt{attempt}.{invocation}.json"
    )
    path.write_bytes(_runtime_json(receipt) + b"\n")
    return path


def _fixture(tmp_path: Path, count: int = 11):
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    for index in range(1, count + 1):
        source = project / "contracts" / f"Scope{index:02d}.sol"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text("contract Scope {}\n", encoding="utf-8")
    _queue(scratchpad, count)
    phase = next(row for row in SC_PHASES if row.name == "attention_repair")
    config = {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "codex",
        "project_root": str(project),
        "scratchpad": str(scratchpad),
        "_run_id": RUN_ID,
    }
    plan, issues = driver._prepare_attention_repair_shard_plan(
        phase=phase,
        scratchpad=scratchpad,
        config=config,
    )
    assert issues == []
    assert plan is not None
    return project, scratchpad, phase, config, plan


def test_compat_attention_leaf_commits_exact_model_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, scratchpad, phase, config, plan = _fixture(tmp_path, 6)
    shard = plan["shards"][0]
    model = driver.phase_model(phase, "thorough", config)
    contract, launch, issues = driver._bind_attention_shard_worker(
        phase=phase,
        scratchpad=scratchpad,
        config=config,
        shard=shard,
        timeout=30,
        effective_model=model,
        attempt=1,
    )
    assert issues == [] and contract is not None and launch is not None
    prompt = driver._attention_shard_worker_prompt(
        scratchpad=scratchpad,
        project_root=project,
        plan=plan,
        shard=shard,
    )
    raw = _safe_output(scratchpad, plan, shard, valid=True)
    receipt_path = _write_compat_receipt(
        scratchpad=scratchpad,
        project=project,
        contract=contract,
        launch=launch,
        label="attention_shard_0001",
        attempt=1,
        prompt=prompt,
        output_raw=raw,
    )
    receipt = json.loads(receipt_path.read_text(encoding="ascii"))
    invocation_id = receipt["invocation_id"]
    assert receipt["phase_io_output_routes"][0]["path"] == os.fspath(
        (
            scratchpad
            / ".posix_v2_compat_private"
            / invocation_id
            / "staged-output"
            / shard["output_path"]
        ).resolve()
    )
    assert receipt["phase_io_output_routes"][0][
        "canonical_path"
    ] == os.fspath((scratchpad / shard["output_path"]).resolve())
    monkeypatch.setattr(driver, "_posix_v2_compat_process_active", lambda: True)

    assert driver._commit_posix_v2_compat_attention_shard(
        scratchpad=scratchpad,
        config=config,
        plan=plan,
        shard=shard,
        contract=contract,
        launch=launch,
        label="attention_shard_0001",
        attempt=1,
        prompt=prompt,
    ) == []
    unit = driver.read_artifact_ledger(scratchpad)["work_units"][contract.key]
    assert unit["semantic_status"] == "ACTIVE"
    assert unit["execution_state"] == "OUTPUT_COMMITTED"
    assert driver._attention_shard_output_authority_issues(
        scratchpad=scratchpad,
        config=config,
        shard=shard,
    ) == []


def test_compat_attention_receipt_rejects_invocation_route_drift(
    tmp_path: Path,
) -> None:
    project, scratchpad, phase, config, plan = _fixture(tmp_path, 6)
    shard = plan["shards"][0]
    model = driver.phase_model(phase, "thorough", config)
    contract, launch, issues = driver._bind_attention_shard_worker(
        phase=phase,
        scratchpad=scratchpad,
        config=config,
        shard=shard,
        timeout=30,
        effective_model=model,
        attempt=1,
    )
    assert issues == [] and contract is not None and launch is not None
    prompt = driver._attention_shard_worker_prompt(
        scratchpad=scratchpad,
        project_root=project,
        plan=plan,
        shard=shard,
    )
    raw = _safe_output(scratchpad, plan, shard, valid=True)
    receipt_path = _write_compat_receipt(
        scratchpad=scratchpad,
        project=project,
        contract=contract,
        launch=launch,
        label="attention_shard_0001",
        attempt=1,
        prompt=prompt,
        output_raw=raw,
    )
    receipt = json.loads(receipt_path.read_text(encoding="ascii"))
    route = receipt["phase_io_output_routes"][0]
    route["path"] = os.fspath(
        (
            scratchpad
            / ".posix_v2_compat_private"
            / uuid.uuid4().hex
            / "staged-output"
            / shard["output_path"]
        ).resolve()
    )
    receipt["phase_io_output_routes_digest"] = hashlib.sha256(
        _runtime_json({"routes": receipt["phase_io_output_routes"]})
    ).hexdigest()
    receipt.pop("receipt_sha256")
    receipt["receipt_sha256"] = hashlib.sha256(
        _runtime_json(receipt)
    ).hexdigest()
    receipt_path.write_bytes(_runtime_json(receipt) + b"\n")

    _, observed_path, receipt_issues = driver._attention_posix_compat_receipt(
        scratchpad=scratchpad,
        config=config,
        shard=shard,
        contract=contract,
        launch=launch,
        label="attention_shard_0001",
        attempt=1,
        prompt_sha256=hashlib.sha256(prompt.encode()).hexdigest(),
    )
    assert observed_path == receipt_path
    assert receipt_issues == ["compat receipt output route drift"]


def test_compat_attention_rejects_then_retries_only_invalid_shard(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, scratchpad, phase, config, plan = _fixture(tmp_path, 11)
    monkeypatch.setattr(driver, "_posix_v2_compat_process_active", lambda: True)
    launches: list[tuple[str, int]] = []
    retry_prompts: list[str] = []

    def fake_exec(**kwargs) -> int:
        label = kwargs["label"]
        attempt = kwargs["attempt"]
        ordinal = int(label.rsplit("_", 1)[1])
        shard = plan["shards"][ordinal - 1]
        valid = not (ordinal == 2 and attempt == 1)
        if attempt > 1:
            retry_prompts.append(kwargs["prompt"])
        raw = _safe_output(scratchpad, plan, shard, valid=valid)
        _write_compat_receipt(
            scratchpad=scratchpad,
            project=project,
            contract=kwargs["phase_io_contract"],
            launch=kwargs["phase_io_launch"],
            label=label,
            attempt=attempt,
            prompt=kwargs["prompt"],
            output_raw=raw,
        )
        launches.append((label, attempt))
        return 0

    monkeypatch.setattr(driver, "_run_one_codex_exec", fake_exec)
    model = driver.phase_model(phase, "thorough", config)
    assert driver._run_attention_repair_sharded_fanout(
        phase=phase,
        scratchpad=scratchpad,
        config=config,
        plan=plan,
        attempt=1,
        timeout=30,
        effective_model=model,
    ) == -2
    assert sorted(launches) == [
        ("attention_shard_0001", 1),
        ("attention_shard_0002", 1),
    ]
    assert not (scratchpad / plan["shards"][1]["output_path"]).exists()
    assert list(
        (scratchpad / ".posix_v2_compat_rejected" / "attention_repair").glob(
            "attention_shard_0002.attempt1.*.md"
        )
    )

    launches.clear()
    assert driver._run_attention_repair_sharded_fanout(
        phase=phase,
        scratchpad=scratchpad,
        config=config,
        plan=plan,
        attempt=2,
        timeout=30,
        effective_model=model,
    ) == 0
    assert launches == [("attention_shard_0002", 2)]
    assert len(retry_prompts) == 1
    assert "# PRIOR ATTEMPT DIAGNOSTICS" in retry_prompts[0]
    assert "verdict is unsupported" in retry_prompts[0]


def test_compat_attention_authority_rejects_tampered_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, scratchpad, phase, config, plan = _fixture(tmp_path, 6)
    shard = plan["shards"][0]
    model = driver.phase_model(phase, "thorough", config)
    contract, launch, issues = driver._bind_attention_shard_worker(
        phase=phase,
        scratchpad=scratchpad,
        config=config,
        shard=shard,
        timeout=30,
        effective_model=model,
        attempt=1,
    )
    assert issues == [] and contract is not None and launch is not None
    prompt = driver._attention_shard_worker_prompt(
        scratchpad=scratchpad,
        project_root=project,
        plan=plan,
        shard=shard,
    )
    raw = _safe_output(scratchpad, plan, shard, valid=True)
    receipt_path = _write_compat_receipt(
        scratchpad=scratchpad,
        project=project,
        contract=contract,
        launch=launch,
        label="attention_shard_0001",
        attempt=1,
        prompt=prompt,
        output_raw=raw,
    )
    monkeypatch.setattr(driver, "_posix_v2_compat_process_active", lambda: True)
    assert driver._commit_posix_v2_compat_attention_shard(
        scratchpad=scratchpad,
        config=config,
        plan=plan,
        shard=shard,
        contract=contract,
        launch=launch,
        label="attention_shard_0001",
        attempt=1,
        prompt=prompt,
    ) == []

    original_receipt = receipt_path.read_bytes()
    receipt_path.write_bytes(original_receipt + b" ")
    authority_issues = driver._attention_shard_output_authority_issues(
        scratchpad=scratchpad,
        config=config,
        shard=shard,
    )
    assert any("compat receipt hash authority mismatch" in row for row in authority_issues)

    receipt_path.write_bytes(original_receipt)
    output_path = scratchpad / shard["output_path"]
    output_path.write_bytes(output_path.read_bytes() + b"tampered\n")
    output_issues = driver._attention_shard_output_authority_issues(
        scratchpad=scratchpad,
        config=config,
        shard=shard,
    )
    assert output_issues == [
        "attention shard output producer binding is invalid or stale"
    ]
