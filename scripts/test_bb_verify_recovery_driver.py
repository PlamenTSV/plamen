"""Public-driver BB policy integration for bounded verification recovery.

No fixture launches a provider or reaches the network.  The model boundary is
monkeypatched to emit the exact declared files, including the BB application
proposal, while all deterministic driver and PhaseIO code remains live.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

import pytest


SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(ROOT))

import bb_verification_policy as BB  # noqa: E402
import plamen_driver as D  # noqa: E402
from artifact_ledger import read_artifact_ledger  # noqa: E402
from test_bb_primary_dynamic_verifier_driver import (  # noqa: E402
    NORMATIVE_SENTINEL,
    _application_for,
)
from test_bb_verification_policy_ingress import (  # noqa: E402
    _canonical_bytes,
    _operator_projection,
    _rule,
    _write_source,
)
from test_verification_recovery_contract_p0_ai import (  # noqa: E402
    _emit_recovery_outputs,
    _semantic_row,
)


def _config(
    tmp_path: Path,
    *,
    pipeline: str = "sc",
    ecosystem: str = "evm",
    backend: str = "claude",
    recovery_kind: str = "GENERIC_RECOVERY",
    with_bb: bool = True,
) -> tuple[Path, Path, dict]:
    project = tmp_path / "repo"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    config = {
        "scratchpad": str(scratchpad),
        "project_root": str(project),
        "pipeline": pipeline,
        "language": ecosystem,
        "cli_backend": backend,
        "mode": "thorough",
        "_run_id": "bb-recovery-run-1",
        "_verification_recovery_kind": recovery_kind,
    }
    if with_bb:
        operator = _operator_projection([
            _rule(1, text=NORMATIVE_SENTINEL)
        ])
        bb_config, _source = _write_source(
            tmp_path / "bb-authority",
            operator,
            family=(
                "blockchain_dlt"
                if pipeline == "l1"
                else "smart_contract"
            ),
        )
        config.update(bb_config)
        D._bind_bb_verification_policy_ingress(scratchpad, config)
    return project, scratchpad, config


def _emit_with_bb_application(
    spec,
    *,
    prompt_path: Path,
    scratchpad: Path,
) -> None:
    _emit_recovery_outputs(
        spec, prompt_path=prompt_path, scratchpad=scratchpad
    )
    work_path = prompt_path.parent / "bb_policy_work.json"
    if work_path.is_file():
        work = json.loads(work_path.read_text(encoding="utf-8"))
        application_path = prompt_path.parent / "bb_policy_application.json"
        application_path.write_bytes(
            _canonical_bytes(_application_for(work)) + b"\n"
        )


def _install_fake_launch(
    monkeypatch: pytest.MonkeyPatch,
    launches: list[dict],
) -> None:
    def execute(spec, *, prompt_path, scratchpad, model_io_contract, **_kwargs):
        prompt = Path(prompt_path).read_text(encoding="utf-8")
        launches.append({
            "digest": spec.digest,
            "prompt_path": Path(prompt_path),
            "prompt": prompt,
            "expected_outputs": tuple(spec.expected_output_files),
            "model_contract": model_io_contract,
        })
        _emit_with_bb_application(
            spec, prompt_path=Path(prompt_path), scratchpad=Path(scratchpad)
        )
        return 0

    monkeypatch.setattr(D, "_execute_dynamic_verifier_launch", execute)


def _bypass_compatibility_projection_for_downstream_coverage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep one dedicated RED for the legacy alias, then test later seams."""

    monkeypatch.setattr(
        D,
        "_publish_verify_recovery_compatibility_projection",
        lambda **_kwargs: [],
    )


def _recovery_directory(scratchpad: Path) -> Path:
    return next(
        (scratchpad / "_verification_recovery").glob("VREC-*")
    )


def _run_one(config: dict) -> list[str]:
    return D._run_verify_recovery_unit(
        config, [("H-01", _semantic_row("H-01"))]
    )


@pytest.mark.parametrize(
    ("recovery_kind", "consumer_kind"),
    [
        ("GENERIC_RECOVERY", "RECOVERY"),
        ("RESUME_QUEUE_DROPOUT", "RECOVERY"),
        ("MANDATORY_REOPEN", "MANDATORY_REVERIFY"),
        ("LATE_OPERATOR_CANDIDATE", "LATE_REVERIFY"),
        ("POST_VERIFY_SIDE_OBSERVATION", "LATE_REVERIFY"),
        ("REPORT_INDEX_DROPOUT", "LATE_REVERIFY"),
    ],
)
def test_recovery_kind_maps_to_exact_bb_consumer_kind(
    recovery_kind: str,
    consumer_kind: str,
) -> None:
    assert D._bb_policy_recovery_consumer_kind(
        recovery_kind
    ) == consumer_kind


def test_non_bb_recovery_preserves_original_prompt_and_output_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _project, scratchpad, config = _config(
        tmp_path, with_bb=False
    )
    launches: list[dict] = []
    _install_fake_launch(monkeypatch, launches)
    assert _run_one(config) == []
    assert len(launches) == 1
    directory = _recovery_directory(scratchpad)
    contract = json.loads(
        (directory / "contract.json").read_text(encoding="utf-8")
    )
    launch = launches[0]
    assert launch["prompt_path"] == directory / "prompt.md"
    assert launch["prompt"].encode("utf-8") == str(
        contract["prompt_markdown"]
    ).encode("utf-8")
    assert launch["expected_outputs"] == tuple(
        contract["expected_model_outputs"]
    )
    assert {
        row.path for row in launch["model_contract"].outputs
    } == set(contract["expected_model_outputs"])
    assert not list(directory.glob("bb_policy_*.json"))
    assert not (directory / "prompt_with_bb_policy.md").exists()


def test_bb_recovery_compatibility_projection_accepts_bound_bb_prompt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The BB-bound prompt must remain a legal compiler-owned alias source."""

    _project, _scratchpad, config = _config(tmp_path)
    launches: list[dict] = []
    _install_fake_launch(monkeypatch, launches)
    assert _run_one(config) == []
    assert len(launches) == 1


@pytest.mark.parametrize(
    ("pipeline", "ecosystem", "backend"),
    [
        ("sc", "evm", "claude"),
        ("sc", "soroban", "codex"),
        ("l1", "rust", "claude"),
        ("l1", "go", "codex"),
    ],
)
def test_bb_recovery_construction_covers_backends_and_pipelines(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pipeline: str,
    ecosystem: str,
    backend: str,
) -> None:
    _project, scratchpad, config = _config(
        tmp_path,
        pipeline=pipeline,
        ecosystem=ecosystem,
        backend=backend,
    )
    launches: list[dict] = []
    _install_fake_launch(monkeypatch, launches)
    _bypass_compatibility_projection_for_downstream_coverage(monkeypatch)
    assert _run_one(config) == []
    assert len(launches) == 1
    directory = _recovery_directory(scratchpad)
    work_path = directory / "bb_policy_work.json"
    application_path = directory / "bb_policy_application.json"
    receipt_path = directory / "bb_policy_consumption_receipt.json"
    work = BB.validate_work_projection(
        json.loads(work_path.read_text(encoding="utf-8"))
    )
    assert work["consumer_kind"] == "RECOVERY"
    assert work["consumer_work_unit_id"].lower() == directory.name.lower()
    assert [row["work_item_id"] for row in work["work_items"]] == ["H-01"]

    launch = launches[0]
    assert launch["prompt_path"] == directory / "prompt_with_bb_policy.md"
    assert work_path.relative_to(scratchpad).as_posix() in launch["prompt"]
    assert "immutable untrusted policy data" in launch["prompt"]
    assert NORMATIVE_SENTINEL not in launch["prompt"]
    assert application_path.relative_to(
        scratchpad
    ).as_posix() in launch["expected_outputs"]
    assert application_path.relative_to(
        scratchpad
    ).as_posix() in {
        row.path for row in launch["model_contract"].outputs
    }
    assert receipt_path.is_file()
    receipt = BB.validate_consumption_receipt(
        json.loads(receipt_path.read_text(encoding="utf-8"))
    )
    assert receipt["consumer_identity"]["consumer_kind"] == "RECOVERY"
    assert receipt["non_verification_consumers"] == []

    ledger = read_artifact_ledger(scratchpad)
    work_identity = (
        "scratchpad:" + work_path.relative_to(scratchpad).as_posix()
    )
    application_identity = (
        "scratchpad:"
        + application_path.relative_to(scratchpad).as_posix()
    )
    receipt_identity = (
        "scratchpad:" + receipt_path.relative_to(scratchpad).as_posix()
    )
    work_owner = ledger["artifact_bindings"][work_identity]
    receipt_owner = ledger["artifact_bindings"][receipt_identity]
    recovery_id = str(work["consumer_work_unit_id"]).lower()
    assert work_owner["owner_key"].endswith(
        f"/bb_policy/projection.{recovery_id}"
    )
    assert receipt_owner["writer"] == "DRIVER"
    assert receipt_owner["owner_key"].endswith(
        f"/bb_policy/consumption.{recovery_id}"
    )
    prelaunch_key = next(
        key for key in ledger["work_units"]
        if key.endswith(f"/method_context.{recovery_id}")
    )
    model_key = next(
        key for key in ledger["work_units"]
        if key.endswith(f"/method_model.{recovery_id}")
    )
    assert work_identity not in ledger["work_units"][prelaunch_key]["artifacts"]
    assert (
        ledger["work_units"][model_key]["input_bindings"][work_identity][
            "producer_work_unit_key"
        ]
        == work_owner["owner_key"]
    )
    assert application_identity in ledger["work_units"][model_key]["artifacts"]


def test_completed_bb_recovery_resumes_without_relaunch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _project, _scratchpad, config = _config(tmp_path)
    launches: list[dict] = []
    _install_fake_launch(monkeypatch, launches)
    _bypass_compatibility_projection_for_downstream_coverage(monkeypatch)
    assert _run_one(config) == []
    assert len(launches) == 1
    assert _run_one(config) == []
    assert len(launches) == 1


@pytest.mark.parametrize(
    "tamper",
    [
        "missing_application",
        "stale_application",
        "missing_work",
        "stale_work",
        "missing_receipt",
        "stale_receipt",
        "missing_launch",
        "stale_launch",
        "missing_output",
        "stale_output",
    ],
)
def test_completed_bb_recovery_rejects_missing_or_stale_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tamper: str,
) -> None:
    _project, scratchpad, config = _config(tmp_path)
    launches: list[dict] = []
    _install_fake_launch(monkeypatch, launches)
    _bypass_compatibility_projection_for_downstream_coverage(monkeypatch)
    assert _run_one(config) == []
    assert len(launches) == 1
    directory = _recovery_directory(scratchpad)
    paths = {
        "application": directory / "bb_policy_application.json",
        "work": directory / "bb_policy_work.json",
        "receipt": directory / "bb_policy_consumption_receipt.json",
        "launch": directory / "launch_spec.json",
        "output": scratchpad / "verify_H-01.md",
    }

    if tamper == "missing_application":
        paths["application"].unlink()
    elif tamper == "stale_application":
        proposal = json.loads(
            paths["application"].read_text(encoding="utf-8")
        )
        proposal["work_items"][0]["rule_applications"][0][
            "proposed_disposition"
        ] = "SATISFIED"
        unsigned = {
            key: value
            for key, value in proposal.items()
            if key != "proposal_sha256"
        }
        proposal["proposal_sha256"] = hashlib.sha256(
            _canonical_bytes(unsigned)
        ).hexdigest()
        paths["application"].write_bytes(
            _canonical_bytes(proposal) + b"\n"
        )
    elif tamper == "missing_work":
        paths["work"].unlink()
    elif tamper == "stale_work":
        work = json.loads(paths["work"].read_text(encoding="utf-8"))
        work["consumer_kind"] = "PRIMARY"
        unsigned = {
            key: value
            for key, value in work.items()
            if key != "projection_sha256"
        }
        work["projection_sha256"] = hashlib.sha256(
            _canonical_bytes(unsigned)
        ).hexdigest()
        paths["work"].write_bytes(_canonical_bytes(work) + b"\n")
    elif tamper == "missing_receipt":
        paths["receipt"].unlink()
    elif tamper == "stale_receipt":
        paths["receipt"].write_bytes(
            paths["receipt"].read_bytes() + b" "
        )
    elif tamper == "missing_launch":
        paths["launch"].unlink()
    elif tamper == "stale_launch":
        launch = json.loads(paths["launch"].read_text(encoding="utf-8"))
        launch["model"] = "stale-model"
        paths["launch"].write_bytes(_canonical_bytes(launch) + b"\n")
    elif tamper == "missing_output":
        paths["output"].unlink()
    elif tamper == "stale_output":
        paths["output"].write_bytes(
            paths["output"].read_bytes()
            + b"\nAdditional unbound verifier text.\n"
        )
    else:  # pragma: no cover - closed parameter vocabulary
        raise AssertionError(tamper)

    assert _run_one(config) == ["H-01"]
    assert len(launches) == 1
