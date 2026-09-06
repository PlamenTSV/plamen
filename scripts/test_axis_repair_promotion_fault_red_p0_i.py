"""Independent RED fault specifications for P0-I repair and promotion.

These fixtures exercise the live driver helpers while replacing only process
launch and PhaseIO persistence with hermetic in-memory seams.  They pin failure
semantics at the two places where a valid base finding could otherwise be lost:

* malformed or partial repair output always terminates in a typed FAILED
  receipt, without suppressing an independently valid base FINDING;
* an explicit zero repair cap remains zero and records OVERFLOW without
  launching a worker;
* a crash after inventory append but before the promotion receipt can be
  replayed without duplicate or lost actions;
* logical inventory identities do not depend on LF versus CRLF bytes; and
* a pre-existing AXISGAP label is not delivery authority when its inventory
  block is unrelated to the action that label claims.

No real model, subprocess, network request, install, audit, or production
mutation is performed by these fixtures.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Mapping

import pytest

import axis_canonical_prior as AXIS_PRIOR
import axis_disposition as AXIS
import plamen_driver as DRIVER
from plamen_types import SC_PHASES, Phase
from test_axis_driver_transaction_red_p0_i import (
    RUN_ID,
    _one_item_authority,
    _sidecar,
    _source_clear,
)


def _axis_phase() -> Phase:
    return next(phase for phase in SC_PHASES if phase.name == "axis_coverage")


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _write_json(path: Path, value: object) -> None:
    path.write_bytes(_canonical(value))


def _action(item: Mapping[str, Any], *, title: str = "bound axis candidate") -> str:
    return (
        f"### Finding [{item['required_action_id']}]: {title}\n"
        f"**Work Item ID**: {item['work_item_id']}\n"
        "**Severity**: Low\n"
        f"**Location**: {item['source_locus']}\n"
        "**Description**: exact typed candidate retained for verification\n"
        "**Impact**: independent verification determines material harm\n\n"
    )


def _base_rows(
    worklist: Mapping[str, Any],
    *,
    omit_after_first: bool,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for index, item in enumerate(worklist["items"]):
        if index == 0:
            rows.append(
                {
                    "work_item_id": item["work_item_id"],
                    "disposition": "FINDING",
                    "action_id": item["required_action_id"],
                    "evidence": [],
                    "rationale": "candidate requires independent verification",
                }
            )
        elif not omit_after_first:
            rows.append(
                {
                    "work_item_id": item["work_item_id"],
                    "disposition": "CLEAR",
                    "action_id": "",
                    "evidence": [_source_clear(item)],
                    "rationale": "exact bound source locus closes this cell",
                }
            )
    return rows


def _seed_base(
    tmp_path: Path,
    *,
    omit_after_first: bool,
) -> tuple[
    Path,
    Path,
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    bytes,
    bytes,
]:
    project, scratchpad, config, worklist, evidence = _one_item_authority(
        tmp_path
    )
    prior = AXIS_PRIOR.capture_axis_canonical_prior_authority(
        scratchpad,
        run_id=RUN_ID,
        worklist_hash=str(worklist["worklist_hash"]),
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
    )
    config["_fixture_axis_prior_digest"] = prior.authority_digest
    first = worklist["items"][0]
    findings_raw = _action(first).encode("utf-8")
    dispositions_raw = _sidecar(
        worklist,
        _base_rows(worklist, omit_after_first=omit_after_first),
    )
    (scratchpad / "axis_coverage_findings.md").write_bytes(findings_raw)
    (scratchpad / "axis_coverage_dispositions.json").write_bytes(
        dispositions_raw
    )
    initial, plan = AXIS.reconcile_axis_dispositions_initial(
        worklist,
        base_dispositions_raw=dispositions_raw,
        base_findings_raw=findings_raw,
        execution_evidence_authority=evidence,
        canonical_prior_ids={},
        canonical_prior_authority_digest=prior.authority_digest,
        repair_cap=16,
    )
    AXIS.write_axis_disposition_v2_artifacts(
        scratchpad,
        worklist=worklist,
        initial_receipt=initial,
        repair_plan=plan,
    )
    return (
        project,
        scratchpad,
        config,
        worklist,
        evidence,
        findings_raw,
        dispositions_raw,
    )


def _final_application(
    *,
    project: Path,
    config: Mapping[str, Any],
    scratchpad: Path,
    worklist: Mapping[str, Any],
    evidence: Mapping[str, Any],
    findings_raw: bytes,
    repair_execution: Mapping[str, Any],
) -> dict[str, Any]:
    initial = json.loads(
        (scratchpad / "axis_disposition_initial_receipt.json").read_text(
            encoding="utf-8",
            errors="strict",
        )
    )
    plan = json.loads(
        (scratchpad / "axis_repair_plan.json").read_text(
            encoding="utf-8",
            errors="strict",
        )
    )
    repair_dispositions_path = (
        scratchpad / "axis_coverage_repair_dispositions.json"
    )
    repair_findings_path = scratchpad / "axis_coverage_repair_findings.md"
    application = AXIS.reconcile_axis_dispositions_final(
        worklist,
        initial_receipt=initial,
        repair_plan=plan,
        repair_execution_receipt=repair_execution,
        base_findings_raw=findings_raw,
        execution_evidence_authority=evidence,
        canonical_prior_ids={},
        canonical_prior_authority_digest=str(
            config["_fixture_axis_prior_digest"]
        ),
        repair_dispositions_raw=(
            repair_dispositions_path.read_bytes()
            if repair_dispositions_path.is_file()
            else None
        ),
        repair_findings_raw=(
            repair_findings_path.read_bytes()
            if repair_findings_path.is_file()
            else None
        ),
    )
    AXIS.write_axis_disposition_v2_artifacts(
        scratchpad,
        repair_execution_receipt=repair_execution,
    )
    exact_inputs = DRIVER._axis_disposition_exact_inputs(
        scratchpad,
        work_unit_id="reconcile.final",
        project_root=project,
    )
    contract, launch = DRIVER._axis_disposition_contract_and_launch(
        phase=_axis_phase(),
        config=dict(config),
        scratchpad=scratchpad,
        work_unit_id="reconcile.final",
        exact_inputs=exact_inputs,
    )
    execute, arm_issues = DRIVER._arm_deterministic_driver_work_unit(
        scratchpad=scratchpad,
        project_root=project,
        contract=contract,
        launch=launch,
        run_id=RUN_ID,
    )
    assert execute is True, arm_issues
    assert arm_issues == []
    AXIS.write_axis_disposition_v2_artifacts(
        scratchpad,
        worklist=worklist,
        application_receipt=application,
    )
    assert DRIVER._commit_deterministic_driver_work_unit(
        scratchpad=scratchpad,
        project_root=project,
        contract=contract,
        launch=launch,
        run_id=RUN_ID,
    ) == []
    return application


def _install_driver_transaction_seam(
    monkeypatch: pytest.MonkeyPatch,
    *,
    scratchpad: Path | None = None,
    merge_events: list[Any] | None = None,
) -> None:
    committed: set[tuple[str, str]] = set()
    committed_contracts: dict[tuple[str, str], tuple[Any, Any]] = {}
    seeded_units: dict[tuple[str, str], dict[str, Any]] = {}
    if scratchpad is not None:
        resolved = str(Path(scratchpad).resolve())
        existing = DRIVER.read_artifact_ledger(Path(scratchpad))
        committed.update(
            (resolved, str(key))
            for key, unit in dict(existing.get("work_units") or {}).items()
            if isinstance(unit, Mapping)
            and unit.get("run_id") == RUN_ID
            and str(key).endswith(
                "/axis_disposition/reconcile.final"
            )
        )
        seeded_units.update(
            {
                (resolved, str(key)): dict(unit)
                for key, unit in dict(
                    existing.get("work_units") or {}
                ).items()
                if isinstance(unit, Mapping)
                and unit.get("run_id") == RUN_ID
            }
        )

    def contract_and_launch(**kwargs: Any) -> tuple[Any, Any]:
        unit = str(kwargs["work_unit_id"])
        contract = SimpleNamespace(
            key=f"sc/thorough/evm/claude/axis_disposition/{unit}",
            digest=hashlib.sha256(unit.encode("utf-8")).hexdigest(),
            work_unit_id=unit,
            immutable_inputs=tuple(kwargs.get("exact_inputs") or ()),
        )
        launch = SimpleNamespace(
            backend="claude",
            model="fixture",
            timeout_s=30,
            digest=hashlib.sha256(
                f"launch:{unit}".encode("utf-8")
            ).hexdigest(),
        )
        return contract, launch

    monkeypatch.setattr(
        DRIVER,
        "_axis_disposition_contract_and_launch",
        contract_and_launch,
    )

    def arm(**kwargs: Any) -> tuple[bool, list[str]]:
        identity = (
            str(Path(kwargs["scratchpad"]).resolve()),
            str(kwargs["contract"].key),
        )
        return identity not in committed, []

    monkeypatch.setattr(
        DRIVER,
        "_arm_deterministic_driver_work_unit",
        arm,
    )
    monkeypatch.setattr(
        DRIVER,
        "validate_work_unit_inputs",
        lambda *_args, **_kwargs: [],
    )

    def commit(**kwargs: Any) -> list[str]:
        identity = (
            str(Path(kwargs["scratchpad"]).resolve()),
            str(kwargs["contract"].key),
        )
        committed.add(identity)
        committed_contracts[identity] = (
            kwargs["contract"],
            kwargs["launch"],
        )
        if merge_events is not None:
            merge_events.extend(
                (kwargs.get("merge_events") or {}).values()
            )
        return []

    monkeypatch.setattr(
        DRIVER,
        "_commit_deterministic_driver_work_unit",
        commit,
    )
    monkeypatch.setattr(
        DRIVER,
        "active_committed_work_unit_authority_issues",
        lambda ledger, *, work_unit_key, **_kwargs: (
            []
            if (
                str(ledger.get("_fixture_root") or ""),
                str(work_unit_key),
            )
            in committed
            else [f"{work_unit_key}: fixture authority absent"]
        ),
    )
    def fixture_ledger(root: Path) -> dict[str, Any]:
        resolved = str(Path(root).resolve())
        application_path = (
            Path(root) / AXIS.AXIS_APPLICATION_RECEIPT_NAME
        )
        application_raw = (
            application_path.read_bytes()
            if application_path.is_file()
            else b""
        )
        units: dict[str, Any] = {}
        for fixture_root, key in committed:
            if fixture_root != resolved:
                continue
            unit_name = str(key).rsplit("/", 1)[-1]
            seeded = seeded_units.get((fixture_root, key))
            if seeded is not None:
                units[key] = dict(seeded)
                continue
            contract, launch = committed_contracts.get(
                (fixture_root, key),
                (None, None),
            )
            exact_inputs = tuple(
                getattr(contract, "immutable_inputs", ()) or ()
            )
            canonical_inputs = [
                (
                    "project:" + str(value)[len("project::"):]
                    if str(value).startswith("project::")
                    else str(value)
                    if str(value).startswith(("project:", "scratchpad:"))
                    else "scratchpad:" + str(value)
                )
                for value in exact_inputs
            ]
            artifacts: dict[str, Any] = {}
            if key.endswith("/axis_disposition/reconcile.final"):
                identity = (
                    "scratchpad:" + AXIS.AXIS_APPLICATION_RECEIPT_NAME
                )
                artifacts[identity] = {
                    "sha256": hashlib.sha256(application_raw).hexdigest(),
                    "size": len(application_raw),
                }
            units[key] = {
                "run_id": RUN_ID,
                "contract_manifest": {
                    "key": key,
                    "immutable_inputs": canonical_inputs,
                    "bounded_lookup_inputs": [],
                },
                "contract_digest": str(
                    getattr(contract, "digest", "")
                    or hashlib.sha256(
                        unit_name.encode("utf-8")
                    ).hexdigest()
                ),
                "launch_digest": str(
                    getattr(launch, "digest", "")
                    or hashlib.sha256(
                        f"launch:{unit_name}".encode("utf-8")
                    ).hexdigest()
                ),
                "artifacts": artifacts,
            }
        return {
            "_fixture_root": resolved,
            "work_units": units,
        }

    monkeypatch.setattr(DRIVER, "read_artifact_ledger", fixture_ledger)

    def live_artifact(
        _ledger: Mapping[str, Any],
        *,
        work_unit_key: str,
        path: Path,
        **_kwargs: Any,
    ) -> tuple[bytes | None, list[str]]:
        identity = (
            str(Path(path).parent.resolve()),
            str(work_unit_key),
        )
        if identity not in committed:
            return None, [f"{work_unit_key}: fixture authority absent"]
        return Path(path).read_bytes(), []

    monkeypatch.setattr(
        DRIVER,
        "_axis_live_committed_artifact_issues",
        live_artifact,
    )


def _install_repair_model_seam(
    monkeypatch: pytest.MonkeyPatch,
    *,
    scratchpad: Path,
    output_case: str,
) -> None:
    _install_driver_transaction_seam(
        monkeypatch,
        scratchpad=scratchpad,
    )
    validation_calls = 0

    monkeypatch.setattr(
        DRIVER,
        "record_work_unit_inputs",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        DRIVER,
        "record_work_unit_artifacts",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        DRIVER,
        "validate_work_unit_inputs",
        lambda *_args, **_kwargs: [],
    )

    def validate_artifacts(*_args: Any, **_kwargs: Any) -> list[str]:
        nonlocal validation_calls
        validation_calls += 1
        if validation_calls == 1:
            return ["repair outputs are not committed"]
        if output_case == "partial":
            return ["paired repair outputs are incomplete"]
        return ["repair dispositions are malformed JSON"]

    monkeypatch.setattr(
        DRIVER,
        "validate_work_unit_artifacts",
        validate_artifacts,
    )

    def fake_worker(**_kwargs: Any) -> int:
        (scratchpad / "axis_coverage_repair_findings.md").write_text(
            "# bounded but incomplete repair output\n",
            encoding="utf-8",
        )
        if output_case == "malformed":
            (
                scratchpad / "axis_coverage_repair_dispositions.json"
            ).write_bytes(b"{not-json")
        return 0

    monkeypatch.setattr(
        DRIVER,
        "_run_one_claude_headless_breadth_worker",
        fake_worker,
    )


@pytest.mark.parametrize("output_case", ("partial", "malformed"))
def test_bad_repair_is_typed_failed_but_base_finding_still_promotes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    output_case: str,
) -> None:
    (
        project,
        scratchpad,
        config,
        worklist,
        evidence,
        findings_raw,
        _dispositions_raw,
    ) = _seed_base(
        tmp_path / output_case,
        omit_after_first=True,
    )
    plan = json.loads(
        (scratchpad / "axis_repair_plan.json").read_text(encoding="utf-8")
    )
    assert plan["observed_count"] > 0
    assert plan["retained_count"] > 0
    _install_repair_model_seam(
        monkeypatch,
        scratchpad=scratchpad,
        output_case=output_case,
    )

    repair, issues = DRIVER._run_axis_disposition_repair(
        phase=_axis_phase(),
        config=config,
        scratchpad=scratchpad,
        repair_plan=plan,
    )

    persisted = json.loads(
        (scratchpad / "axis_repair_execution_receipt.json").read_text(
            encoding="utf-8",
            errors="strict",
        )
    )
    assert persisted == repair
    assert repair["schema_version"] == AXIS.REPAIR_EXECUTION_RECEIPT_SCHEMA
    assert repair["state"] == "FAILED"
    assert repair["repair_plan_digest"] == plan["plan_digest"]
    assert repair["execution_digest"]
    assert repair["issues"]
    assert issues

    application = _final_application(
        project=project,
        config=config,
        scratchpad=scratchpad,
        worklist=worklist,
        evidence=evidence,
        findings_raw=findings_raw,
        repair_execution=repair,
    )
    promotion, promotion_issues = DRIVER._promote_axis_disposition_actions(
        phase=_axis_phase(),
        config=config,
        scratchpad=scratchpad,
        application_receipt=application,
    )
    action_id = worklist["items"][0]["required_action_id"]
    inventory = (scratchpad / "findings_inventory.md").read_text(
        encoding="utf-8",
        errors="strict",
    )
    assert promotion["status"] == "COMPLETE"
    assert promotion["action_ids"] == [action_id]
    assert promotion["delivery_count"] == 1
    assert inventory.count(f"AXISGAP:{action_id}") == 1
    assert promotion_issues == []


def test_explicit_zero_repair_cap_stays_zero_and_records_overflow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        project,
        scratchpad,
        config,
        worklist,
        _evidence,
        _findings_raw,
        _dispositions_raw,
    ) = _seed_base(tmp_path, omit_after_first=True)
    config["axis_repair_cap"] = 0
    _install_driver_transaction_seam(
        monkeypatch,
        scratchpad=scratchpad,
    )
    monkeypatch.setattr(
        DRIVER,
        "_load_axis_canonical_prior",
        lambda *_args, **_kwargs: SimpleNamespace(
            aliases={},
            authority_digest="c" * 64,
        ),
    )

    _initial, plan, reconcile_issues = DRIVER._reconcile_axis_dispositions(
        phase=_axis_phase(),
        config=config,
        scratchpad=scratchpad,
    )
    assert reconcile_issues == []
    assert plan["observed_count"] > 0
    assert plan["retained_count"] == 0
    assert plan["omitted_count"] == plan["observed_count"]
    assert plan["retained_work_item_ids"] == []
    assert plan["overflow"] is True

    launches: list[object] = []

    def forbidden_worker(**kwargs: Any) -> int:
        launches.append(kwargs)
        raise AssertionError("zero-cap repair must not launch a model")

    monkeypatch.setattr(
        DRIVER,
        "_run_one_claude_headless_breadth_worker",
        forbidden_worker,
    )
    receipt, _repair_issues = DRIVER._run_axis_disposition_repair(
        phase=_axis_phase(),
        config=config,
        scratchpad=scratchpad,
        repair_plan=plan,
    )
    assert launches == []
    assert receipt["state"] == "OVERFLOW"
    assert receipt["worker_executed"] is False
    assert receipt["repair_plan_digest"] == plan["plan_digest"]
    assert receipt["issues"] == [
        f"repair plan overflow omitted {plan['observed_count']} AXW item(s)"
    ]
    assert worklist["count"] >= plan["observed_count"]


def _complete_base_application(
    tmp_path: Path,
) -> tuple[
    Path,
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    bytes,
]:
    (
        project,
        scratchpad,
        config,
        worklist,
        evidence,
        findings_raw,
        _dispositions_raw,
    ) = _seed_base(tmp_path, omit_after_first=False)
    plan = json.loads(
        (scratchpad / "axis_repair_plan.json").read_text(encoding="utf-8")
    )
    assert plan["observed_count"] == 0
    repair = AXIS.build_axis_repair_execution_receipt(
        plan,
        state="NOT_REQUIRED",
    )
    application = _final_application(
        project=project,
        config=config,
        scratchpad=scratchpad,
        worklist=worklist,
        evidence=evidence,
        findings_raw=findings_raw,
        repair_execution=repair,
    )
    return scratchpad, config, worklist, application, findings_raw


def test_inventory_append_receipt_crash_replays_without_duplicate_or_loss(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad, config, worklist, application, _findings = (
        _complete_base_application(tmp_path)
    )
    _install_driver_transaction_seam(
        monkeypatch,
        scratchpad=scratchpad,
    )
    original_atomic_json = DRIVER._atomic_driver_json
    crash_once = True

    def crash_after_append(path: Path, value: Mapping[str, Any]) -> None:
        nonlocal crash_once
        if (
            Path(path).name == "axis_coverage_promotion_receipt.json"
            and crash_once
        ):
            crash_once = False
            raise RuntimeError("fixture crash after inventory append")
        original_atomic_json(path, value)

    monkeypatch.setattr(DRIVER, "_atomic_driver_json", crash_after_append)
    with pytest.raises(RuntimeError, match="after inventory append"):
        DRIVER._promote_axis_disposition_actions(
            phase=_axis_phase(),
            config=config,
            scratchpad=scratchpad,
            application_receipt=application,
        )

    inventory_path = scratchpad / "findings_inventory.md"
    after_crash = inventory_path.read_bytes()
    action_id = worklist["items"][0]["required_action_id"]
    assert after_crash.decode("utf-8").count(f"AXISGAP:{action_id}") == 1
    assert not (scratchpad / "axis_coverage_promotion_receipt.json").exists()

    promotion, issues = DRIVER._promote_axis_disposition_actions(
        phase=_axis_phase(),
        config=config,
        scratchpad=scratchpad,
        application_receipt=application,
    )
    assert issues == []
    assert promotion["status"] == "COMPLETE"
    assert promotion["delivery_count"] == 1
    assert inventory_path.read_bytes() == after_crash
    assert (
        inventory_path.read_text(encoding="utf-8").count(
            f"AXISGAP:{action_id}"
        )
        == 1
    )

    replay, replay_issues = DRIVER._promote_axis_disposition_actions(
        phase=_axis_phase(),
        config=config,
        scratchpad=scratchpad,
        application_receipt=application,
    )
    assert replay == promotion
    assert replay_issues == []
    assert inventory_path.read_bytes() == after_crash


def test_crlf_and_lf_inventory_preimages_have_equal_logical_identities(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[Any] = []
    preimage_lf = (
        "# Findings Inventory\n\n"
        "### Finding [INV-007]: existing candidate\n"
        "**Severity**: Low\n"
        "**Description**: existing candidate\n"
    )

    for name, preimage in (
        ("lf", preimage_lf),
        ("crlf", preimage_lf.replace("\n", "\r\n")),
    ):
        scratchpad, config, _worklist, application, _findings = (
            _complete_base_application(tmp_path / name)
        )
        _install_driver_transaction_seam(
            monkeypatch,
            scratchpad=scratchpad,
            merge_events=events,
        )
        (scratchpad / "findings_inventory.md").write_bytes(
            preimage.encode("utf-8")
        )
        promotion, issues = DRIVER._promote_axis_disposition_actions(
            phase=_axis_phase(),
            config=config,
            scratchpad=scratchpad,
            application_receipt=application,
        )
        assert promotion["status"] == "COMPLETE"
        assert issues == []
        replay, replay_issues = DRIVER._promote_axis_disposition_actions(
            phase=_axis_phase(),
            config=config,
            scratchpad=scratchpad,
            application_receipt=application,
        )
        assert replay == promotion
        assert replay_issues == []

    assert len(events) == 2
    assert events[0].identities_before == ("INV-007",)
    assert events[1].identities_before == ("INV-007",)
    assert events[0].identities_before == events[1].identities_before
    assert events[0].before_sha256 != events[1].before_sha256
    assert hashlib.sha256(preimage_lf.encode("utf-8")).hexdigest() == (
        events[0].before_sha256
    )


def test_unrelated_preexisting_axisgap_claim_is_not_accepted_but_real_action_delivers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad, config, worklist, application, _findings = (
        _complete_base_application(tmp_path)
    )
    _install_driver_transaction_seam(
        monkeypatch,
        scratchpad=scratchpad,
    )
    action_id = worklist["items"][0]["required_action_id"]
    unrelated = (
        "# Findings Inventory\n\n"
        "### Finding [INV-041]: unrelated pre-existing candidate\n"
        f"**Source IDs**: AXISGAP:{action_id}\n"
        "**Verdict**: NEEDS_VERIFICATION\n"
        "**Severity**: Low\n"
        "**Location**: contracts/Unrelated.sol:L999\n"
        "**Description**: content unrelated to the authorized axis action\n"
        "**Impact**: unrelated impact\n"
    )
    (scratchpad / "findings_inventory.md").write_text(
        unrelated,
        encoding="utf-8",
    )

    promotion, issues = DRIVER._promote_axis_disposition_actions(
        phase=_axis_phase(),
        config=config,
        scratchpad=scratchpad,
        application_receipt=application,
    )

    assert promotion["status"] == "COMPLETED_WITH_DEBT"
    assert promotion["delivery_count"] == 1
    assert promotion["missing_action_ids"] == []
    assert promotion["conflicting_claim_action_ids"] == [action_id]
    assert promotion["deliveries"][0]["inventory_id"] != "INV-041"
    assert (
        (scratchpad / "findings_inventory.md")
        .read_text(encoding="utf-8", errors="strict")
        .count(f"AXISGAP:{action_id}")
        == 2
    )
    assert any(
        action_id in issue and "conflicting claim" in issue
        for issue in issues
    )
