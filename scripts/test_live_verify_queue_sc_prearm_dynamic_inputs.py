"""Adversarial contract for SC verify-queue pre-arm dynamic inputs.

The live T0 transaction cannot discover candidate-referenced fact sources
after it has armed its immutable input denominator.  This fixture specifies a
separate pre-arm resolver/builder which:

* enumerates only the typed P0-AF candidate denominator;
* requires exact current-run PhaseIO producer ancestry for the candidate,
  canonical identity denominator, and every referenced fact source;
* commits an always-present resolution receipt plus exactly one conditional
  manifest/debt branch through its own PhaseIO work unit; and
* gives T0 a closed, content-addressed roster without live globs or late reads.

All identifiers and evidence are generic fixture data.  The tests contain no
protocol-specific bug hint or audit answer.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from typing import Any, Callable, Mapping

import pytest

from artifact_ledger import (
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
)
from compound_verification import (
    CompoundCandidate,
    ConstituentAuthorityBinding,
)
from live_verify_queue_semantics import (
    LiveVerifyQueueSemanticError,
    build_live_verify_queue_semantic_executor,
)
import p0af_v2_queue_adapter as P0AF
from phase_io_contracts import (
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    canonical_work_unit_key,
)
import test_live_verify_queue_transaction_semantic_closure as LIVE
import verify_queue_transaction as TRANSACTION


SCRIPTS = Path(__file__).resolve().parent
SUT_PATH = SCRIPTS / "live_verify_queue_prearm_inputs.py"

RUN_ID = "prearm-current-run"
FOREIGN_RUN_ID = "prearm-foreign-run"
MANIFEST_FILE = "prearm_content_addressed_inputs.json"
DEBT_FILE = "prearm_content_addressed_inputs.debt.json"
RECEIPT_FILE = "prearm_content_addressed_inputs.receipt.json"
IDENTITY_FILE = P0AF.IDENTITY_DENOMINATOR_FILE
CANDIDATE_FILE = P0AF.CANDIDATE_FILE
FACT_SOURCE = "generic_fact_authority.json"
PREARM_WORK_UNIT_ID = "prearm_dynamic_inputs"
PREARM_OWNER = canonical_work_unit_key(
    "sc",
    "thorough",
    "evm",
    "claude",
    "sc_verify_queue",
    PREARM_WORK_UNIT_ID,
)
MAX_VISIBLE_DEBT_BYTES = 64 * 1024
MAX_VISIBLE_DEBT_ISSUES = 32
MAX_VISIBLE_DEBT_DETAIL = 512


def _canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _payload_digest(value: Mapping[str, Any]) -> str:
    return _digest({
        key: item for key, item in value.items()
        if key != "payload_digest"
    })


def _manifest_digest(value: Mapping[str, Any]) -> str:
    return _sha(_canonical_bytes({
        key: item for key, item in value.items()
        if key != "manifest_digest"
    }))


def _load_sut():
    assert SUT_PATH.is_file(), (
        "production must add scripts/live_verify_queue_prearm_inputs.py"
    )
    name = "_plamen_sc_prearm_dynamic_inputs_acceptance"
    cached = sys.modules.get(name)
    if cached is not None:
        return cached
    spec = importlib.util.spec_from_file_location(name, SUT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _prepare_callable() -> Callable[..., Mapping[str, Any]]:
    candidate = getattr(_load_sut(), "prepare_sc_prearm_dynamic_inputs", None)
    assert callable(candidate), (
        "production must expose prepare_sc_prearm_dynamic_inputs"
    )
    return candidate


def _config(pipeline: str = "sc") -> dict[str, Any]:
    return {
        "pipeline": pipeline,
        "mode": "thorough",
        "ecosystem": "evm" if pipeline == "sc" else "rust",
        "backend": "claude",
        "phase_name": (
            "sc_verify_queue" if pipeline == "sc" else "verify_queue"
        ),
    }


def _prepare(
    root: Path,
    project: Path,
    *,
    pipeline: str = "sc",
) -> Mapping[str, Any]:
    outcome = _prepare_callable()(
        scratchpad=root,
        project_root=project,
        config=_config(pipeline),
        run_id=RUN_ID,
    )
    assert isinstance(outcome, Mapping)
    return outcome


def _producer(
    root: Path,
    project: Path,
    *,
    relative: str,
    raw: bytes,
    work_unit_id: str,
    run_id: str = RUN_ID,
) -> tuple[PhaseIOContract, LaunchSpec]:
    owner = canonical_work_unit_key(
        "sc",
        "thorough",
        "evm",
        "claude",
        "chain_iter2",
        work_unit_id,
    )
    contract = PhaseIOContract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="chain_iter2",
        work_unit_id=work_unit_id,
        outputs=(ArtifactSpec(
            root="scratchpad",
            path=relative,
            owner_key=owner,
            artifact_class="DRIVER_GENERATED",
            writer="DRIVER",
            write_mode="CREATE",
            schema_version="fixture.generic-prearm-source.v1",
            minimum_gate="STRUCTURAL",
            consumers=(
                "sc_verify_queue/prearm_dynamic_inputs",
                "sc_verify_queue/t0.live_upstream_authority",
            ),
        ),),
        immutable_inputs=(),
        bounded_lookup_inputs=(),
        model_invoked=False,
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="driver",
        timeout_s=60,
        exec_mode="python",
        tool_policy=("filesystem",),
    )
    record_work_unit_inputs(
        root, project, contract, launch, run_id=run_id
    )
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    record_work_unit_artifacts(
        root,
        project,
        contract,
        launch,
        run_id=run_id,
        actor="DRIVER",
    )
    return contract, launch


def _fixture_payloads() -> dict[str, bytes]:
    identity = {
        "schema_version": "plamen.canonical_finding_ids.v1",
        "generated_at": "2026-01-01T00:00:00+00:00",
        "last_phase": "chain",
        "pipeline": "sc",
        "mode": "thorough",
        "record_count": 0,
        "records": [],
    }
    identity_raw = _canonical_bytes(identity)

    facts = [
        {
            "fact_id": "GENERIC-FACT-0001",
            "evidence": [{"locus": "src/Unit.sol:L10-L20"}],
        },
        {
            "fact_id": "GENERIC-FACT-0002",
            "evidence": [{"locus": "src/Unit.sol:L30-L40"}],
        },
    ]
    for fact in facts:
        fact["fact_digest"] = _digest(fact)
    authority = {
        "schema_version": "plamen.generic_fact_authority.v1",
        "facts": facts,
    }
    authority["authority_digest"] = _digest(authority)
    authority_raw = _canonical_bytes(authority)

    bindings = tuple(
        ConstituentAuthorityBinding.create({
            "constituent_id": fact["fact_id"],
            "constituent_kind": "EVIDENCE_FACT",
            "fact_digest": fact["fact_digest"],
            "authority_digest": authority["authority_digest"],
            "source_artifact": FACT_SOURCE,
        })
        for fact in facts
    )
    candidate = CompoundCandidate.create(
        chain_id="CH-17",
        constituents=tuple(
            binding.constituent_id for binding in bindings
        ),
        evidence_constituent_bindings=bindings,
        severity_upgrade_justified=False,
        ordering_edges=(),
        preconditions=("The typed fact remains subject to verification.",),
        postconditions=("Independent verification determines disposition.",),
        combined_impact_claim=(
            "A generic composition hypothesis requiring verification."
        ),
        proposed_severity="Medium",
        source_lineage=("generic_composition.json:candidate=1",),
        coverage_lineage=("GENERIC-COVERAGE-0001",),
        pipeline="SC",
        mode="thorough",
    )
    candidates = {
        "schema_version": (
            "plamen.arm_before_trust_compound_candidates.v1"
        ),
        "source_analysis_digest": "a" * 64,
        "source_composition_digest": "b" * 64,
        "source_fact_authority_digest": authority["authority_digest"],
        "identity_denominator_artifact": IDENTITY_FILE,
        "identity_denominator_digest": _sha(identity_raw),
        "proof_authority": "NONE",
        "candidate_count": 1,
        "candidates": [candidate.to_record()],
    }
    candidates["payload_digest"] = _payload_digest(candidates)
    return {
        IDENTITY_FILE: identity_raw,
        FACT_SOURCE: authority_raw,
        CANDIDATE_FILE: _canonical_bytes(candidates),
    }


def _seed(
    root: Path,
    project: Path,
    *,
    case: str = "valid",
) -> dict[str, bytes]:
    payloads = _fixture_payloads()
    candidate_raw = payloads[CANDIDATE_FILE]
    if case == "malformed-candidate":
        candidate_raw = b'{"schema_version":'
    elif case == "oversized-candidate":
        candidate_raw = (
            b'{"oversized":"' + b"x" * P0AF.MAX_AUTHORITY_BYTES + b'"}\n'
        )

    _producer(
        root,
        project,
        relative=IDENTITY_FILE,
        raw=payloads[IDENTITY_FILE],
        work_unit_id="identity_source",
    )
    _producer(
        root,
        project,
        relative=CANDIDATE_FILE,
        raw=candidate_raw,
        work_unit_id="candidate_source",
    )

    if case in {"valid", "malformed-candidate", "oversized-candidate"}:
        _producer(
            root,
            project,
            relative=FACT_SOURCE,
            raw=payloads[FACT_SOURCE],
            work_unit_id="fact_source",
        )
    elif case == "malformed-source":
        _producer(
            root,
            project,
            relative=FACT_SOURCE,
            raw=b'{"schema_version":',
            work_unit_id="fact_source",
        )
    elif case == "oversized-source":
        _producer(
            root,
            project,
            relative=FACT_SOURCE,
            raw=b'{"oversized":"' + b"x" * P0AF.MAX_AUTHORITY_BYTES + b'"}\n',
            work_unit_id="fact_source",
        )
    elif case == "unowned":
        (root / FACT_SOURCE).write_bytes(payloads[FACT_SOURCE])
    elif case == "cross-run":
        _producer(
            root,
            project,
            relative=FACT_SOURCE,
            raw=payloads[FACT_SOURCE],
            work_unit_id="fact_source",
            run_id=FOREIGN_RUN_ID,
        )
    elif case == "status-only":
        (root / FACT_SOURCE).write_bytes(payloads[FACT_SOURCE])
        (root / f"{FACT_SOURCE}.status.json").write_bytes(
            _canonical_bytes({
                "state": "OUTPUT_COMMITTED",
                "safe_to_consume": True,
                "run_id": RUN_ID,
                "sha256": _sha(payloads[FACT_SOURCE]),
            })
        )
    elif case != "missing-source":
        raise AssertionError(f"unknown fixture case: {case}")
    return payloads


def _json_file(root: Path, relative: str) -> Mapping[str, Any]:
    value = json.loads((root / relative).read_text(encoding="utf-8"))
    assert isinstance(value, Mapping)
    return value


def _assert_active_binding(
    root: Path,
    relative: str,
    *,
    owner: str = PREARM_OWNER,
) -> Mapping[str, Any]:
    ledger = read_artifact_ledger(root)
    binding = ledger["artifact_bindings"]["scratchpad:" + relative]
    assert binding["status"] == "ACTIVE"
    assert binding["authority_level"] == "ACTIVE_AUTHORITY"
    assert binding["owner_key"] == owner
    assert binding["run_id"] == RUN_ID
    assert binding["writer"] == "DRIVER"
    assert binding["sha256"] == _sha((root / relative).read_bytes())
    assert binding["size"] == (root / relative).stat().st_size
    producer = ledger["work_units"][owner]
    assert producer["execution_state"] == "OUTPUT_COMMITTED"
    assert producer["run_id"] == RUN_ID
    return binding


def _assert_inactive_or_absent_binding(root: Path, relative: str) -> None:
    ledger = read_artifact_ledger(root)
    binding = ledger.get("artifact_bindings", {}).get(
        "scratchpad:" + relative
    )
    assert not isinstance(binding, Mapping) or binding.get("status") != "ACTIVE"


def _assert_receipt(
    root: Path,
    outcome: Mapping[str, Any],
    state: str,
) -> Mapping[str, Any]:
    assert outcome["state"] == state
    assert outcome["receipt_path"] == RECEIPT_FILE
    receipt = _json_file(root, RECEIPT_FILE)
    assert receipt["state"] == state
    assert receipt["run_id"] == RUN_ID
    assert receipt["pipeline"] == "sc"
    assert receipt["proof_authority"] == "NONE"
    assert receipt["payload_digest"] == _payload_digest(receipt)
    _assert_active_binding(root, RECEIPT_FILE)
    return receipt


def _assert_bounded_debt(
    root: Path,
    outcome: Mapping[str, Any],
) -> None:
    receipt = _assert_receipt(
        root, outcome, "COMPLETED_WITH_DEBT"
    )
    assert receipt["selected_conditional"] == DEBT_FILE
    assert not (root / MANIFEST_FILE).exists()
    assert (root / DEBT_FILE).is_file()
    assert (root / DEBT_FILE).stat().st_size <= MAX_VISIBLE_DEBT_BYTES
    debt = _json_file(root, DEBT_FILE)
    assert debt["state"] == "COMPLETED_WITH_DEBT"
    assert debt["proof_authority"] == "NONE"
    assert isinstance(debt["issues"], list)
    assert debt["issue_count"] >= 1
    assert len(debt["issues"]) <= MAX_VISIBLE_DEBT_ISSUES
    assert all(
        isinstance(issue, str)
        and 0 < len(issue) <= MAX_VISIBLE_DEBT_DETAIL
        for issue in debt["issues"]
    )
    assert debt["payload_digest"] == _payload_digest(debt)
    assert set(outcome["t0_additional_inputs"]) == {
        RECEIPT_FILE,
        DEBT_FILE,
    }
    assert outcome["dynamic_source_paths"] == []
    _assert_active_binding(root, DEBT_FILE)
    _assert_inactive_or_absent_binding(root, MANIFEST_FILE)


def _resolved_plan(
    outcome: Mapping[str, Any],
    *,
    resolution_override: Mapping[str, Any] | None = None,
) -> Mapping[str, Any]:
    additional = set(map(str, outcome["t0_additional_inputs"]))
    upstream = {
        *LIVE._upstream_inputs("sc"),
        *additional,
    }
    return TRANSACTION.resolve_live_verify_queue_transaction_plan(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase_name="sc_verify_queue",
        run_id=RUN_ID,
        upstream_inputs=tuple(sorted(upstream)),
        runtime_authority={
            **LIVE.RUNTIME_AUTHORITY_BASE,
            "pipeline": "sc",
            "mode": "thorough",
            "ecosystem": "evm",
            "backend": "claude",
            "run_id": RUN_ID,
        },
        shard_manifests=LIVE._shard_manifests("sc"),
        context_capture=LIVE.CONTEXT_CAPTURE,
        prearm_resolution=dict(resolution_override or outcome),
        preverify_frozen_projection=LIVE._frozen_projection(
            "sc", "claude", run_id=RUN_ID
        ),
        preverify_chain_pair_projection=LIVE._chain_pair_projection(
            "sc", "claude", run_id=RUN_ID
        ),
    )


def _seed_other_t0_inputs(root: Path, plan: Mapping[str, Any]) -> None:
    t0 = LIVE._child_map(plan)[LIVE.CHILD_IDS[0]]
    for relative in map(str, t0["exact_inputs"]):
        path = root / relative
        if path.exists():
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(_canonical_bytes({"artifact": relative}))


def test_prearm_module_exposes_one_bounded_sc_preparation_seam() -> None:
    module = _load_sut()

    assert callable(getattr(module, "prepare_sc_prearm_dynamic_inputs", None))
    assert module.MANIFEST_FILE == MANIFEST_FILE
    assert module.DEBT_FILE == DEBT_FILE
    assert module.RECEIPT_FILE == RECEIPT_FILE
    assert module.WORK_UNIT_ID == PREARM_WORK_UNIT_ID


def test_absent_candidate_is_not_triggered_with_receipt_only(
    tmp_path: Path,
) -> None:
    root = tmp_path / ".scratchpad"
    root.mkdir()

    outcome = _prepare(root, tmp_path)
    receipt = _assert_receipt(root, outcome, "NOT_TRIGGERED")

    assert receipt["selected_conditional"] == "NONE"
    assert set(outcome["t0_additional_inputs"]) == {RECEIPT_FILE}
    assert outcome["dynamic_source_paths"] == []
    assert not (root / MANIFEST_FILE).exists()
    assert not (root / DEBT_FILE).exists()
    _assert_inactive_or_absent_binding(root, MANIFEST_FILE)
    _assert_inactive_or_absent_binding(root, DEBT_FILE)


def test_not_triggered_resolution_freezes_receipt_without_conditional_branch(
    tmp_path: Path,
) -> None:
    root = tmp_path / ".scratchpad"
    root.mkdir()
    outcome = _prepare(root, tmp_path)

    plan = _resolved_plan(outcome)
    t0 = LIVE._child_map(plan)[LIVE.CHILD_IDS[0]]
    inputs = set(map(str, t0["exact_inputs"]))

    assert RECEIPT_FILE in inputs
    assert MANIFEST_FILE not in inputs
    assert DEBT_FILE not in inputs
    assert FACT_SOURCE not in inputs
    assert t0["prearm_dynamic_input_resolution"]["state"] == "NOT_TRIGGERED"


@pytest.mark.parametrize(
    "case",
    (
        "malformed-candidate",
        "oversized-candidate",
        "malformed-source",
        "oversized-source",
        "missing-source",
        "unowned",
        "cross-run",
        "status-only",
    ),
)
def test_invalid_or_unauthorized_dynamic_input_degrades_to_bounded_debt(
    tmp_path: Path,
    case: str,
) -> None:
    root = tmp_path / ".scratchpad"
    root.mkdir()
    _seed(root, tmp_path, case=case)

    outcome = _prepare(root, tmp_path)

    _assert_bounded_debt(root, outcome)
    ledger = read_artifact_ledger(root)
    manifest_binding = ledger.get("artifact_bindings", {}).get(
        "scratchpad:" + MANIFEST_FILE
    )
    assert not isinstance(manifest_binding, Mapping) or (
        manifest_binding.get("authority_level") != "ACTIVE_AUTHORITY"
    )


def test_debt_resolution_freezes_receipt_and_debt_without_dynamic_sources(
    tmp_path: Path,
) -> None:
    root = tmp_path / ".scratchpad"
    root.mkdir()
    _seed(root, tmp_path, case="missing-source")
    outcome = _prepare(root, tmp_path)

    plan = _resolved_plan(outcome)
    t0 = LIVE._child_map(plan)[LIVE.CHILD_IDS[0]]
    inputs = set(map(str, t0["exact_inputs"]))

    assert {RECEIPT_FILE, DEBT_FILE} <= inputs
    assert MANIFEST_FILE not in inputs
    assert FACT_SOURCE not in inputs
    assert t0["prearm_dynamic_input_resolution"]["state"] == (
        "COMPLETED_WITH_DEBT"
    )


def test_valid_sources_commit_exact_manifest_through_own_phaseio_producer(
    tmp_path: Path,
) -> None:
    root = tmp_path / ".scratchpad"
    root.mkdir()
    payloads = _seed(root, tmp_path)

    outcome = _prepare(root, tmp_path)
    receipt = _assert_receipt(root, outcome, "RESOLVED")
    manifest = _json_file(root, MANIFEST_FILE)

    assert receipt["selected_conditional"] == MANIFEST_FILE
    assert not (root / DEBT_FILE).exists()
    assert set(outcome["dynamic_source_paths"]) == {FACT_SOURCE}
    assert set(outcome["t0_additional_inputs"]) == {
        RECEIPT_FILE,
        MANIFEST_FILE,
        IDENTITY_FILE,
        FACT_SOURCE,
    }
    assert outcome["manifest"] == manifest
    assert manifest["schema_version"] == (
        "plamen.prearm_content_addressed_input_manifest.v1"
    )
    assert manifest["pipeline"] == "sc"
    assert manifest["run_id"] == RUN_ID
    assert manifest["selection_authority"] == {
        "identity": "scratchpad:" + CANDIDATE_FILE,
        "sha256": _sha(payloads[CANDIDATE_FILE]),
        "size": len(payloads[CANDIDATE_FILE]),
    }
    assert manifest["identity_denominator"] == {
        "identity": "scratchpad:" + IDENTITY_FILE,
        "sha256": _sha(payloads[IDENTITY_FILE]),
        "size": len(payloads[IDENTITY_FILE]),
    }
    assert manifest["referenced_source_identities"] == [
        "scratchpad:" + FACT_SOURCE
    ]
    assert manifest["entries"] == [{
        "identity": "scratchpad:" + FACT_SOURCE,
        "sha256": _sha(payloads[FACT_SOURCE]),
        "size": len(payloads[FACT_SOURCE]),
    }]
    assert manifest["manifest_digest"] == _manifest_digest(manifest)
    assert manifest["content_addressed"] is True
    assert manifest["live_glob_allowed"] is False
    assert manifest["live_read_after_arm_allowed"] is False
    _assert_active_binding(root, MANIFEST_FILE)
    _assert_inactive_or_absent_binding(root, DEBT_FILE)

    ledger = read_artifact_ledger(root)
    producer = ledger["work_units"][PREARM_OWNER]
    manifest_record = producer["artifacts"]["scratchpad:" + MANIFEST_FILE]
    debt_record = producer["artifacts"]["scratchpad:" + DEBT_FILE]
    assert manifest_record["conditional_receipt"]["state"] == "PRODUCED"
    assert debt_record["conditional_receipt"]["state"] == "NOT_TRIGGERED"


def test_resolver_freezes_resolution_manifest_and_every_source_before_t0_arm(
    tmp_path: Path,
) -> None:
    root = tmp_path / ".scratchpad"
    root.mkdir()
    _seed(root, tmp_path)
    outcome = _prepare(root, tmp_path)

    plan = _resolved_plan(outcome)
    t0 = LIVE._child_map(plan)[LIVE.CHILD_IDS[0]]
    inputs = set(map(str, t0["exact_inputs"]))

    assert {
        RECEIPT_FILE,
        MANIFEST_FILE,
        IDENTITY_FILE,
        CANDIDATE_FILE,
        FACT_SOURCE,
    } <= inputs
    assert set(outcome["t0_additional_inputs"]) <= inputs
    assert set(outcome["t0_additional_inputs"]) <= set(
        map(str, t0["required_inputs"])
    )
    resolution = t0["prearm_dynamic_input_resolution"]
    assert resolution["state"] == "RESOLVED"
    assert resolution["receipt_path"] == RECEIPT_FILE
    assert resolution["active_conditional_path"] == MANIFEST_FILE
    assert resolution["phase_io_owner_key"] == PREARM_OWNER
    assert resolution["status_json_is_authority"] is False
    assert resolution["live_glob_allowed"] is False
    assert resolution["live_read_after_arm_allowed"] is False


def test_t0_semantic_replay_accepts_byte_exact_resolved_manifest(
    tmp_path: Path,
) -> None:
    root = tmp_path / ".scratchpad"
    root.mkdir()
    _seed(root, tmp_path)
    outcome = _prepare(root, tmp_path)
    plan = _resolved_plan(outcome)
    _seed_other_t0_inputs(root, plan)
    t0 = LIVE._child_map(plan)[LIVE.CHILD_IDS[0]]
    frozen = {
        relative: (root / relative).read_bytes()
        for relative in map(str, t0["exact_inputs"])
    }

    result = build_live_verify_queue_semantic_executor(plan)(
        unit=t0,
        frozen_inputs=frozen,
    )

    assert result["state"] == "COMMITTED_APPLIED"
    output_paths = set(map(str, result["outputs"]))
    assert any(path.endswith("/input_bundle.json") for path in output_paths)
    assert any(
        path.endswith("/input_presence_roster.json")
        for path in output_paths
    )


def _rehash_manifest(manifest: dict[str, Any]) -> None:
    manifest["manifest_digest"] = _manifest_digest(manifest)


def _omit_manifest_entry(manifest: dict[str, Any]) -> None:
    manifest["entries"] = []
    manifest["entry_count"] = 0
    manifest["entry_identity_digest"] = _sha(_canonical_bytes([]))
    _rehash_manifest(manifest)


def _add_manifest_entry(manifest: dict[str, Any]) -> None:
    manifest["unexpected"] = "not-in-schema"
    _rehash_manifest(manifest)


def _allow_live_glob(manifest: dict[str, Any]) -> None:
    manifest["live_glob_allowed"] = True
    _rehash_manifest(manifest)


def _foreign_manifest(manifest: dict[str, Any]) -> None:
    manifest["run_id"] = FOREIGN_RUN_ID
    _rehash_manifest(manifest)


def _stale_manifest_binding(manifest: dict[str, Any]) -> None:
    manifest["entries"][0]["sha256"] = "f" * 64


@pytest.mark.parametrize(
    "mutation",
    (
        _stale_manifest_binding,
        _omit_manifest_entry,
        _add_manifest_entry,
        _allow_live_glob,
        _foreign_manifest,
    ),
    ids=("mutated", "omitted", "extra", "live-glob", "foreign"),
)
def test_resolver_rejects_noncanonical_or_open_manifest(
    tmp_path: Path,
    mutation: Callable[[dict[str, Any]], None],
) -> None:
    root = tmp_path / ".scratchpad"
    root.mkdir()
    _seed(root, tmp_path)
    outcome = dict(_prepare(root, tmp_path))
    manifest = copy.deepcopy(outcome["manifest"])
    mutation(manifest)
    outcome["manifest"] = manifest

    with pytest.raises(
        (TRANSACTION.VerifyQueueTransactionError, TypeError, ValueError),
        match="manifest|source|run|glob|field|digest|denominator",
    ):
        _resolved_plan(outcome, resolution_override=outcome)


def test_t0_semantic_replay_rejects_source_mutation_after_resolution(
    tmp_path: Path,
) -> None:
    root = tmp_path / ".scratchpad"
    root.mkdir()
    _seed(root, tmp_path)
    outcome = _prepare(root, tmp_path)
    plan = _resolved_plan(outcome)
    _seed_other_t0_inputs(root, plan)
    (root / FACT_SOURCE).write_bytes(b'{"mutated":true}\n')
    t0 = LIVE._child_map(plan)[LIVE.CHILD_IDS[0]]
    frozen = {
        relative: (root / relative).read_bytes()
        for relative in map(str, t0["exact_inputs"])
    }

    with pytest.raises(
        LiveVerifyQueueSemanticError,
        match="drift|binding|manifest|source",
    ):
        build_live_verify_queue_semantic_executor(plan)(
            unit=t0,
            frozen_inputs=frozen,
        )


def test_resume_is_byte_exact_and_does_not_change_phaseio_authority(
    tmp_path: Path,
) -> None:
    root = tmp_path / ".scratchpad"
    root.mkdir()
    _seed(root, tmp_path)

    first = _prepare(root, tmp_path)
    before = {
        relative: (root / relative).read_bytes()
        for relative in (RECEIPT_FILE, MANIFEST_FILE)
    }
    ledger_before = read_artifact_ledger(root)
    binding_before = copy.deepcopy(
        ledger_before["artifact_bindings"]["scratchpad:" + MANIFEST_FILE]
    )

    second = _prepare(root, tmp_path)
    after = {
        relative: (root / relative).read_bytes()
        for relative in (RECEIPT_FILE, MANIFEST_FILE)
    }
    binding_after = read_artifact_ledger(root)[
        "artifact_bindings"
    ]["scratchpad:" + MANIFEST_FILE]

    assert first == second
    assert before == after
    for field in (
        "owner_key",
        "run_id",
        "contract_digest",
        "launch_digest",
        "sha256",
        "size",
        "status",
        "authority_level",
    ):
        assert binding_after[field] == binding_before[field]


def test_l1_is_unaffected_and_never_creates_sc_prearm_outputs(
    tmp_path: Path,
) -> None:
    root = tmp_path / ".scratchpad"
    root.mkdir()

    outcome = _prepare(root, tmp_path, pipeline="l1")

    assert outcome["state"] == "NOT_APPLICABLE"
    assert outcome["t0_additional_inputs"] == []
    assert outcome["dynamic_source_paths"] == []
    assert not any(
        (root / relative).exists()
        for relative in (RECEIPT_FILE, MANIFEST_FILE, DEBT_FILE)
    )
    baseline = LIVE._plan("l1", "claude")
    t0 = LIVE._child_map(baseline)[LIVE.CHILD_IDS[0]]
    assert "prearm_dynamic_input_resolution" not in t0
    assert not {
        RECEIPT_FILE,
        MANIFEST_FILE,
        DEBT_FILE,
    } & set(map(str, t0["exact_inputs"]))
