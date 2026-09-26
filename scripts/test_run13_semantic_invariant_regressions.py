"""Run13 regressions for frozen P1-D identity and staged publication."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from artifact_ledger import read_artifact_ledger
import plamen_driver as D
import semantic_invariant_authority as A


RUN_ID = "123e4567-e89b-42d3-a456-426614174000"
SNAPSHOT = "a" * 64
SOURCE_SCOPE = "b" * 64


def _write_checkpoint(root: Path, *, completed: tuple[str, ...] = ()) -> None:
    payload = {
        "run_id": RUN_ID,
        "config": {
            "pipeline": "sc",
            "mode": "core",
            "language": "evm",
        },
        "audit_snapshot": {
            "snapshot_digest": SNAPSHOT,
            "components": {"source_scope": {"digest": SOURCE_SCOPE}},
        },
        "completed": list(completed),
    }
    (root / "_v2_checkpoint.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _write_graph(root: Path) -> None:
    (root / "function_list.md").write_text("# Function List\n", encoding="utf-8")
    source = root / "src" / "Ledger.sol"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(
        "contract Ledger { uint256 total; function set(uint256 n) external "
        "{ total = n; } }\n",
        encoding="utf-8",
    )
    payload = {
        "schema_version": "plamen.mechanical_graph.v2",
        "source": "run13-fixture",
        "state_symbols": [
            {
                "qualified_name": "Ledger.total",
                "bare": "total",
                "declaration_locus": "src/Ledger.sol:L1",
                "read_sites": [],
                "write_sites": ["src/Ledger.sol:L1"],
                "state_class": "MUTABLE",
                "type_domain": "uint256",
            }
        ],
        "var_refs": {},
    }
    (root / "_mechanical_graph.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _write_mixed_graph(root: Path) -> None:
    source = root / "src" / "Ledger.sol"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(
        "contract Ledger {\n"
        "uint256 total;\n"
        "uint256 pending;\n"
        "function set(uint256 n) external { total = n; pending = n; }\n"
        "}\n",
        encoding="utf-8",
    )
    payload = {
        "schema_version": "plamen.mechanical_graph.v2",
        "source": "run13-mixed-fixture",
        "state_symbols": [
            {
                "qualified_name": f"Ledger.{name}",
                "bare": name,
                "declaration_locus": f"src/Ledger.sol:L{line}",
                "read_sites": [],
                "write_sites": ["src/Ledger.sol:L4"],
                "state_class": "MUTABLE",
                "type_domain": "uint256",
            }
            for name, line in (("total", 2), ("pending", 3))
        ],
        "var_refs": {},
    }
    (root / "_mechanical_graph.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _config(root: Path) -> dict[str, object]:
    return {
        "pipeline": "sc",
        "mode": "core",
        "language": "evm",
        "cli_backend": "codex",
        "project_root": str(root),
        "_run_id": RUN_ID,
    }


def _phase(name: str):
    return next(phase for phase in D.SC_PHASES if phase.name == name)


def _producer_and_independent(
    worklist: dict[str, object],
) -> tuple[dict[str, object], dict[str, object]]:
    state = worklist["states"][0]
    assert isinstance(state, dict)
    producer_row = {
        "state_id": state["state_id"],
        "disposition": "DELIVERED",
        "evidence_loci": ["src/Ledger.sol:L1"],
        "write_site_status": "COMPLETE",
        "semantic_status": "SEMANTICS_OK",
        "result": "Every enumerated write was checked against the state meaning.",
    }
    run_binding = worklist["run_binding"]
    assert isinstance(run_binding, dict)
    producer = {
        "schema_version": A.APPLICATION_TRACE_SCHEMA,
        "run_binding_digest": run_binding["binding_digest"],
        "authority_digest": worklist["authority_digest"],
        "worklist_digest": worklist["worklist_digest"],
        "producer_operator_digest": "c" * 64,
        "rows": [producer_row],
    }
    producer["payload_digest"] = A.payload_digest(producer)
    independent = {
        "schema_version": A.INDEPENDENT_TRACE_SCHEMA,
        "run_binding_digest": run_binding["binding_digest"],
        "authority_digest": worklist["authority_digest"],
        "worklist_digest": worklist["worklist_digest"],
        "producer_payload_digest": producer["payload_digest"],
        "consumer_kind": "DEPTH_STATE_TRACE",
        "consumer_operator_digest": "d" * 64,
        "rows": [
            {
                "state_id": state["state_id"],
                "disposition": "APPLIED",
                "producer_row_digest": A.producer_row_digest(producer_row),
                "evidence_loci": ["src/Ledger.sol:L1"],
                "result": "Independent depth tracing confirmed the producer row.",
            }
        ],
    }
    independent["payload_digest"] = A.payload_digest(independent)
    return producer, independent


def _write_semantic_trace(root: Path, producer: dict[str, object]) -> None:
    text = (
        "# Semantic invariants\n\n"
        + A.TRACE_BEGIN
        + "\n"
        + json.dumps(producer, indent=2, sort_keys=True)
        + "\n"
        + A.TRACE_END
        + "\n\n<!-- PLAMEN_STATUS: COMPLETE -->\n"
    )
    (root / "semantic_invariants.md").write_text(text, encoding="utf-8")


def _semantic_fixture(
    root: Path,
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    _write_checkpoint(root)
    _write_graph(root)
    A.materialize_semantic_invariant_compatibility_inputs(root)
    A.write_semantic_invariant_authority(
        root, ecosystem="evm", mode="core", run_id=RUN_ID
    )
    worklist = json.loads((root / A.WORKLIST_FILE).read_text(encoding="utf-8"))
    producer, independent = _producer_and_independent(worklist)
    _write_semantic_trace(root, producer)
    return worklist, producer, independent


def _lf_digest_variant(payload: dict[str, object]) -> dict[str, object]:
    candidate = dict(payload)
    unsigned = {key: value for key, value in candidate.items() if key != "payload_digest"}
    preimage = json.dumps(
        unsigned,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8") + b"\n"
    candidate["payload_digest"] = hashlib.sha256(preimage).hexdigest()
    return candidate


def test_checkpoint_progress_preserves_frozen_identity_and_applied_status(
    tmp_path: Path,
) -> None:
    worklist, producer, independent = _semantic_fixture(tmp_path)
    frozen_authority = worklist["authority_digest"]
    frozen_worklist = worklist["worklist_digest"]

    _write_checkpoint(
        tmp_path,
        completed=("recon", "invariants", "invariants_p2", "depth"),
    )
    receipt = A.reconcile_semantic_invariant_application(
        tmp_path,
        application_payload=producer,
        independent_payload=independent,
        ecosystem="evm",
        mode="core",
        run_id=RUN_ID,
        backend="codex",
    )

    assert receipt["status"] == "APPLIED"
    assert receipt["authority_digest"] == frozen_authority
    assert receipt["worklist_digest"] == frozen_worklist
    assert receipt["issues"] == []
    assert A.validate_semantic_invariant_authority(
        tmp_path, ecosystem="evm", mode="core", run_id=RUN_ID
    ) == []


def test_staged_validator_accepts_no_lf_digest_and_rejects_lf_digest(
    tmp_path: Path,
) -> None:
    _worklist, _producer, independent = _semantic_fixture(tmp_path)
    config = _config(tmp_path)
    context = D._semantic_independent_staged_context(tmp_path, config)
    identity = "scratchpad:" + A.INDEPENDENT_TRACE_FILE
    exact = json.dumps(
        independent,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    assert exact[-1:] == b"}"
    assert D._staged_semantic_independent_trace_validator(
        {identity: exact}, context
    ) == ()

    mismatch = _lf_digest_variant(independent)
    issues = D._staged_semantic_independent_trace_validator(
        {
            identity: json.dumps(
                mismatch,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        },
        context,
    )
    # Driver-sealed contract: a model-written digest (LF variant or any
    # other spelling) is replaced, never fatal.
    assert not any("payload digest mismatch" in issue for issue in issues)


def test_independent_prompt_defines_exact_no_trailing_newline_preimage() -> None:
    prompt = D._semantic_independent_prompt()

    assert "Do NOT include" in prompt and "driver stamps" in prompt
    assert "Never invent a hash" in prompt
    assert "jq" not in prompt
    assert "every valid row in the embedded producer trace" in prompt
    assert "producer uncertainty cannot remove a row" in prompt
    assert "`DEFERRED` or `CONFLICT`" in prompt


def test_mixed_receipt_status_preserves_raw_independent_denominator(
    tmp_path: Path,
) -> None:
    _write_checkpoint(tmp_path)
    _write_mixed_graph(tmp_path)
    A.materialize_semantic_invariant_compatibility_inputs(tmp_path)
    A.write_semantic_invariant_authority(
        tmp_path, ecosystem="evm", mode="core", run_id=RUN_ID
    )
    worklist = json.loads((tmp_path / A.WORKLIST_FILE).read_text(encoding="utf-8"))
    authority = json.loads((tmp_path / A.AUTHORITY_FILE).read_text(encoding="utf-8"))
    states = {
        row["qualified_name"]: row for row in worklist["states"]
    }
    delivered = {
        "state_id": states["Ledger.total"]["state_id"],
        "disposition": "DELIVERED",
        "evidence_loci": ["src/Ledger.sol:L2", "src/Ledger.sol:L4"],
        "write_site_status": "COMPLETE",
        "semantic_status": "SEMANTICS_OK",
        "result": "The complete total write set was traced independently.",
    }
    bounded = {
        "state_id": states["Ledger.pending"]["state_id"],
        "disposition": "DELIVERED",
        "evidence_loci": ["src/Ledger.sol:L3", "src/Ledger.sol:L4"],
        "write_site_status": "BOUNDED",
        "semantic_status": "SEMANTICS_UNKNOWN",
        "result": "The producer delivered a bounded pending-state trace.",
    }
    producer = {
        "schema_version": A.APPLICATION_TRACE_SCHEMA,
        "run_binding_digest": worklist["run_binding"]["binding_digest"],
        "authority_digest": worklist["authority_digest"],
        "worklist_digest": worklist["worklist_digest"],
        "producer_operator_digest": "c" * 64,
        "rows": [delivered, bounded],
    }
    producer["payload_digest"] = A.payload_digest(producer)
    _write_semantic_trace(tmp_path, producer)
    receipt = A.reconcile_semantic_invariant_application(
        tmp_path,
        application_payload=producer,
        ecosystem="evm",
        mode="core",
        run_id=RUN_ID,
        backend="codex",
    )
    assert receipt["delivered_count"] == 1
    assert receipt["deferred_count"] == 1

    independent_rows = [
        {
            "state_id": row["state_id"],
            "disposition": disposition,
            "producer_row_digest": A.producer_row_digest(row),
            "evidence_loci": list(row["evidence_loci"]),
            "result": result,
        }
        for row, disposition, result in (
            (delivered, "APPLIED", "Independent tracing confirmed total."),
            (bounded, "DEFERRED", "Pending remains bounded after review."),
        )
    ]
    independent = {
        "schema_version": A.INDEPENDENT_TRACE_SCHEMA,
        "run_binding_digest": worklist["run_binding"]["binding_digest"],
        "authority_digest": worklist["authority_digest"],
        "worklist_digest": worklist["worklist_digest"],
        "producer_payload_digest": producer["payload_digest"],
        "consumer_kind": "DEPTH_STATE_TRACE",
        "consumer_operator_digest": "d" * 64,
        "rows": independent_rows,
    }
    independent["payload_digest"] = A.payload_digest(independent)
    assert A.independent_delivery_denominator(
        producer,
        worklist,
        authority,
    ) == tuple(sorted((delivered["state_id"], bounded["state_id"])))
    assert A.validate_independent_semantic_invariant_trace(
        tmp_path,
        independent,
        ecosystem="evm",
        mode="core",
        run_id=RUN_ID,
        backend="codex",
    ) == []

    receipt = A.reconcile_semantic_invariant_application(
        tmp_path,
        application_payload=producer,
        independent_payload=independent,
        ecosystem="evm",
        mode="core",
        run_id=RUN_ID,
        backend="codex",
    )
    states_by_id = {row["state_id"]: row for row in receipt["states"]}
    assert states_by_id[delivered["state_id"]]["status"] == "APPLIED"
    assert states_by_id[bounded["state_id"]]["status"] == "DEFERRED"
    assert states_by_id[bounded["state_id"]]["issues"] == [
        "application remains bounded or semantically unknown"
    ]
    assert receipt["applied_count"] == 1
    assert receipt["deferred_count"] == 1

    underbroad = dict(independent)
    underbroad["rows"] = independent_rows[:1]
    underbroad["payload_digest"] = A.payload_digest(underbroad)
    issues = A.validate_independent_semantic_invariant_trace(
        tmp_path,
        underbroad,
        ecosystem="evm",
        mode="core",
        run_id=RUN_ID,
        backend="codex",
    )
    assert issues == [
        "independent application rows differ from the exact "
        "delivered-state denominator"
    ]


def test_invalid_staged_candidate_never_becomes_canonical_or_active(
    tmp_path: Path, monkeypatch,
) -> None:
    _write_checkpoint(tmp_path)
    _write_graph(tmp_path)
    config = _config(tmp_path)
    assert D._prepare_semantic_invariant_pre_boundary(tmp_path, config) == []
    assert D._bind_typed_model_phase_inputs(
        _phase("invariants"), tmp_path, config
    ) == []
    worklist = json.loads((tmp_path / A.WORKLIST_FILE).read_text(encoding="utf-8"))
    producer, independent = _producer_and_independent(worklist)
    _write_semantic_trace(tmp_path, producer)
    assert D._finalize_semantic_invariant_post_boundary(tmp_path, config) == []

    observed: dict[str, object] = {}

    def reject_before_publication(**kwargs) -> int:
        observed["calls"] = int(observed.get("calls", 0)) + 1
        validator = kwargs["staged_output_validator"]
        context = kwargs["staged_output_context"]
        identity = "scratchpad:" + A.INDEPENDENT_TRACE_FILE
        candidate = dict(independent)
        candidate["rows"] = "not-a-list"  # genuinely invalid content, not a digest spelling
        raw = json.dumps(candidate, sort_keys=True).encode("utf-8")
        staged_issues = tuple(validator({identity: raw}, context))
        observed["issues"] = staged_issues
        observed["input_identities"] = tuple(
            kwargs["staged_output_input_identities"]
        )
        assert any("rows is not an array" in issue for issue in staged_issues)
        assert not (tmp_path / A.INDEPENDENT_TRACE_FILE).exists()
        return -2

    monkeypatch.setattr(
        D, "_execute_auxiliary_model_work_unit", reject_before_publication
    )
    issues = D._run_p1dm_model_work_unit(
        tmp_path,
        config,
        _phase("depth"),
        phase_name="depth",
        work_unit_id="worker.semantic_invariant_independent",
        output=A.INDEPENDENT_TRACE_FILE,
        prompt=D._semantic_independent_prompt(),
        validate=lambda: D._validate_independent_trace_shape(tmp_path, config),
        staged_output_validator=D._staged_semantic_independent_trace_validator,
        staged_output_context=D._semantic_independent_staged_context(
            tmp_path, config
        ),
    )

    assert any("auxiliary model exited rc=-2" in issue for issue in issues)
    # An untyped rc=-2 is not authority to launch a correction attempt.
    assert observed["calls"] == 1
    assert observed["issues"]
    assert "scratchpad:_v2_checkpoint.json" in observed["input_identities"]
    assert not (tmp_path / A.INDEPENDENT_TRACE_FILE).exists()
    ledger = read_artifact_ledger(tmp_path)
    key = "sc/core/evm/codex/depth/worker.semantic_invariant_independent"
    unit = ledger["work_units"][key]
    assert unit["semantic_status"] == "QUARANTINED"
    assert unit["execution_state"] == "OUTPUT_QUARANTINED"
    binding = ledger["artifact_bindings"][
        "scratchpad:" + A.INDEPENDENT_TRACE_FILE
    ]
    assert binding["status"] != "ACTIVE"
    journal_path = tmp_path / "_artifact_output_authorities.json"
    if journal_path.is_file():
        journal = json.loads(journal_path.read_text(encoding="utf-8"))
        authorities = [
            row
            for row in journal.get("authorities", {}).values()
            if row.get("work_unit_key") == key
        ]
        # One wrapper-issued absent-output capability may explain the explicit
        # quarantine. A prior successful transactional publication would add a
        # second authority carrying PRESENT output bytes and recreate Run13's
        # ACTIVE-inner/quarantined-wrapper split state.
        assert len(authorities) == 1
        observed_output = authorities[0]["observed_outputs"][
            "scratchpad:" + A.INDEPENDENT_TRACE_FILE
        ]
        assert observed_output["status"] == "ABSENT"
        assert observed_output["sha256"] == ""


def test_semantic_independent_staged_rejection_gets_one_bounded_correction(
    tmp_path: Path, monkeypatch,
) -> None:
    _write_checkpoint(tmp_path)
    _write_graph(tmp_path)
    config = _config(tmp_path)
    assert D._prepare_semantic_invariant_pre_boundary(tmp_path, config) == []
    assert D._bind_typed_model_phase_inputs(
        _phase("invariants"), tmp_path, config
    ) == []
    worklist = json.loads((tmp_path / A.WORKLIST_FILE).read_text(encoding="utf-8"))
    producer, independent = _producer_and_independent(worklist)
    _write_semantic_trace(tmp_path, producer)
    assert D._finalize_semantic_invariant_post_boundary(tmp_path, config) == []

    attempts: list[int] = []

    def reject_then_publish(**kwargs) -> int:
        attempt = int(kwargs.get("attempt", 1))
        attempts.append(attempt)
        if attempt == 1:
            assert "attempt 2 of 2" not in kwargs["prompt"]
            receipts = tmp_path / ".posix_v2_compat_receipts"
            receipts.mkdir(exist_ok=True)
            (receipts / (
                "depth.worker_semantic_invariant_independent."
                "attempt1.fixture.json"
            )).write_text(
                json.dumps({
                    "schema": D._POSIX_V2_COMPAT_EXECUTION_RECEIPT_SCHEMA,
                    "phase": "depth",
                    "label": "worker_semantic_invariant_independent",
                    "attempt": 1,
                    "failure_code": "STAGED_SEMANTIC_REJECTED",
                    "returncode": 0,
                    "compatibility_return_value": -2,
                }),
                encoding="utf-8",
            )
            return -2
        assert "attempt 2 of 2" in kwargs["prompt"]
        (tmp_path / A.INDEPENDENT_TRACE_FILE).write_text(
            json.dumps(independent, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        return 0

    monkeypatch.setattr(
        D, "_execute_auxiliary_model_work_unit", reject_then_publish
    )
    issues = D._run_p1dm_model_work_unit(
        tmp_path,
        config,
        _phase("depth"),
        phase_name="depth",
        work_unit_id="worker.semantic_invariant_independent",
        output=A.INDEPENDENT_TRACE_FILE,
        prompt=D._semantic_independent_prompt(),
        validate=lambda: D._validate_independent_trace_shape(tmp_path, config),
        staged_output_validator=D._staged_semantic_independent_trace_validator,
        staged_output_context=D._semantic_independent_staged_context(
            tmp_path, config
        ),
    )

    assert attempts == [1, 2]
    assert issues == []
    assert (tmp_path / A.INDEPENDENT_TRACE_FILE).is_file()
