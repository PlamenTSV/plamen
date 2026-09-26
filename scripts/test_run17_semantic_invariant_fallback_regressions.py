"""Run17 regressions for producer trace hashing and governed fallback debt."""

from __future__ import annotations

import base64
import hashlib
import json
import uuid
import zlib
from pathlib import Path
from types import SimpleNamespace

import plamen_driver as D
import semantic_invariant_authority as A
from phase_io_contracts import resolve_phase_io_contract
from plamen_types import Checkpoint, Phase
from worker_transaction import staged_output_validator_binding


RUN_ID = "123e4567-e89b-42d3-a456-426614174017"
SNAPSHOT = "a" * 64
SOURCE_SCOPE = "b" * 64
RUN17_STALE_DIGEST = (
    "8eeb5a53e0b21f77bf99d3c479d71d93d9e38af8467e1a18666b6644a7eeb3fd"
)
RUN17_OLD_OPERATOR = (
    "a566ec2938c4034fd67165074c21a846566b6b429318175cf94f8e75c8b4e0ed"
)
RUN17_FINAL_OPERATOR = (
    "4443ab14030eb2c65d5177e0f8cbeb08a03d1cf337f797d5c4a2a8e053c6eea2"
)
RUN17_EXPECTED_DIGEST = (
    "fbe955246b19a43f317d1027478ec0b5cba079e392711956266f8b623b00f2c1"
)
# Exact rejected Run17 trace, compressed only to keep the regression readable.
RUN17_REJECTED_TRACE_ZLIB_B64 = """
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
"""


def _config(root: Path, *, backend: str = "codex") -> dict[str, object]:
    return {
        "pipeline": "sc",
        "mode": "core",
        "language": "evm",
        "cli_backend": backend,
        "project_root": str(root),
        "_run_id": RUN_ID,
    }


def _write_checkpoint(
    root: Path,
    *,
    run_id: str = RUN_ID,
    completed: tuple[str, ...] = (),
) -> None:
    payload = {
        "run_id": run_id,
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


def _write_graph(root: Path, *, state_count: int = 41) -> None:
    source = root / "src" / "Ledger.sol"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(
        "contract Ledger {\n"
        + "".join(f"uint256 value{index};\n" for index in range(state_count))
        + "}\n",
        encoding="utf-8",
    )
    payload = {
        "schema_version": "plamen.mechanical_graph.v2",
        "source": "run17-staged-validator-fixture",
        "state_symbols": [
            {
                "qualified_name": f"Ledger.value{index}",
                "bare": f"value{index}",
                "declaration_locus": f"src/Ledger.sol:L{index + 2}",
                "read_sites": [],
                "write_sites": [f"src/Ledger.sol:L{index + 2}"],
                "state_class": "MUTABLE",
                "type_domain": "uint256",
            }
            for index in range(state_count)
        ],
        "var_refs": {},
    }
    (root / "_mechanical_graph.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _producer_fixture(
    root: Path,
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    _write_checkpoint(root)
    _write_graph(root)
    A.materialize_semantic_invariant_compatibility_inputs(root)
    A.write_semantic_invariant_authority(
        root, ecosystem="evm", mode="core", run_id=RUN_ID
    )
    authority = json.loads((root / A.AUTHORITY_FILE).read_text(encoding="utf-8"))
    worklist = json.loads((root / A.WORKLIST_FILE).read_text(encoding="utf-8"))
    rows = []
    for index, state in enumerate(worklist["states"]):
        delivered = index < 21
        rows.append({
            "state_id": state["state_id"],
            "disposition": "DELIVERED",
            "evidence_loci": [state["declaration_locus"]],
            "write_site_status": "COMPLETE",
            "semantic_status": (
                "SEMANTICS_OK" if delivered else "SEMANTICS_UNKNOWN"
            ),
            "result": (
                "Complete state transition semantics were traced."
                if delivered
                else "The state was enumerated but semantics remain bounded."
            ),
        })
    producer = {
        "schema_version": A.APPLICATION_TRACE_SCHEMA,
        "run_binding_digest": worklist["run_binding"]["binding_digest"],
        "authority_digest": worklist["authority_digest"],
        "worklist_digest": worklist["worklist_digest"],
        "producer_operator_digest": RUN17_OLD_OPERATOR,
        "rows": rows,
    }
    producer["payload_digest"] = A.payload_digest(producer)
    producer["producer_operator_digest"] = RUN17_FINAL_OPERATOR
    return authority, worklist, producer


def _semantic_markdown(payload: dict[str, object]) -> bytes:
    return (
        "# Semantic invariants\n\n"
        + A.TRACE_BEGIN
        + "\n"
        + json.dumps(payload, indent=2, sort_keys=True)
        + "\n"
        + A.TRACE_END
        + "\n\n<!-- PLAMEN_STATUS: COMPLETE -->\n"
    ).encode("utf-8")


def test_producer_prompt_defines_exact_no_lf_canonical_digest(monkeypatch) -> None:
    monkeypatch.setattr(
        D,
        "_p1dm_contract_and_launch",
        lambda *args, **kwargs: (SimpleNamespace(), SimpleNamespace()),
    )
    monkeypatch.setattr(
        D,
        "compile_phase_io_prompt",
        lambda prompt, contract, *, actor: prompt,
    )

    prompt = D._compile_semantic_invariant_model_prompt(
        "base prompt",
        Phase("invariants", ["phase"], ["semantic_invariants.md"], 60),
        Path("/not-read"),
        {},
    )

    # Driver-sealed contract (DODO run47): the worker is told NOT to hash;
    # the driver stamps every cryptographic field after binding.
    assert "Do NOT include" in prompt
    assert "driver stamps" in prompt
    assert "Never invent a hash" in prompt
    assert "jq" not in prompt
    assert "nothing else between them" in prompt


def test_run17_digest_constants_capture_the_observed_operator_mutation() -> None:
    payload = json.loads(
        zlib.decompress(base64.b64decode(RUN17_REJECTED_TRACE_ZLIB_B64))
    )

    assert len(payload["rows"]) == 41
    assert payload["producer_operator_digest"] == RUN17_FINAL_OPERATOR
    assert payload["payload_digest"] == RUN17_STALE_DIGEST
    assert A.payload_digest(payload) == RUN17_EXPECTED_DIGEST
    prior = dict(payload)
    prior["producer_operator_digest"] = RUN17_OLD_OPERATOR
    assert A.payload_digest(prior) == RUN17_STALE_DIGEST


def test_staged_run17_operator_mutation_rejects_without_publication_and_fix_replays(
    tmp_path: Path,
) -> None:
    _authority, _worklist, producer = _producer_fixture(tmp_path)
    context = D._semantic_invariant_staged_context(
        tmp_path, _config(tmp_path)
    )
    identity = "scratchpad:semantic_invariants.md"
    canonical = tmp_path / "semantic_invariants.md"
    canonical_prestate = b"# immutable canonical prestate\n"
    canonical.write_bytes(canonical_prestate)

    expected = A.payload_digest(producer)
    assert producer["payload_digest"] != expected
    issues = D._staged_semantic_invariant_output_validator(
        {identity: _semantic_markdown(producer)}, context
    )

    # Driver-sealed contract: a model-written digest is replaced, never a
    # rejection; the staged validator still never touches the canonical file.
    assert not any("payload digest mismatch" in issue for issue in issues)
    assert canonical.read_bytes() == canonical_prestate

    corrected = dict(producer)
    corrected["payload_digest"] = expected
    assert D._staged_semantic_invariant_output_validator(
        {identity: _semantic_markdown(corrected)}, context
    ) == ()
    receipt, _projection = A.derive_semantic_invariant_application(
        tmp_path,
        application_payload=corrected,
        ecosystem="evm",
        mode="core",
        run_id=RUN_ID,
        load_independent_from_disk=False,
        backend="codex",
    )
    assert receipt["delivered_count"] == 21
    assert receipt["deferred_count"] == 20
    assert receipt["unmeasurable_count"] == 0


def test_staged_validator_normalizes_checkpoint_progress_but_rejects_drift(
    tmp_path: Path,
) -> None:
    cases = ("worklist", "authority", "run")
    for case in cases:
        root = tmp_path / case
        root.mkdir()
        _authority, _worklist, stale = _producer_fixture(root)
        producer = dict(stale)
        producer["payload_digest"] = A.payload_digest(producer)
        context = D._semantic_invariant_staged_context(root, _config(root))
        identity = "scratchpad:semantic_invariants.md"
        outputs = {identity: _semantic_markdown(producer)}

        _write_checkpoint(root, completed=("recon", "invariants"))
        assert D._staged_semantic_invariant_output_validator(
            outputs, context
        ) == ()

        if case == "worklist":
            payload = json.loads(
                (root / A.WORKLIST_FILE).read_text(encoding="utf-8")
            )
            payload["states"][0]["qualified_name"] = "Ledger.drifted"
            (root / A.WORKLIST_FILE).write_text(
                json.dumps(payload, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        elif case == "authority":
            payload = json.loads(
                (root / A.AUTHORITY_FILE).read_text(encoding="utf-8")
            )
            payload["status"] = "UNMEASURABLE"
            (root / A.AUTHORITY_FILE).write_text(
                json.dumps(payload, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        else:
            _write_checkpoint(
                root,
                run_id="123e4567-e89b-42d3-a456-426614174099",
                completed=("recon", "invariants"),
            )

        issues = D._staged_semantic_invariant_output_validator(
            outputs, context
        )
        assert issues
        assert any(
            token in issue.casefold()
            for issue in issues
            for token in ("differs", "mismatch", "run_id")
        )


def test_both_monolithic_provider_routes_bind_the_semantic_staged_validator(
    tmp_path: Path,
) -> None:
    phase = Phase("invariants", ["phase"], ["semantic_invariants.md"], 60)
    for backend in ("codex", "claude"):
        config = _config(tmp_path, backend=backend)
        contract = resolve_phase_io_contract(
            pipeline="sc",
            mode="core",
            ecosystem="evm",
            backend=backend,
            phase="invariants",
            work_unit_id="worker.semantic_invariants",
        )
        kwargs = D._semantic_invariant_monolithic_staged_arguments(
            phase, tmp_path, config, contract
        )
        assert kwargs["staged_output_validator"] is (
            D._staged_semantic_invariant_output_validator
        )
        assert kwargs["staged_output_context"] is not None
        assert tuple(kwargs["staged_output_input_identities"]) == tuple(
            contract.immutable_inputs
        )
        validator = kwargs["staged_output_validator"]
        context = kwargs["staged_output_context"]
        if backend == "claude":
            validator = D._staged_claude_semantic_invariant_output_validator
            context = {
                "schema": D._CLAUDE_SEMANTIC_INVARIANT_STAGED_GATE_SCHEMA,
                "exact_gate": {"fixture": "exact-write-receipt"},
                "semantic_gate": context,
            }
        binding = staged_output_validator_binding(
            validator,
            context=context,
            required_input_bindings={},
        )
        assert binding["schema"] == "plamen.staged_output_semantic_gate.v1"
        assert binding["binding_sha256"]


def test_lf_contaminated_digest_differs_from_validator_preimage() -> None:
    unsigned = {
        "authority_digest": "a" * 64,
        "rows": [],
        "schema_version": "plamen.semantic_invariant_application_trace.v2",
    }
    canonical = json.dumps(
        unsigned,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    assert canonical[-1:] == b"}"
    assert hashlib.sha256(canonical).hexdigest() != hashlib.sha256(
        canonical + b"\n"
    ).hexdigest()


def test_consumable_fallback_preserves_rejected_model_gate_in_phase_commit(
    tmp_path: Path,
    monkeypatch,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    issue = (
        "semantic invariant typed application: application trace payload "
        "digest mismatch"
    )
    assert D._record_semantic_invariant_fallback_gate_debt(
        scratchpad, [issue, issue]
    ) == (issue,)

    sentinel = scratchpad / "invariants.degraded"
    assert sentinel.read_text(encoding="utf-8").count(issue) == 1

    fixed = "a" * 64
    monkeypatch.setattr(D, "_record_phase_artifact_state", lambda *a, **k: None)
    monkeypatch.setattr(D, "_resolved_phase_contract_digest", lambda *a, **k: fixed)
    monkeypatch.setattr(D, "_resolved_phase_launch_digest", lambda *a, **k: fixed)
    monkeypatch.setattr(D, "_resolved_phase_artifact_digest", lambda *a, **k: fixed)
    monkeypatch.setattr(D, "_resolved_phase_input_digest", lambda *a, **k: fixed)

    phase = Phase("invariants", ["phase"], ["semantic_invariants.md"], 60)
    checkpoint = Checkpoint(run_id=str(uuid.uuid4()))
    config = {
        "project_root": str(tmp_path),
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "codex",
        "_run_id": checkpoint.run_id,
    }
    commit = D._commit_phase_from_disk_debt(
        phase,
        checkpoint,
        scratchpad,
        config,
        [phase],
        clean_transients=True,
    )

    assert commit.state == "COMPLETED_WITH_DEBT"
    assert "invariants" in checkpoint.completed
    assert "invariants" in checkpoint.degraded
    assert len(commit.unresolved_failures) == 1
    assert issue in commit.unresolved_failures[0].message
    projection = (scratchpad / "phase_completion_debt.md").read_text(
        encoding="utf-8"
    )
    assert "invariants" in projection
    assert issue in projection
