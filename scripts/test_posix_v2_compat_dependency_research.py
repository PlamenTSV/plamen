"""Focused authority tests for the POSIX V2 Codex R-EXT bridge."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import textwrap

import pytest

from artifact_ledger import read_artifact_ledger, record_work_unit_inputs
import codex_dependency_research as research
import plamen_driver as D
import posix_v2_compat_runtime as compat
from phase_io_contracts import resolve_phase_io_contract


def _config(tmp_path: Path) -> dict[str, object]:
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    return {
        "pipeline": "sc",
        "mode": "light",
        "language": "evm",
        "cli_backend": "codex",
        "project_root": str(project),
        "scratchpad": str(scratchpad),
        "_run_id": "compat-research-test",
    }


_DEPENDENCY = "vendor/package"
_KIND = "solidity-import"
_SOURCE_LOCATION = "src/A.sol:L1"
_OBLIGATION_ID = "DEP-" + hashlib.sha256(
    (
        _KIND + "\0" + _DEPENDENCY.casefold() + "\0"
        + _SOURCE_LOCATION.casefold()
    ).encode("utf-8")
).hexdigest()[:12].upper()
_OBLIGATION_ROW = {
    "obligation_id": _OBLIGATION_ID,
    "dependency": _DEPENDENCY,
    "kind": _KIND,
    "source_location": _SOURCE_LOCATION,
    "declaration_evidence": "import vendor/package",
    "research_question": "What behavior is relied on?",
}


def _obligations() -> dict[str, object]:
    return {
        "schema": "plamen.external-dependency-obligations.v1",
        "provider": "deterministic-direct-nonlocal-referenced-v1",
        "obligations": [dict(_OBLIGATION_ROW)],
        "observed_count": 1,
        "retained_count": 1,
        "truncated": False,
        "overflow_ids": [],
    }


_CANONICAL_QUERY = research.compile_model_visible_projection(
    _obligations()
)["query_groups"][0]["query"]


def _report() -> bytes:
    return (
        "| Obligation ID | Dependency | Integration Surface | Assumed Behavior "
        "| Real Behavior | Source | Conformance | Fetch Status |\n"
        "|---|---|---|---|---|---|---|---|\n"
        f"| {_OBLIGATION_ID} | vendor/package | src/A.sol:L1 | stable API | stable API "
        "| https://docs.vendor.com/reference | MATCH | RESEARCHED |\n"
    ).encode()


_CODEX_CANONICAL_SEARCH_EVENT = (
    json.dumps({
        "type": "item.completed",
        "item": {
            "type": "web_search",
            "id": "exec-04b2ce83-4ba6-42b7-9ace-f2737bb9598d",
            "query": _CANONICAL_QUERY,
            "action": {"type": "search", "query": _CANONICAL_QUERY},
        },
    }, separators=(",", ":")) + "\n"
).encode("utf-8")
_CODEX_0154_SEARCH_STARTED_EVENT = (
    b'{"type":"item.started","item":'
    b'{"id":"item_1","type":"web_search",'
    b'"id":"exec-04b2ce83-4ba6-42b7-9ace-f2737bb9598d",'
    b'"query":"","action":{"type":"other"}}}\n'
)
_CODEX_0154_OPEN_STARTED_EVENT = (
    b'{"type":"item.started","item":'
    b'{"id":"item_2","type":"web_search",'
    b'"id":"exec-94b2ce83-4ba6-42b7-9ace-f2737bb9598d",'
    b'"query":"","action":{"type":"other"}}}\n'
)
_CODEX_0154_OPEN_EVENT = (
    b'{"type":"item.completed","item":'
    b'{"id":"item_2","type":"web_search",'
    b'"id":"exec-94b2ce83-4ba6-42b7-9ace-f2737bb9598d",'
    b'"query":"https://docs.vendor.com/reference",'
    b'"action":{"type":"other"}}}\n'
)
_CODEX_0154_WEB_EVENT = (
    _CODEX_0154_SEARCH_STARTED_EVENT
    + _CODEX_CANONICAL_SEARCH_EVENT
    + _CODEX_0154_OPEN_STARTED_EVENT
    + _CODEX_0154_OPEN_EVENT
)


def _fake_research_codex(path: Path) -> Path:
    path.write_text(
        "#!" + sys.executable + "\n" + textwrap.dedent(f"""
        import json
        from pathlib import Path
        import re
        import sys

        if sys.argv[1:] == ["--version"]:
            print("codex-cli 0.test")
            raise SystemExit(0)
        if sys.argv[1:4] != ["--search", "exec", "--json"]:
            raise SystemExit(91)
        prompt = sys.stdin.buffer.read().decode("utf-8")
        routing = json.loads(re.findall(r"```json\\n(.*?)\\n```", prompt, re.S)[-1])
        output = Path(routing["output_routes"][0]["path"])
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes({_report()!r})
        Path(sys.argv[sys.argv.index("-o") + 1]).write_text("done\\n")
        sys.stdout.buffer.write({_CODEX_0154_WEB_EVENT!r})
        sys.stdout.buffer.write(b'{{"type":"turn.completed"}}\\n')
        """),
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


def _runtime_policy(*_args: object) -> dict[str, object]:
    return {
        "backend": "codex",
        "model": "gpt-5.4",
        "timeout_s": 600,
        "exec_mode": "headless",
    }


def _execute_and_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[dict[str, object], Path, object, object]:
    config = _config(tmp_path)
    project = Path(str(config["project_root"]))
    scratchpad = Path(str(config["scratchpad"]))
    (scratchpad / "external_dependency_obligations.json").write_text(
        json.dumps(_obligations(), sort_keys=True) + "\n",
        encoding="utf-8",
    )
    for name in ("recon_build_static.md", "recon_inventory_surface.md"):
        (scratchpad / name).write_text(f"# {name}\n", encoding="utf-8")
    monkeypatch.setattr(D, "_live_phase_runtime_launch_policy", _runtime_policy)
    phase = next(row for row in D.SC_PHASES if row.name == "recon")
    contract, launch = D._typed_model_worker_contract_and_launch(
        phase=phase,
        config=config,
        scratchpad=scratchpad,
        project_root=str(project),
        agent_id="R-EXT",
        agent_role="external_dependency_research",
        output="recon_external_dependency_research.md",
        timeout_s=600,
        attempt=1,
    )
    record_work_unit_inputs(
        scratchpad,
        project,
        contract,
        launch,
        run_id=str(config["_run_id"]),
    )
    session = compat.issue_posix_v2_compat_session_for_installed_front(
        run_id=str(config["_run_id"]),
        project_root=project,
        scratchpad=scratchpad,
    )
    binary = _fake_research_codex(tmp_path / "codex")
    monkeypatch.setattr(compat.shutil, "which", lambda _name: str(binary))
    monkeypatch.setattr(
        compat,
        "_load_ambient_codex_auth",
        lambda: ("PRIVATE_AUTH_JSON_COPY", b'{"tokens":{}}\n', "a" * 64),
    )
    validator, context = D._codex_dependency_research_staged_gate(
        root=scratchpad,
        attempt_completion=(
            compat.CODEX_RESEARCH_ATTEMPT_COMPLETION_PLACEHOLDER
        ),
    )
    expected_inputs = tuple(sorted({
        *contract.immutable_inputs,
        *contract.bounded_lookup_inputs,
    }))
    assert compat.run_codex_exec(
        session_authority=session,
        prompt="research exact dependency",
        phase_name="recon",
        needs_mcp=True,
        config=config,
        scratchpad=scratchpad,
        attempt=1,
        label="recon_worker_R-EXT",
        expected_outputs=("recon_external_dependency_research.md",),
        timeout=600,
        effective_model="gpt-5.4",
        working_directory=scratchpad,
        writable_directories=(scratchpad,),
        phase_io_contract=contract,
        phase_io_launch=launch,
        staged_output_validator=validator,
        staged_output_context=context,
        staged_output_input_identities=expected_inputs,
        provider_event_profile=compat.CODEX_LIVE_WEB_JSONL_PROFILE,
    ) == 0
    monkeypatch.setattr(D, "_posix_v2_compat_process_active", lambda: True)
    assert D._record_typed_model_worker_artifact(
        phase=phase,
        config=config,
        scratchpad=scratchpad,
        project_root=str(project),
        agent_id="R-EXT",
        agent_role="external_dependency_research",
        output="recon_external_dependency_research.md",
        timeout_s=600,
        attempt=1,
    ) == []
    return config, scratchpad, contract, launch


@pytest.mark.parametrize(
    "raw",
    (
        b'{"type":"turn.completed","type":"turn.completed"}\n',
        b'{"type":"item.completed","item":{"type":"web_search"}}\n',
        b'{"type":"turn.completed"}\n{"type":"turn.completed"}\n',
        b'{"type":"turn.completed"}\n{"type":"item.completed"}\n',
        b'{"type":"turn.failed"}\n{"type":"turn.completed"}\n',
        b'{"type":"item.failed","item":{"type":"error"}}\n'
        b'{"type":"turn.completed"}\n',
        b'{"type":"item.completed","item":{"type":"error"}}\n'
        b'{"type":"turn.completed"}\n',
    ),
)
def test_research_jsonl_closure_rejects_ambiguous_or_failed_stream(
    raw: bytes,
) -> None:
    with pytest.raises((UnicodeError, ValueError, json.JSONDecodeError)):
        compat.validate_codex_research_event_stream(raw)


def test_codex_0154_web_search_double_id_is_normalized_exactly() -> None:
    raw = _CODEX_0154_WEB_EVENT + b'{"type":"turn.completed"}\n'
    events = research.parse_codex_research_event_stream(raw)
    assert events[3]["item"] == {
        "item_id": "item_2",
        "type": "web_search",
        "id": "exec-94b2ce83-4ba6-42b7-9ace-f2737bb9598d",
        "query": "https://docs.vendor.com/reference",
        "action": {"type": "other"},
    }
    assert research._web_search_objects(raw) == [
        events[1]["item"], events[3]["item"]
    ]
    compat.validate_codex_research_event_stream(raw)


@pytest.mark.parametrize(
    "raw",
    (
        b'{"id":"item_2","type":"web_search",'
        b'"id":"exec-94b2ce83-4ba6-42b7-9ace-f2737bb9598d"}\n',
        b'{"type":"item.completed","item":'
        b'{"type":"web_search","id":"item_2",'
        b'"id":"exec-94b2ce83-4ba6-42b7-9ace-f2737bb9598d"}}\n',
        b'{"type":"item.completed","item":'
        b'{"id":"item_2","type":"web_search",'
        b'"id":"exec-94b2ce83-4ba6-42b7-9ace-f2737bb9598d",'
        b'"id":"exec-84b2ce83-4ba6-42b7-9ace-f2737bb9598d"}}\n',
        b'{"type":"item.completed","item":'
        b'{"id":"wrong","type":"web_search",'
        b'"id":"exec-94b2ce83-4ba6-42b7-9ace-f2737bb9598d"}}\n',
        b'{"type":"item.completed","item":'
        b'{"id":"item_2","type":"web_search",'
        b'"id":"exec-94b2ce83-4ba6-42b7-9ace-f2737bb9598d",'
        b'"query":"one","query":"two"}}\n',
    ),
)
def test_codex_web_search_normalizer_rejects_every_other_duplicate_shape(
    raw: bytes,
) -> None:
    with pytest.raises(ValueError, match="duplicate JSON key"):
        research.parse_codex_research_event_stream(
            raw + b'{"type":"turn.completed"}\n'
        )
    with pytest.raises(ValueError, match="duplicate JSON key"):
        compat.validate_codex_research_event_stream(
            raw + b'{"type":"turn.completed"}\n'
        )


def test_research_runtime_and_model_commit_replay_exact_compat_chain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, scratchpad, contract, _launch = _execute_and_commit(
        tmp_path, monkeypatch
    )
    with pytest.raises(D.ArtifactLedgerError, match="fetch"):
        D._validated_dependency_research_authority(scratchpad, config)
    authority = D._validated_dependency_research_authority(
        scratchpad,
        config,
        require_codex_fetch=False,
    )
    assert authority["state"] == "ACTIVE"
    row = read_artifact_ledger(scratchpad)["work_units"][contract.key]
    execution = row["execution_authority"]
    assert execution["attempt_completion_relative_path"].startswith(
        ".worker_transactions/posix_v2_compat_dependency_research/"
    )
    completion = scratchpad / execution["attempt_completion_relative_path"]
    plan = json.loads((completion.parent / "view" / "plan.json").read_text())
    assert plan["schema"] == D._POSIX_V2_COMPAT_RESEARCH_PLAN_SCHEMA
    assert plan["completion_policy"]["staged_semantic_gate"][
        "compatibility_qualification"
    ] == D._POSIX_V2_COMPAT_RESEARCH_QUALIFICATION
    receipt_path = next(
        (scratchpad / ".posix_v2_compat_receipts").glob("*.json")
    )
    receipt = json.loads(receipt_path.read_text(encoding="ascii"))
    stdout_path = scratchpad / receipt["provider_event_evidence"][
        "stdout_relative_path"
    ]
    retained_raw = stdout_path.read_bytes()
    expected_raw = _CODEX_0154_WEB_EVENT + b'{"type":"turn.completed"}\n'
    assert retained_raw == expected_raw
    assert receipt["stdout_sha256"] == hashlib.sha256(expected_raw).hexdigest()


def test_research_replay_rejects_tampered_retained_jsonl(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, scratchpad, _contract, _launch = _execute_and_commit(
        tmp_path, monkeypatch
    )
    receipt_path = next(
        (scratchpad / ".posix_v2_compat_receipts").glob("*.json")
    )
    receipt = json.loads(receipt_path.read_text(encoding="ascii"))
    stdout_path = scratchpad / receipt["provider_event_evidence"][
        "stdout_relative_path"
    ]
    stdout_path.chmod(0o600)
    stdout_path.write_bytes(
        stdout_path.read_bytes() + b'{"type":"turn.completed"}\n'
    )
    with pytest.raises(D.ArtifactLedgerError, match="compat R-EXT inner replay"):
        D._validated_dependency_research_authority(
            scratchpad, config, require_codex_fetch=False
        )


@pytest.mark.parametrize(
    "relative",
    (
        "external_dependency_obligations.json",
        "recon_build_static.md",
    ),
)
def test_research_replay_rejects_obligation_or_base_input_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relative: str,
) -> None:
    config, scratchpad, _contract, _launch = _execute_and_commit(
        tmp_path, monkeypatch
    )
    path = scratchpad / relative
    path.write_bytes(path.read_bytes() + b"drift\n")
    with pytest.raises(D.ArtifactLedgerError, match="transactional replay"):
        D._validated_dependency_research_authority(
            scratchpad, config, require_codex_fetch=False
        )


def test_compat_research_rejects_generic_transaction_schema(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, scratchpad, contract, _launch = _execute_and_commit(
        tmp_path, monkeypatch
    )
    ledger = read_artifact_ledger(scratchpad)
    row = ledger["work_units"][contract.key]
    execution = row["execution_authority"]
    completion = scratchpad / execution["attempt_completion_relative_path"]
    plan_path = completion.parent / "view" / "plan.json"
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    plan["schema"] = "plamen.posix_v2_compat_attention_plan.v1"
    plan.pop("work_plan_digest")
    plan["work_plan_digest"] = D._stable_payload_digest(plan)
    plan_path.write_text(
        json.dumps(plan, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    row["execution_authority"]["work_plan_digest"] = plan[
        "work_plan_digest"
    ]
    monkeypatch.setattr(D, "read_artifact_ledger", lambda _root: ledger)
    monkeypatch.setattr(D, "validate_work_unit_artifacts", lambda *_a, **_k: [])
    with pytest.raises(
        D.ArtifactLedgerError,
        match="requires its dependency-specific transaction",
    ):
        D._validated_dependency_research_authority(
            scratchpad, config, require_codex_fetch=False
        )


def test_research_retry_contract_adds_exact_retry_plan_authority(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    scratchpad = Path(str(config["scratchpad"]))
    inputs = D._typed_worker_registered_input_paths(
        phase_name="recon",
        scratchpad=scratchpad,
        config=config,
        agent_id="R-EXT",
        agent_role="external_dependency_research",
        output="recon_external_dependency_research.md",
        attempt=2,
    )
    assert "recon_retry_plan.json" in inputs
    contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="light",
        ecosystem="evm",
        backend="codex",
        phase="recon",
        work_unit_id="dependency_research.attempt-0002",
        exact_inputs=inputs,
        exact_outputs=("recon_external_dependency_research.md",),
    )
    assert "scratchpad:recon_retry_plan.json" in contract.immutable_inputs
    assert "scratchpad:recon_retry_plan.json" not in contract.bounded_lookup_inputs


def test_committed_model_without_fetch_retries_only_driver_fetch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    scratchpad = Path(str(config["scratchpad"]))
    obligations = _obligations()
    (scratchpad / "recon_external_dependency_research.md").write_bytes(
        _report()
    )
    states = iter(({"state": "INVALID"}, {"state": "ACTIVE"}))
    monkeypatch.setattr(
        D, "_publish_dependency_obligations", lambda *_a, **_k: obligations
    )
    monkeypatch.setattr(
        D, "_dependency_research_base_shard_issues", lambda *_a, **_k: []
    )
    monkeypatch.setattr(D, "_dependency_research_authority", lambda *_a: next(states))
    monkeypatch.setattr(
        D,
        "_validated_dependency_research_authority",
        lambda *_a, **kwargs: (
            {"state": "ACTIVE"}
            if kwargs.get("require_codex_fetch") is False
            else pytest.fail("unexpected full replay")
        ),
    )
    fetch_calls: list[int] = []
    monkeypatch.setattr(
        D,
        "_prepare_codex_dependency_fetch_receipt",
        lambda *_a: fetch_calls.append(1) or [],
    )
    monkeypatch.setattr(
        D,
        "_publish_dependency_reconcile",
        lambda *_a, **_k: {"researched": 1, "unresolved": 0},
    )
    monkeypatch.setattr(
        D,
        "_run_one_codex_exec",
        lambda **_k: pytest.fail("MODEL provider must not be replayed"),
    )
    phase = next(row for row in D.SC_PHASES if row.name == "recon")
    result = D._run_recon_dependency_research_headless(
        backend="codex",
        phase=phase,
        config=config,
        scratchpad=scratchpad,
        attempt=1,
        timeout=1,
        effective_model="fixture",
    )
    assert fetch_calls == [1]
    assert result["status"] == "complete"
    assert result["provider_invocations"] == 0
