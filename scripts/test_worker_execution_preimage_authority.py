"""Historical replay of real POSIX worker incorporation records.

The harmless-child fixture is POSIX-only because it exercises the explicit
compatibility transport that produces the three real worker records.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

import worker_transaction as T


pytestmark = pytest.mark.integration


@pytest.fixture
def real_worker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, request):
    if os.name != "posix":
        pytest.skip("real-child worker fixture requires POSIX compatibility")
    import artifact_ledger as ledger
    from audit_snapshot import build_audit_snapshot
    import plamen_driver as driver
    import posix_v2_compat_runtime as compat
    from test_posix_report_execution_lineage import _case
    from test_support_startup_permit import durable_startup_permit

    project, root, phase, contract, launch, config = _case(tmp_path)
    (project / "Unit.sol").write_text(
        "pragma solidity ^0.8.20; contract Unit {}\n", encoding="utf-8"
    )
    run_id = config["_run_id"]
    config["_auxiliary_writable_root_startup_binding"] = durable_startup_permit(
        root, run_id=run_id
    )
    config["_audit_snapshot"] = build_audit_snapshot(
        config, Path(__file__).resolve().parent.parent
    )
    ledger.record_work_unit_inputs(root, project, contract, launch, run_id=run_id)
    output_text = getattr(request, "param", {})
    binary = tmp_path / "codex-worker-preimage-fixture"
    binary.write_text(
        f"#!{sys.executable} -B\n"
        "import json,re,sys\nfrom pathlib import Path\n"
        "if sys.argv[1:] == ['--version']:\n"
        " print('codex-cli worker-preimage-fixture'); raise SystemExit(0)\n"
        "prompt=sys.stdin.read()\n"
        "sys.stderr.write('OpenAI Codex v0.test\\n--------\\nworkdir: /fixture\\n"
        "model: gpt-5.6-sol\\nprovider: openai\\n--------\\nuser\\n')\n"
        "blocks=[json.loads(b) for b in re.findall(r'```json\\s*(.*?)\\s*```',prompt,re.S)]\n"
        "routing=next(b for b in blocks if b.get('schema')=='plamen.posix_v2_codex_local_phaseio.v1')\n"
        f"outputs={output_text!r}\n"
        "for route in routing['output_routes']:\n"
        " target=Path(route['path']); target.write_text(outputs.get(target.name, '# Deterministic worker preimage fixture\\n'))\n"
        "Path(sys.argv[sys.argv.index('-o')+1]).write_text('complete\\n')\n"
        "print(json.dumps({'type':'turn.completed'}))\n",
        encoding="utf-8",
    )
    binary.chmod(0o755)
    session = compat.issue_posix_v2_compat_session_for_installed_front(
        run_id=run_id, project_root=project, scratchpad=root
    )
    monkeypatch.setattr(
        driver, "_POSIX_COMPAT_V2_PROCESS_MARKER",
        driver._POSIX_COMPAT_V2_MARKER_TOKEN,
    )
    monkeypatch.setattr(driver, "_POSIX_COMPAT_V2_SESSION_AUTHORITY", session)
    monkeypatch.setattr(compat.shutil, "which", lambda _name: str(binary))
    monkeypatch.setattr(
        compat, "_load_ambient_codex_auth",
        lambda: ("PRIVATE_AUTH_JSON_COPY", b'{"tokens":{}}\n', "c" * 64),
    )
    try:
        assert driver._run_one_codex_exec(
            prompt="Write the two assigned harmless report fixtures.\n",
            phase=phase, config=config, scratchpad=root, attempt=1,
            label="report_index",
            expected_outputs=[spec.path for spec in contract.outputs],
            timeout=float(launch.timeout_s), effective_model=launch.model,
            phase_io_contract=contract, phase_io_launch=launch,
        ) == 0
        unit = ledger.read_artifact_ledger(root)["work_units"][contract.key]
        yield SimpleNamespace(
            scratchpad=root, contract=contract, launch=launch, run_id=run_id,
            authority=unit["execution_authority"],
            project=project, config=config,
        )
    finally:
        session.close()


def _replay(fixture, authority=None):
    return T.replay_worker_execution_preimage_authority(
        scratchpad=fixture.scratchpad,
        authority=authority or fixture.authority,
        contract=fixture.contract, launch=fixture.launch, run_id=fixture.run_id,
    )


def _strict(fixture, authority=None):
    return T.validate_worker_execution_authority(
        scratchpad=fixture.scratchpad,
        authority=authority or fixture.authority,
        contract=fixture.contract, launch=fixture.launch, run_id=fixture.run_id,
    )


def _digest(value: dict, field: str) -> str:
    unsigned = {key: item for key, item in value.items() if key != field}
    raw = json.dumps(
        unsigned, ensure_ascii=False, allow_nan=False,
        sort_keys=True, separators=(",", ":"),
    ).encode()
    return hashlib.sha256(raw).hexdigest()


def test_historical_replay_survives_changed_full_report_denominator(real_worker) -> None:
    replay = _replay(real_worker)
    assert {row.canonical_identity for row in replay.projected_members} == {
        "scratchpad:report_index.md", "scratchpad:report_coverage.md",
    }
    assert _strict(real_worker) == real_worker.authority
    with pytest.raises(TypeError):
        replay.normalized_authority["generation"] = 2
    for row in replay.projected_members:
        path = real_worker.scratchpad / row.canonical_identity.split(":", 1)[1]
        path.write_bytes(b"successor\n")
    assert _replay(real_worker) == replay
    with pytest.raises(T.WorkerTransactionError, match="canonical bytes changed"):
        _strict(real_worker)


@pytest.mark.parametrize("record_index", range(3))
@pytest.mark.parametrize("damage", ("missing", "tampered"))
def test_both_replays_reject_damaged_records(real_worker, record_index, damage) -> None:
    path = real_worker.scratchpad / _replay(real_worker).record_relative_paths[
        record_index
    ]
    path.unlink() if damage == "missing" else path.write_bytes(b"{}\n")
    for replay in (_replay, _strict):
        with pytest.raises(T.WorkerTransactionError):
            replay(real_worker)


def test_projected_output_denominator_must_be_exact(real_worker) -> None:
    authority = dict(real_worker.authority)
    path = real_worker.scratchpad / authority["incorporation_relative_path"]
    value = json.loads(path.read_text(encoding="utf-8"))
    value["projected_members"].append(dict(value["projected_members"][0]))
    value["incorporation_digest"] = _digest(value, "incorporation_digest")
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
    authority["incorporation_digest"] = value["incorporation_digest"]
    authority["authority_digest"] = _digest(authority, "authority_digest")
    for replay in (_replay, _strict):
        with pytest.raises(T.WorkerTransactionError, match="output denominator"):
            replay(real_worker, authority)


@pytest.mark.parametrize("field,bad", [
    ("generation", [1]), ("work_plan_digest", {"digest": "x"}),
    ("attempt_id", ["attempt"]),
])
def test_authority_identity_fields_are_immutable_scalars(real_worker, field, bad) -> None:
    authority = dict(real_worker.authority)
    # Keep both historical records consistent with the malformed authority.
    # Otherwise ordinary chain equality alone would reject the fixture and
    # would not exercise the added primitive-type admission requirement.
    for path_field, digest_field in (
        ("attempt_completion_relative_path", "completion_digest"),
        ("incorporation_relative_path", "incorporation_digest"),
    ):
        path = real_worker.scratchpad / authority[path_field]
        value = json.loads(path.read_text())
        value[field] = bad
        value[digest_field] = _digest(value, digest_field)
        path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
        authority[
            "attempt_completion_digest" if digest_field == "completion_digest"
            else "incorporation_digest"
        ] = value[digest_field]
    authority[field] = bad
    authority["authority_digest"] = _digest(authority, "authority_digest")
    for replay in (_replay, _strict):
        with pytest.raises(T.WorkerTransactionError, match=(
            "positive integer" if field == "generation" else
            "lowercase SHA-256" if field == "work_plan_digest" else
            "identifier shape"
        )):
            replay(real_worker, authority)


@pytest.mark.parametrize("field", [
    "attempt_completion_relative_path", "provider_completion_relative_path",
    "incorporation_relative_path",
])
def test_record_paths_require_canonical_spelling(real_worker, field) -> None:
    authority = dict(real_worker.authority)
    assert "/" in authority[field]
    authority[field] = authority[field].replace("/", "\\")
    authority["authority_digest"] = _digest(authority, "authority_digest")
    for replay in (_replay, _strict):
        with pytest.raises(T.WorkerTransactionError, match="path is not canonical"):
            replay(real_worker, authority)
