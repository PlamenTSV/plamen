"""Immutable severity-planning source snapshot coverage."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import severity_adjudication_work as work
from severity_decision_ledger import (
    build_severity_decision,
    build_severity_decision_ledger,
)
from test_severity_decision_ledger_p0_ag import _assessment


def _write_snapshot(root: Path, *, run_id: str = "run-1") -> tuple[Path, str]:
    decision = build_severity_decision(_assessment(run_id=run_id))
    payload = build_severity_decision_ledger(run_id, (decision,))
    raw = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    path = root / work.SOURCE_LEDGER_SNAPSHOT_NAME
    path.parent.mkdir(parents=True)
    path.write_bytes(raw)
    return path, hashlib.sha256(raw).hexdigest()


def _args(root: Path, snapshot: Path, digest: str) -> dict[str, object]:
    methodology = root / "method.md"
    methodology.write_text("# Severity method\n", encoding="utf-8")
    return {
        "run_id": "run-1",
        "audit_snapshot_digest": "1" * 64,
        "audit_config_digest": "2" * 64,
        "methodology_files": {"method": methodology},
        "backend": "codex",
        "transport": "posix-v2-compat",
        "effective_model": "fixture-model",
        "working_directory": root,
        "source_root": root,
        "tool_policy": ("read-bound-inputs",),
        "environment_allowlist_digest": "3" * 64,
        "adjudicator_identity": "severity-adjudicator",
        "invocation_prefix": "severity-run",
        "source_ledger_path": snapshot.relative_to(root).as_posix(),
        "expected_source_ledger_digest": digest,
    }


def test_snapshot_derivation_ignores_later_mutable_sidecar(tmp_path: Path) -> None:
    snapshot, digest = _write_snapshot(tmp_path)
    args = _args(tmp_path, snapshot, digest)
    first = work.derive_adjudication_work(tmp_path, **args)
    (tmp_path / "verify_HYP-001.severity_decision.json").write_text(
        "{}\n", encoding="utf-8"
    )
    second = work.derive_adjudication_work(tmp_path, **args)
    assert second == first
    manifest, plan, _outputs = first
    assert manifest["source_ledger_file"] == work.SOURCE_LEDGER_SNAPSHOT_NAME
    assert manifest["source_ledger_snapshot_sha256"] == digest
    assert plan["source_ledger_file"] == manifest["source_ledger_file"]
    assert plan["source_ledger_snapshot_sha256"] == digest


@pytest.mark.parametrize("field,value", (
    ("source_ledger_path", "severity_decision_ledger.shadow.json"),
    ("expected_source_ledger_digest", "0" * 64),
))
def test_snapshot_rejects_wrong_path_or_digest(
    tmp_path: Path, field: str, value: str,
) -> None:
    snapshot, digest = _write_snapshot(tmp_path)
    args = _args(tmp_path, snapshot, digest)
    args[field] = value
    with pytest.raises(work.AdjudicationWorkError):
        work.derive_adjudication_work(tmp_path, **args)


@pytest.mark.parametrize("mutation", ("schema", "run"))
def test_snapshot_rejects_wrong_schema_or_run(
    tmp_path: Path, mutation: str,
) -> None:
    snapshot, _digest = _write_snapshot(tmp_path)
    payload = json.loads(snapshot.read_text(encoding="utf-8"))
    if mutation == "schema":
        payload["schema_version"] = "plamen.severity_decision_ledger.invalid"
    else:
        payload["run_id"] = "foreign-run"
    raw = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    snapshot.write_bytes(raw)
    args = _args(tmp_path, snapshot, hashlib.sha256(raw).hexdigest())
    with pytest.raises(work.AdjudicationWorkError):
        work.derive_adjudication_work(tmp_path, **args)


def test_snapshot_rejects_malformed_present_skeptic_state(tmp_path: Path) -> None:
    snapshot, digest = _write_snapshot(tmp_path)
    (tmp_path / "skeptic_challenges.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(
        work.AdjudicationWorkError, match="explicit captured skeptic"
    ):
        work.derive_adjudication_work(
            tmp_path, **_args(tmp_path, snapshot, digest)
        )


@pytest.mark.parametrize("bad", (b'{"x":1,"x":2}\n', b'{"x":NaN}\n'))
def test_snapshot_rejects_duplicate_keys_and_nonfinite(
    tmp_path: Path, bad: bytes,
) -> None:
    snapshot = tmp_path / work.SOURCE_LEDGER_SNAPSHOT_NAME
    snapshot.parent.mkdir(parents=True)
    snapshot.write_bytes(bad)
    with pytest.raises(work.AdjudicationWorkError):
        work.derive_adjudication_work(
            tmp_path,
            **_args(tmp_path, snapshot, hashlib.sha256(bad).hexdigest()),
        )


def test_snapshot_rejects_duplicate_candidate_casefold(tmp_path: Path) -> None:
    snapshot, _digest = _write_snapshot(tmp_path)
    payload = json.loads(snapshot.read_text(encoding="utf-8"))
    duplicate = dict(payload["decisions"][0])
    duplicate["candidate_id"] = str(duplicate["candidate_id"]).lower()
    payload["decisions"].append(duplicate)
    raw = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    snapshot.write_bytes(raw)
    with pytest.raises(work.AdjudicationWorkError, match="candidate denominator"):
        work.derive_adjudication_work(
            tmp_path,
            **_args(tmp_path, snapshot, hashlib.sha256(raw).hexdigest()),
        )


@pytest.mark.parametrize("link_kind", ("symlink", "hardlink"))
def test_snapshot_rejects_linked_input(tmp_path: Path, link_kind: str) -> None:
    snapshot, digest = _write_snapshot(tmp_path)
    raw = snapshot.read_bytes()
    snapshot.unlink()
    source = tmp_path / "external-ledger.json"
    source.write_bytes(raw)
    if link_kind == "symlink":
        snapshot.symlink_to(source)
    else:
        snapshot.hardlink_to(source)
    with pytest.raises(work.AdjudicationWorkError):
        work.derive_adjudication_work(
            tmp_path, **_args(tmp_path, snapshot, digest)
        )


def test_prepared_snapshot_replay_ignores_mutable_sidecar(tmp_path: Path) -> None:
    snapshot, digest = _write_snapshot(tmp_path)
    args = _args(tmp_path, snapshot, digest)
    first = work.prepare_adjudication_work(tmp_path, **args)
    (tmp_path / "verify_HYP-001.severity_decision.json").write_text(
        '{"foreign":true}\n', encoding="utf-8"
    )
    second = work.prepare_adjudication_work(tmp_path, **args)
    assert second == first


def test_resume_rejects_resigned_foreign_snapshot_binding(tmp_path: Path) -> None:
    snapshot, original_digest = _write_snapshot(tmp_path)
    args = _args(tmp_path, snapshot, original_digest)
    work.prepare_adjudication_work(tmp_path, **args)

    foreign = build_severity_decision_ledger(
        "run-1",
        (build_severity_decision(_assessment(
            assessor_invocation_id="foreign-assessor-run"
        )),),
    )
    foreign_raw = (json.dumps(foreign, indent=2, sort_keys=True) + "\n").encode()
    foreign_digest = hashlib.sha256(foreign_raw).hexdigest()
    snapshot.write_bytes(foreign_raw)

    manifest_path = tmp_path / work.MANIFEST_NAME
    plan_path = tmp_path / work.WORK_PLAN_NAME
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    manifest["source_ledger_snapshot_sha256"] = foreign_digest
    manifest["source_ledger_digest"] = foreign["ledger_digest"]
    foreign_decision = foreign["decisions"][0]
    manifest["source_decision_digests"] = {
        foreign_decision["candidate_id"]: foreign_decision["decision_digest"]
    }
    manifest["work_items"] = []
    manifest = work._signed(
        {key: value for key, value in manifest.items() if key != "manifest_digest"},
        digest_field="manifest_digest",
    )
    plan["source_ledger_snapshot_sha256"] = foreign_digest
    plan["source_ledger_digest"] = foreign["ledger_digest"]
    plan["manifest_digest"] = manifest["manifest_digest"]
    plan = work._signed(
        {key: value for key, value in plan.items() if key != "plan_digest"},
        digest_field="plan_digest",
    )
    manifest_path.write_bytes(work._canonical_json_bytes(manifest))
    plan_path.write_bytes(work._canonical_json_bytes(plan))

    with pytest.raises(work.AdjudicationWorkError, match="resume binding mismatch"):
        work.prepare_adjudication_work(tmp_path, **args)
