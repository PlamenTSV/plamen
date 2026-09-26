"""Component tests for pure severity bind postimage derivation."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

import severity_bind_postimages as postimages
from severity_bind_postimages import (
    SeverityBindPostimageError,
    derive_shadow_adjudication_postimages,
)
import severity_runtime


CANDIDATE_ID = "H-COMPAT-SEVERITY"


def _case(tmp_path, monkeypatch, request):
    if os.name != "posix":
        pytest.skip("real compatibility child requires POSIX")
    from test_posix_v2_compat_severity_execution import _prepared_case, _run

    _project, root, _config, shard, session, _counter = _prepared_case(
        tmp_path, monkeypatch, request,
    )
    worker = _run(root, _config, shard, session)
    import severity_adjudication_work as work
    intent = work._read_json(root / str(shard["launch_intent_file"]))
    arguments = {
        "backend": str(intent["backend"]),
        "launch_digest": str(worker["receipt_digest"]),
        "run_id": str(worker["run_id"]),
        "worker_identity": str(intent["worker_identity"]),
        "invocation_id": str(intent["invocation_id"]),
    }
    return root, shard, arguments


def _tree(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*") if path.is_file()
    }


@pytest.mark.posix_only
def test_new_bind_derivation_is_read_only_and_matches_existing_writer(
    tmp_path: Path, monkeypatch, request,
) -> None:
    root, _shard, arguments = _case(tmp_path, monkeypatch, request)
    before = _tree(root)

    derived = derive_shadow_adjudication_postimages(
        root, CANDIDATE_ID, **arguments,
    )

    assert derived.mode == "NEW_BIND"
    assert _tree(root) == before
    written, issues = severity_runtime.bind_shadow_adjudication_for_candidate(
        root, CANDIDATE_ID, **arguments,
    )
    assert not issues
    assert tuple(path.name for path in written) == (
        f"verify_{CANDIDATE_ID}.severity_decision.json",
        f"verify_{CANDIDATE_ID}.severity_adjudication_receipt.json",
        "severity_decision_ledger.shadow.json",
    )
    assert {
        name: (root / name).read_bytes()
        for name in derived.output_bytes
    } == dict(derived.output_bytes)


@pytest.mark.posix_only
def test_receipt_pending_derives_same_three_postimages_without_writes(
    tmp_path: Path, monkeypatch, request,
) -> None:
    root, _shard, arguments = _case(tmp_path, monkeypatch, request)
    first = derive_shadow_adjudication_postimages(
        root, CANDIDATE_ID, **arguments,
    )
    receipt_name = f"verify_{CANDIDATE_ID}.severity_adjudication_receipt.json"
    (root / receipt_name).write_bytes(first.output_bytes[receipt_name])
    before = _tree(root)

    pending = derive_shadow_adjudication_postimages(
        root, CANDIDATE_ID, **arguments,
    )

    assert pending.mode == "RECEIPT_PENDING"
    assert dict(pending.output_bytes) == dict(first.output_bytes)
    assert _tree(root) == before


@pytest.mark.posix_only
def test_exact_replay_requires_receipt_and_is_read_only(tmp_path: Path, monkeypatch, request) -> None:
    root, _shard, arguments = _case(tmp_path, monkeypatch, request)
    written, issues = severity_runtime.bind_shadow_adjudication_for_candidate(
        root, CANDIDATE_ID, **arguments,
    )
    assert written and not issues
    before = _tree(root)

    replay = derive_shadow_adjudication_postimages(
        root, CANDIDATE_ID, **arguments,
    )

    assert replay.mode == "EXACT_REPLAY"
    assert _tree(root) == before
    receipt = root / f"verify_{CANDIDATE_ID}.severity_adjudication_receipt.json"
    receipt.unlink()
    with pytest.raises(SeverityBindPostimageError, match="receipt"):
        derive_shadow_adjudication_postimages(
            root, CANDIDATE_ID, **arguments,
        )


@pytest.mark.parametrize(
    "field,value",
    (
        ("backend", "foreign"),
        ("launch_digest", "f" * 64),
        ("run_id", "foreign-run"),
        ("worker_identity", "foreign-worker"),
        ("invocation_id", "foreign-invocation"),
    ),
)
@pytest.mark.posix_only
def test_caller_authority_drift_is_rejected_without_writes(
    tmp_path: Path, monkeypatch, request, field: str, value: str,
) -> None:
    root, _shard, arguments = _case(tmp_path, monkeypatch, request)
    before = _tree(root)
    arguments[field] = value

    with pytest.raises(SeverityBindPostimageError, match="authority"):
        derive_shadow_adjudication_postimages(
            root, CANDIDATE_ID, **arguments,
        )
    assert _tree(root) == before


@pytest.mark.posix_only
def test_conflicting_existing_receipt_is_not_adopted(tmp_path: Path, monkeypatch, request) -> None:
    root, _shard, arguments = _case(tmp_path, monkeypatch, request)
    receipt = root / f"verify_{CANDIDATE_ID}.severity_adjudication_receipt.json"
    receipt.write_bytes(b"{}")
    before = _tree(root)

    with pytest.raises(SeverityBindPostimageError, match="conflicts"):
        derive_shadow_adjudication_postimages(
            root, CANDIDATE_ID, **arguments,
        )
    assert _tree(root) == before


@pytest.mark.posix_only
def test_pending_receipt_symlink_is_rejected_without_following(
    tmp_path: Path, monkeypatch, request,
) -> None:
    root, _shard, arguments = _case(tmp_path, monkeypatch, request)
    receipt = root / f"verify_{CANDIDATE_ID}.severity_adjudication_receipt.json"
    outside = tmp_path / "outside-receipt.json"
    outside.write_text("{}", encoding="utf-8")
    receipt.symlink_to(outside)
    before = outside.read_bytes()

    with pytest.raises(SeverityBindPostimageError, match="unreadable"):
        derive_shadow_adjudication_postimages(
            root, CANDIDATE_ID, **arguments,
        )
    assert outside.read_bytes() == before


@pytest.mark.parametrize("candidate", ("../H", "H/OTHER", "H\\OTHER", "", 7))
def test_unsafe_candidate_rejected_before_worker(candidate) -> None:
    with pytest.raises(SeverityBindPostimageError, match="candidate identity"):
        derive_shadow_adjudication_postimages(
            Path("."), candidate,
            backend="codex", launch_digest="a" * 64, run_id="run",
            worker_identity="worker", invocation_id="invocation",
        )


@pytest.mark.parametrize(
    "relative",
    ("dir\\file.json", "C:/file.json", "name:stream", "nul\x00.json"),
)
def test_relative_authority_paths_reject_cross_platform_ambiguity(
    tmp_path: Path, relative: str,
) -> None:
    with pytest.raises(SeverityBindPostimageError, match="path"):
        postimages._relative(tmp_path, relative, "test authority")


@pytest.mark.posix_only
def test_real_validator_late_receipt_appearance_is_rejected(
    tmp_path: Path, monkeypatch, request,
) -> None:
    root, _shard, arguments = _case(tmp_path, monkeypatch, request)
    original = postimages.validate_completed_worker_run_for_candidate
    calls = 0

    def validate_then_mutate(scratchpad, candidate):
        nonlocal calls
        result = original(scratchpad, candidate)
        calls += 1
        if calls == 2:
            path = root / (
                f"verify_{CANDIDATE_ID}.severity_adjudication_receipt.json"
            )
            path.write_bytes(b"{}")
        return result

    monkeypatch.setattr(
        postimages,
        "validate_completed_worker_run_for_candidate",
        validate_then_mutate,
    )
    with pytest.raises(SeverityBindPostimageError, match="receipt roster"):
        derive_shadow_adjudication_postimages(
            root, CANDIDATE_ID, **arguments,
        )
    assert calls == 2
