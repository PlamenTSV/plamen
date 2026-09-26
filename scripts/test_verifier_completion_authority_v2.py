"""Aggregate verifier completion requires a replayed gate-v2 MODEL chain."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from artifact_ledger import read_artifact_ledger
from plamen_validators import _verifier_completion_authority_issues
import test_security_obligation_lifecycle_p1_c as lifecycle_fixture
from verifier_work_roster import VerifierWorkRoster


def _item():
    return lifecycle_fixture._item("INV-001", ("SEC-FIXTURE-001",))


def _assert_driver_control_authority(root: Path) -> None:
    roster = VerifierWorkRoster.from_json(
        (root / "verification_runtime_roster.json").read_text(
            encoding="utf-8", errors="strict"
        )
    )
    unit = roster.work_units[0]
    ledger = read_artifact_ledger(root)
    expected_suffix = (
        f"/verify_medium_a/method_receipt.{unit.work_unit_id}"
    )
    owners = set()
    for name in ("gate_receipt.json", "unit_receipt.json"):
        identity = (
            "scratchpad:_verifier_runtime_units/"
            f"{unit.work_unit_id}/{name}"
        )
        binding = ledger["artifact_bindings"][identity]
        assert binding["status"] == "ACTIVE"
        assert binding["writer"] == "DRIVER"
        assert binding["owner_key"].endswith(expected_suffix)
        owners.add(binding["owner_key"])
    assert len(owners) == 1


def _seed(root: Path, *, gate_authority: str = "valid"):
    root.mkdir()
    item = _item()
    if gate_authority == "valid":
        lifecycle_fixture._write_runtime(root, [item], verdict="CONFIRMED")
    else:
        original_json = lifecycle_fixture._json

        def mutate_gate(path: Path, value: object) -> None:
            if (
                path.name == "gate_receipt.json"
                and isinstance(value, dict)
                and value.get("schema_version")
                == "plamen.verifier_unit_gate_receipt.v2"
            ):
                value = dict(value)
                if gate_authority == "absent":
                    value.pop("model_execution_authority_digest")
                else:
                    value["model_execution_authority_digest"] = "f" * 64
            original_json(path, value)

        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setattr(lifecycle_fixture, "_json", mutate_gate)
            lifecycle_fixture._write_runtime(root, [item], verdict="CONFIRMED")
    _assert_driver_control_authority(root)
    return item


def test_aggregate_accepts_genuine_gate_v2_model_and_control_authority(
    tmp_path: Path,
) -> None:
    root = tmp_path / ".scratchpad"
    item = _seed(root)

    assert _verifier_completion_authority_issues(
        root, item.work_item_id
    ) == []


@pytest.mark.parametrize("gate_authority", ["absent", "forged"])
def test_aggregate_rejects_unbound_gate_v2_model_authority(
    tmp_path: Path,
    gate_authority: str,
) -> None:
    root = tmp_path / ".scratchpad"
    item = _seed(root, gate_authority=gate_authority)

    issues = _verifier_completion_authority_issues(root, item.work_item_id)

    assert issues
    assert "verifier completion authority invalid" in issues[0]


def test_aggregate_accepts_valid_mechanical_successor_chain(
    tmp_path: Path,
) -> None:
    root = tmp_path / ".scratchpad"
    item = _seed(root)
    lifecycle_fixture._apply_successor(root, item.work_item_id)

    assert _verifier_completion_authority_issues(
        root, item.work_item_id
    ) == []


@pytest.mark.parametrize(
    ("field", "value"),
    [("launch_digest", "e" * 64), ("verifier_backend", "claude")],
)
def test_aggregate_rejects_receipt_bound_to_a_different_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str, value: str,
) -> None:
    """Consistent outer hashes cannot substitute for actual launch identity.

    Seed the wrong receipt before the genuine MODEL/control transactions, so
    rejection cannot rely merely on detecting a later sidecar edit. No actual
    provider is contacted by the harmless-child fixture.
    """
    receipt_type = lifecycle_fixture.VerifierOutputReceipt
    original_bind = receipt_type.bind

    def bind_to_wrong_launch(cls, *args, **kwargs):
        kwargs[field] = value
        return original_bind(*args, **kwargs)

    monkeypatch.setattr(receipt_type, "bind", classmethod(bind_to_wrong_launch))
    root = tmp_path / ".scratchpad"
    item = _seed(root)

    issues = _verifier_completion_authority_issues(root, item.work_item_id)

    assert issues
    assert "verifier receipt launch binding" in issues[0]


@pytest.mark.parametrize(
    ("field", "value"),
    [("launch_digest", "e" * 64), ("verifier_backend", "claude")],
)
def test_lifecycle_retains_wrong_launch_receipt_as_unresolved_debt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str, value: str,
) -> None:
    receipt_type = lifecycle_fixture.VerifierOutputReceipt
    original_bind = receipt_type.bind

    def bind_to_wrong_launch(cls, *args, **kwargs):
        kwargs[field] = value
        return original_bind(*args, **kwargs)

    monkeypatch.setattr(receipt_type, "bind", classmethod(bind_to_wrong_launch))
    root, aliases = lifecycle_fixture._setup(tmp_path, count=1)
    lifecycle_fixture._write_mandatory_chain(root, aliases, verdict="CONFIRMED")

    authority = lifecycle_fixture.L.build_security_obligation_lifecycle(root)

    assert len(authority["rows"]) == 1
    row = authority["rows"][0]
    assert row["state"] == "VERIFICATION_DEBT"
    assert row["retention"] == "RETAIN"
    assert "CURRENT_TYPED_VERIFIER_COMPLETION_AUTHORITY_INVALID" in row["debt_reasons"]
    assert "verifier receipt launch binding" in str(authority["issues"])


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("work_unit_id", "verify-other-unit"),
        ("work_unit_resume_digest", "d" * 64),
        ("expected_output_files", ("verify_OTHER.md",)),
    ],
)
def test_aggregate_rejects_launch_spec_for_a_different_runtime_assignment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str, value: object,
) -> None:
    """A genuine launch chain must still cover the selected roster assignment."""
    original_build = lifecycle_fixture.build_verifier_launch_spec

    def build_wrong_assignment(*args, **kwargs):
        return replace(original_build(*args, **kwargs), **{field: value})

    monkeypatch.setattr(
        lifecycle_fixture, "build_verifier_launch_spec", build_wrong_assignment
    )
    if field == "work_unit_id":
        original_commit = lifecycle_fixture._genuine_compat_model_commit

        def commit_from_foreign_launch_directory(**kwargs):
            # Supply the same harmless prompt at the foreign launch location
            # so the real child can run. A missing fixture file would test
            # neither completion authority nor the roster-assignment join.
            unit_id = kwargs["contract"].work_unit_id.removeprefix("method_model.")
            units = kwargs["root"] / "_verifier_runtime_units"
            destination = units / kwargs["spec"].work_unit_id
            destination.mkdir()
            (destination / "prompt.md").write_bytes(
                (units / unit_id / "prompt.md").read_bytes()
            )
            return original_commit(**kwargs)

        monkeypatch.setattr(
            lifecycle_fixture, "_genuine_compat_model_commit",
            commit_from_foreign_launch_directory,
        )
    root = tmp_path / ".scratchpad"
    item = _seed(root)

    issues = _verifier_completion_authority_issues(root, item.work_item_id)

    assert issues
    assert "launch spec does not bind work unit" in issues[0]
