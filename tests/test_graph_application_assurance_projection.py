from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
TESTS = ROOT / "tests"
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(TESTS))

import assurance_limitations as assurance  # noqa: E402
import graph_application_authority as graph_authority  # noqa: E402
import test_graph_application_authority as graph_fixture  # noqa: E402


def _publish(
    tmp_path: Path,
    monkeypatch,
    *,
    complete: bool,
) -> tuple[dict, dict, dict]:
    world = graph_fixture._world(tmp_path, monkeypatch)
    _committed_observations, _committed_reconciliation, reconciliation = (
        graph_fixture._finish(world, complete=complete)
    )
    observations = graph_authority.load_graph_application_observations_bytes(
        (world["scratch"] / graph_authority.OBSERVATIONS_ARTIFACT).read_bytes(),
        authority=world["plan"],
    )
    return world["plan"], observations, reconciliation


def _rows(scratchpad: Path) -> tuple[dict, ...]:
    return assurance._graph_application_assurance_rows(
        scratchpad,
        run_id=graph_fixture.RUN_ID,
    )


def test_complete_graph_application_has_no_assurance_debt(
    tmp_path: Path, monkeypatch,
):
    scratchpad = tmp_path / ".scratchpad"
    _publish(tmp_path, monkeypatch, complete=True)

    assert _rows(scratchpad) == ()
    paths = assurance.assurance_projection_input_paths(scratchpad)
    assert graph_authority.AUTHORITY_ARTIFACT in paths
    assert graph_fixture.EVIDENCE_ID.split(":", 1)[1] in paths


def test_every_graph_application_debt_is_losslessly_projected(
    tmp_path: Path, monkeypatch,
):
    scratchpad = tmp_path / ".scratchpad"
    authority, _observations, reconciliation = _publish(
        tmp_path, monkeypatch, complete=False
    )

    first = _rows(scratchpad)
    second = _rows(scratchpad)
    assert first == second
    assert len(first) == len(reconciliation["debts"])
    assert len({row["failure_instance_id"] for row in first}) == len(first)
    assert [row["source_authority"]["debt"] for row in first] == (
        reconciliation["debts"]
    )
    for row in first:
        source = row["source_authority"]
        assert source["authority_sha256"] == authority["authority_sha256"]
        assert source["reconciliation_sha256"] == reconciliation[
            "reconciliation_sha256"
        ]
        assert source["sources"]
        assert row["gate_class"] == "GRAPH_APPLICATION_OUTCOME"
        assert row["activation_state"] == "INACTIVE_SHADOW"
        assert row["consumer_activation"] is False
        assert row["terminal_success_blocking"] is False


@pytest.mark.parametrize(
    "mutation",
    ["missing-control", "tampered-source", "stale-evidence", "false-complete"],
)
def test_graph_application_adversarial_states_fail_visible(
    tmp_path: Path,
    monkeypatch,
    mutation: str,
):
    scratchpad = tmp_path / ".scratchpad"
    _authority, _observations, reconciliation = _publish(
        tmp_path, monkeypatch, complete=(mutation == "stale-evidence")
    )
    if mutation == "missing-control":
        (scratchpad / graph_authority.RECONCILIATION_ARTIFACT).unlink()
    elif mutation == "tampered-source":
        path = scratchpad / "_mechanical_graph.json"
        path.write_bytes(path.read_bytes() + b" ")
    elif mutation == "stale-evidence":
        path = scratchpad / graph_fixture.EVIDENCE_ID.split(":", 1)[1]
        path.write_bytes(b"replacement evidence\n")
    else:
        deceptive = copy.deepcopy(reconciliation)
        deceptive["state"] = "COMPLETE"
        deceptive["debts"] = []
        deceptive["reconciled_pair_count"] = deceptive["required_pair_count"]
        deceptive.pop("reconciliation_sha256")
        deceptive["reconciliation_sha256"] = hashlib.sha256(
            json.dumps(
                deceptive,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode()
        ).hexdigest()
        (scratchpad / graph_authority.RECONCILIATION_ARTIFACT).write_bytes(
            graph_authority.canonical_file_bytes(deceptive)
        )

    rows = _rows(scratchpad)
    assert len(rows) == 1
    assert rows[0]["gate_class"] == "GRAPH_APPLICATION_AUTHORITY"
    assert rows[0]["activation_state"] == "INACTIVE_SHADOW"
    assert rows[0]["terminal_success_blocking"] is False
    assert "no clean graph-consumption claim is authorized" in rows[0]["message"]


def test_mechanical_graph_shadow_diagnostic_does_not_deny_clean_active_audit(
    tmp_path: Path,
):
    scratchpad = tmp_path / "scratchpad"
    scratchpad.mkdir()
    (scratchpad / "_mechanical_graph.json").write_bytes(b"{}\n")

    checkpoint = type(
        "Checkpoint",
        (),
        {"run_id": graph_fixture.RUN_ID, "phase_commits": {}, "degraded": []},
    )()
    manifest = assurance.build_current_assurance_manifest(
        checkpoint,
        scratchpad,
        tmp_path,
    )

    assert manifest["row_count"] == 1
    assert manifest["clean_full_audit_claim_allowed"] is True
    assert manifest["rows"][0]["gate_class"] == "GRAPH_APPLICATION_AUTHORITY"
    assert "_mechanical_graph.json" in assurance.assurance_projection_input_paths(
        scratchpad
    )


def test_graph_application_control_symlink_fails_visible(
    tmp_path: Path, monkeypatch,
):
    scratchpad = tmp_path / ".scratchpad"
    _publish(tmp_path, monkeypatch, complete=True)
    target = scratchpad / graph_authority.RECONCILIATION_ARTIFACT
    replacement = scratchpad / "replacement.json"
    target.rename(replacement)
    target.symlink_to(replacement.name)

    rows = _rows(scratchpad)
    assert len(rows) == 1
    assert rows[0]["gate_class"] == "GRAPH_APPLICATION_AUTHORITY"
    assert rows[0]["source_authority"]["files"][
        graph_authority.RECONCILIATION_ARTIFACT
    ]["state"] == "SYMLINK_REJECTED"


def test_structurally_complete_controls_without_phaseio_commit_fail_visible(
    tmp_path: Path, monkeypatch,
):
    scratchpad = tmp_path / ".scratchpad"
    _publish(tmp_path, monkeypatch, complete=True)
    (scratchpad / "_artifact_state.json").unlink()

    rows = _rows(scratchpad)
    assert len(rows) == 1
    assert rows[0]["gate_class"] == "GRAPH_APPLICATION_AUTHORITY"
    assert "no clean graph-consumption claim is authorized" in rows[0]["message"]


def test_partial_graph_production_without_control_trio_fails_visible(
    tmp_path: Path,
):
    scratchpad = tmp_path / "scratchpad"
    scratchpad.mkdir()
    (scratchpad / "_mechanical_graph.json").write_bytes(b"{}\n")

    rows = _rows(scratchpad)
    assert len(rows) == 1
    assert rows[0]["gate_class"] == "GRAPH_APPLICATION_AUTHORITY"
