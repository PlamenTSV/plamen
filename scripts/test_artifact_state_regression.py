import hashlib
from pathlib import Path

import plamen_driver as D


def _substantial(name: str) -> str:
    return "# " + name + "\n\n" + ("substantial artifact content " * 30) + "\n"


QUEUE_NAMES = (
    "verification_queue.md",
    "verification_queue_evidence_excluded.md",
)


def _typed_queue_projection(path: Path, name: str) -> dict[str, object]:
    payload = path.read_bytes()
    return {
        "path": name,
        "owner_phase": "sc_verify_queue",
        "owner_key": (
            "phaseio/v4/sc/core/sc_verify_queue/"
            "live_verify_queue_publication"
        ),
        "status": "ACTIVE",
        "mtime_ns": path.stat().st_mtime_ns,
        "size": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "updated_at": "2026-08-18T00:00:00+00:00",
        "contract_digest": "1" * 64,
        "launch_digest": "2" * 64,
        "run_id": "typed-queue-run",
        "authority_level": "ACTIVE_AUTHORITY",
    }


def _typed_queue_state(scratchpad: Path) -> dict[str, object]:
    rows = {
        name: _typed_queue_projection(scratchpad / name, name)
        for name in QUEUE_NAMES
    }
    return {
        "version": 4,
        "artifacts": {
            **rows,
            "unrelated_typed.md": {
                **rows[QUEUE_NAMES[0]],
                "path": "unrelated_typed.md",
            },
        },
        "artifact_bindings": {"scratchpad:unrelated_typed.md": {"sentinel": True}},
        "work_units": {"unrelated/owner": {"sentinel": True}},
    }


def _seed_queue_files(scratchpad: Path) -> None:
    for name in QUEUE_NAMES:
        (scratchpad / name).write_text(_substantial(name), encoding="utf-8")


def test_artifact_recovery_does_not_blame_phase_for_preexisting_future_files(tmp_path: Path):
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    (scratchpad / "rag_validation.md").write_text(_substantial("rag"), encoding="utf-8")
    # These are legitimate dirty-scratchpad artifacts from a later phase in a
    # prior run. Recovery must not treat presence alone as rag_sweep overreach.
    for name in (
        "hypotheses.md",
        "finding_mapping.md",
        "findings_inventory_deduped.md",
        "verification_queue.md",
    ):
        (scratchpad / name).write_text(_substantial(name), encoding="utf-8")

    offenders = D._existing_later_phase_artifacts(
        scratchpad,
        str(project),
        D.SC_PHASES,
        "rag_sweep",
        "sc",
    )

    assert offenders == []
    assert (scratchpad / "hypotheses.md").exists()
    assert (scratchpad / "verification_queue.md").exists()


def test_containment_still_detects_future_files_written_by_current_attempt(tmp_path: Path):
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    before = D._snapshot_file_state(scratchpad, str(project))

    (scratchpad / "rag_validation.md").write_text(_substantial("rag"), encoding="utf-8")
    (scratchpad / "hypotheses.md").write_text(_substantial("future"), encoding="utf-8")

    offenders = D._detect_foreign_phase_writes(
        scratchpad,
        str(project),
        D.SC_PHASES,
        "rag_sweep",
        "sc",
        before,
    )

    assert offenders == ["hypotheses.md"]


def test_phase_artifact_state_records_owner_and_quarantine_status(tmp_path: Path):
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    (scratchpad / "rag_validation.md").write_text(_substantial("rag"), encoding="utf-8")

    recorded = D._record_phase_artifact_state(
        scratchpad,
        str(project),
        D.SC_PHASES,
        "rag_sweep",
        "sc",
    )
    state = D._read_artifact_state(scratchpad)

    assert recorded == ["rag_validation.md"]
    assert state["artifacts"]["rag_validation.md"]["owner_phase"] == "rag_sweep"
    assert state["artifacts"]["rag_validation.md"]["status"] == "ACTIVE"
    assert state["artifacts"]["rag_validation.md"]["size"] > 100

    before = D._snapshot_file_state(scratchpad, str(project))
    (scratchpad / "hypotheses.md").write_text(_substantial("future"), encoding="utf-8")
    offenders = D._detect_foreign_phase_writes(
        scratchpad,
        str(project),
        D.SC_PHASES,
        "rag_sweep",
        "sc",
        before,
    )
    moved, failed = D._quarantine_foreign_phase_writes(
        scratchpad,
        str(project),
        "rag_sweep",
        offenders,
    )
    state = D._read_artifact_state(scratchpad)

    assert moved == ["hypotheses.md"]
    assert failed == []
    assert state["artifacts"]["hypotheses.md"]["status"] == "QUARANTINED"
    assert state["artifacts"]["hypotheses.md"]["quarantined_by_phase"] == "rag_sweep"


def test_generic_recorder_preserves_current_typed_queue_projection_bytes(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    _seed_queue_files(scratchpad)
    state = _typed_queue_state(scratchpad)
    D._write_artifact_state(scratchpad, state)
    ledger_path = scratchpad / "_artifact_state.json"
    before = ledger_path.read_bytes()

    recorded = D._record_phase_artifact_state(
        scratchpad,
        str(project),
        D.SC_PHASES,
        "sc_verify_queue",
        "sc",
    )

    assert recorded == list(QUEUE_NAMES)
    assert ledger_path.read_bytes() == before
    assert D._read_artifact_state(scratchpad) == state


def test_generic_recorder_never_reblesses_typed_queue_mismatches(
    tmp_path: Path,
) -> None:
    mutations = (
        ("owner_phase", "foreign_phase"),
        ("owner_key", "foreign/owner"),
        ("status", "QUARANTINED"),
        ("size", 1),
        ("sha256", "0" * 64),
        ("run_id", "foreign-run"),
        ("contract_digest", "3" * 64),
        ("launch_digest", "4" * 64),
        ("authority_level", "PROPOSAL_ONLY"),
    )
    for index, (field, value) in enumerate(mutations):
        project = tmp_path / f"project-{index}"
        scratchpad = project / ".scratchpad"
        scratchpad.mkdir(parents=True)
        _seed_queue_files(scratchpad)
        state = _typed_queue_state(scratchpad)
        state["artifacts"][QUEUE_NAMES[0]][field] = value
        if field == "contract_digest":
            del state["artifacts"][QUEUE_NAMES[1]][field]
        D._write_artifact_state(scratchpad, state)
        ledger_path = scratchpad / "_artifact_state.json"
        before = ledger_path.read_bytes()

        assert D._record_phase_artifact_state(
            scratchpad,
            str(project),
            D.SC_PHASES,
            "sc_verify_queue",
            "sc",
        ) == list(QUEUE_NAMES)
        assert ledger_path.read_bytes() == before
        assert D._read_artifact_state(scratchpad) == state


def test_generic_recorder_does_not_replace_malformed_queue_ledger(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    _seed_queue_files(scratchpad)
    ledger_path = scratchpad / "_artifact_state.json"
    before = b'{"version":4,"artifacts":'
    ledger_path.write_bytes(before)

    assert D._record_phase_artifact_state(
        scratchpad,
        str(project),
        D.SC_PHASES,
        "sc_verify_queue",
        "sc",
    ) == list(QUEUE_NAMES)
    assert ledger_path.read_bytes() == before


def test_generic_recorder_preserves_typed_recon_producer_authority_bytes(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    name = "recon_summary.md"
    path = scratchpad / name
    path.write_text(_substantial(name), encoding="utf-8")
    payload = path.read_bytes()
    projection = {
        "path": name,
        "owner_phase": "recon",
        "owner_key": "phaseio/v4/sc/core/recon/recon_handoff",
        "status": "ACTIVE",
        "mtime_ns": path.stat().st_mtime_ns,
        "size": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "updated_at": "2026-08-26T00:00:00+00:00",
        "contract_digest": "3" * 64,
        "launch_digest": "4" * 64,
        "run_id": "typed-recon-run",
        "authority_level": "ACTIVE_AUTHORITY",
    }
    state = {
        "version": 4,
        "artifacts": {name: projection},
        "artifact_bindings": {
            f"scratchpad:{name}": {"sentinel": "binding-must-survive"},
        },
        "work_units": {
            "phaseio/v4/sc/core/recon/recon_handoff": {
                "sentinel": "producer-receipt-must-survive",
            },
        },
    }
    D._write_artifact_state(scratchpad, state)
    ledger_path = scratchpad / "_artifact_state.json"
    before = ledger_path.read_bytes()

    assert D._record_phase_artifact_state(
        scratchpad,
        str(project),
        D.SC_PHASES,
        "recon",
        "sc",
    ) == [name]
    assert ledger_path.read_bytes() == before
    assert D._read_artifact_state(scratchpad) == state
