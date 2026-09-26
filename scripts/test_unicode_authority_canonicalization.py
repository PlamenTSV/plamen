"""Unicode authority self-digests use the artifact-ledger canonical form."""
from __future__ import annotations

import hashlib
import json

import pytest

from artifact_ledger import (
    ArtifactLedgerError,
    _canonical_preexecution_authority_extension,
)
import severity_initial_source as initial
import severity_planning as planning
import severity_planning_inputs as planning_inputs
import severity_source_aggregate as aggregate


UNICODE_ROOTS = {
    "scratchpad": {
        "path": "/tmp/Plamen-λ/.scratchpad",
        "device": 1,
        "inode": 2,
        "mode": 0o700,
        "kind": "directory",
    },
    "project": {
        "path": "/tmp/Plamen-λ/审计",
        "device": 1,
        "inode": 3,
        "mode": 0o700,
        "kind": "directory",
    },
}


def _assert_ledger_canonical(invocation):
    replayed, digest = _canonical_preexecution_authority_extension(invocation)
    assert replayed == invocation
    assert digest == invocation["authority_sha256"]
    unsigned = dict(invocation)
    unsigned.pop("authority_sha256")
    legacy = hashlib.sha256(json.dumps(
        unsigned,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")).hexdigest()
    assert legacy != digest
    forged = {**invocation, "authority_sha256": legacy}
    with pytest.raises(ArtifactLedgerError, match="self-digest is invalid"):
        _canonical_preexecution_authority_extension(forged)


@pytest.mark.parametrize(
    "builder",
    (
        lambda core: initial._invocation_authority(core),
        lambda core: aggregate._invocation({"authority": core}),
        lambda core: planning_inputs._invocation_authority(core),
    ),
)
def test_severity_publishers_use_ledger_canonical_unicode_authority(builder):
    core = {
        "schema": "plamen.test-unicode-authority.v1",
        "run_id": "unicode-authority-run",
        "root_identities": UNICODE_ROOTS,
    }
    _assert_ledger_canonical(builder(core))


def test_severity_planning_actual_invocation_is_ledger_canonical_for_unicode():
    invocation = planning._invocation(
        run_id="unicode-authority-run",
        capture={
            "phase_io_owner_key": "sc/core/evm/codex/source/capture",
            "source_ledger_snapshot": (
                "_severity_adjudication_inputs/source_ledger.initial.json"
            ),
            "source_ledger_digest": "a" * 64,
        },
        inputs={"input-λ.json": b"{}\n"},
        outputs={"output-审计.json": b"{}\n"},
        planning_args={"working_directory": "/tmp/Plamen-λ/审计"},
        root_identities=UNICODE_ROOTS,
    )
    _assert_ledger_canonical(invocation)
    assert planning._authority_from_prior({
        "preexecution_authority": invocation,
    }) == invocation
