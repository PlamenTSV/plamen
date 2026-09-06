"""Integration checks for the committed pre-T0 presence authority."""
from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest

from live_verify_queue_prearm_inputs import (
    prepare_prearm_presence_authority,
    validate_prearm_presence_authority,
)
import test_live_verify_queue_transaction_semantic_closure as acceptance
import verify_queue_transaction as transaction


CASES = (
    ("sc", "evm", "sc_verify_queue", "claude"),
    ("sc", "evm", "sc_verify_queue", "codex"),
    ("l1", "rust", "verify_queue", "claude"),
    ("l1", "rust", "verify_queue", "codex"),
)


def _config(
    pipeline: str,
    ecosystem: str,
    phase_name: str,
    backend: str,
) -> dict[str, str]:
    return {
        "pipeline": pipeline,
        "mode": "thorough",
        "ecosystem": ecosystem,
        "backend": backend,
        "phase_name": phase_name,
    }


def _prepare(
    tmp_path: Path,
    pipeline: str,
    ecosystem: str,
    phase_name: str,
    backend: str,
) -> tuple[Path, dict[str, Any], dict[str, str], str]:
    root = tmp_path / ".scratchpad"
    acceptance._seed_inputs(root, tmp_path, pipeline, backend)
    config = _config(pipeline, ecosystem, phase_name, backend)
    run_id = f"live-{pipeline}-{backend}"
    presence = prepare_prearm_presence_authority(
        scratchpad=root,
        project_root=tmp_path,
        config=config,
        run_id=run_id,
        roster=acceptance._upstream_inputs(pipeline),
    )
    return root, presence, config, run_id


def _plan(
    presence: dict[str, Any],
    config: dict[str, str],
    run_id: str,
) -> dict[str, Any]:
    pipeline = config["pipeline"]
    upstream = tuple(sorted({
        *acceptance._upstream_inputs(pipeline),
        str(presence["authority_path"]),
    }))
    return transaction.resolve_live_verify_queue_transaction_plan(
        **config,
        run_id=run_id,
        upstream_inputs=upstream,
        runtime_authority=acceptance._runtime_authority(
            pipeline, config["backend"]
        ),
        shard_manifests=acceptance._shard_manifests(pipeline),
        context_capture=acceptance.CONTEXT_CAPTURE,
        prearm_presence=presence,
        preverify_frozen_projection=acceptance._frozen_projection(
            pipeline, config["backend"]
        ),
        preverify_chain_pair_projection=(
            acceptance._chain_pair_projection(
                pipeline, config["backend"]
            )
        ),
    )


@pytest.mark.parametrize(
    "pipeline,ecosystem,phase_name,backend",
    CASES,
)
def test_presence_authority_is_backend_neutral_live_t0_input(
    tmp_path: Path,
    pipeline: str,
    ecosystem: str,
    phase_name: str,
    backend: str,
) -> None:
    root, presence, config, run_id = _prepare(
        tmp_path, pipeline, ecosystem, phase_name, backend
    )
    plan = _plan(presence, config, run_id)
    t0 = acceptance._child_map(plan)[acceptance.CHILD_IDS[0]]

    assert presence["authority_path"] in t0["required_inputs"]
    assert t0["prearm_presence_authority"] == presence["authority"]
    result = transaction.execute_live_verify_queue_transaction(
        scratchpad=root,
        project_root=tmp_path,
        plan=plan,
        run_id=run_id,
        semantic_executor=acceptance._LiveSemanticExecutor(plan),
    )
    assert result["state"] == "OUTPUT_COMMITTED"
    assert result["safe_to_consume"] is True


def test_presence_preparation_resume_is_byte_exact(
    tmp_path: Path,
) -> None:
    root, first, config, run_id = _prepare(
        tmp_path, "sc", "evm", "sc_verify_queue", "claude"
    )
    before = (root / first["authority_path"]).read_bytes()
    second = prepare_prearm_presence_authority(
        scratchpad=root,
        project_root=tmp_path,
        config=config,
        run_id=run_id,
        roster=acceptance._upstream_inputs("sc"),
    )

    assert second == first
    assert (root / first["authority_path"]).read_bytes() == before


def test_resolver_rejects_presence_roster_omission_even_when_rehashed(
    tmp_path: Path,
) -> None:
    _root, presence, config, run_id = _prepare(
        tmp_path, "l1", "rust", "verify_queue", "codex"
    )
    tampered = copy.deepcopy(presence)
    authority = tampered["authority"]
    authority["roster_identities"] = authority["roster_identities"][:-1]

    with pytest.raises(
        transaction.VerifyQueueTransactionError,
        match="presence|roster|digest|denominator",
    ):
        _plan(tampered, config, run_id)


def test_presence_directory_roster_cannot_be_arbitrary_when_rehashed(
    tmp_path: Path,
) -> None:
    root, presence, config, run_id = _prepare(
        tmp_path, "sc", "evm", "sc_verify_queue", "claude"
    )
    tampered = copy.deepcopy(presence)
    authority = tampered["authority"]
    authority["directory_roster"] = [{
        "root": "scratchpad",
        "directory": "invented",
        "member_identities": list(authority["roster_identities"]),
        "member_identity_digest": transaction._stable_digest(
            authority["roster_identities"]
        ),
    }]
    authority["directory_roster_digest"] = transaction._stable_digest(
        authority["directory_roster"]
    )
    unsigned = {
        key: value for key, value in authority.items()
        if key != "authority_digest"
    }
    authority["authority_digest"] = transaction._stable_digest(unsigned)

    issues = validate_prearm_presence_authority(
        scratchpad=root,
        project_root=tmp_path,
        authority_identity="scratchpad:" + presence["authority_path"],
        authority=authority,
        **config,
        run_id=run_id,
    )
    assert issues
    assert any("directory" in issue.lower() for issue in issues)
    with pytest.raises(
        transaction.VerifyQueueTransactionError,
        match="presence|directory|roster|denominator",
    ):
        _plan(tampered, config, run_id)
