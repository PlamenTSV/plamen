"""Fixture-only construction of a real durable startup permit.

Tests that exercise the headless transaction boundary must not manufacture a
mapping that merely resembles startup authority.  This helper publishes and
replays the same epoch-bound receipt used by production while isolating the
provider lease registry under the pytest temporary tree.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

import auxiliary_writable_root_lease as lease_authority
import auxiliary_writable_root_startup as startup_authority


FIXTURE_RUN_ID = "12345678-1234-4abc-8def-1234567890ab"


def rotate_startup_permit(
    scratchpad: Path,
    *,
    run_id: str = FIXTURE_RUN_ID,
) -> dict[str, object]:
    """Publish and replay a fresh startup epoch for one fixture scratchpad."""

    root = Path(scratchpad).resolve(strict=True)
    # Production keeps this provider-owned runtime namespace outside the
    # audited project.  Mirror that boundary when a fixture root is the
    # conventional in-project scratchpad; otherwise the registry lock becomes
    # a late source-snapshot input and creates fixture-only audit drift.
    if root.name.startswith(".scratchpad"):
        runtime_parent = root.parent.parent
        namespace_identity = f"{root.parent.name}-{root.name}"
    else:
        runtime_parent = root.parent
        namespace_identity = root.name
    runtime_namespace = runtime_parent / (
        f".fixture-aux-runtime-{namespace_identity}"
    )
    with mock.patch.object(
        lease_authority,
        "_default_runtime_namespace",
        lambda: runtime_namespace,
    ):
        receipt = (
            startup_authority.reconcile_and_persist_startup_receipt(
                scratchpad=root,
                run_id=run_id,
            )
        )
    replay = startup_authority.load_and_replay_startup_receipt(
        scratchpad=root,
        expected_run_id=run_id,
        expected_startup_epoch=str(receipt["startup_epoch"]),
    )
    binding = replay.get("binding")
    if not isinstance(binding, dict):
        raise AssertionError("fixture startup reconciliation denied allocation")
    return binding


def durable_startup_permit(
    scratchpad: Path,
    *,
    run_id: str = FIXTURE_RUN_ID,
) -> dict[str, object]:
    """Return the current replayed permit, creating one exactly once."""

    root = Path(scratchpad).resolve(strict=True)
    current_path = root / startup_authority.STARTUP_CURRENT_NAME
    if current_path.is_file():
        current = json.loads(current_path.read_text(encoding="utf-8"))
        replay = startup_authority.load_and_replay_startup_receipt(
            scratchpad=root,
            expected_run_id=run_id,
            expected_startup_epoch=str(current["startup_epoch"]),
        )
        binding = replay.get("binding")
        if isinstance(binding, dict):
            return binding

    return rotate_startup_permit(root, run_id=run_id)
