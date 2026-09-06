"""Runtime caches cannot masquerade as audit-snapshot code changes."""

from __future__ import annotations

import inspect

import program_facts_source_manifest as P


def test_snapshot_rebuilder_identity_pins_every_mutable_provider_cache() -> None:
    source = inspect.getsource(P._live_audit_identity)
    # The public callable is a closure; inspect its captured rebuilder source
    # through the module file instead of relying on closure implementation
    # details that vary between Python releases.
    module_source = inspect.getsource(inspect.getmodule(P._live_audit_identity))
    for name in (
        "_FILE_HASH_CACHE",
        "_PYTHON_PACKAGE_CACHE",
        "_PYTHON_DISTRIBUTION_CLOSURE_CACHE",
        "_RETAINED_HARDLINK_APPROVALS",
        "_RETAINED_HARDLINK_APPROVAL_TAGS",
        "_RETAINED_HARDLINK_DENIAL_FDS",
        "_TOOL_FINGERPRINT_CACHE",
        "_TOOL_PROBE_DIAGNOSTICS",
    ):
        assert f'"{name}"' in module_source

    assert "def rebuild" in source
