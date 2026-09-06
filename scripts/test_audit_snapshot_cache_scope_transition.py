"""A retained provider cache may miss cleanly across independent audits."""

from __future__ import annotations

import inspect

import audit_snapshot as A


def test_authenticated_provider_cache_uses_scope_miss_not_global_failure() -> None:
    source = inspect.getsource(A._replay_python_distribution_closure_cache)

    assert 'if payload.get("project_root") != project_name:' in source
    assert 'return None' in source[source.index(
        'if payload.get("project_root") != project_name:'
    ):]
