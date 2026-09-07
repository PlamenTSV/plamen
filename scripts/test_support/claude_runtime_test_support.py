"""Public test-only seam for lower-level Claude materializer unit tests.

Production callers must use ``compile_claude_runtime_materialization_request``
and ``materialize_claude_runtime`` with a claimed provider parent.  A narrow
set of legacy unit tests still exercises failure and cleanup behavior below
that authority boundary.  Keeping that bypass here makes the exceptional
scope explicit and keeps it out of the production API and call graph.
"""

from __future__ import annotations

import sys
from typing import Any

import claude_runtime_materialization as runtime


def _require_pytest() -> None:
    if "pytest" not in sys.modules:
        raise RuntimeError(
            "unbound Claude runtime support is available only under pytest"
        )


def compile_unbound_request(
    **kwargs: Any,
) -> runtime.ClaudeRuntimeMaterializationRequest:
    _require_pytest()
    return runtime._compile_claude_runtime_materialization_request(
        **kwargs
    )


def materialize_unbound_request(
    request: runtime.ClaudeRuntimeMaterializationRequest,
) -> runtime.ClaudeRuntimeMaterialization:
    _require_pytest()
    if type(request) is not runtime.ClaudeRuntimeMaterializationRequest:
        raise TypeError("exact runtime request is required")
    return runtime._materialize_claude_runtime(**request._claim())
