"""Focused tests for prompt-free Claude transport presentation policy."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys

import pytest


MODULE_PATH = Path(__file__).with_name("claude_transport_messages.py")


def _load_module():
    name = "plamen_test_claude_transport_messages"
    spec = importlib.util.spec_from_file_location(name, MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(name, None)
    return module


def test_available_single_transport_is_auto_selected_without_a_prompt() -> None:
    messages = _load_module()

    decision = messages.claude_transport_ux({
        "available": True,
        "platform": "darwin",
        "reason": "",
        "write_authority": "SERIALIZED_PLAMEN_STAGE",
    })

    assert decision.action == messages.AUTO_SELECT_HEADLESS
    assert decision.transport == "headless"
    assert decision.diagnostic_code == ""
    assert decision.message == (
        "Contained Claude execution is available and will be used."
    )


@pytest.mark.parametrize(
    "diagnostic",
    (
            "DARWIN_KQUEUE_NOTE_TRACK_REJECTED_ERRNO_45",
        "DARWIN_KQUEUE_NOTE_TRACK_API_UNAVAILABLE",
    ),
)
def test_darwin_probe_detail_is_retained_but_never_shown(
    diagnostic: str,
) -> None:
    messages = _load_module()

    decision = messages.claude_transport_ux({
        "available": False,
        "platform": "darwin",
        "reason": diagnostic,
    })

    assert decision.action == messages.RETURN_BACK
    assert decision.transport is None
    assert decision.diagnostic_code == diagnostic
    assert "ERRNO" not in decision.message
    assert "DARWIN_" not in decision.message
    assert decision.message == (
        "Plamen's contained Claude runtime relies on process supervision "
        "that macOS no longer supports. Choose Codex to continue."
    )


def test_probe_exception_gets_stable_user_copy_and_separate_diagnostic() -> None:
    messages = _load_module()
    diagnostic = "CONTAINED_WORKER_CAPABILITY_PROBE_FAILED:RuntimeError"

    decision = messages.claude_transport_ux({
        "available": False,
        "platform": "darwin",
        "reason": diagnostic,
    })

    assert decision.action == messages.RETURN_BACK
    assert decision.transport is None
    assert decision.diagnostic_code == diagnostic
    assert diagnostic not in decision.message
    assert decision.message == (
        "Plamen could not verify the contained Claude runtime on this host. "
        "Go back and choose Codex."
    )


def test_unknown_darwin_limitation_has_mac_specific_friendly_copy() -> None:
    messages = _load_module()

    decision = messages.claude_transport_ux({
        "available": False,
        "platform": "darwin",
        "reason": "NATIVE_SANDBOX_PROCESS_AUTHORITY_NOT_CONFIGURED",
    })

    assert decision.action == messages.RETURN_BACK
    assert decision.diagnostic_code == (
        "NATIVE_SANDBOX_PROCESS_AUTHORITY_NOT_CONFIGURED"
    )
    assert decision.diagnostic_code not in decision.message
    assert decision.message == (
        "Contained Claude execution is not available on this Mac. "
        "Go back and choose Codex."
    )


def test_missing_or_non_string_reason_fails_back_with_stable_diagnostic() -> None:
    messages = _load_module()

    for capability in (
        {"available": False, "platform": "linux"},
        {"available": False, "platform": "linux", "reason": 22},
        {"available": 1, "platform": "linux", "reason": ""},
    ):
        decision = messages.claude_transport_ux(capability)
        assert decision.action == messages.RETURN_BACK
        assert decision.transport is None
        assert decision.diagnostic_code == (
            "CONTAINED_WORKER_AUTHORITY_UNAVAILABLE"
        )
        assert decision.diagnostic_code not in decision.message
        assert decision.message == (
            "Contained Claude execution is not available on this host. "
            "Go back and choose Codex."
        )


def test_available_probe_can_retain_nonempty_diagnostic_without_rendering_it() -> None:
    messages = _load_module()
    diagnostic = "STALE_DIAGNOSTIC_FOR_SUPPORT"

    decision = messages.claude_transport_ux({
        "available": True,
        "platform": "darwin",
        "reason": diagnostic,
    })

    assert decision.action == messages.AUTO_SELECT_HEADLESS
    assert decision.transport == "headless"
    assert decision.diagnostic_code == diagnostic
    assert diagnostic not in decision.message


def test_result_is_immutable_and_input_is_not_modified() -> None:
    messages = _load_module()
    capability = {
        "available": False,
        "platform": "darwin",
        "reason": "DARWIN_KQUEUE_NOTE_TRACK_REJECTED_ERRNO_1",
    }
    before = dict(capability)

    decision = messages.claude_transport_ux(capability)

    assert capability == before
    with pytest.raises((AttributeError, TypeError)):
        decision.message = "raw diagnostic"  # type: ignore[misc]


def test_non_mapping_input_is_rejected() -> None:
    messages = _load_module()

    with pytest.raises(TypeError, match="must be a mapping"):
        messages.claude_transport_ux(None)
