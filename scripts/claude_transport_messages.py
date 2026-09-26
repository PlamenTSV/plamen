"""Pure presentation policy for the public Claude transport chooser.

Capability diagnostics are retained for support and audit logs, but they are
never suitable as terminal wizard copy.  In particular, Darwin process-scope
probes can contain an OS errno that is useful diagnostically and meaningless
to someone choosing an audit backend.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Mapping


AUTO_SELECT_HEADLESS: Final = "AUTO_SELECT_HEADLESS"
RETURN_BACK: Final = "RETURN_BACK"
HEADLESS_TRANSPORT: Final = "headless"
_UNKNOWN_DIAGNOSTIC: Final = "CONTAINED_WORKER_AUTHORITY_UNAVAILABLE"


@dataclass(frozen=True, slots=True)
class ClaudeTransportUX:
    """A prompt-free decision plus separately retained diagnostic detail."""

    action: str
    transport: str | None
    message: str
    diagnostic_code: str


def _diagnostic_code(capability: Mapping[str, object]) -> str:
    reason = capability.get("reason")
    if type(reason) is str and reason:
        return reason
    return _UNKNOWN_DIAGNOSTIC


def _unavailable_message(diagnostic_code: str, platform: object) -> str:
    if diagnostic_code.startswith("DARWIN_KQUEUE_NOTE_TRACK_"):
        return (
            "Plamen's contained Claude runtime relies on process supervision "
            "that macOS no longer supports. Choose Codex to continue."
        )
    if diagnostic_code.startswith("CONTAINED_WORKER_CAPABILITY_PROBE_FAILED:"):
        return (
            "Plamen could not verify the contained Claude runtime on this host. "
            "Go back and choose Codex."
        )
    if platform == "darwin":
        return (
            "Contained Claude execution is not available on this Mac. "
            "Go back and choose Codex."
        )
    return (
        "Contained Claude execution is not available on this host. "
        "Go back and choose Codex."
    )


def claude_transport_ux(
    capability: Mapping[str, object],
) -> ClaudeTransportUX:
    """Translate an authority probe into a deterministic wizard decision.

    There is exactly one supported Claude transport.  When it is available,
    the wizard should select it directly.  When it is unavailable, the wizard
    should display ``message`` and return to backend selection directly.  A
    one-choice or Back-only transport prompt is never required.
    """

    if not isinstance(capability, Mapping):
        raise TypeError("Claude transport capability must be a mapping")
    diagnostic_code = _diagnostic_code(capability)
    if capability.get("available") is True:
        return ClaudeTransportUX(
            action=AUTO_SELECT_HEADLESS,
            transport=HEADLESS_TRANSPORT,
            message="Contained Claude execution is available and will be used.",
            diagnostic_code=(
                "" if diagnostic_code == _UNKNOWN_DIAGNOSTIC else diagnostic_code
            ),
        )
    return ClaudeTransportUX(
        action=RETURN_BACK,
        transport=None,
        message=_unavailable_message(
            diagnostic_code,
            capability.get("platform"),
        ),
        diagnostic_code=diagnostic_code,
    )
