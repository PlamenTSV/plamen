"""Tests for Ship 4 of the artifact-complete PTY supervision plan.

Validates the standalone ``preflight_pty_transports`` module:

  - Cache hit short-circuits the probes.
  - Cache miss invokes the probes and persists the result.
  - Cache invalidates automatically when ``claude --version`` changes.
  - ``should_run_preflight`` gates correctly so the driver only invokes
    the preflight from the supervised PTY branch.

All probes are mocked via ``monkeypatch``. The tests never invoke the
live Claude API. Test numbers 26-29 match the plan's
``test_preflight_pty.py`` section.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

import preflight_pty_transports as pf  # noqa: E402


def test_preflight_child_env_strips_parent_claude_identity():
    env = pf._filtered_child_subprocess_environ({
        "CLAUDECODE": "1",
        "CLAUDE_CODE_SESSION_ID": "parent-session",
        "CLAUDE_CODE_ENTRYPOINT": "cli",
        "CLAUDE_CODE_EXECPATH": "/Users/example/.claude/local/claude",
        "AI_AGENT": "claude-code_2-1-150_agent",
        "PATH": "/usr/bin",
    })

    for key in (
        "CLAUDECODE",
        "CLAUDE_CODE_SESSION_ID",
        "CLAUDE_CODE_ENTRYPOINT",
        "CLAUDE_CODE_EXECPATH",
        "AI_AGENT",
    ):
        assert key not in env
    assert env["PATH"] == "/usr/bin"


def _stub_version(value: str):
    """Return a callable that ignores its arg and returns ``value``."""
    def _v(_claude_bin: str) -> str:
        return value
    return _v


def _stub_probe(result: tuple[bool, str], counter: dict):
    """Return a callable that records its invocation and returns ``result``.

    Ship 8.10: probes now take an optional isolation-payload arg; the stub
    accepts it (and any future positional/keyword args) so wiring changes
    do not break the cache-hit/miss tests.
    """
    def _p(_claude_bin: str, *args, **kwargs) -> tuple[bool, str]:
        counter["calls"] = counter.get("calls", 0) + 1
        return result
    return _p


# ---------------------------------------------------------------------------
# Test 26 -- cache hit skips probes
# ---------------------------------------------------------------------------


def test_preflight_cache_hit_skips_test(tmp_path: Path, monkeypatch):
    """A cache file matching the current claude --version must be
    returned without re-running the probes."""
    version = "2.1.146"
    monkeypatch.setattr(pf, "get_claude_version", _stub_version(version))

    cache_file = pf._cache_path(tmp_path, version)
    # Ship 8.10: a "matching" cache must now match the full key
    # (version + platform + argv shape + isolation overlay), so the
    # fixture carries the current-platform + current shape/overlay hashes.
    cached_payload = {
        "schema_version": pf._SCHEMA_VERSION,
        "claude_version": version,
        "tested_at": "2026-05-21T15:00:00Z",
        "tested_on_platform": sys.platform,
        "argv_shape_hash": pf._probe_shape_hash(),
        "isolation_overlay_hash": pf.isolation_overlay_hash(
            pf.SUBPROCESS_ISOLATION_PAYLOAD
        ),
        "live_pty_continue_supported": True,
        "agentid_resume_supported": False,
        "test_details": {
            "live_pty_continue": "(cached) PTY accepted continuation",
            "agentid_resume": "(cached) agentId resume not supported",
        },
    }
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    cache_file.write_text(json.dumps(cached_payload), encoding="utf-8")

    live_counter: dict = {}
    aid_counter: dict = {}
    monkeypatch.setattr(
        pf, "_test_live_pty_continue", _stub_probe((True, "should not be called"), live_counter)
    )
    monkeypatch.setattr(
        pf, "_test_agentid_resume", _stub_probe((True, "should not be called"), aid_counter)
    )

    result = pf.ensure_preflight_cache("claude", tmp_path)

    assert result["live_pty_continue_supported"] is True
    assert result["agentid_resume_supported"] is False
    assert result["test_details"]["live_pty_continue"].startswith("(cached)")
    # Probes MUST NOT have been called on a cache hit.
    assert live_counter == {}
    assert aid_counter == {}


# ---------------------------------------------------------------------------
# Test 27 -- cache miss runs probes and writes cache
# ---------------------------------------------------------------------------


def test_preflight_cache_miss_runs_test(tmp_path: Path, monkeypatch):
    """No cache file -> probes run and the result is written to the
    cache slot keyed by current claude --version."""
    version = "2.1.146"
    monkeypatch.setattr(pf, "get_claude_version", _stub_version(version))

    live_counter: dict = {}
    aid_counter: dict = {}
    monkeypatch.setattr(
        pf,
        "_test_live_pty_continue",
        _stub_probe((True, "mocked: PTY continued"), live_counter),
    )
    monkeypatch.setattr(
        pf,
        "_test_agentid_resume",
        _stub_probe((False, "mocked: agentId resume failed"), aid_counter),
    )

    result = pf.ensure_preflight_cache("claude", tmp_path)

    assert live_counter["calls"] == 1
    assert aid_counter["calls"] == 1

    # Returned dict reflects mocked values.
    assert result["claude_version"] == version
    assert result["schema_version"] == pf._SCHEMA_VERSION
    assert result["live_pty_continue_supported"] is True
    assert result["agentid_resume_supported"] is False
    assert result["test_details"]["live_pty_continue"] == "mocked: PTY continued"
    assert result["test_details"]["agentid_resume"] == "mocked: agentId resume failed"
    assert result["tested_on_platform"] == sys.platform

    # Cache file was persisted; reading it back round-trips.
    cache_file = pf._cache_path(tmp_path, version)
    assert cache_file.exists()
    on_disk = json.loads(cache_file.read_text(encoding="utf-8"))
    assert on_disk["claude_version"] == version
    assert on_disk["live_pty_continue_supported"] is True
    assert on_disk["agentid_resume_supported"] is False


# ---------------------------------------------------------------------------
# Test 28 -- version change invalidates cache
# ---------------------------------------------------------------------------


def test_preflight_version_change_invalidates(tmp_path: Path, monkeypatch):
    """A cache file written for one Claude version must NOT be returned
    when the binary now reports a different version. Probes re-run and
    a fresh cache slot is written."""
    old_version = "2.0.50"
    new_version = "2.1.146"

    # Seed the old cache slot.
    old_cache = pf._cache_path(tmp_path, old_version)
    old_cache.parent.mkdir(parents=True, exist_ok=True)
    old_cache.write_text(
        json.dumps(
            {
                "schema_version": pf._SCHEMA_VERSION,
                "claude_version": old_version,
                "tested_at": "2026-04-01T00:00:00Z",
                "tested_on_platform": "win32",
                "live_pty_continue_supported": True,
                "agentid_resume_supported": True,
                "test_details": {
                    "live_pty_continue": "(stale) old version",
                    "agentid_resume": "(stale) old version",
                },
            }
        ),
        encoding="utf-8",
    )

    # Now claude --version returns the new version.
    monkeypatch.setattr(pf, "get_claude_version", _stub_version(new_version))

    live_counter: dict = {}
    aid_counter: dict = {}
    monkeypatch.setattr(
        pf,
        "_test_live_pty_continue",
        _stub_probe((False, "fresh probe ran"), live_counter),
    )
    monkeypatch.setattr(
        pf,
        "_test_agentid_resume",
        _stub_probe((False, "fresh probe ran"), aid_counter),
    )

    result = pf.ensure_preflight_cache("claude", tmp_path)

    # Probes ran (stale cache was correctly invalidated by version mismatch).
    assert live_counter["calls"] == 1
    assert aid_counter["calls"] == 1
    assert result["claude_version"] == new_version
    assert result["test_details"]["live_pty_continue"] == "fresh probe ran"

    # New cache slot exists; old cache slot is left untouched (no
    # cross-version cleanup -- the new slot just lives alongside).
    new_cache = pf._cache_path(tmp_path, new_version)
    assert new_cache.exists()
    on_disk_new = json.loads(new_cache.read_text(encoding="utf-8"))
    assert on_disk_new["claude_version"] == new_version
    assert on_disk_new["live_pty_continue_supported"] is False

    # Old cache slot still readable and still bears the old version.
    on_disk_old = json.loads(old_cache.read_text(encoding="utf-8"))
    assert on_disk_old["claude_version"] == old_version


# ---------------------------------------------------------------------------
# Test 29 -- should_run_preflight gates correctly
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "backend,is_claude_pty,phase_name,supervised,expected",
    [
        # Default supervised set is {"breadth"} (Ship 4 ships breadth only).
        # The happy path: claude backend + PTY transport + supervised phase.
        ("claude", True, "breadth", None, True),
        # Non-claude backend (Codex) MUST NOT trigger the preflight, even
        # if the call site otherwise matches.
        ("codex", True, "breadth", None, False),
        # Headless (non-PTY) claude MUST NOT trigger -- deprecated branch
        # per the plan's hard constraint #2.
        ("claude", False, "breadth", None, False),
        # An unsupervised phase MUST NOT trigger even if backend and
        # transport match. This is what prevents the preflight from
        # running at the top of every run_phase() invocation.
        ("claude", True, "recon", None, False),
        ("claude", True, "depth", None, False),
        ("claude", True, "verify_aggregate", None, False),
        # Empty phase name fails the gate (defensive).
        ("claude", True, "", None, False),
        # Caller can broaden the supervised set (e.g. Ship 8 adds depth).
        ("claude", True, "depth", frozenset({"breadth", "depth"}), True),
        # Caller can narrow the supervised set (excluding breadth).
        ("claude", True, "breadth", frozenset({"depth"}), False),
        # Empty supervised set always returns False (no phases supervised).
        ("claude", True, "breadth", frozenset(), False),
    ],
)
def test_preflight_only_runs_for_claude_pty_supervised_phases(
    backend: str,
    is_claude_pty: bool,
    phase_name: str,
    supervised,
    expected: bool,
):
    """``should_run_preflight`` enforces the three-part gate described
    in the plan: claude backend + PTY transport + supervised phase. The
    gate exists so the driver does NOT run the preflight (~5 min,
    ~$0.10 first time per Claude version) at the top of every
    ``run_phase`` invocation -- only for phases that actually
    participate in the supervision loop."""
    actual = pf.should_run_preflight(
        backend, is_claude_pty, phase_name, supervised
    )
    assert actual is expected, (
        f"gate mismatch for "
        f"backend={backend!r} is_claude_pty={is_claude_pty} "
        f"phase={phase_name!r} supervised={supervised!r}: "
        f"expected {expected}, got {actual}"
    )


# ===========================================================================
# Ship 8.10 -- production-shaped probe + shape-hash cache key
# ===========================================================================
#
# Acceptance (verbatim from the user):
#   "preflight and production use the same PTY argv/isolation shape, and old
#    cached false negatives are invalidated by the shape hash."


import pty_exec as _ptx  # noqa: E402
from plamen_types import PLAMEN_HAIKU_MODEL, plamen_home  # noqa: E402


def _production_pty_argv(model="sonnet", session_id="prod-sid",
                         project="/proj", iso="/sp/_subprocess_isolation.json"):
    """The argv production builds for a non-MCP supervised PTY phase
    (breadth/depth), reproduced via the shared builder. This is what
    run_phase computes claude_pty_shape_hash(cmd) over."""
    argv = _ptx.build_claude_pty_argv(
        claude_bin="claude", model=model, session_id=session_id,
        add_dirs=[project, plamen_home().as_posix()],
        disallow_mcp=True, isolation_path=iso,
    )
    return _ptx.append_claude_pty_prompt_arg(
        argv,
        "Read and fully execute every instruction in "
        "prod-prompt.md. When done, output your one-line DONE summary.",
    )


def test_810_probe_shape_equals_production_shape():
    """The probe argv and the production argv hash to the SAME shape,
    modulo session-id / model / dir / iso paths (all normalized out)."""
    prod = _production_pty_argv()
    prod_shape = _ptx.claude_pty_shape_hash(prod)
    probe_shape = pf._probe_shape_hash()
    assert probe_shape == prod_shape, (
        "probe and production PTY argv shapes diverge -- preflight would "
        "never hit cache and the false-negative class is not closed"
    )


def test_810_probe_argv_carries_isolation_set(tmp_path):
    """The aligned probe argv MUST carry the full isolation set
    (--disallowedTools mcp__* + --settings/--strict-mcp-config/--mcp-config)
    -- the omission of which caused the historical false negative -- and
    MUST write the isolation overlay into its throwaway scratchpad."""
    argv = pf._build_probe_argv(
        "claude", "sid", tmp_path, pf.SUBPROCESS_ISOLATION_PAYLOAD,
        prompt=(
            "Read and fully execute every instruction in probe.md. "
            "When done, output your one-line DONE summary."
        ),
    )
    assert "--disallowedTools" in argv and "mcp__*" in argv
    assert "--strict-mcp-config" in argv and "--mcp-config" in argv
    assert "--settings" in argv
    assert "--no-chrome" in argv
    assert argv[argv.index("--model") + 1] == PLAMEN_HAIKU_MODEL
    assert argv[-1].startswith("Read and fully execute every instruction in ")
    # two --add-dir (tmp scratchpad + plamen_home), mirroring production.
    assert argv.count("--add-dir") == 2
    # overlay written to disk with the production payload.
    iso = tmp_path / "_subprocess_isolation.json"
    assert iso.exists()
    assert iso.read_text(encoding="utf-8") == pf.SUBPROCESS_ISOLATION_PAYLOAD


def test_810_old_false_negative_cache_invalidated_by_shape_hash(
    tmp_path, monkeypatch
):
    """The exact failure: a pre-8.10 cache stamped live=False (because the
    probe ran WITHOUT isolation) must be IGNORED once production passes the
    aligned shape hash. The probe re-runs; the new (correct) result wins."""
    version = "2.1.146"
    monkeypatch.setattr(pf, "get_claude_version", _stub_version(version))

    # Seed an old cache that LACKS argv_shape_hash (pre-8.10 false negative).
    cache_file = pf._cache_path(tmp_path, version)
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    cache_file.write_text(json.dumps({
        "schema_version": pf._SCHEMA_VERSION,
        "claude_version": version,
        "tested_on_platform": sys.platform,
        "isolation_overlay_hash": pf.isolation_overlay_hash(
            pf.SUBPROCESS_ISOLATION_PAYLOAD
        ),
        # NOTE: no argv_shape_hash -> this is the stale false-negative shape.
        "live_pty_continue_supported": False,
        "agentid_resume_supported": False,
        "test_details": {"live_pty_continue": "(stale) no isolation",
                         "agentid_resume": "(stale)"},
    }), encoding="utf-8")

    live_counter: dict = {}
    aid_counter: dict = {}
    monkeypatch.setattr(
        pf, "_test_live_pty_continue",
        _stub_probe((True, "fresh: PTY continued under isolation"), live_counter),
    )
    monkeypatch.setattr(
        pf, "_test_agentid_resume",
        _stub_probe((True, "fresh: resume ok"), aid_counter),
    )

    # Production passes its aligned shape hash; the stale cache lacks it.
    result = pf.ensure_preflight_cache(
        "claude", tmp_path,
        expected_shape_hash=_ptx.claude_pty_shape_hash(_production_pty_argv()),
    )

    assert live_counter["calls"] == 1, "stale false-negative cache was NOT re-probed"
    assert result["live_pty_continue_supported"] is True
    # The freshly written cache records the probe's shape hash.
    assert result["argv_shape_hash"] == pf._probe_shape_hash()


def test_810_cache_hits_when_shape_matches(tmp_path, monkeypatch):
    """Once a cache carries the matching shape hash + overlay + platform,
    a subsequent call with the same expected_shape_hash HITS (no re-probe)
    -- the steady-state cheap path is preserved."""
    version = "2.1.146"
    monkeypatch.setattr(pf, "get_claude_version", _stub_version(version))
    shape = pf._probe_shape_hash()

    cache_file = pf._cache_path(tmp_path, version)
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    cache_file.write_text(json.dumps({
        "schema_version": pf._SCHEMA_VERSION,
        "claude_version": version,
        "tested_on_platform": sys.platform,
        "argv_shape_hash": shape,
        "isolation_overlay_hash": pf.isolation_overlay_hash(
            pf.SUBPROCESS_ISOLATION_PAYLOAD
        ),
        "live_pty_continue_supported": True,
        "agentid_resume_supported": False,
        "test_details": {"live_pty_continue": "(cached)", "agentid_resume": "(cached)"},
    }), encoding="utf-8")

    live_counter: dict = {}
    monkeypatch.setattr(
        pf, "_test_live_pty_continue",
        _stub_probe((False, "should not run"), live_counter),
    )
    monkeypatch.setattr(
        pf, "_test_agentid_resume",
        _stub_probe((False, "should not run"), {}),
    )

    result = pf.ensure_preflight_cache(
        "claude", tmp_path, expected_shape_hash=shape,
    )
    assert live_counter == {}, "cache should have HIT but probe ran"
    assert result["live_pty_continue_supported"] is True


def test_810_schema_bump_invalidates_v1_cache(tmp_path, monkeypatch):
    """A literal pre-8.10 schema_version=1 cache is ignored (re-probe)."""
    version = "2.1.146"
    monkeypatch.setattr(pf, "get_claude_version", _stub_version(version))
    cache_file = pf._cache_path(tmp_path, version)
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    cache_file.write_text(json.dumps({
        "schema_version": 1,
        "claude_version": version,
        "tested_on_platform": sys.platform,
        "live_pty_continue_supported": False,
        "agentid_resume_supported": False,
        "test_details": {"live_pty_continue": "(v1 stale)", "agentid_resume": "x"},
    }), encoding="utf-8")
    counter: dict = {}
    monkeypatch.setattr(
        pf, "_test_live_pty_continue", _stub_probe((True, "fresh"), counter)
    )
    monkeypatch.setattr(
        pf, "_test_agentid_resume", _stub_probe((True, "fresh"), {})
    )
    result = pf.ensure_preflight_cache("claude", tmp_path)
    assert counter["calls"] == 1
    assert result["schema_version"] == pf._SCHEMA_VERSION
    assert result["live_pty_continue_supported"] is True
