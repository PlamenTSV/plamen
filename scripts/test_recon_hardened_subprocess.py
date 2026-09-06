"""Regression: `_run_hardened` cannot be deadlocked by a grandchild holding the
output handle (the confirmed root cause that wedged the driver forever).

CONFIRMED ROOT CAUSE reproduced live: `subprocess.run(capture_output=True,
timeout=T)` kills only the DIRECT child on TimeoutExpired, then drains the OS
PIPE. A grandchild (solc spawned by forge; cc/ld by cargo; rust-analyzer/scip-go
workers) inherits and HOLDS the stdout pipe write-handle, so the parent's drain
read never sees EOF → TimeoutExpired never completes → the driver wedges FOREVER.

These tests prove `_run_hardened`:
  (a) returns within timeout + grace (NOT forever), even when a long-lived
      grandchild has inherited and is holding the parent's stdout handle;
  (b) returns the sentinel rc 124 on timeout so callers degrade;
  (c) actually kills the grandchild (no orphan left holding the handle).

Cross-platform: the same test body runs on Windows (taskkill /T tree-kill) and
POSIX (killpg on a new session).
"""
from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import recon_prepass as RP


# Child program: spawn a long-lived GRANDCHILD that INHERITS this process's
# stdout (simulating solc holding the build pipe), record the grandchild PID to
# a file the test can read, then sleep far past the parent's timeout. With a
# real OS pipe the inherited handle would wedge the drain forever; _run_hardened
# drains to a temp FILE instead, so nothing can block.
_CHILD_SRC = textwrap.dedent(
    """
    import os, sys, subprocess, time
    pidfile = sys.argv[1]
    # Grandchild inherits our stdout/stderr (no stdout= override) and sleeps
    # long — this is the handle-holder that historically deadlocked the parent.
    gc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(600)"]
    )
    with open(pidfile, "w") as fh:
        fh.write(str(gc.pid))
        fh.flush()
        os.fsync(fh.fileno())
    sys.stdout.write("child-started\\n")
    sys.stdout.flush()
    time.sleep(600)
    """
)


def _pid_alive(pid: int) -> bool:
    """Cross-platform best-effort liveness check (False once the process is gone
    or a reaped zombie)."""
    if os.name == "nt":
        try:
            out = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}", "/NH"],
                capture_output=True, text=True, timeout=15,
            )
        except Exception:
            return False
        return str(pid) in (out.stdout or "")
    # POSIX
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    # Distinguish a live process from a not-yet-reaped zombie: a zombie's
    # /proc/<pid>/stat State field is 'Z'. If /proc is unavailable, treat the
    # successful kill(0) as alive.
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
        # format: pid (comm) STATE ...  — STATE is the token after the ')'
        state = stat.rsplit(")", 1)[1].split()[0]
        return state != "Z"
    except Exception:
        return True


def test_hardened_does_not_deadlock_on_held_handle(tmp_path):
    """A grandchild holding the inherited stdout handle can no longer wedge the
    parent: _run_hardened returns rc 124 within timeout+grace, and the
    grandchild is dead afterward (no orphan)."""
    child_py = tmp_path / "deadlock_child.py"
    child_py.write_text(_CHILD_SRC, encoding="utf-8")
    pidfile = tmp_path / "grandchild.pid"

    timeout = 3
    deadline = timeout + RP._HARDENED_GRACE_S + 8  # generous wall-time ceiling

    start = time.time()
    rc, output = RP._run_hardened(
        [sys.executable, str(child_py), str(pidfile)],
        tmp_path, timeout, writable_roots=(tmp_path,),
    )
    elapsed = time.time() - start

    # (a) bounded wall time — it did NOT hang forever
    assert elapsed < deadline, (
        f"_run_hardened took {elapsed:.1f}s (>= {deadline}s) — it hung"
    )
    # (b) sentinel rc so callers degrade
    assert rc == 124, f"expected sentinel rc 124 on timeout, got {rc}"
    assert "timed out" in output

    # (c) the grandchild that held the handle is actually dead (no orphan)
    assert pidfile.exists(), "child never recorded the grandchild PID"
    gc_pid = int(pidfile.read_text().strip())
    # Poll briefly: tree-kill is synchronous but reparented-zombie reaping may
    # lag a beat on POSIX.
    gone = False
    for _ in range(40):
        if not _pid_alive(gc_pid):
            gone = True
            break
        time.sleep(0.5)
    assert gone, f"grandchild PID {gc_pid} survived — orphan handle-holder leaked"


def test_hardened_normal_command_succeeds(tmp_path):
    """Fast command returns rc 0 and its captured output via the temp-file drain."""
    rc, output = RP._run_hardened(
        [sys.executable, "-c", "print('hello-hardened')"],
        tmp_path, 30,
    )
    assert rc == 0, f"expected rc 0, got {rc}: {output!r}"
    assert "hello-hardened" in output


def test_hardened_binary_not_found_returns_127():
    """Missing binary degrades to rc 127, never raises."""
    rc, output = RP._run_hardened(
        ["plamen_definitely_no_such_binary_xyz"], None, 10,
    )
    assert rc == 127
    assert "not found" in output


def test_run_cmd_delegates_and_never_raises(tmp_path):
    """`_run_cmd` (rc-only) still works through the hardened path."""
    rc = RP._run_cmd([sys.executable, "-c", "import sys; sys.exit(3)"], tmp_path, 30)
    assert rc == 3


if __name__ == "__main__":  # pragma: no cover - manual run
    import tempfile
    d = Path(tempfile.mkdtemp())
    test_hardened_does_not_deadlock_on_held_handle(d)
    test_hardened_normal_command_succeeds(d)
    test_hardened_binary_not_found_returns_127()
    test_run_cmd_delegates_and_never_raises(d)
    print("all hardened-subprocess tests passed")
