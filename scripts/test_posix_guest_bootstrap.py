from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = ROOT / "native/posix/plamen_guest_bootstrap.py"


def test_guest_bootstrap_has_fixed_isolated_interpreter_and_runtime_root() -> None:
    raw = BOOTSTRAP.read_bytes()
    assert raw.startswith(b"#!/usr/bin/python3 -I\n")
    assert raw.count(b'"/opt/plamen/scripts"') == 1
    assert raw.count(b'"/opt/plamen/scripts/plamen_driver.py"') == 1
    assert b"PYTHONPATH" not in raw and b"site.addsitedir" not in raw


def test_guest_bootstrap_runs_sibling_import_argv_and_inherited_fd(
    tmp_path: Path,
) -> None:
    scripts = tmp_path / "opt/plamen/scripts"
    scripts.mkdir(parents=True)
    (scripts / "plamen_types.py").write_text("VALUE = 'retained-import'\n")
    output = tmp_path / "result.json"
    (scripts / "plamen_driver.py").write_text(
        "import json,os,sys\n"
        "from plamen_types import VALUE\n"
        "with open(os.environ['PLAMEN_TEST_RESULT'], 'w') as stream:\n"
        " json.dump({'argv':sys.argv,'fd':os.read(int(sys.argv[1]),32).decode(),"
        "'value':VALUE},stream,sort_keys=True)\n"
    )
    mirror = tmp_path / "plamen-guest"
    mirror.write_bytes(BOOTSTRAP.read_bytes().replace(
        b"/opt/plamen/scripts", os.fspath(scripts).encode("utf-8"),
    ))
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, b"descriptor-custody")
        os.close(write_fd); write_fd = -1
        completed = subprocess.run(
            [sys.executable, "-I", "-B", os.fspath(mirror), str(read_fd), "tail"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, pass_fds=(read_fd,), close_fds=True,
            env={
                "LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin",
                "PLAMEN_TEST_RESULT": os.fspath(output),
            }, check=False,
        )
    finally:
        os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")
    assert completed.stdout == completed.stderr == b""
    assert json.loads(output.read_text()) == {
        "argv": [os.fspath(scripts / "plamen_driver.py"), str(read_fd), "tail"],
        "fd": "descriptor-custody", "value": "retained-import",
    }
