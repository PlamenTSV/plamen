"""Cold package-front import must be declaration-only and exact-name gated."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
FRONT = ROOT / "plamen.py"


_CHILD = r'''
import os,pathlib,sys,types
source_path=pathlib.Path(sys.argv[1])
module_name=sys.argv[2]
raw=source_path.read_bytes()
sys.dont_write_bytecode=True
def audit(event,args):
    if event in {
        "os.mkdir","os.remove","os.rename","os.rmdir","os.unlink",
        "os.chmod","os.chown","os.link","os.symlink","os.truncate",
        "os.exec","os.fork","os.forkpty","os.posix_spawn","os.system",
        "subprocess.Popen","socket.connect","socket.connect_ex","socket.bind",
        "socket.getaddrinfo","socket.gethostbyname","socket.gethostbyaddr",
    }:
        raise RuntimeError("MUTATION:"+event)
    if event=="open" and len(args)>=2:
        mode=args[1]
        flags=args[2] if len(args)>2 else 0
        mutation_flags=(os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND|os.O_EXCL)
        if (isinstance(mode,str) and any(c in mode for c in "wax+")) or (
            isinstance(flags,int) and bool(flags & mutation_flags)
        ):
            raise RuntimeError("MUTATION:open")
sys.addaudithook(audit)
module=types.ModuleType(module_name)
module.__file__=str(source_path)
module.__package__=""
sys.modules[module_name]=module
try:
    exec(compile(raw,str(source_path),"exec",dont_inherit=True),module.__dict__)
except BaseException as exc:
    print("BLOCKED",type(exc).__name__,str(exc))
    raise SystemExit(73)
required=("_install_codex_package_transaction",
          "_rollback_committed_codex_package_transaction")
if not module.__dict__.get("_FROZEN_PACKAGE_FRONT_STDLIB_ONLY"):
    raise SystemExit(74)
if not all(callable(module.__dict__.get(name)) for name in required):
    raise SystemExit(75)
print("DECLARATION_ONLY",*required)
'''


def _probe(module_name: str, home: Path) -> subprocess.CompletedProcess[str]:
    environment = {
        "HOME": str(home), "LANG": "C", "LC_ALL": "C",
        "PATH": "/usr/bin:/bin", "PYTHONHASHSEED": "0",
    }
    return subprocess.run(
        [sys.executable, "-I", "-B", "-c", _CHILD, str(FRONT), module_name],
        check=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True, env=environment, timeout=60,
    )


def test_exact_frozen_package_front_import_is_declaration_only(tmp_path: Path) -> None:
    home = tmp_path / "account"; home.mkdir()
    completed = _probe("_plamen_frozen_package_front", home)
    assert completed.returncode == 0, completed.stdout
    assert completed.stdout.strip() == (
        "DECLARATION_ONLY _install_codex_package_transaction "
        "_rollback_committed_codex_package_transaction"
    )
    assert list(home.iterdir()) == []


@pytest.mark.parametrize("module_name, expected", [
    ("plamen", "BLOCKED RuntimeError MUTATION:"),
    ("_plamen_frozen_package_front_typo", "BLOCKED RuntimeError MUTATION:"),
    ("__main__", "BLOCKED SystemExit 3"),
])
def test_every_other_module_name_retains_bootstrap_boundary(
    tmp_path: Path, module_name: str, expected: str,
) -> None:
    home = tmp_path / module_name.replace("/", "_"); home.mkdir()
    completed = _probe(module_name, home)
    assert completed.returncode == 73, completed.stdout
    assert expected in completed.stdout
    assert list(home.iterdir()) == []
