from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parent.parent
BOOTSTRAP = ROOT / "scripts" / "bootstrap_macos_dev.sh"


def _bootstrap_text() -> str:
    raw = BOOTSTRAP.read_bytes()
    assert b"\r\n" not in raw
    return raw.decode("utf-8", errors="strict")


def test_bootstrap_is_source_development_only() -> None:
    text = _bootstrap_text()
    assert text.startswith("#!/bin/sh\n")
    assert "set -eu" in text
    assert "--require-hashes" in text
    assert "--only-binary=:all:" in text
    assert "requirements-ci.lock" in text
    assert "bootstrap-gate" in text
    assert '"$repo_root/plamen.py" install' not in text
    assert "python3.12 plamen.py install" not in text
    assert "Native macOS audit runtime: UNSUPPORTED IN THIS TREE." in text
    assert "docs/continuation/GOAL.md" in text


def test_bootstrap_help_is_platform_independent() -> None:
    shell = shutil.which("sh")
    if shell is None:
        pytest.skip("POSIX shell is unavailable")
    completed = subprocess.run(
        [shell, str(BOOTSTRAP), "--help"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
    )
    assert completed.returncode == 0
    assert "--extended-validation" in completed.stdout
    assert "--require-native-audit" in completed.stdout


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX executable semantics")
@pytest.mark.parametrize("architecture", ["arm64", "x86_64"])
def test_native_audit_requirement_fails_before_bootstrap_mutation(
    tmp_path: Path,
    architecture: str,
) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_uname = fake_bin / "uname"
    fake_uname.write_text(
        "#!/bin/sh\n"
        "case \"${1:-}\" in\n"
        "  -s) printf '%s\\n' Darwin ;;\n"
        f"  -m) printf '%s\\n' {architecture} ;;\n"
        "  *) exit 2 ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    fake_uname.chmod(0o755)
    shell = shutil.which("sh")
    assert shell is not None
    environment = dict(os.environ)
    environment["PATH"] = str(fake_bin) + os.pathsep + environment.get("PATH", "")
    environment["PLAMEN_DEV_VENV"] = str(tmp_path / "must-not-exist")
    completed = subprocess.run(
        [shell, str(BOOTSTRAP), "--require-native-audit"],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
    )
    assert completed.returncode == 3
    assert "native macOS E2E audit execution is not supported" in completed.stderr
    assert not (tmp_path / "must-not-exist").exists()


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX executable semantics")
def test_non_darwin_host_is_rejected(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_uname = fake_bin / "uname"
    fake_uname.write_text(
        "#!/bin/sh\n"
        "case \"${1:-}\" in\n"
        "  -s) printf '%s\\n' Linux ;;\n"
        "  -m) printf '%s\\n' x86_64 ;;\n"
        "  *) exit 2 ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    fake_uname.chmod(0o755)
    shell = shutil.which("sh")
    assert shell is not None
    environment = dict(os.environ)
    environment["PATH"] = str(fake_bin) + os.pathsep + environment.get("PATH", "")
    completed = subprocess.run(
        [shell, str(BOOTSTRAP)],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
    )
    assert completed.returncode == 2
    assert "supports macOS (Darwin) only" in completed.stderr
