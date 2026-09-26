"""Focused cold-install, recovery, and last-publication regressions."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat

import pytest

import posix_native_install_transaction as T


pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX only")


def _canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _file_authority(path: Path, raw: bytes, mode: int, ordinal: int = 1):
    return {
        "schema": "plamen.posix-native-install.file-authority.v1",
        "path": str(path), "device": ordinal, "inode": ordinal,
        "mode": mode, "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def _observed_file_authority(path: Path):
    observed = path.lstat(); raw = path.read_bytes()
    return {
        "schema": "plamen.posix-native-install.file-authority.v1",
        "path": str(path), "device": observed.st_dev, "inode": observed.st_ino,
        "mode": stat.S_IMODE(observed.st_mode), "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def _artifact(path: Path, kind: str):
    raw = path.read_bytes()
    result = {
        "schema": T.ARTIFACT_SCHEMA, "kind": kind, "path": str(path),
        "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
    }
    if kind == "package-receipt":
        result["transaction_id"] = "a" * 32
    return result


def _source(home: Path):
    return {
        "schema": T.SOURCE_SCHEMA, "platform": "darwin-arm64",
        "source_root": str(home / "source"),
        "manifest_sha256": "1" * 64,
        "roster_definition_sha256": "2" * 64,
        "source_roster_sha256": "3" * 64, "source_count": 7,
    }


class _Effects:
    python_raw = b"managed-cpython-3.12\n"
    front_raw = b"print('plamen front')\n"
    package_raw = b'{"state":"COMMITTED"}\n'
    install_raw = b"signed-native-install-receipt\n"
    deployment_raw = b"signed-native-deployment-receipt\n"

    def __init__(self, home: Path, *, fail_native=False):
        self.home = home
        self.fail_native = fail_native
        self.events = []
        self.stage_files = []
        self.python = home / ".local/share/plamen/runtime/py312/bin/python3"
        self.front = home / ".plamen/plamen.py"
        self.package = home / ".codex/.plamen-codex-install.json"
        self.install = home / ".local/share/plamen/share/plamen/native-install-receipt-v2.bin"
        self.deployment = home / ".local/share/plamen/share/plamen/native-deployment-receipt-v2.bin"
        self.public = home / ".local/bin/plamen"

    def observe_prior(self, _home):
        present = [path.exists() for path in (self.package, self.install, self.deployment)]
        launcher = os.path.lexists(self.public)
        if not any(present) and not launcher:
            return {
                "schema": T.PRIOR_SCHEMA, "state": "ABSENT",
                "package_receipt": None, "native_install_receipt": None,
                "deployment_receipt": None, "public_launcher": None,
            }
        if all(present) and launcher:
            return {
                "schema": T.PRIOR_SCHEMA, "state": "VERIFIED",
                "package_receipt": _artifact(self.package, "package-receipt"),
                "native_install_receipt": _artifact(self.install, "native-install-receipt"),
                "deployment_receipt": _artifact(self.deployment, "deployment-receipt"),
                "public_launcher": _observed_file_authority(self.public),
            }
        raise RuntimeError("partial install is not predecessor authority")

    def stage_package(self, _home, transaction_root, _source):
        self.events.append("stage_package")
        marker = transaction_root / "package.stage"
        marker.write_bytes(b"package-stage\n"); self.stage_files.append(marker)
        return {
            "schema": T.STAGE_SCHEMA, "kind": "package",
            "transaction_id": transaction_root.name,
            "manifest_sha256": hashlib.sha256(marker.read_bytes()).hexdigest(),
            "artifact_count": 2,
            "prestate_sha256": "e" * 64,
            "interpreter_authority": _file_authority(
                self.python, self.python_raw, 0o500, 11,
            ),
            "front_authority": _file_authority(
                self.front, self.front_raw, 0o400, 12,
            ),
        }

    def validate_package_stage(self, stage, _source):
        self.events.append("validate_package_stage")
        assert stage["kind"] == "package"

    def stage_native(self, _home, transaction_root, _source, _package_stage):
        self.events.append("stage_native")
        marker = transaction_root / "native.stage"
        marker.write_bytes(b"native-stage\n"); self.stage_files.append(marker)
        return {
            "schema": T.STAGE_SCHEMA, "kind": "native",
            "transaction_id": transaction_root.name,
            "manifest_sha256": hashlib.sha256(marker.read_bytes()).hexdigest(),
            "artifact_count": 8,
        }

    def validate_native_stage(self, stage, _source, package_stage):
        self.events.append("validate_native_stage")
        assert stage["kind"] == "native" and package_stage["kind"] == "package"


    def commit_package(self, _stage, _source):
        self.events.append("commit_package")
        for path, raw, mode in (
            (self.python, self.python_raw, 0o500),
            (self.front, self.front_raw, 0o400),
            (self.package, self.package_raw, 0o600),
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
            if not path.exists():
                path.write_bytes(raw); path.chmod(mode)
            assert path.read_bytes() == raw
        return _artifact(self.package, "package-receipt")

    def validate_package_receipt(self, receipt):
        self.events.append("validate_package_receipt")
        assert receipt == _artifact(self.package, "package-receipt")

    def commit_native(self, _stage, _source, _package):
        self.events.append("commit_native")
        if self.fail_native:
            raise RuntimeError("native coordinator rejected staging")
        for path, raw in (
            (self.install, self.install_raw), (self.deployment, self.deployment_raw),
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
            if not path.exists():
                path.write_bytes(raw); path.chmod(0o400)
            assert path.read_bytes() == raw
        return {
            "install_receipt": _artifact(self.install, "native-install-receipt"),
            "deployment_receipt": _artifact(self.deployment, "deployment-receipt"),
        }

    def validate_native_receipts(self, receipts, _package):
        self.events.append("validate_native_receipts")
        assert receipts["install_receipt"] == _artifact(
            self.install, "native-install-receipt",
        )
        assert receipts["deployment_receipt"] == _artifact(
            self.deployment, "deployment-receipt",
        )

    def rollback_native(self, _receipts, prior):
        self.events.append("rollback_native")
        assert prior["state"] == "ABSENT"
        self.install.unlink(missing_ok=True); self.deployment.unlink(missing_ok=True)

    def rollback_package(self, _receipt, prior):
        self.events.append("rollback_package")
        assert prior["state"] == "ABSENT"
        self.package.unlink(missing_ok=True)
        self.python.unlink(missing_ok=True); self.front.unlink(missing_ok=True)

    def cleanup_stages(self, _package, _native):
        self.events.append("cleanup_stages")
        for path in self.stage_files:
            path.unlink(missing_ok=True)


def test_cold_install_commits_all_receipts_then_public_and_replays(tmp_path):
    home = tmp_path / "account"; home.mkdir(); (home / "source").mkdir()
    effects = _Effects(home)
    receipt = T.execute_cold_install_transaction(
        home=home, source_authority=_source(home), effects=effects,
    )
    assert receipt["state"] == "COMMITTED"
    assert receipt["package_receipt"]["path"] == str(effects.package)
    assert receipt["native_install_receipt"]["path"] == str(effects.install)
    assert receipt["deployment_receipt"]["path"] == str(effects.deployment)
    assert effects.public.read_bytes().startswith(b"#!/bin/sh\n")
    assert effects.public.stat().st_mode & 0o777 == 0o700
    assert effects.events.index("stage_native") < effects.events.index("commit_package")
    assert effects.events.index("commit_package") < effects.events.index("commit_native")

    commits = effects.events.count("commit_package"), effects.events.count("commit_native")
    replay = T.execute_cold_install_transaction(
        home=home, source_authority=_source(home), effects=effects,
    )
    assert replay == receipt
    assert commits == (
        effects.events.count("commit_package"), effects.events.count("commit_native"),
    )


@pytest.mark.parametrize(
    "crash_state", ("PACKAGE_COMMITTED", "NATIVE_COMMITTED", "PUBLIC_COMMITTED"),
)
def test_crash_recovery_completes_without_blessing_partial_install(tmp_path, crash_state):
    home = tmp_path / "account"; home.mkdir(); (home / "source").mkdir()
    effects = _Effects(home)

    def fault(state):
        if state == crash_state:
            raise T.TEST_ONLY_ColdInstallCrash(state)

    with pytest.raises(T.TEST_ONLY_ColdInstallCrash):
        T.execute_cold_install_transaction(
            home=home, source_authority=_source(home), effects=effects, fault=fault,
        )
    receipt = T.execute_cold_install_transaction(
        home=home, source_authority=_source(home), effects=effects,
    )
    assert receipt["state"] == "COMMITTED"
    assert effects.public.exists()


def test_native_failure_rolls_back_package_and_never_publishes_launcher(tmp_path):
    home = tmp_path / "account"; home.mkdir(); (home / "source").mkdir()
    effects = _Effects(home, fail_native=True)
    with pytest.raises(RuntimeError, match="native coordinator rejected"):
        T.execute_cold_install_transaction(
            home=home, source_authority=_source(home), effects=effects,
        )
    assert not effects.package.exists()
    assert not effects.python.exists()
    assert not effects.front.exists()
    assert not effects.public.exists()
    assert "rollback_package" in effects.events


def test_unverified_public_launcher_is_never_overwritten(tmp_path):
    home = tmp_path / "account"; home.mkdir(); (home / "source").mkdir()
    public = home / ".local/bin/plamen"
    public.parent.mkdir(parents=True); public.write_bytes(b"foreign\n"); public.chmod(0o700)
    effects = _Effects(home)
    effects.observe_prior = lambda _home: {
        "schema": T.PRIOR_SCHEMA, "state": "ABSENT",
        "package_receipt": None, "native_install_receipt": None,
        "deployment_receipt": None, "public_launcher": None,
    }
    with pytest.raises(Exception, match="not authenticated"):
        T.execute_cold_install_transaction(
            home=home, source_authority=_source(home), effects=effects,
        )
    assert public.read_bytes() == b"foreign\n"
    assert not effects.package.exists()


def test_validated_freeze_replays_real_bytes_and_rejects_drift_before_controls(tmp_path):
    home = tmp_path / "account"; home.mkdir()
    source = home / "source"; (source / "scripts").mkdir(parents=True)
    member = source / "scripts/member.py"; member.write_bytes(b"VALUE = 1\n")
    row = {
        "path": "scripts/member.py", "role": "member",
        "size": member.stat().st_size,
        "sha256": hashlib.sha256(member.read_bytes()).hexdigest(),
    }
    manifest = {
        "platform": "darwin-arm64", "roster_definition_sha256": "4" * 64,
        "schema": "plamen.native-production-source-freeze.v2",
        "source_count": 1, "source_roster_sha256": "5" * 64,
        "sources": [row], "version": 2,
    }
    manifest["manifest_sha256"] = hashlib.sha256(_canonical(manifest)).hexdigest()
    authority = T.source_authority_from_validated_freeze(source, manifest)
    assert authority["source_count"] == 1
    member.write_bytes(b"VALUE = 2\n")
    with pytest.raises(T.PosixNativeInstallTransactionError, match="member member differs"):
        T.source_authority_from_validated_freeze(source, manifest)
    assert not (home / ".local").exists()
