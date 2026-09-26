"""Concrete cold-install effects integration against a temporary account."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import venv

import pytest

import posix_native_install_effects as E
import posix_native_install_transaction as T
import posix_managed_evm_setup_transaction as S


pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX only")


def _file(path: Path, raw: bytes, mode: int, number: int):
    return {
        "schema": "plamen.posix-native-install.file-authority.v1",
        "path": str(path), "device": number, "inode": number,
        "mode": mode, "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def _fixture(tmp_path: Path):
    home = tmp_path / "account"; home.mkdir()
    source = tmp_path / "source"; source.mkdir()
    snapshot = tmp_path / "package-snapshot"; snapshot.mkdir()
    package_source = snapshot / "package-source"; package_source.mkdir()
    managed_runtime = snapshot / "managed-runtime"
    front_source = package_source / "plamen.py"
    front_source.write_bytes(
        b"import sys\nprint('fixture-v3' if sys.argv[1:] == ['--version'] else 'front')\n"
    ); front_source.chmod(0o400)
    policy = package_source / "policy.json"; policy.write_bytes(b"{}\n"); policy.chmod(0o400)
    venv.EnvBuilder(with_pip=False, symlinks=False).create(managed_runtime)
    for activation in (managed_runtime / "bin").glob("activate*"):
        activation.unlink()
    (managed_runtime / "bin/Activate.ps1").unlink(missing_ok=True)
    config = managed_runtime / "pyvenv.cfg"
    config.write_text(
        "\n".join(
            line for line in config.read_text().splitlines()
            if not line.startswith("command = ")
        ) + "\n"
    )
    site = managed_runtime / "lib/python3.12/site-packages"
    site.mkdir(parents=True, exist_ok=True)
    for module in ("InquirerPy", "jsonschema", "mcp", "pydantic", "rich"):
        package_dir = site / module
        package_dir.mkdir()
        (package_dir / "__init__.py").write_text("# fixture dependency\n")
    google = site / "google"; google.mkdir()
    (google / "__init__.py").write_text("# fixture namespace\n")
    (google / "protobuf.py").write_text("# fixture protobuf\n")
    for directory in sorted(
        (path for path in managed_runtime.rglob("*") if path.is_dir()),
        key=lambda path: len(path.parts), reverse=True,
    ):
        if not any(directory.iterdir()):
            directory.rmdir()
    rows = []
    for path in (front_source, policy):
        raw = path.read_bytes()
        rows.append({
            "namespace": "package-source", "path": path.name,
            "mode": 0o400, "size": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        })
    for path in sorted(managed_runtime.rglob("*")):
        assert not path.is_symlink()
        if not path.is_file():
            continue
        mode = 0o500 if stat.S_IMODE(path.stat().st_mode) & 0o111 else 0o400
        path.chmod(mode)
        raw = path.read_bytes()
        rows.append({
            "namespace": "managed-runtime",
            "path": path.relative_to(managed_runtime).as_posix(),
            "mode": mode, "size": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        })
    python_source = managed_runtime / "bin/python"
    python_raw = python_source.read_bytes()
    front_raw = front_source.read_bytes()
    manifest = {"schema": E.PACKAGE_SNAPSHOT_SCHEMA, "rows": rows}
    manifest_sha256 = hashlib.sha256(
        (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
    ).hexdigest()
    snapshot_authority = {
        "schema": E.PACKAGE_SNAPSHOT_SCHEMA, "root": str(snapshot),
        "manifest_sha256": manifest_sha256, "rows": rows,
        "interpreter_authority": _file(
            home / ".local/share/plamen/runtime/py312/bin/python",
            python_raw, stat.S_IMODE(python_source.stat().st_mode), 1,
        ),
        "front_authority": _file(
            home / ".plamen/plamen.py", front_raw, 0o400, 2,
        ),
    }
    source_authority = {
        "schema": T.SOURCE_SCHEMA, "platform": "darwin-arm64",
        "source_root": str(source), "manifest_sha256": "1" * 64,
        "roster_definition_sha256": "2" * 64,
        "source_roster_sha256": "3" * 64, "source_count": 2,
    }
    package = home / ".codex/.plamen-codex-install.json"
    native = home / ".local/share/plamen/share/plamen/native-install-receipt-v2.bin"
    deployment = home / ".local/share/plamen/share/plamen/native-deployment-receipt-v2.bin"
    managed_receipt = (
        home / ".local/share/plamen/share/plamen/managed-evm-generation-receipt-v1.bin"
    )
    evm_policy = tmp_path / "managed-evm-policy.json"
    evm_policy.write_bytes(b'{"schema":"fixture-policy"}\n'); evm_policy.chmod(0o400)
    acquisition = tmp_path / "signed-acquisition-receipt.bin"
    acquisition.write_bytes(b"signed-acquisition\n"); acquisition.chmod(0o400)
    managed_root = tmp_path / "managed-evm"
    (managed_root / "cache").mkdir(parents=True, mode=0o700)
    (managed_root / "generations").mkdir(mode=0o700)
    managed_root.chmod(0o700)
    staged = []

    class _OpaqueManagedAuthority:
        pass

    native_runtime_authority = object()

    def managed_evm_provision(
        policy_path, python, root, *, acquisition_receipt_path,
        project_root, native_runtime_authority: object,
    ):
        assert Path(policy_path) == evm_policy
        assert Path(python) == Path(snapshot_authority["interpreter_authority"]["path"])
        assert Path(root) == managed_root
        assert Path(acquisition_receipt_path) == acquisition
        assert Path(project_root) == source
        assert native_runtime_authority is not None
        return _OpaqueManagedAuthority()

    def managed_evm_require(authority):
        assert type(authority) is _OpaqueManagedAuthority
        return {
            "schema": "plamen.managed-evm-generation-execution-authority.v1",
            "binding_sha256": "f" * 64,
        }

    def managed_evm_receipt_publish(
        _account, path, transaction_id, authority, binding, inputs_binding,
        _package_receipt, _native_receipts,
    ):
        managed_evm_require(authority)
        value = {
            "schema": "plamen.managed-evm-installed-generation-receipt.v1",
            "transaction_id": transaction_id,
            "generation_binding_sha256": binding["binding_sha256"],
            "input_binding_sha256": hashlib.sha256(
                (json.dumps(inputs_binding, sort_keys=True, separators=(",", ":")) + "\n").encode()
            ).hexdigest(),
        }
        target = Path(path); target.parent.mkdir(parents=True, exist_ok=True)
        raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        if target.exists():
            assert target.read_bytes() == raw
        else:
            target.write_bytes(raw); target.chmod(0o400)
        return value

    def managed_evm_receipt_validate(
        _account, receipt, _stage, _package, _native, _inputs,
    ):
        assert receipt["path"] == str(managed_receipt)
        assert managed_receipt.exists()
        return _OpaqueManagedAuthority()

    def managed_evm_receipt_rollback(
        _account, receipt, stage, prior, _inputs,
    ):
        assert stage["kind"] == "managed-evm"
        if receipt is not None:
            assert receipt["path"] == str(managed_receipt)
        assert prior is None
        managed_receipt.unlink(missing_ok=True)
        return True

    def package_commit(account, durable_source, _stage, _source):
        for path, raw, mode in (
            (Path(snapshot_authority["front_authority"]["path"]),
             (durable_source / "plamen.py").read_bytes(), 0o400),
            (package, b'{"schema":"plamen.codex_install.v2","state":"COMMITTED","transaction_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}\n', 0o600),
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw); path.chmod(mode)
        return {"state": "COMMITTED"}

    def package_validate(_account):
        assert b"plamen.codex_install.v2" in package.read_bytes()
        return {
            "state": "EXACT_COMMITTED_PACKAGE_AND_TERMINAL_REPLAYED",
            "transaction_id": "a" * 32,
        }

    def package_rollback(_account, _receipt, prior):
        assert prior["state"] == "ABSENT"
        for path in (
            package, Path(snapshot_authority["front_authority"]["path"]),
        ):
            path.unlink(missing_ok=True)
        return True

    def native_stage(_account, transaction_root, _source, _package_stage):
        marker = transaction_root / "retained-native.stage"
        marker.write_bytes(b"eight signed members\n"); marker.chmod(0o400); staged.append(marker)
        return {
            "schema": T.STAGE_SCHEMA, "kind": "native",
            "transaction_id": transaction_root.name,
            "manifest_sha256": hashlib.sha256(marker.read_bytes()).hexdigest(),
            "artifact_count": 8,
        }

    def native_stage_validate(stage, _source, _package_stage):
        return stage["artifact_count"] == 8

    def native_commit(_account, _stage, _source, _package):
        for path, raw in ((native, b"install\n"), (deployment, b"deployment\n")):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw); path.chmod(0o400)
        return {"state": "COMMITTED"}

    def native_validate(_account, _package):
        assert native.read_bytes() == b"install\n"
        assert deployment.read_bytes() == b"deployment\n"
        return {"state": "EXACT_NATIVE_RECEIPTS_REPLAYED"}

    def native_rollback(_account, _receipts, prior):
        assert prior["state"] == "ABSENT"
        native.unlink(missing_ok=True); deployment.unlink(missing_ok=True)
        return True

    def cleanup(_account, _package_stage, _native_stage):
        for path in staged:
            path.unlink(missing_ok=True)
        return True

    managed_inputs = E.ManagedEVMInstallInputs(
        policy_path=evm_policy, managed_root=managed_root,
        project_root=source, acquisition_receipt_path=acquisition,
        installed_receipt_path=managed_receipt,
        native_runtime_authority=native_runtime_authority,
    )
    effects = E.DarwinColdInstallEffects(
        home=home, package_snapshot=snapshot_authority,
        package_commit=package_commit, package_validate=package_validate,
        package_rollback=package_rollback, native_stage=native_stage,
        native_stage_validate=native_stage_validate, native_commit=native_commit,
        native_validate=native_validate, native_rollback=native_rollback,
        managed_evm_inputs=managed_inputs,
        managed_evm_receipt_publish=managed_evm_receipt_publish,
        managed_evm_receipt_validate=managed_evm_receipt_validate,
        managed_evm_receipt_rollback=managed_evm_receipt_rollback,
        managed_evm_provision=managed_evm_provision,
        managed_evm_require=managed_evm_require,
        cleanup=cleanup,
    )
    return home, source_authority, effects, package, native, deployment


def test_concrete_effects_complete_cold_transaction_and_replay(tmp_path):
    home, source, effects, package, native, deployment = _fixture(tmp_path)
    receipt = T.execute_cold_install_transaction(
        home=home, source_authority=source, effects=effects,
    )
    assert receipt["state"] == "COMMITTED"
    assert package.exists() and native.exists() and deployment.exists()
    assert (home / ".local/bin/plamen").exists()
    assert not effects.managed_evm_receipt_path.exists()
    assert T.execute_cold_install_transaction(
        home=home, source_authority=source, effects=effects,
    ) == receipt


def test_concrete_effects_reject_partial_predecessor(tmp_path):
    home, _source, effects, package, _native, _deployment = _fixture(tmp_path)
    package.parent.mkdir(parents=True); package.write_bytes(b"partial\n"); package.chmod(0o600)
    with pytest.raises(E.PosixNativeInstallEffectsError, match="partial"):
        effects.observe_prior(home)


def test_managed_evm_retained_input_drift_blocks_before_any_commit(tmp_path):
    home, source, effects, package, native, deployment = _fixture(tmp_path)
    T.execute_cold_install_transaction(
        home=home, source_authority=source, effects=effects,
    )
    acquisition = effects.managed_evm_inputs.acquisition_receipt_path
    acquisition.chmod(0o600)
    acquisition.write_bytes(b"different-signed-acquisition\n")
    acquisition.chmod(0o400)
    with pytest.raises(E.PosixNativeInstallEffectsError, match="retained inputs changed"):
        S.execute_managed_evm_setup_transaction(home=home, effects=effects)
    assert package.exists() and native.exists() and deployment.exists()
    assert not effects.managed_evm_receipt_path.exists()


def test_managed_evm_signer_failure_reverses_native_package_and_runtime(tmp_path):
    home, source, effects, package, native, deployment = _fixture(tmp_path)
    T.execute_cold_install_transaction(
        home=home, source_authority=source, effects=effects,
    )

    def fail_signer(*_args):
        raise RuntimeError("MANAGED_EVM_SIGNER_REJECTED")

    effects._operations["managed_evm_receipt_publish"] = fail_signer
    with pytest.raises(RuntimeError, match="MANAGED_EVM_SIGNER_REJECTED"):
        S.execute_managed_evm_setup_transaction(home=home, effects=effects)
    assert package.exists() and native.exists() and deployment.exists()
    assert effects.runtime_root.exists()
    assert not effects.managed_evm_receipt_path.exists()
    assert (home / ".local/bin/plamen").exists()


def test_managed_evm_project_setup_commits_replays_and_exposes_only_opaque(tmp_path):
    home, source, effects, _package, _native, _deployment = _fixture(tmp_path)
    cold = T.execute_cold_install_transaction(
        home=home, source_authority=source, effects=effects,
    )
    assert "managed_evm_generation_receipt" not in cold
    receipt = S.execute_managed_evm_setup_transaction(home=home, effects=effects)
    assert receipt["state"] == "COMMITTED"
    assert receipt["managed_evm_generation_receipt"]["path"] == str(
        effects.managed_evm_receipt_path
    )
    authority = effects.managed_evm_generation_authority()
    assert type(authority).__name__ == "_OpaqueManagedAuthority"
    assert S.execute_managed_evm_setup_transaction(
        home=home, effects=effects,
    ) == receipt


@pytest.mark.parametrize("crash_state", ("STAGED", "COMMITTED"))
def test_managed_evm_project_setup_crash_replays_exact_transaction(
    tmp_path, crash_state,
):
    home, source, effects, _package, _native, _deployment = _fixture(tmp_path)
    T.execute_cold_install_transaction(
        home=home, source_authority=source, effects=effects,
    )

    def fault(state):
        if state == crash_state:
            raise S.TEST_ONLY_ManagedEVMSetupCrash(state)

    with pytest.raises(S.TEST_ONLY_ManagedEVMSetupCrash):
        S.execute_managed_evm_setup_transaction(
            home=home, effects=effects, fault=fault,
        )
    receipt = S.execute_managed_evm_setup_transaction(home=home, effects=effects)
    assert receipt["state"] == "COMMITTED"
    effects.managed_evm_generation_authority()


def test_concrete_effects_require_postcommit_package_rollback_capability(tmp_path):
    home, _source, effects, _package, _native, _deployment = _fixture(tmp_path)
    with pytest.raises(E.PosixNativeInstallEffectsError, match="roster is incomplete"):
        E.DarwinColdInstallEffects(
            home=home, package_snapshot=effects.snapshot,
            package_commit=lambda *_a: {}, package_validate=lambda *_a: {},
            package_rollback=None, native_stage=lambda *_a: {},
            native_stage_validate=lambda *_a: True, native_commit=lambda *_a: {},
            native_validate=lambda *_a: {}, native_rollback=lambda *_a: True,
            managed_evm_inputs=effects.managed_evm_inputs,
            managed_evm_receipt_publish=lambda *_a: {},
            managed_evm_receipt_validate=lambda *_a: object(),
            managed_evm_receipt_rollback=lambda *_a: True,
            managed_evm_provision=lambda *_a, **_k: object(),
            managed_evm_require=lambda *_a: {},
            cleanup=lambda *_a: True,
        )


def test_package_stage_is_durable_after_ephemeral_snapshot_disappears(tmp_path):
    home, source, effects, _package, _native, _deployment = _fixture(tmp_path)
    transaction_id = "b" * 32
    transaction_root = home.joinpath(*T.CONTROL_SUFFIX, transaction_id)
    transaction_root.mkdir(parents=True)
    stage = effects.stage_package(home, transaction_root, source)
    snapshot_root = Path(effects.snapshot["root"])
    for path in sorted(snapshot_root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        path.unlink() if path.is_file() else path.rmdir()
    snapshot_root.rmdir()
    effects.validate_package_stage(stage, source)


def test_native_failure_restores_fresh_package_and_managed_runtime(tmp_path):
    home, source, effects, package, _native, _deployment = _fixture(tmp_path)
    front = Path(effects.snapshot["front_authority"]["path"])
    python = Path(effects.snapshot["interpreter_authority"]["path"])

    def fail_native(*_args):
        raise RuntimeError("NATIVE_COMMIT_REJECTED")

    effects._operations["native_commit"] = fail_native
    with pytest.raises(RuntimeError, match="NATIVE_COMMIT_REJECTED"):
        T.execute_cold_install_transaction(
            home=home, source_authority=source, effects=effects,
        )
    assert not package.exists()
    assert not front.exists()
    assert not python.exists()
    assert not effects.runtime_root.exists()
    assert not (home / ".local/bin/plamen").exists()


def test_same_bytes_third_state_is_not_removed_or_blessed(tmp_path):
    home, source, effects, package, _native, _deployment = _fixture(tmp_path)
    front = Path(effects.snapshot["front_authority"]["path"])
    original = effects._operations["package_commit"]

    def publish_foreign_runtime(account, durable_source, stage, authority):
        result = original(account, durable_source, stage, authority)
        _package, _source, managed, _next = effects._stage_roots(
            stage["transaction_id"],
        )
        effects.runtime_root.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(managed, effects.runtime_root, copy_function=shutil.copy2)
        return result

    effects._operations["package_commit"] = publish_foreign_runtime
    with pytest.raises(E.PosixNativeInstallEffectsError, match="third state"):
        T.execute_cold_install_transaction(
            home=home, source_authority=source, effects=effects,
        )
    assert effects.runtime_root.is_dir()
    E._replay_tree(
        effects.runtime_root, E._rows_for(effects.snapshot, "managed-runtime"),
    )
    assert not package.exists()
    assert not front.exists()
    assert not (home / ".local/bin/plamen").exists()


def test_missing_committed_runtime_blocks_package_predecessor_restore(tmp_path):
    home, source, effects, package, _native, _deployment = _fixture(tmp_path)

    def remove_then_fail(*_args):
        E._remove_exact_tree(
            effects.runtime_root,
            E._rows_for(effects.snapshot, "managed-runtime"),
        )
        raise RuntimeError("NATIVE_REJECTED_AFTER_EXTERNAL_REMOVAL")

    effects._operations["native_commit"] = remove_then_fail
    with pytest.raises(
        T.PosixNativeInstallTransactionError,
        match="managed runtime disappeared",
    ):
        T.execute_cold_install_transaction(
            home=home, source_authority=source, effects=effects,
        )
    # The strict package rollback was not allowed to claim success over the
    # missing runtime generation; its exact successor receipt remains visible
    # for explicit recovery.
    assert package.exists()
