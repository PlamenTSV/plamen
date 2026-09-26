"""Darwin behavioral coverage for the real committed Codex projector."""

import hashlib
import importlib.util
import os
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(sys.platform != "darwin", reason="Darwin installer")


def _load_front():
    spec = importlib.util.spec_from_file_location(
        "plamen_darwin_codex_install", ROOT / "plamen.py"
    )
    module = importlib.util.module_from_spec(spec)
    saved = sys.argv
    sys.argv = ["plamen.py"]
    try:
        spec.loader.exec_module(module)
    finally:
        sys.argv = saved
    return module


def _row(source_path, destination_root, destination_path, raw):
    return {
        "source_path": source_path,
        "install_kind": (
            "runtime" if destination_root == "plamen" else "codex-adapter"
        ),
        "destination_root": destination_root,
        "destination_path": destination_path,
        "destination_key": f"{destination_root}/{destination_path}".casefold(),
        "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def _run_four_row_transaction(monkeypatch, tmp_path, *, failpoint=None):
    front = _load_front()
    source = (tmp_path / "source").absolute()
    runtime = (tmp_path / "runtime").absolute()
    codex = (tmp_path / "codex").absolute()
    for root in (source, runtime, codex):
        root.mkdir()
    (source / "VERSION").write_bytes(b"3.0-test\n")
    (source / "plamen.py").write_bytes(b"projector-test\n")
    specs = (
        ("runtime-a.bin", "plamen", "runtime-a.bin", b"runtime-a\n"),
        ("runtime-b.bin", "plamen", "nested/runtime-b.bin", b"runtime-b\n"),
        (
            "plamen-wizard.md", "codex", "skills/plamen/plamen-wizard.md",
            b"smart-contract wizard\n",
        ),
        (
            "plamen-l1-wizard.md", "codex", "skills/plamen/plamen-l1-wizard.md",
            b"l1 wizard\n",
        ),
    )
    rows = []
    for source_path, destination_root, destination_path, raw in specs:
        (source / source_path).write_bytes(raw)
        rows.append(_row(source_path, destination_root, destination_path, raw))

    prior = {
        "transaction_id": "1" * 32,
        "source_manifest_sha256": "2" * 64,
        "source_root": str(source),
        "plamen_root": str(runtime),
        "codex_root": str(codex),
        "terminal_verification": {
            "verified_count": 0,
            "verified_manifest_sha256": "2" * 64,
            "completed_ns": 1,
            "projection_public_key": "3" * 64,
            "projection_lock_public_key": "3" * 64,
            "projection_lock_authority_sha256": "4" * 64,
        },
    }
    prior_raw = front._borrowed_reader_canonical_bytes(prior)
    receipt_path = codex / front._CODEX_INSTALL_RECEIPT
    receipt_path.write_bytes(prior_raw)

    monkeypatch.setattr(front, "_CODEX_INSTALL_SOURCE_COUNT", 4)
    monkeypatch.setattr(front, "_CODEX_INSTALL_RUNTIME_COUNT", 2)
    monkeypatch.setattr(front, "_CODEX_INSTALL_ADAPTER_COUNT", 2)
    monkeypatch.setattr(
        front, "_toolchain_runtime_required_integrity_issues",
        lambda *_a, **_k: {"missing": [], "mismatched": []},
    )
    monkeypatch.setattr(
        front, "_codex_install_source_rows",
        lambda *_a, **_k: [dict(row) for row in rows],
    )
    monkeypatch.setattr(front, "_validated_committed_install_receipt", lambda: prior)
    monkeypatch.setattr(
        front, "_validated_prior_committed_receipt",
        lambda *_a, **_k: (prior, {}),
    )
    monkeypatch.setattr(
        front, "_claude_projection_private_key",
        lambda **_k: (object(), "3" * 64),
    )
    monkeypatch.setattr(
        front, "_capture_codex_install_batch_boundary", lambda **_k: None,
    )
    monkeypatch.setattr(
        front, "_codex_install_keeper_descriptor",
        lambda **_k: {"pipe_instance_nonce": "5" * 32},
    )
    monkeypatch.setattr(
        front, "_start_codex_install_keeper",
        lambda **_k: {"writer_generation": "test", "process": os.getpid()},
    )
    monkeypatch.setattr(front, "_release_codex_install_keeper", lambda _keeper: None)
    monkeypatch.setattr(front, "_run_codex_install_integrated_smoke", lambda **_k: [])
    monkeypatch.setattr(
        front, "_prepare_codex_install_terminal_evidence",
        lambda **_k: {
            "pointer": {"schema": "plamen.install.terminal.pointer.v1"},
            "reservation": None,
        },
    )
    monkeypatch.setattr(
        front, "_finish_codex_install_terminal_evidence", lambda **_k: {},
    )
    monkeypatch.setattr(
        front, "_validate_codex_install_terminal_evidence", lambda *_a, **_k: None,
    )
    try:
        receipt = front._install_codex_package_transaction(
            source_root=source,
            plamen_root=runtime,
            codex_home=codex,
            failpoint=failpoint,
            enable_claude_projection=False,
        )
    except BaseException:
        receipt = None
        raise
    finally:
        # Expose state to callers even when an injected transition fails.
        _run_four_row_transaction.state = {
            "front": front,
            "source": source,
            "runtime": runtime,
            "codex": codex,
            "receipt_path": receipt_path,
            "prior_raw": prior_raw,
            "rows": rows,
            "receipt": receipt,
        }
    return _run_four_row_transaction.state


def test_darwin_four_row_projector_commits_exact_runtime_and_adapter(monkeypatch, tmp_path):
    state = _run_four_row_transaction(monkeypatch, tmp_path)

    assert state["receipt"]["state"] == "COMMITTED"
    assert (state["runtime"] / "runtime-a.bin").read_bytes() == b"runtime-a\n"
    assert (state["runtime"] / "nested" / "runtime-b.bin").read_bytes() == b"runtime-b\n"
    assert (
        state["codex"] / "skills" / "plamen" / "plamen-wizard.md"
    ).read_bytes() == b"smart-contract wizard\n"
    assert (
        state["codex"] / "skills" / "plamen" / "plamen-l1-wizard.md"
    ).read_bytes() == b"l1 wizard\n"
    runtime_link = state["codex"] / "plamen"
    assert runtime_link.is_symlink()
    assert os.readlink(runtime_link) == str(state["runtime"])
    assert state["receipt"]["created_junction"] is True
    assert state["receipt"]["junction_identity"]["target"] == str(
        state["runtime"]
    )
    assert state["front"]._strict_json_bytes(
        state["receipt_path"].read_bytes()
    ) == state["receipt"]
    assert state["front"]._codex_install_doctor_issues(
        state["codex"], state["runtime"],
    ) == []


@pytest.mark.parametrize("row_index", (0, 1, 2, 3))
def test_darwin_four_row_projector_compensates_each_live_boundary(
    monkeypatch, tmp_path, row_index,
):
    fired = False

    def failpoint(name, ordinal):
        nonlocal fired
        if not fired and name == "after_live_row" and ordinal == row_index:
            fired = True
            raise RuntimeError("DARWIN_PROJECTOR_FAILPOINT")

    with pytest.raises(RuntimeError, match="DARWIN_PROJECTOR_FAILPOINT"):
        _run_four_row_transaction(monkeypatch, tmp_path, failpoint=failpoint)
    state = _run_four_row_transaction.state
    assert fired
    assert state["receipt_path"].read_bytes() == state["prior_raw"]
    assert not (state["runtime"] / "runtime-a.bin").exists()
    assert not (state["runtime"] / "nested" / "runtime-b.bin").exists()
    assert not (
        state["codex"] / "skills" / "plamen" / "plamen-wizard.md"
    ).exists()
    assert not (
        state["codex"] / "skills" / "plamen" / "plamen-l1-wizard.md"
    ).exists()


def test_darwin_projector_after_commit_compensation_removes_runtime_link(
    monkeypatch, tmp_path,
):
    def failpoint(name, _ordinal):
        if name == "after_committed":
            raise RuntimeError("DARWIN_AFTER_COMMITTED_FAILPOINT")

    with pytest.raises(RuntimeError, match="DARWIN_AFTER_COMMITTED_FAILPOINT"):
        _run_four_row_transaction(monkeypatch, tmp_path, failpoint=failpoint)
    state = _run_four_row_transaction.state
    assert state["receipt_path"].read_bytes() == state["prior_raw"]
    assert not os.path.lexists(state["codex"] / "plamen")
    assert not (state["runtime"] / "runtime-a.bin").exists()
    assert not (state["runtime"] / "nested" / "runtime-b.bin").exists()


def _postcommit_authorities(state):
    front = state["front"]
    current_raw = state["receipt_path"].read_bytes()
    current = front._strict_json_bytes(current_raw)
    successor = {
        "schema": "plamen.posix-native-install.artifact.v1",
        "kind": "package-receipt", "path": str(state["receipt_path"]),
        "size": len(current_raw),
        "sha256": hashlib.sha256(current_raw).hexdigest(),
        "transaction_id": current["transaction_id"],
    }
    prior_value = front._strict_json_bytes(state["prior_raw"])
    predecessor = {
        "schema": "plamen.posix-native-install.artifact.v1",
        "kind": "package-receipt", "path": str(state["receipt_path"]),
        "size": len(state["prior_raw"]),
        "sha256": hashlib.sha256(state["prior_raw"]).hexdigest(),
        "transaction_id": prior_value["transaction_id"],
    }
    inert = {
        "schema": "plamen.posix-native-install.artifact.v1",
        "kind": "native-install-receipt", "path": str(state["runtime"] / "inert"),
        "size": 1, "sha256": "9" * 64,
    }
    prior = {
        "schema": "plamen.posix-native-install.prior.v1",
        "state": "VERIFIED", "package_receipt": predecessor,
        "native_install_receipt": inert,
        "deployment_receipt": {**inert, "kind": "deployment-receipt"},
        "public_launcher": {"authenticated": True},
    }
    return successor, prior


def test_postcommit_package_rollback_restores_exact_prior_and_is_idempotent(
    monkeypatch, tmp_path,
):
    state = _run_four_row_transaction(monkeypatch, tmp_path)
    successor, prior = _postcommit_authorities(state)
    front = state["front"]

    assert front._rollback_committed_codex_package_transaction(
        successor, prior, codex_home=state["codex"],
        plamen_root=state["runtime"],
    ) is True
    assert state["receipt_path"].read_bytes() == state["prior_raw"]
    assert not os.path.lexists(state["codex"] / "plamen")
    assert not (state["runtime"] / "runtime-a.bin").exists()
    assert not (state["runtime"] / "nested/runtime-b.bin").exists()
    assert not (state["codex"] / "skills/plamen/plamen-wizard.md").exists()
    assert not (state["codex"] / "skills/plamen/plamen-l1-wizard.md").exists()

    assert front._rollback_committed_codex_package_transaction(
        successor, prior, codex_home=state["codex"],
        plamen_root=state["runtime"],
    ) is True


def test_postcommit_package_rollback_rejects_third_state_before_any_mutation(
    monkeypatch, tmp_path,
):
    state = _run_four_row_transaction(monkeypatch, tmp_path)
    successor, prior = _postcommit_authorities(state)
    drifted = state["runtime"] / "nested/runtime-b.bin"
    drifted.chmod(0o600); drifted.write_bytes(b"foreign third state\n")
    before = {
        path: path.read_bytes()
        for path in (
            state["receipt_path"], state["runtime"] / "runtime-a.bin",
            drifted, state["codex"] / "skills/plamen/plamen-wizard.md",
            state["codex"] / "skills/plamen/plamen-l1-wizard.md",
        )
    }
    with pytest.raises(RuntimeError, match="foreign destination authority"):
        state["front"]._rollback_committed_codex_package_transaction(
            successor, prior, codex_home=state["codex"],
            plamen_root=state["runtime"],
        )
    assert {path: path.read_bytes() for path in before} == before
    assert os.path.lexists(state["codex"] / "plamen")


def test_postcommit_package_rollback_recovers_after_row_boundary(
    monkeypatch, tmp_path,
):
    state = _run_four_row_transaction(monkeypatch, tmp_path)
    successor, prior = _postcommit_authorities(state)
    fired = False

    def failpoint(name, ordinal):
        nonlocal fired
        if not fired and name == "after_postcommit_rollback_row" and ordinal == 2:
            fired = True
            raise RuntimeError("POSTCOMMIT_ROLLBACK_CRASH")

    with pytest.raises(RuntimeError, match="POSTCOMMIT_ROLLBACK_CRASH"):
        state["front"]._rollback_committed_codex_package_transaction(
            successor, prior, codex_home=state["codex"],
            plamen_root=state["runtime"], failpoint=failpoint,
        )
    assert fired
    assert state["front"]._rollback_committed_codex_package_transaction(
        successor, prior, codex_home=state["codex"],
        plamen_root=state["runtime"],
    ) is True
    assert state["receipt_path"].read_bytes() == state["prior_raw"]
