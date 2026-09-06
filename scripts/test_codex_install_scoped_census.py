"""Regression tests for the live Codex install namespace boundary."""

import importlib.util
import hashlib
import json
import os
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _load_front():
    spec = importlib.util.spec_from_file_location(
        "plamen_scoped_census_front", ROOT / "plamen.py"
    )
    module = importlib.util.module_from_spec(spec)
    saved = sys.argv
    sys.argv = ["plamen.py"]
    try:
        spec.loader.exec_module(module)
    finally:
        sys.argv = saved
    return module


def test_absent_receipt_accepts_fresh_or_authenticated_legacy_runtime_only():
    front = _load_front()

    assert front._codex_install_absent_receipt_authorized(
        legacy_owned=False, root_names=()
    )
    assert front._codex_install_absent_receipt_authorized(
        legacy_owned=True, root_names=("VERSION", "scripts")
    )
    assert not front._codex_install_absent_receipt_authorized(
        legacy_owned=False, root_names=("foreign-file",)
    )


def test_historical_sentinel_capture_discards_rows_but_keeps_fold_authority():
    front = _load_front()
    capture = {
        "label": "PRE_STAGE",
        "a_count": 1,
        "a_rows": ["large-a-row"],
        "a_sha256": "a" * 64,
        "b_count": 1,
        "b_rows": ["large-b-row"],
        "b_sha256": "b" * 64,
        "c_count": 1,
        "c_rows": ["large-c-row"],
        "c_sha256": "c" * 64,
        "event_count": 4,
        "event_sha256": "d" * 64,
        "unknown_count": 0,
    }

    summary = front._codex_install_capture_summary(capture)

    assert all(name not in summary for name in ("a_rows", "b_rows", "c_rows"))
    assert summary["a_count"] == summary["b_count"] == summary["c_count"] == 1
    assert summary["a_sha256"] == "a" * 64
    assert summary["event_sha256"] == "d" * 64
    assert capture["a_rows"] == ["large-a-row"]


def test_current_source_roster_excludes_generated_bytecode_and_is_exact():
    front = _load_front()
    closure = json.loads(
        (ROOT / "verification_policy/toolchain_runtime_closure.v1.json").read_text(
            encoding="utf-8"
        )
    )
    runtime_paths = {
        "verification_policy/toolchain_runtime_closure.v1.json",
        "verification_policy/__init__.py",
        "verification_policy/methodology_reachability.v1.json",
        "verification_policy/verification_method_registry.v1.json",
        *front._CODEX_INSTALL_TOP_LEVEL,
        *front._CODEX_INSTALL_MCP_FILES,
        *(row["path"] for row in closure["assets"]),
    }
    exact_files = set(runtime_paths) | {"codex-adapter/AGENTS.md"}
    tree_roots = list(front._CODEX_INSTALL_METHOD_ROOTS) + [
        "codex-adapter/" + root for root in front._CODEX_INSTALL_ADAPTER_ROOTS
    ]
    snapshot, _authority = front._codex_install_source_snapshot(
        ROOT, exact_files=exact_files, tree_roots=tree_roots,
    )
    for root_name in front._CODEX_INSTALL_METHOD_ROOTS:
        prefix = root_name + "/"
        runtime_paths.update(path for path in snapshot if path.startswith(prefix))
    adapter_paths = {"AGENTS.md"}
    for root_name in front._CODEX_INSTALL_ADAPTER_ROOTS:
        prefix = "codex-adapter/" + root_name + "/"
        adapter_paths.update(
            path[len("codex-adapter/"):] for path in snapshot if path.startswith(prefix)
        )
    source_paths = [
        *sorted(runtime_paths),
        *("codex-adapter/" + path for path in sorted(adapter_paths)),
    ]

    assert len(closure["assets"]) == 295
    assert len(source_paths) == front._CODEX_INSTALL_SOURCE_COUNT == 764
    assert len(runtime_paths) == front._CODEX_INSTALL_RUNTIME_COUNT == 733
    assert len(adapter_paths) == front._CODEX_INSTALL_ADAPTER_COUNT == 31
    assert source_paths.count("scripts/claude_worker_prompt_consistency.py") == 1
    assert source_paths.count("scripts/windows_private_execution_root.py") == 1
    assert source_paths.count("scripts/late_committed_invariant_authority.py") == 1
    assert not any(
        "__pycache__" in {component.casefold() for component in path.split("/")}
        or path.casefold().endswith(".pyc")
        for path in source_paths
    )


def test_bootstrap_recovery_requires_complete_plan_and_zero_live_journal(tmp_path):
    front = _load_front()
    transaction_id = "1" * 32
    codex_home = (tmp_path / "codex").absolute()
    plamen_home = (tmp_path / "plamen").absolute()
    rows = [
        {
            "source_path": f"source/{index:03d}.bin",
            "destination_root": "plamen",
            "destination_path": f"runtime/{index:03d}.bin",
            "size": index,
            "sha256": f"{index:064x}",
        }
        for index in range(front._CODEX_INSTALL_SOURCE_COUNT)
    ]
    descriptor = {
        "schema": "plamen.codex_install.receipt_prestate.v1",
        "transaction_id": transaction_id,
        "state": "PRESENT",
        "lock_identity": [7, 11],
    }
    inverse = {
        "transaction_id": transaction_id,
        "receipt_prestate": descriptor,
        "source_rows": rows,
        "rows": [],
    }
    inverse_raw = front._borrowed_reader_canonical_bytes(inverse)
    current = {
        "schema": front._CODEX_INSTALL_SCHEMA,
        "transaction_id": transaction_id,
        "state": "PREPARING",
        "source_count": front._CODEX_INSTALL_SOURCE_COUNT,
        "source_manifest_sha256": front._raw_rows_sha256(rows),
        "created_junction": False,
        "terminal_evidence": None,
        "rows": rows[:17],
        "journal": [],
        "codex_root": str(codex_home),
        "plamen_root": str(plamen_home),
        "transaction_root": str(
            codex_home / ".plamen-install-transactions" / transaction_id
        ),
        "inverse_sha256": hashlib.sha256(inverse_raw).hexdigest(),
    }

    plan = front._codex_install_bootstrap_recovery_plan(
        transaction_id=transaction_id,
        codex_home=codex_home,
        current=current,
        inverse=inverse,
        descriptor=descriptor,
        inverse_raw=inverse_raw,
        writer_identity={"volume": 7, "file_id": 11},
    )

    assert plan["source_rows"] == rows
    assert plan["plamen_root"] == plamen_home
    rolling_back = dict(current)
    rolling_back["state"] = "ROLLING_BACK"
    assert front._codex_install_bootstrap_recovery_plan(
        transaction_id=transaction_id,
        codex_home=codex_home,
        current=rolling_back,
        inverse=inverse,
        descriptor=descriptor,
        inverse_raw=inverse_raw,
        writer_identity={"volume": 7, "file_id": 11},
    )["source_rows"] == rows
    for numeric_alias in (float(front._CODEX_INSTALL_SOURCE_COUNT), True):
        aliased = dict(current)
        aliased["source_count"] = numeric_alias
        with pytest.raises(RuntimeError, match="bootstrap recovery authority"):
            front._codex_install_bootstrap_recovery_plan(
                transaction_id=transaction_id,
                codex_home=codex_home,
                current=aliased,
                inverse=inverse,
                descriptor=descriptor,
                inverse_raw=inverse_raw,
                writer_identity={"volume": 7, "file_id": 11},
            )
    poisoned = dict(current)
    poisoned["journal"] = [{"destination": "live"}]
    with pytest.raises(RuntimeError, match="bootstrap recovery authority"):
        front._codex_install_bootstrap_recovery_plan(
            transaction_id=transaction_id,
            codex_home=codex_home,
            current=poisoned,
            inverse=inverse,
            descriptor=descriptor,
            inverse_raw=inverse_raw,
            writer_identity={"volume": 7, "file_id": 11},
        )


def test_missing_prekeeper_archive_routes_to_bootstrap_recovery(tmp_path, monkeypatch):
    front = _load_front()
    transaction_id = "2" * 32
    transaction_components = (".plamen-install-transactions", transaction_id)
    codex_home = (tmp_path / "codex").absolute()
    writer = object()
    closed = []
    calls = []

    def committed_read(_root, components, *, directory=False, **_kwargs):
        components = tuple(components)
        if components == transaction_components and directory:
            return {"kind": "directory"}, ()
        raise FileNotFoundError(2, "synthetic missing bootstrap artifact")

    monkeypatch.setattr(front, "_codex_install_committed_read", committed_read)
    monkeypatch.setattr(
        front,
        "_open_install_admission_anchor",
        lambda *_args, **_kwargs: (
            codex_home / front._CODEX_INSTALL_ANCHOR,
            writer,
            lambda: closed.append(True),
        ),
    )

    def bootstrap_recovery(**kwargs):
        calls.append(kwargs)
        return {"state": "RECOVERED_BOOTSTRAP"}

    monkeypatch.setattr(
        front, "_recover_codex_bootstrap_transaction", bootstrap_recovery
    )

    result = front._recover_codex_package_transaction(
        transaction_id, codex_home=codex_home
    )

    assert result == {"state": "RECOVERED_BOOTSTRAP"}
    assert calls == [
        {
            "transaction_id": transaction_id,
            "codex_home": codex_home,
            "writer_handle": writer,
            "writer_generation": "recovery:" + transaction_id,
        }
    ]
    assert closed == [True]


@pytest.mark.skipif(os.name != "nt", reason="native install dispatcher is Windows-only")
def test_census_ignores_unrelated_codex_root_but_protects_managed_adjacency(
    tmp_path, monkeypatch,
):
    front = _load_front()
    codex_root = (tmp_path / "codex").absolute()
    plamen_root = (tmp_path / "plamen").absolute()
    codex_root.mkdir()
    plamen_root.mkdir()
    (codex_root / "skills" / "plamen").mkdir(parents=True)
    (codex_root / "skills" / "plamen" / "SKILL.md").write_text(
        "managed", encoding="utf-8"
    )
    (codex_root / "skills" / "foreign-sibling.txt").write_text(
        "preserve me", encoding="utf-8"
    )
    (codex_root / "skills" / ".system").mkdir()
    (codex_root / "skills" / ".system" / "host-cache.json").write_text(
        "volatile host state", encoding="utf-8"
    )
    (codex_root / "logs_2.sqlite").write_text(
        "active Codex state", encoding="utf-8"
    )
    anchor_path = codex_root / front._CODEX_INSTALL_ANCHOR
    anchor_path.write_bytes(b"anchor")

    codex_handle = plamen_handle = writer_handle = None
    codex_close = plamen_close = None
    try:
        codex_handle, codex_close = front._codex_dispatcher_open_root(
            codex_root, full_mutation=False
        )
        plamen_handle, plamen_close = front._codex_dispatcher_open_root(
            plamen_root, full_mutation=False
        )
        writer_handle = front._codex_native_open_relative(
            codex_handle,
            front._CODEX_INSTALL_ANCHOR,
            directory=False,
            create=False,
            access=0x80000000 | 0x00000080 | 0x00100000,
            share_delete=False,
        )
        dispatcher = front._CodexInstallMutationDispatcher.__new__(
            front._CodexInstallMutationDispatcher
        )
        dispatcher.codex_home = codex_root
        dispatcher.plamen_root = plamen_root
        dispatcher.writer_handle = writer_handle
        dispatcher.anchor_identity = front._borrowed_reader_handle_identity(
            writer_handle
        )
        dispatcher._root_handles = {
            str(codex_root): (codex_handle, codex_close),
            str(plamen_root): (plamen_handle, plamen_close),
        }
        dispatcher._root_identity = {
            str(codex_root): {
                "handle": front._borrowed_reader_handle_identity(codex_handle)
            },
            str(plamen_root): {
                "handle": front._borrowed_reader_handle_identity(plamen_handle)
            },
        }
        dispatcher._operation_policy = {
            ("codex", ("skills",)): {"MKDIR"},
            ("codex", ("skills", "plamen")): {"MKDIR"},
            ("codex", ("skills", "plamen", "SKILL.md")): {
                "REPLACE_DESTINATION"
            },
        }
        dispatcher._native_descriptor_cache = {}

        original = front._CodexInstallMutationDispatcher._native_handle_descriptor
        native_sha256 = front._codex_native_sha256
        hash_calls = []

        def counted_sha256(handle, **kwargs):
            hash_calls.append(front._codex_native_final_name(handle))
            return native_sha256(handle, **kwargs)

        monkeypatch.setattr(front, "_codex_native_sha256", counted_sha256)

        def guarded_descriptor(handle, **kwargs):
            name = front._codex_native_final_name(handle).rstrip("\\/").rsplit(
                "\\", 1
            )[-1]
            if name == "logs_2.sqlite":
                raise AssertionError("unrelated Codex database entered install census")
            return original(handle, **kwargs)

        monkeypatch.setattr(
            front._CodexInstallMutationDispatcher,
            "_native_handle_descriptor",
            staticmethod(guarded_descriptor),
        )
        census = dispatcher._native_census("codex")

        assert ("codex", ("logs_2.sqlite",)) not in census
        assert ("codex", ("skills", ".system")) not in census
        assert ("codex", ("skills",)) in census
        assert ("codex", ("skills", "foreign-sibling.txt")) in census
        assert ("codex", ("skills", "plamen", "SKILL.md")) in census
        assert ("codex", (front._CODEX_INSTALL_ANCHOR,)) in census
        assert census[("codex", ("skills", "plamen", "SKILL.md"))][
            "sha256"
        ] == hashlib.sha256(b"managed").hexdigest()
        first_hash_count = len(hash_calls)
        repeated = dispatcher._native_census("codex")
        assert repeated == census
        assert len(hash_calls) == first_hash_count

        (codex_root / "skills" / ".system" / "host-refresh.json").write_text(
            "new volatile host state", encoding="utf-8"
        )
        assert dispatcher._native_census("codex") == census

        (codex_root / "skills" / "plamen" / "SKILL.md").write_text(
            "mutated", encoding="utf-8"
        )
        changed = dispatcher._native_census("codex")
        assert len(hash_calls) > first_hash_count
        assert changed[("codex", ("skills", "plamen", "SKILL.md"))][
            "sha256"
        ] == hashlib.sha256(b"mutated").hexdigest()
    finally:
        if writer_handle is not None:
            front._codex_native_close(writer_handle)
        if codex_close is not None:
            codex_close()
        if plamen_close is not None:
            plamen_close()
