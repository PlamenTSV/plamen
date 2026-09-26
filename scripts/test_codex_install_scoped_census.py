"""Regression tests for the live Codex install namespace boundary."""

import importlib.util
import hashlib
import json
import os
from pathlib import Path
import sys

import pytest

import opengrep_rule_authority as rule_authority


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
        "verification_policy/js_toolchain_acquisition.v1.json",
        "verification_policy/methodology_reachability.v1.json",
        "verification_policy/verification_method_registry.v1.json",
        *front._CODEX_INSTALL_TOP_LEVEL,
        *front._CODEX_INSTALL_MCP_FILES,
        *(row["path"] for row in closure["assets"]),
    }
    rule_roster = rule_authority.source_rule_projection_roster(
        ROOT / "opengrep-rules"
    )
    exact_files = set(runtime_paths) | {"codex-adapter/AGENTS.md"}
    exact_files.update("opengrep-rules/" + path for path in rule_roster)
    tree_roots = [
        root for root in front._CODEX_INSTALL_METHOD_ROOTS
        if root != "opengrep-rules"
    ] + [
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

    assert all(
        os.path.lexists(ROOT / "opengrep-rules" / name / ".git")
        for name in rule_authority.OPENGREP_RULE_SOURCES
    )
    assert len(closure["assets"]) == front._CODEX_INSTALL_CLOSURE_ASSET_COUNT == 492
    assert len(rule_roster) == 226
    assert len(source_paths) == front._CODEX_INSTALL_SOURCE_COUNT == 1189
    assert len(runtime_paths) == front._CODEX_INSTALL_RUNTIME_COUNT == 1158
    assert len(adapter_paths) == front._CODEX_INSTALL_ADAPTER_COUNT == 31
    assert "scripts/headless_phase_identity.py" in runtime_paths
    assert source_paths.count("scripts/claude_worker_prompt_consistency.py") == 1
    assert source_paths.count("scripts/windows_private_execution_root.py") == 1
    assert source_paths.count("scripts/late_committed_invariant_authority.py") == 1
    for prefix in (
        "custom-mcp/farofino-mcp/farofino_mcp/",
        "custom-mcp/slither-mcp/slither_mcp/",
        "custom-mcp/solana-fender/solana_fender_mcp/",
        "custom-mcp/unified-vuln-db/unified_vuln/",
    ):
        assert any(path.startswith(prefix) for path in runtime_paths)
    installed_rule_paths = {
        path.removeprefix("opengrep-rules/")
        for path in runtime_paths if path.startswith("opengrep-rules/")
    }
    assert installed_rule_paths == set(rule_roster)
    assert "opengrep-rules/solidity/security/proxy-storage-collision.yaml" in rule_roster
    assert "decurity-rules/solidity/security/proxy-storage-collision.yaml" in rule_roster
    assert "aptos-move-rules/rules/move_on_aptos/lang/security/signer-leak.yaml" in rule_roster
    assert "opengrep-rules/python/lang/security/audit/eval-detected.yaml" not in rule_roster
    assert "opengrep-rules/README.md" not in rule_roster
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


def test_snapshot_parent_chain_separates_census_and_mutation_rights(monkeypatch):
    """Read census must never ask an intermediate directory for write rights."""
    front = _load_front()
    dispatcher = front._CodexInstallMutationDispatcher.__new__(
        front._CodexInstallMutationDispatcher
    )
    root = Path("C:/synthetic-retained-root")
    dispatcher._root_handles = {str(root): (100, lambda: None)}
    opened = []

    def identity(handle):
        return {
            "volume": 7, "file_id": int(handle), "attributes": 0x10,
            "reparse_tag": 0,
        }

    def open_relative(parent, component, **kwargs):
        opened.append((parent, component, kwargs))
        return 101 + len(opened)

    monkeypatch.setattr(front, "_borrowed_reader_handle_identity", identity)
    monkeypatch.setattr(front, "_codex_native_open_relative", open_relative)
    monkeypatch.setattr(
        front, "_codex_native_exact_component",
        lambda handle, _component: identity(handle),
    )
    monkeypatch.setattr(front, "_codex_native_close", lambda _handle: None)

    _parent, read_handles, _identities = dispatcher._native_parent_chain(
        root, ("agents", "recon.toml"), mutation=False,
    )
    dispatcher._close_native_chain(read_handles)
    _parent, mutation_handles, _identities = dispatcher._native_parent_chain(
        root, ("agents", "recon.toml"), mutation=True,
    )
    dispatcher._close_native_chain(mutation_handles)

    read_access = opened[0][2]["access"]
    mutation_access = opened[1][2]["access"]
    assert read_access == 0x00000001 | 0x00000020 | 0x00000080 | 0x00100000
    assert read_access & (0x00000002 | 0x00000004 | 0x00000040) == 0
    assert mutation_access & (0x00000002 | 0x00000004 | 0x00000040) == (
        0x00000002 | 0x00000004 | 0x00000040
    )


@pytest.mark.skipif(os.name != "nt", reason="native install dispatcher is Windows-only")
def test_read_parent_chain_blocks_swap_and_rejects_reparse(
    tmp_path, monkeypatch,
):
    front = _load_front()
    source_root = (tmp_path / "source").absolute()
    agents = source_root / "agents"
    outside = (tmp_path / "outside").absolute()
    agents.mkdir(parents=True)
    outside.mkdir()
    (agents / "worker.toml").write_bytes(b"trusted")
    (outside / "worker.toml").write_bytes(b"external")
    linked = source_root / "linked"
    try:
        os.symlink(outside, linked, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlinks unavailable: {exc}")

    root_handle = None
    root_close = None
    opened = []
    dispatcher = front._CodexInstallMutationDispatcher.__new__(
        front._CodexInstallMutationDispatcher
    )
    try:
        root_handle, root_close = front._codex_dispatcher_open_root(
            source_root, full_mutation=False,
        )
        dispatcher._root_handles = {str(source_root): (root_handle, root_close)}
        dispatcher._root_identity = {
            str(source_root): {
                "handle": front._borrowed_reader_handle_identity(root_handle)
            }
        }
        native_open = front._codex_native_open_relative
        swap_errors = []

        def attempt_swap(parent, component, **kwargs):
            handle = native_open(parent, component, **kwargs)
            if component == "agents":
                try:
                    os.replace(agents, source_root / "agents-displaced")
                except OSError as exc:
                    swap_errors.append(exc)
                else:  # pragma: no cover - would be a security regression
                    raise AssertionError("retained no-delete-share parent was displaced")
            return handle

        monkeypatch.setattr(front, "_codex_native_open_relative", attempt_swap)
        _parent, opened, identities = dispatcher._native_parent_chain(
            source_root, ("agents", "worker.toml"), mutation=False,
        )
        assert len(identities) == 1
        assert swap_errors
        dispatcher._close_native_chain(opened)
        opened = []

        with pytest.raises(RuntimeError, match="reparse/invalid component"):
            dispatcher._native_parent_chain(
                source_root, ("linked", "worker.toml"), mutation=False,
            )
        assert (agents / "worker.toml").read_bytes() == b"trusted"
        assert (outside / "worker.toml").read_bytes() == b"external"
        assert linked.is_symlink()
    finally:
        if opened:
            dispatcher._close_native_chain(opened)
        if root_close is not None:
            root_close()


@pytest.mark.skipif(os.name != "nt", reason="native install census is Windows-only")
def test_fresh_secondary_volume_agents_survives_isolated_census_child(tmp_path):
    """Exercise the exact D-volume/fresh-clone census path that regressed."""
    front = _load_front()
    configured_source = os.environ.get("PLAMEN_TEST_SECONDARY_SOURCE")
    if not configured_source:
        pytest.skip("no explicitly configured secondary-volume source fixture")
    source_root = Path(configured_source).absolute()
    if not (source_root / "agents").is_dir():
        pytest.skip("no secondary-volume Plamen source fixture")
    if source_root.drive.casefold() == ROOT.drive.casefold():
        pytest.skip("secondary-volume source fixture is not on another volume")

    codex_root = (tmp_path / "codex").absolute()
    plamen_root = (tmp_path / "plamen").absolute()
    codex_root.mkdir()
    plamen_root.mkdir()
    anchor = codex_root / front._CODEX_INSTALL_ANCHOR
    anchor.write_bytes(b"isolated-census-writer")
    source_rows = front._codex_install_source_rows(source_root)

    root_handle = writer_handle = None
    root_close = None
    dispatcher = None
    try:
        root_handle, root_close = front._codex_dispatcher_open_root(
            codex_root, full_mutation=True,
        )
        writer_handle = front._codex_native_open_relative(
            root_handle, anchor.name, directory=False, create=False,
            access=0x80000000 | 0x40000000 | 0x00000080 | 0x00100000,
            share_delete=False,
        )
        root_close()
        root_close = None
        dispatcher = front._CodexInstallMutationDispatcher(
            front._CODEX_INSTALL_CONTEXT_AUTHORITY,
            transaction_id="9" * 32,
            writer_generation="secondary-volume-regression",
            writer_handle=writer_handle,
            source_root=source_root,
            plamen_root=plamen_root,
            codex_home=codex_root,
            source_rows=source_rows,
        )
        capture = front._capture_codex_install_sentinel_isolated(
            dispatcher=dispatcher,
            source_rows=source_rows,
            transaction_components=(".plamen-install-transactions", "9" * 32),
            label="PRE_STAGE",
            include_rows=False,
        )
        assert capture["unknown_count"] == 0
        assert capture["b_count"] >= len(dispatcher._stable_b_keys)
        agents = dispatcher._current(
            dispatcher.address("source", ("agents",))
        )
        assert agents["kind"] == "directory"
        assert agents["reparse_tag"] == 0
    finally:
        if dispatcher is not None and not dispatcher.closed:
            dispatcher.close()
        if writer_handle is not None:
            front._codex_native_close(writer_handle)
        if root_close is not None:
            root_close()


def test_retained_directory_identity_uses_only_immutable_object_fields():
    front = _load_front()
    expected = {
        "volume": 11, "file_id": 22, "attributes": 0x10,
        "reparse_tag": 0, "links": 1, "size": 0,
    }
    ci_duplicate = dict(
        expected, attributes=0x10 | 0x1 | 0x20, links=7, size=4096,
    )

    assert front._borrowed_retained_directory_identity_drift(
        expected, ci_duplicate,
    ) == ()
    for field, value, label in (
        ("volume", 12, "volume"),
        ("file_id", 23, "file_id"),
        ("attributes", 0, "object_class"),
        ("attributes", 0x10 | 0x400, "object_class"),
        ("reparse_tag", 0xA0000003, "reparse_tag"),
    ):
        observed = dict(ci_duplicate, **{field: value})
        assert label in front._borrowed_retained_directory_identity_drift(
            expected, observed,
        )
    assert front._borrowed_retained_directory_identity_drift(
        expected, {**ci_duplicate, "file_id": True},
    ) == ("observed_scalar",)
    malformed = dict(ci_duplicate)
    malformed.pop("size")
    assert front._borrowed_retained_directory_identity_drift(
        expected, malformed,
    ) == ("field_set",)


def test_census_child_accepts_ci_duplicate_metadata_but_rejects_object_drift(
    monkeypatch,
):
    front = _load_front()
    identities = {}
    roots = []
    for ordinal, typed_root in enumerate(("codex", "plamen", "source"), 1):
        expected = {
            "volume": 41, "file_id": ordinal, "attributes": 0x10,
            "reparse_tag": 0, "links": 1, "size": 0,
        }
        handle = 100 + ordinal
        roots.append({
            "typed_root": typed_root,
            "path": f"C:/retained/{typed_root}",
            "handle": handle,
            "identity": expected,
        })
        identities[handle] = dict(
            expected, attributes=0x10 | 0x20, links=3, size=8192,
        )
    writer_identity = {
        "volume": 41, "file_id": 50, "attributes": 0,
        "reparse_tag": 0, "links": 1, "size": 1,
    }
    identities[150] = writer_identity
    state = {
        "schema": front._CODEX_INSTALL_CENSUS_SCHEMA,
        "nonce": "1" * 32,
        "label": "PRE_STAGE",
        "include_rows": False,
        "transaction_id": "2" * 32,
        "writer_generation": "ci-runner",
        "writer_handle": 150,
        "writer_identity": writer_identity,
        "installer_pid": 7,
        "installer_started_100ns": 8,
        "installer_parent_pid": 6,
        "started_ns": 9,
        "roots": roots,
        "operation_policy": [],
        "stable_b_keys": [],
        "foreign_b_baseline": [],
        "events": [],
        "volatile": [],
        "volatile_observations": {},
        "volatile_manifest_sha256": "3" * 64,
        "volatile_capability_secret": "4" * 64,
        "interpreter_handle": 160,
        "interpreter_identity": {"kind": "file", "sha256": "5" * 64},
        "script_handle": 170,
        "script_identity": {"kind": "file", "sha256": "6" * 64},
    }
    monkeypatch.setattr(
        front, "_borrowed_reader_handle_identity", lambda handle: identities[handle],
    )
    monkeypatch.setattr(
        front._CodexInstallMutationDispatcher,
        "_native_handle_descriptor",
        staticmethod(lambda _handle, **_kwargs: state["script_identity"]),
    )

    dispatcher = front._codex_install_census_dispatcher_from_state(state)
    assert dispatcher.source_root == Path("C:/retained/source").absolute()

    identities[103] = dict(identities[103], file_id=999)
    with pytest.raises(RuntimeError, match="source root differs: file_id"):
        front._codex_install_census_dispatcher_from_state(state)


def test_old_backend_shim_requires_exact_authenticated_retained_generation(
    tmp_path, monkeypatch,
):
    front = _load_front()
    plamen_root = (tmp_path / "plamen").absolute()
    plamen_root.mkdir()
    (plamen_root / "plamen.py").write_bytes(b"# installed\n")
    store_root = (tmp_path / "mcp-runtime").absolute()
    request = "a" * 64
    selection = {
        "store_root": str(store_root),
        "generation_id": "npm-" + request,
        "receipt_sha256": "b" * 64,
        "census_sha256": "c" * 64,
        "request_sha256": request,
        "generation_policy_sha256": "d" * 64,
        "backend_launches": {"claude": {}},
    }
    raw = front._backend_shim_bytes(
        "claude", plamen_root, sys.executable, selection=selection,
    )
    calls = []

    class Runtime:
        @staticmethod
        def validate_generation_authority_fast(root, generation_id, **kwargs):
            authority = (
                str(Path(root).absolute()), generation_id,
                kwargs["expected_receipt_sha256"],
                kwargs["expected_census_sha256"],
                kwargs["expected_request_sha256"],
                kwargs["expected_generation_policy_sha256"],
            )
            calls.append(authority)
            if authority != (
                str(store_root), "npm-" + request, "b" * 64,
                "c" * 64, request, "d" * 64,
            ):
                raise RuntimeError("unknown retained generation")

    monkeypatch.setattr(
        front, "_validated_committed_install_receipt",
        lambda: {"plamen_root": str(plamen_root)},
    )
    monkeypatch.setattr(
        front, "_mcp_receipt_callbacks",
        lambda _receipt: (None, object(), "e" * 64, "f" * 64),
    )
    monkeypatch.setattr(front, "_mcp_runtime_module", lambda _root: Runtime())

    assert front._authenticated_retained_backend_shim(
        raw, backend="claude", plamen_root=plamen_root,
        interpreter=sys.executable, store_root=store_root,
    )
    assert len(calls) == 1

    unknown = raw.replace(("npm-" + request).encode(), ("npm-" + "9" * 64).encode())
    unknown = unknown.replace(
        f'"--request-sha256" "{request}"'.encode(),
        f'"--request-sha256" "{"9" * 64}"'.encode(),
    )
    assert not front._authenticated_retained_backend_shim(
        unknown, backend="claude", plamen_root=plamen_root,
        interpreter=sys.executable, store_root=store_root,
    )
    assert not front._authenticated_retained_backend_shim(
        raw.replace(b"authenticated", b"marker-only"),
        backend="claude", plamen_root=plamen_root,
        interpreter=sys.executable, store_root=store_root,
    )
    if sys.platform != "win32":
        for mutated in (
            raw.replace(b'exec ', b'exec  ', 1),
            raw.replace(b' "$@"\n', b' $@\n'),
            raw.replace(b' "$@"\n', b' "$@"; id\n'),
            raw + b"true\n",
            raw.replace(b"--receipt-sha256", b"'--receipt-sha256'", 1),
        ):
            assert not front._authenticated_retained_backend_shim(
                mutated, backend="claude", plamen_root=plamen_root,
                interpreter=sys.executable, store_root=store_root,
            )
    foreign_root = (tmp_path / "foreign").absolute()
    foreign_root.mkdir()
    (foreign_root / "plamen.py").write_bytes(b"# foreign\n")
    assert not front._authenticated_retained_backend_shim(
        raw, backend="claude", plamen_root=foreign_root,
        interpreter=sys.executable, store_root=store_root,
    )


def test_backend_shim_plan_admits_only_authenticated_old_generation_without_mutation(
    tmp_path, monkeypatch,
):
    front = _load_front()
    plamen_root = (tmp_path / "plamen").absolute()
    plamen_root.mkdir()
    (plamen_root / "plamen.py").write_bytes(b"# installed\n")
    store_root = (tmp_path / "mcp-runtime").absolute()
    shim_root = (tmp_path / "bin").absolute()
    shim_root.mkdir()
    shim_paths = {
        backend: shim_root / f"plamen-{backend}.cmd"
        for backend in ("claude", "codex")
    }

    def selection(seed):
        hexadecimal = "0123456789abcdef"
        shifted = lambda offset: hexadecimal[(int(seed, 16) + offset) % 16]
        return {
            "store_root": str(store_root),
            "generation_id": "npm-" + seed * 64,
            "receipt_sha256": shifted(1) * 64,
            "census_sha256": shifted(2) * 64,
            "request_sha256": seed * 64,
            "generation_policy_sha256": shifted(3) * 64,
            "backend_launches": {"claude": {}, "codex": {}},
        }

    old = selection("1")
    current = selection("5")
    old_raw = front._backend_shim_bytes(
        "claude", plamen_root, sys.executable, selection=old,
    )
    current_raw = front._backend_shim_bytes(
        "claude", plamen_root, sys.executable, selection=current,
    )
    current_legacy_raw = front._backend_shim_bytes(
        "claude", plamen_root, sys.executable, selection=current,
        suppress_bytecode=False,
    )
    assert old_raw not in {current_raw, current_legacy_raw}
    shim_paths["claude"].write_bytes(old_raw)
    shim_paths["codex"].write_bytes(front._backend_shim_bytes(
        "codex", plamen_root, sys.executable, selection=current,
    ))
    if os.name != "nt":
        for path in shim_paths.values():
            path.chmod(0o700)

    class Runtime:
        signature_valid = True

        def validate_generation_authority_fast(self, root, generation_id, **kwargs):
            if not self.signature_valid:
                raise RuntimeError("retained generation signature differs")
            authority = (
                str(Path(root).absolute()), generation_id,
                kwargs["expected_receipt_sha256"],
                kwargs["expected_census_sha256"],
                kwargs["expected_request_sha256"],
                kwargs["expected_generation_policy_sha256"],
            )
            expected = (
                str(store_root), old["generation_id"], old["receipt_sha256"],
                old["census_sha256"], old["request_sha256"],
                old["generation_policy_sha256"],
            )
            if authority != expected:
                raise RuntimeError("retained generation authority differs")

    runtime = Runtime()
    monkeypatch.setattr(
        front, "_validated_mcp_current_selection",
        lambda **_kwargs: current,
    )
    monkeypatch.setattr(
        front, "_backend_shim_path", lambda backend: shim_paths[backend],
    )
    monkeypatch.setattr(
        front, "_validated_committed_install_receipt",
        lambda: {"plamen_root": str(plamen_root)},
    )
    monkeypatch.setattr(
        front, "_mcp_receipt_callbacks",
        lambda _receipt: (None, object(), "e" * 64, "f" * 64),
    )
    monkeypatch.setattr(front, "_mcp_runtime_module", lambda _root: runtime)

    plan = front._backend_cli_shim_plan(plamen_root, sys.executable)
    assert plan["claude"][0] == shim_paths["claude"]
    assert plan["claude"][1] == current_raw
    assert plan["claude"][2]["kind"] == "exact-existing"
    assert plan["claude"][2]["raw"] == old_raw
    assert shim_paths["claude"].read_bytes() == old_raw

    rejected = []
    runtime.signature_valid = False
    rejected.append(old_raw)
    runtime.signature_valid = True
    bad_hash = front._backend_shim_bytes(
        "claude", plamen_root, sys.executable,
        selection={**old, "receipt_sha256": "0" * 64},
    )
    unknown = selection("9")
    unknown_raw = front._backend_shim_bytes(
        "claude", plamen_root, sys.executable, selection=unknown,
    )
    rejected.extend((bad_hash, unknown_raw, b"foreign backend command\r\n"))

    for index, candidate in enumerate(rejected):
        runtime.signature_valid = index != 0
        shim_paths["claude"].write_bytes(candidate)
        with pytest.raises(RuntimeError, match="foreign backend shim"):
            front._backend_cli_shim_plan(plamen_root, sys.executable)
        assert shim_paths["claude"].read_bytes() == candidate
