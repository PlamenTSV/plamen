"""Regression: Windows installs without symlink privilege (Developer Mode off /
non-elevated shell) must fall back to copying FILES instead of leaving the
install half-wired.

Bug (pre-fix): `_safe_link` created directory junctions (no privilege needed)
but linked individual FILES via `os.symlink`, which needs
SeCreateSymbolicLinkPrivilege. On a fresh non-Developer-Mode Windows box every
per-file link (agents/*.md, rules/*.md, commands/*.md, plamen.py, VERSION)
raised a privilege OSError, so the methodology was only partially wired and the
install reported many 'failed to link' lines with no fallback.

Fix: on Windows, when `os.symlink` of a FILE raises a privilege OSError,
`_safe_link` falls back to `shutil.copy2` and returns "copied". Copied
destinations are recorded in the manifest's `copied` list so `run_uninstall`
removes them (they are plain files, not links, and the link-only removal path
would otherwise leak them).
"""
import os
import json
import hashlib
import importlib.util
import shutil
import subprocess
import tempfile

import pytest

_PLAMEN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "plamen.py")


def _load():
    import sys
    spec = importlib.util.spec_from_file_location("plamen_mod_win_copy_fallback", _PLAMEN)
    m = importlib.util.module_from_spec(spec)
    saved = sys.argv
    sys.argv = ["plamen.py"]
    try:
        spec.loader.exec_module(m)
    finally:
        sys.argv = saved
    return m


def _stage_runtime_denominator(module, root):
    """Build a synthetic install tree from the production denominator."""
    production_root = os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))
    )
    for relative in module._toolchain_runtime_required_files():
        path = os.path.join(root, *relative.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        shutil.copy2(
            os.path.join(production_root, *relative.split("/")),
            path,
        )
    # The installer and doctor now validate the public front controller as an
    # explicit runtime prerequisite. Keep that fixture invariant independent
    # of any already-imported denominator-provider cache in the shared pytest
    # process.
    entrypoint = os.path.join(root, "plamen.py")
    if not os.path.isfile(entrypoint):
        shutil.copy2(
            os.path.join(production_root, "plamen.py"),
            entrypoint,
        )


def _committed_projection_fixture(monkeypatch, module, source, codex):
    os.makedirs(codex, exist_ok=True)
    rows = []
    for current, directories, files in os.walk(source):
        directories.sort(); files.sort()
        for name in files:
            path = os.path.join(current, name)
            relative = os.path.relpath(path, source).replace(os.sep, "/")
            authority, raw = module._codex_install_committed_descriptor(
                source, tuple(relative.split("/")), return_raw=True,
            )
            rows.append({
                "destination_root": "plamen",
                "destination_path": relative,
                "destination": path,
                "size": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "terminal_authority": authority,
            })
    monkeypatch.setattr(module, "_CODEX_INSTALL_RUNTIME_COUNT", len(rows))
    generation = {
        "schema": "plamen.codex_install.v2",
        "state": "COMMITTED",
        "transaction_id": "1" * 32,
        "source_count": len(rows),
        "runtime_count": len(rows),
        "adapter_count": 0,
        "source_manifest_sha256": "2" * 64,
        "runtime_manifest_sha256": "3" * 64,
        "adapter_manifest_sha256": "4" * 64,
        "source_root": os.path.abspath(source),
        "plamen_root": os.path.abspath(source),
        "codex_root": os.path.abspath(codex),
        "rows": rows,
        "terminal_verification": {
            "verified_count": len(rows),
            "verified_manifest_sha256": "2" * 64,
            "completed_ns": 1,
        },
    }
    monkeypatch.setattr(
        module, "_validated_committed_install_receipt", lambda: generation,
    )
    monkeypatch.setattr(
        module, "_open_install_admission_anchor",
        lambda *_a, **_k: (None, object(), lambda: None),
    )
    monkeypatch.setattr(
        module, "_claude_projection_key_path",
        lambda *_a: os.path.join(codex, ".projection-key.json"),
    )
    _private, public = module._claude_projection_private_key(create=True)
    generation["projection_public_key"] = public
    generation["terminal_verification"]["projection_public_key"] = public
    with open(
        os.path.join(codex, module._CODEX_INSTALL_RECEIPT), "w", encoding="utf-8",
    ) as stream:
        json.dump(generation, stream, sort_keys=True)
    return generation


def _patch_runtime_rows(monkeypatch, module, source):
    def rows(_closure_root=None):
        result = []
        for relative in module._toolchain_runtime_required_files(_closure_root):
            path = os.path.join(source, *relative.split("/"))
            with open(path, "rb") as stream:
                raw = stream.read()
            result.append({
                "path": relative,
                "digest_mode": "raw-v1",
                "sha256": hashlib.sha256(raw).hexdigest(),
            })
        return tuple(result)

    monkeypatch.setattr(module, "_toolchain_runtime_asset_rows", rows)


def _force_no_symlink_privilege(monkeypatch, m):
    """Simulate Windows without SeCreateSymbolicLinkPrivilege: pretend we are on
    win32 and make os.symlink raise the privilege OSError the OS would raise."""
    monkeypatch.setattr(m.sys, "platform", "win32", raising=False)

    def _raise_privilege(src, dst, target_is_directory=False):
        raise OSError(1314, "A required privilege is not held by the client")

    monkeypatch.setattr(m.os, "symlink", _raise_privilege)


def _force_junction_failure(monkeypatch, m):
    """Simulate Windows where `mklink /J` fails — most commonly because the
    junction would span volumes (src on D:, dst on C:). `subprocess.run(...,
    check=True)` raises CalledProcessError on the non-zero exit."""
    import subprocess as _sp
    monkeypatch.setattr(m.sys, "platform", "win32", raising=False)

    def _fake_run(args, *a, **kw):
        if args[:3] == ["cmd", "/c", "mklink"]:
            raise _sp.CalledProcessError(1, args, stderr=b"cannot span volumes")
        raise AssertionError(f"unexpected subprocess.run({args})")

    monkeypatch.setattr(m.subprocess, "run", _fake_run)


def test_safe_link_copies_dir_when_junction_fails(monkeypatch):
    """Cross-volume junction failure must fall back to copytree and return
    'copied_dir' — not crash on the uncaught CalledProcessError, and not leave
    the methodology tree absent (which hard-fails the Codex backend)."""
    m = _load()
    _force_junction_failure(monkeypatch, m)
    with tempfile.TemporaryDirectory() as root:
        src = os.path.join(root, "plamen_tree")
        os.makedirs(os.path.join(src, "rules"))
        with open(os.path.join(src, "rules", "a.md"), "w") as f:
            f.write("rule a\n")
        with open(os.path.join(src, "CLAUDE.md"), "w") as f:
            f.write("root\n")
        dst = os.path.join(root, ".codex", "plamen")

        status = m._safe_link(src, dst, lambda *_: None)
        assert status == "copied_dir"
        # The destination is a real copied tree, NOT a junction/symlink.
        assert os.path.isdir(dst)
        assert not os.path.islink(dst)
        # Every methodology file is present.
        with open(os.path.join(dst, "CLAUDE.md")) as f:
            assert f.read() == "root\n"
        with open(os.path.join(dst, "rules", "a.md")) as f:
            assert f.read() == "rule a\n"


def test_safe_link_migrates_only_authenticated_prior_target(tmp_path):
    m = _load()
    prior = tmp_path / "prior" / "rules" / "a.md"
    desired = tmp_path / "installed" / "rules" / "a.md"
    destination = tmp_path / ".claude" / "rules" / "a.md"
    prior.parent.mkdir(parents=True)
    desired.parent.mkdir(parents=True)
    destination.parent.mkdir(parents=True)
    prior.write_text("prior\n", encoding="utf-8")
    desired.write_text("installed\n", encoding="utf-8")
    destination.symlink_to(prior)

    assert m._safe_link(
        str(desired),
        str(destination),
        lambda *_args: None,
        authenticated_prior_targets=(str(prior),),
    ) == "linked"
    assert destination.resolve() == desired.resolve()


def test_safe_link_still_refuses_unauthenticated_foreign_target(tmp_path):
    m = _load()
    foreign = tmp_path / "foreign.md"
    desired = tmp_path / "desired.md"
    destination = tmp_path / "destination.md"
    foreign.write_text("foreign\n", encoding="utf-8")
    desired.write_text("desired\n", encoding="utf-8")
    destination.symlink_to(foreign)

    assert m._safe_link(
        str(desired),
        str(destination),
        lambda *_args: None,
        authenticated_prior_targets=(str(tmp_path / "different.md"),),
    ) is False
    assert destination.resolve() == foreign.resolve()


def test_authenticated_prior_install_roots_include_committed_runtime(
    monkeypatch, tmp_path,
):
    m = _load()
    codex_home = tmp_path / ".codex"
    plamen_root = tmp_path / ".plamen"
    prior_source = tmp_path / "prior-source"
    receipt_raw = b"authenticated predecessor"
    receipt_descriptor = {"kind": "file"}
    anchor_descriptor = {"device": 17, "inode": 23}
    calls = []

    real_expanduser = m.os.path.expanduser
    monkeypatch.setattr(
        m.os.path,
        "expanduser",
        lambda value: (
            str(codex_home) if value == "~/.codex" else
            str(plamen_root) if value == "~/.plamen" else
            real_expanduser(value)
        ),
    )

    def committed_read(root, components, **_kwargs):
        calls.append((root, components))
        if components == (m._CODEX_INSTALL_RECEIPT,):
            return receipt_descriptor, receipt_raw
        assert components == (m._CODEX_INSTALL_ANCHOR,)
        return anchor_descriptor, b"lock"

    def validate(raw, **kwargs):
        assert raw == receipt_raw
        assert kwargs["receipt_descriptor"] is receipt_descriptor
        assert kwargs["lock_identity"] == [17, 23]
        assert kwargs["plamen_root"] == plamen_root.absolute()
        return {"source_root": str(prior_source.absolute())}, receipt_descriptor

    monkeypatch.setattr(m, "_codex_install_committed_read", committed_read)
    monkeypatch.setattr(m, "_validated_prior_committed_receipt", validate)

    assert m._authenticated_prior_install_roots() == (
        os.path.normpath(str(plamen_root.absolute())),
    )
    assert len(calls) == 2

    desired = tmp_path / "desired.md"
    destination = tmp_path / "destination.md"
    desired.write_text("desired\n", encoding="utf-8")
    prior_source.mkdir()
    historical = prior_source / "historical.md"
    historical.write_text("old\n", encoding="utf-8")
    destination.symlink_to(historical)
    assert m._safe_link(
        str(desired), str(destination), lambda *_args: None,
        authenticated_prior_targets=m._authenticated_prior_install_roots(),
    ) is False
    assert destination.resolve() == historical.resolve()


@pytest.mark.parametrize(
    ("source_count", "runtime_count"),
    ((756, 725), (758, 727), (760, 729), (762, 731), (764, 733)),
)
def test_exact_predecessor_receipt_is_admitted(
    monkeypatch, tmp_path, source_count, runtime_count,
):
    m = _load()
    receipt = {field: None for field in m._CODEX_COMMITTED_RECEIPT_FIELDS}
    receipt.update({
        "schema": m._CODEX_INSTALL_SCHEMA,
        "state": "COMMITTED",
        "source_count": source_count,
        "runtime_count": runtime_count,
        "adapter_count": m._CODEX_INSTALL_ADAPTER_COUNT,
        "plamen_root": str(tmp_path / ".plamen"),
        "codex_root": str(tmp_path / ".codex"),
        "lock_identity": [17, 23],
        "rows": [{} for _ in range(source_count)],
        "journal": [{} for _ in range(source_count)],
    })
    raw = json.dumps(receipt, sort_keys=True).encode("utf-8")
    descriptor = {
        "kind": "file",
        "attributes": 0,
        "reparse_tag": 0,
        "links": 1,
        "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    observed = []
    monkeypatch.setattr(
        m,
        "_validate_committed_install_rows",
        lambda *args, **kwargs: observed.append((args, kwargs)),
    )

    validated, authority = m._validated_prior_committed_receipt(
        raw,
        receipt_path=tmp_path / ".codex" / m._CODEX_INSTALL_RECEIPT,
        plamen_root=tmp_path / ".plamen",
        codex_home=tmp_path / ".codex",
        anchor=tmp_path / ".codex" / m._CODEX_INSTALL_ANCHOR,
        receipt_descriptor=descriptor,
        lock_identity=[17, 23],
    )

    assert validated["source_count"] == source_count
    assert authority is descriptor
    assert observed[0][1]["expected_count"] == source_count


def test_tampered_predecessor_cannot_authorize_link_migration(
    monkeypatch, tmp_path,
):
    m = _load()
    codex_home = tmp_path / ".codex"
    plamen_root = tmp_path / ".plamen"
    real_expanduser = m.os.path.expanduser
    monkeypatch.setattr(
        m.os.path,
        "expanduser",
        lambda value: (
            str(codex_home) if value == "~/.codex" else
            str(plamen_root) if value == "~/.plamen" else
            real_expanduser(value)
        ),
    )
    monkeypatch.setattr(
        m,
        "_codex_install_committed_read",
        lambda *_args, **_kwargs: (
            {"kind": "file", "device": 17, "inode": 23}, b"tampered"
        ),
    )
    monkeypatch.setattr(
        m,
        "_validated_prior_committed_receipt",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("installed row digest differs")
        ),
    )

    assert m._authenticated_prior_install_roots() == ()


@pytest.mark.parametrize(
    ("source_count", "runtime_count", "adapter_count", "row_count"),
    (
        (755, 725, 31, 755),
        (756, 724, 31, 756),
        (761, 729, 31, 761),
        (999, 968, 31, 999),
        (760.0, 729, 31, 760),
        (True, 729, 31, 1),
        (760, 729.0, 31, 760),
        (760, True, 31, 760),
        (760, 729, 31.0, 760),
        (760, 729, True, 760),
    ),
)
def test_nonexact_immediate_predecessor_receipt_is_rejected(
    monkeypatch, tmp_path, source_count, runtime_count, adapter_count, row_count,
):
    m = _load()
    receipt = {field: None for field in m._CODEX_COMMITTED_RECEIPT_FIELDS}
    receipt.update({
        "schema": m._CODEX_INSTALL_SCHEMA,
        "state": "COMMITTED",
        "source_count": source_count,
        "runtime_count": runtime_count,
        "adapter_count": adapter_count,
        "plamen_root": str(tmp_path / ".plamen"),
        "codex_root": str(tmp_path / ".codex"),
        "lock_identity": [17, 23],
        "rows": [{} for _ in range(row_count)],
        "journal": [{} for _ in range(row_count)],
    })
    raw = json.dumps(receipt, sort_keys=True).encode("utf-8")
    descriptor = {
        "kind": "file", "attributes": 0, "reparse_tag": 0, "links": 1,
        "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
    }
    monkeypatch.setattr(
        m, "_validate_committed_install_rows", lambda *_args, **_kwargs: None,
    )

    with pytest.raises(RuntimeError, match="not exact COMMITTED authority"):
        m._validated_prior_committed_receipt(
            raw,
            receipt_path=tmp_path / ".codex" / m._CODEX_INSTALL_RECEIPT,
            plamen_root=tmp_path / ".plamen",
            codex_home=tmp_path / ".codex",
            anchor=tmp_path / ".codex" / m._CODEX_INSTALL_ANCHOR,
            receipt_descriptor=descriptor,
            lock_identity=[17, 23],
        )


def test_modified_copied_dir_reinstall_fails_closed(monkeypatch):
    """Re-running the copytree fallback over a prior copied tree (with a sibling
    .pre-plamen backup) must refresh the tree, not hit 'backup already exists'."""
    m = _load()
    _force_junction_failure(monkeypatch, m)
    with tempfile.TemporaryDirectory() as root:
        src = os.path.join(root, "plamen_tree")
        os.makedirs(src)
        with open(os.path.join(src, "VERSION"), "w") as f:
            f.write("NEW\n")

        dst = os.path.join(root, ".codex", "plamen")
        # Prior copied tree + a backed-up user original beside it.
        os.makedirs(dst)
        with open(os.path.join(dst, "VERSION"), "w") as f:
            f.write("OLD\n")
        with open(dst + ".pre-plamen", "w") as f:
            f.write("user original\n")

        status = m._safe_link(src, dst, lambda *_: None)
        assert status is False
        with open(os.path.join(dst, "VERSION")) as f:
            assert f.read() == "OLD\n"
        # User's backup untouched (recoverable on uninstall).
        with open(dst + ".pre-plamen") as f:
            assert f.read() == "user original\n"


def test_version_only_manifest_preserves_copied_dirs(monkeypatch):
    """A no-tracking _write_install_manifest() (the unconditional version stamp
    in run_install) must NOT clobber a prior copied_dirs/copied/installed list,
    or uninstall would leak every copied tree."""
    m = _load()
    with tempfile.TemporaryDirectory() as root:
        claude_home = os.path.join(root, ".claude")
        plamen_home = os.path.join(root, ".plamen")
        codex_home = os.path.join(root, ".codex")
        os.makedirs(claude_home)
        os.makedirs(plamen_home)
        os.makedirs(codex_home)
        real_expand = m.os.path.expanduser
        monkeypatch.setattr(m, "CLAUDE_HOME", claude_home, raising=False)
        monkeypatch.setattr(m, "PLAMEN_HOME", plamen_home, raising=False)
        monkeypatch.setattr(
            m.os.path, "expanduser",
            lambda p: codex_home if p == "~/.codex" else real_expand(p),
        )

        # First: a real install recorded a copied dir.
        cdir = os.path.join(codex_home, "plamen")
        m._write_install_manifest(["x"], copied=[], copied_dirs=[cdir])
        # Then: the unconditional version-only stamp runs.
        m._write_install_manifest()

        data = json.load(open(os.path.join(claude_home, m._PLAMEN_MANIFEST)))
        assert data["installed"] == ["x"]
        assert data["copied_dirs"] == [cdir]
        assert data["version"] == m.VERSION


def test_uninstall_preserves_legacy_copied_dir_without_tree_digest(monkeypatch):
    """A copied directory tree (cross-volume fallback) must be rmtree'd by
    run_uninstall and any backed-up user original restored — the link-only
    path skips real directories and would otherwise leak the tree."""
    m = _load()
    with tempfile.TemporaryDirectory() as root:
        claude_home = os.path.join(root, ".claude")
        plamen_home = os.path.join(root, ".plamen")
        os.makedirs(claude_home)
        os.makedirs(plamen_home)
        monkeypatch.setattr(m, "CLAUDE_HOME", claude_home, raising=False)
        monkeypatch.setattr(m, "PLAMEN_HOME", plamen_home, raising=False)
        # HOME isolation: keep _manifest_paths()'s ~/.codex from resolving to a
        # REAL ~/.codex on the machine running the suite (uninstall now reads +
        # removes across backends).
        monkeypatch.setenv("HOME", root)
        monkeypatch.setenv("USERPROFILE", root)

        copied_dir = os.path.join(claude_home, "plamen")
        os.makedirs(os.path.join(copied_dir, "rules"))
        with open(os.path.join(copied_dir, "rules", "a.md"), "w") as f:
            f.write("rule\n")

        manifest = {
            "plamen_home": plamen_home,
            "version": m.VERSION,
            "installed": [],
            "copied": [],
            "copied_dirs": [copied_dir],
        }
        with open(os.path.join(claude_home, m._PLAMEN_MANIFEST), "w") as f:
            json.dump(manifest, f)

        monkeypatch.setenv("PLAMEN_UNINSTALL_YES", "1")
        m.run_uninstall()

        assert os.path.isdir(copied_dir)
        assert not os.path.isfile(os.path.join(claude_home, m._PLAMEN_MANIFEST))


def test_claude_copy_install_includes_verification_policy_and_uninstalls(
    monkeypatch,
):
    """The Claude cross-volume copy layout must include the policy package.

    ``scripts/plamen_driver.py`` and ``scripts/plamen_validators.py`` import
    ``verification_policy`` from their parent.  Installing only ``scripts/``
    therefore produces a layout that works through source-tree symlinks but
    fails when Windows has to copy directories.
    """
    m = _load()
    monkeypatch.setattr(
        m, "_toolchain_runtime_required_integrity_issues",
        lambda *_a, **_k: {"missing": [], "mismatched": []},
    )
    monkeypatch.setattr(m, "_render_claude_config_updates", lambda *_a, **_k: [])
    with tempfile.TemporaryDirectory() as root:
        plamen_home = os.path.join(root, ".plamen")
        claude_home = os.path.join(root, ".claude")
        codex_home = os.path.join(root, ".codex-not-installed")
        policy_src = os.path.join(plamen_home, "verification_policy")
        os.makedirs(os.path.join(plamen_home, "scripts"))
        os.makedirs(policy_src)
        for name in m._VERIFICATION_POLICY_INSTALL_FILES:
            with open(os.path.join(policy_src, name), "w", encoding="utf-8") as f:
                f.write("{}\n" if name.endswith(".json") else "# package\n")
        _stage_runtime_denominator(m, plamen_home)

        monkeypatch.setattr(m, "PLAMEN_HOME", plamen_home, raising=False)
        monkeypatch.setattr(m, "CLAUDE_HOME", claude_home, raising=False)
        real_expand = m.os.path.expanduser
        monkeypatch.setattr(
            m.os.path,
            "expanduser",
            lambda path: codex_home if path == "~/.codex" else real_expand(path),
        )

        def _copy_only(src, dst, _write, **_kwargs):
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            if os.path.isdir(src):
                shutil.copytree(src, dst)
                return "copied_dir"
            shutil.copy2(src, dst)
            return "copied"

        monkeypatch.setattr(m, "_safe_link", _copy_only)
        _patch_runtime_rows(monkeypatch, m, plamen_home)
        generation = _committed_projection_fixture(
            monkeypatch, m, plamen_home, codex_home,
        )
        m._run_symlink_install(
            lambda *_: None,
            source_root=plamen_home,
            committed_generation=generation,
            authenticated_prior_roots=(),
        )

        nested_rule_destinations = [
            os.path.join(claude_home, *relative.split("/"))
            for relative in m._toolchain_runtime_required_files()
            if relative.startswith("rules/")
            and os.path.dirname(relative) != "rules"
        ]
        assert nested_rule_destinations
        assert all(os.path.isfile(path) for path in nested_rule_destinations)

        policy_dst = os.path.join(claude_home, "verification_policy")
        assert m._missing_claude_verification_policy_files() == []
        manifest_path = os.path.join(claude_home, m._PLAMEN_MANIFEST)
        with open(manifest_path, encoding="utf-8") as f:
            manifest = json.load(f)
        assert policy_dst in manifest["installed"]
        assert policy_dst in manifest["copied_dirs"]

        os.remove(
            os.path.join(
                policy_dst,
                "verification_method_registry.v1.json",
            )
        )
        assert m._missing_claude_verification_policy_files() == [
            "verification_method_registry.v1.json"
        ]

        monkeypatch.setenv("HOME", root)
        monkeypatch.setenv("USERPROFILE", root)
        monkeypatch.setenv("PLAMEN_UNINSTALL_YES", "1")
        with pytest.raises(RuntimeError, match="survived uninstall"):
            m.run_uninstall()
        # A partially modified copied tree cannot be proven receipt-identical,
        # so uninstall preserves it and retains the receipt for repair.
        assert os.path.isdir(policy_dst)
        assert os.path.isfile(manifest_path)


def test_claude_install_uses_runtime_denominator_for_generic_nested_rule(
    monkeypatch,
) -> None:
    """A future nested rule is installed and uninstalled without allowlisting."""

    m = _load()
    monkeypatch.setattr(
        m, "_toolchain_runtime_required_integrity_issues",
        lambda *_a, **_k: {"missing": [], "mismatched": []},
    )
    monkeypatch.setattr(m, "_render_claude_config_updates", lambda *_a, **_k: [])
    with tempfile.TemporaryDirectory() as root:
        plamen_home = os.path.join(root, ".plamen")
        claude_home = os.path.join(root, ".claude")
        codex_home = os.path.join(root, ".codex-not-installed")
        _stage_runtime_denominator(m, plamen_home)
        generic = "rules/future/generic-runtime-policy.json"
        generic_source = os.path.join(plamen_home, *generic.split("/"))
        os.makedirs(os.path.dirname(generic_source), exist_ok=True)
        with open(generic_source, "w", encoding="utf-8") as stream:
            stream.write("{}\n")
        base_required = m._toolchain_runtime_required_files()

        monkeypatch.setattr(m, "PLAMEN_HOME", plamen_home, raising=False)
        monkeypatch.setattr(m, "CLAUDE_HOME", claude_home, raising=False)
        monkeypatch.setattr(
            m,
            "_toolchain_runtime_required_files",
            lambda *_a: tuple(sorted({*base_required, generic})),
        )
        real_expand = m.os.path.expanduser
        monkeypatch.setattr(
            m.os.path,
            "expanduser",
            lambda path: (
                codex_home if path == "~/.codex" else real_expand(path)
            ),
        )

        def _copy_only(src, dst, _write, **_kwargs):
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            if os.path.isdir(src):
                shutil.copytree(src, dst)
                return "copied_dir"
            shutil.copy2(src, dst)
            return "copied"

        monkeypatch.setattr(m, "_safe_link", _copy_only)
        _patch_runtime_rows(monkeypatch, m, plamen_home)
        generation = _committed_projection_fixture(
            monkeypatch, m, plamen_home, codex_home,
        )
        m._run_symlink_install(
            lambda *_: None,
            source_root=plamen_home,
            committed_generation=generation,
            authenticated_prior_roots=(),
        )

        destination = os.path.join(claude_home, *generic.split("/"))
        assert os.path.isfile(destination)
        manifest_path = os.path.join(claude_home, m._PLAMEN_MANIFEST)
        with open(manifest_path, encoding="utf-8") as stream:
            manifest = json.load(stream)
        assert destination in manifest["installed"]
        assert destination in manifest["copied"]
        runtime_row = next(
            row
            for row in manifest["runtime_assets"]
            if row["relative_path"] == generic
        )
        assert runtime_row == {
            "backup_disposition": "none",
            "destination": destination,
            "digest_mode": "raw-v1",
            "install_mode": "copied",
            "owned": True,
            "relative_path": generic,
            "source_sha256": hashlib.sha256(
                open(generic_source, "rb").read()
            ).hexdigest(),
        }
        created_parent = os.path.dirname(destination)
        assert created_parent in manifest["created_dirs"]
        unrelated = os.path.join(created_parent, "user-owned.txt")
        with open(unrelated, "w", encoding="utf-8") as stream:
            stream.write("preserve me\n")

        # The source projection may advance before uninstall. Receipt ownership,
        # not the new denominator, must still remove the stale managed asset.
        monkeypatch.setattr(
            m,
            "_toolchain_runtime_required_files",
            lambda: base_required,
        )
        os.remove(generic_source)

        monkeypatch.setenv("HOME", root)
        monkeypatch.setenv("USERPROFILE", root)
        monkeypatch.setenv("PLAMEN_UNINSTALL_YES", "1")
        m.run_uninstall()
        assert not os.path.exists(destination)
        assert os.path.isfile(unrelated)
        assert not os.path.isfile(manifest_path)


def test_uninstall_survivor_retains_receipt_and_fails_loud(
    monkeypatch,
) -> None:
    m = _load()
    with tempfile.TemporaryDirectory() as root:
        claude_home = os.path.join(root, ".claude")
        plamen_home = os.path.join(root, ".plamen")
        os.makedirs(claude_home)
        os.makedirs(plamen_home)
        destination = os.path.join(
            claude_home, "rules", "future", "owned.json"
        )
        os.makedirs(os.path.dirname(destination))
        with open(destination, "w", encoding="utf-8") as stream:
            stream.write("{}\n")
        manifest_path = os.path.join(
            claude_home, m._PLAMEN_MANIFEST
        )
        manifest = {
            "plamen_home": plamen_home,
            "version": m.VERSION,
            "installed": [destination],
            "copied": [destination],
            "copied_dirs": [],
            "created_dirs": [os.path.dirname(destination)],
            "runtime_assets": [
                {
                    "backup_disposition": "none",
                    "destination": destination,
                    "install_mode": "copied",
                    "owned": True,
                    "relative_path": "rules/future/owned.json",
                    "source_sha256": "0" * 64,
                }
            ],
            "shims": [],
        }
        with open(manifest_path, "w", encoding="utf-8") as stream:
            json.dump(manifest, stream)
        monkeypatch.setattr(m, "CLAUDE_HOME", claude_home, raising=False)
        monkeypatch.setattr(m, "PLAMEN_HOME", plamen_home, raising=False)
        monkeypatch.setenv("HOME", root)
        monkeypatch.setenv("USERPROFILE", root)
        monkeypatch.setenv("PLAMEN_UNINSTALL_YES", "1")
        real_remove = m.os.remove

        def refuse_owned(path):
            if os.path.normcase(path) == os.path.normcase(destination):
                raise PermissionError("fixture holds the managed file")
            return real_remove(path)

        monkeypatch.setattr(m.os, "remove", refuse_owned)
        with pytest.raises(
            RuntimeError,
            match="receipt-owned runtime assets survived uninstall",
        ):
            m.run_uninstall()
        assert os.path.isfile(destination)
        assert os.path.isfile(manifest_path)


def test_doctor_hard_fails_incomplete_claude_verification_policy(
    monkeypatch,
) -> None:
    m = _load()
    with tempfile.TemporaryDirectory() as root:
        plamen_home = os.path.join(root, ".plamen")
        claude_home = os.path.join(root, ".claude")
        policy_dir = os.path.join(claude_home, "verification_policy")
        os.makedirs(policy_dir)
        os.makedirs(plamen_home)
        _stage_runtime_denominator(m, plamen_home)
        _stage_runtime_denominator(m, claude_home)
        for submodule in (
            "custom-mcp/slither-mcp",
            "custom-mcp/farofino-mcp",
        ):
            path = os.path.join(plamen_home, submodule)
            os.makedirs(path)
            with open(os.path.join(path, "README"), "w", encoding="utf-8") as f:
                f.write("fixture\n")

        production_root = os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))
        )
        for name in m._VERIFICATION_POLICY_INSTALL_FILES:
            shutil.copy2(
                os.path.join(production_root, "verification_policy", name),
                os.path.join(policy_dir, name),
            )
        missing = m._VERIFICATION_POLICY_INSTALL_FILES[-1]
        os.remove(os.path.join(policy_dir, missing))

        manifest_path = os.path.join(claude_home, m._PLAMEN_MANIFEST)
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "plamen_home": plamen_home,
                    "version": m.VERSION,
                    "installed": [],
                    "copied": [],
                    "copied_dirs": [],
                    "shims": [],
                },
                f,
            )
        with open(
            os.path.join(claude_home, "CLAUDE.md"),
            "w",
            encoding="utf-8",
        ) as f:
            f.write(f"{m._CLAUDE_MD_START}\n{m._CLAUDE_MD_END}\n")

        monkeypatch.setenv("HOME", root)
        monkeypatch.setenv("USERPROFILE", root)
        monkeypatch.setattr(m, "PLAMEN_HOME", plamen_home, raising=False)
        monkeypatch.setattr(m, "CLAUDE_HOME", claude_home, raising=False)
        monkeypatch.setattr(
            m,
            "_toolchain_runtime_required_integrity_issues",
            lambda _root, **_kwargs: {"missing": [], "mismatched": []},
        )
        monkeypatch.setattr(m, "show_banner", lambda: None)
        monkeypatch.setattr(m.console, "print", lambda *_a, **_kw: None)
        monkeypatch.setattr(
            m,
            "_find_bin",
            lambda name: (
                "" if name in {"node", "npm", "npx"}
                else os.path.join(root, f"{name}.fixture")
            ),
        )
        monkeypatch.setattr(
            m,
            "_locked_toolchain_identity_report",
            lambda: [],
        )
        monkeypatch.setattr(
            m,
            "_python_dependency_authority",
            lambda *_a, **_kw: "a" * 64,
        )
        monkeypatch.setattr(
            m,
            "_python_dependency_stamp_status",
            lambda *_a, **_kw: "VALID",
        )
        monkeypatch.setattr(m, "_find_codex_bin", lambda: "")
        monkeypatch.setattr(
            m.subprocess,
            "run",
            lambda *_a, **_kw: subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout="ok",
                stderr="",
            ),
        )

        assert m.run_doctor() == 1

        shutil.copy2(
            os.path.join(production_root, "verification_policy", missing),
            os.path.join(policy_dir, missing),
        )
        assert m.run_doctor() == 0


def test_safe_link_copies_file_when_no_privilege(monkeypatch):
    m = _load()
    _force_no_symlink_privilege(monkeypatch, m)
    with tempfile.TemporaryDirectory() as root:
        src = os.path.join(root, "VERSION")
        dst = os.path.join(root, "VERSION.dst")
        with open(src, "w") as f:
            f.write("2.1.0\n")

        status = m._safe_link(src, dst, lambda *_: None)
        assert status == "copied"
        # The destination is a real copy, NOT a symlink.
        assert os.path.isfile(dst)
        assert not os.path.islink(dst)
        with open(dst) as f:
            assert f.read() == "2.1.0\n"


def test_modified_copy_fallback_reinstall_fails_closed(monkeypatch):
    """Re-running the copy fallback must overwrite the prior copy rather than
    hitting the 'backup already exists' skip and returning False."""
    m = _load()
    _force_no_symlink_privilege(monkeypatch, m)
    with tempfile.TemporaryDirectory() as root:
        src = os.path.join(root, "rule.md")
        dst = os.path.join(root, "rule.dst.md")
        # Simulate a pre-existing USER file at dst that the FIRST install backed
        # up, plus our prior copy now sitting at dst.
        with open(dst + ".pre-plamen", "w") as f:
            f.write("user original\n")
        with open(dst, "w") as f:
            f.write("OLD plamen copy\n")
        with open(src, "w") as f:
            f.write("NEW plamen copy\n")

        status = m._safe_link(src, dst, lambda *_: None)
        assert status is False
        with open(dst) as f:
            assert f.read() == "OLD plamen copy\n"
        # The user's backup is untouched (still recoverable on uninstall).
        with open(dst + ".pre-plamen") as f:
            assert f.read() == "user original\n"


def test_manifest_records_copied_subset(monkeypatch):
    m = _load()
    with tempfile.TemporaryDirectory() as root:
        claude_home = os.path.join(root, ".claude")
        plamen_home = os.path.join(root, ".plamen")
        os.makedirs(claude_home)
        os.makedirs(plamen_home)
        monkeypatch.setattr(m, "CLAUDE_HOME", claude_home, raising=False)
        monkeypatch.setattr(m, "PLAMEN_HOME", plamen_home, raising=False)
        real_expand = m.os.path.expanduser
        monkeypatch.setattr(
            m.os.path, "expanduser",
            lambda p: os.path.join(root, ".codex") if p == "~/.codex" else real_expand(p),
        )

        installed = ["a", "b", "c"]
        copied = ["b", "c"]
        m._write_install_manifest(installed, copied=copied)

        data = json.load(open(os.path.join(claude_home, m._PLAMEN_MANIFEST)))
        assert data["installed"] == installed
        assert data["copied"] == copied


def test_uninstall_preserves_legacy_copies_without_digest_authority(monkeypatch):
    """The copied plain files must be removed by run_uninstall and any
    backed-up user originals restored — mirroring the symlink removal path."""
    m = _load()
    with tempfile.TemporaryDirectory() as root:
        claude_home = os.path.join(root, ".claude")
        plamen_home = os.path.join(root, ".plamen")
        os.makedirs(claude_home)
        os.makedirs(plamen_home)
        monkeypatch.setattr(m, "CLAUDE_HOME", claude_home, raising=False)
        monkeypatch.setattr(m, "PLAMEN_HOME", plamen_home, raising=False)
        monkeypatch.setenv("HOME", root)
        monkeypatch.setenv("USERPROFILE", root)

        # One copied file with NO user backup, one copied file WITH a user
        # backup that must be restored.
        copied_plain = os.path.join(claude_home, "agent.md")
        with open(copied_plain, "w") as f:
            f.write("plamen content\n")

        copied_over_user = os.path.join(claude_home, "rule.md")
        with open(copied_over_user, "w") as f:
            f.write("plamen content\n")
        with open(copied_over_user + ".pre-plamen", "w") as f:
            f.write("user original\n")

        installed = [copied_plain, copied_over_user]
        manifest = {
            "plamen_home": plamen_home,
            "version": m.VERSION,
            "installed": installed,
            "copied": installed,
        }
        with open(os.path.join(claude_home, m._PLAMEN_MANIFEST), "w") as f:
            json.dump(manifest, f)

        monkeypatch.setenv("PLAMEN_UNINSTALL_YES", "1")
        m.run_uninstall()

        # Copied plain file with no backup is gone.
        assert os.path.exists(copied_plain)
        # Copied-over-user file is restored to the user's original content.
        assert os.path.isfile(copied_over_user)
        with open(copied_over_user) as f:
            assert f.read() == "plamen content\n"
        assert os.path.exists(copied_over_user + ".pre-plamen")
        # Manifest removed.
        assert not os.path.isfile(os.path.join(claude_home, m._PLAMEN_MANIFEST))


def test_uninstall_codex_only_preserves_nonempty_shared_trees_and_config(monkeypatch):
    """Codex-only install (manifest under ~/.codex, none under ~/.claude) must
    NOT be a no-op: adapter-owned trees (agents/skills/commands) are removed,
    while shared config.toml / AGENTS.md (may hold user API keys/edits) are KEPT."""
    m = _load()
    with tempfile.TemporaryDirectory() as root:
        claude_home = os.path.join(root, ".claude")
        codex_home = os.path.join(root, ".codex")
        plamen_home = os.path.join(root, ".plamen")
        os.makedirs(claude_home)
        os.makedirs(codex_home)
        os.makedirs(plamen_home)
        monkeypatch.setattr(m, "CLAUDE_HOME", claude_home, raising=False)
        monkeypatch.setattr(m, "PLAMEN_HOME", plamen_home, raising=False)
        monkeypatch.setenv("HOME", root)
        monkeypatch.setenv("USERPROFILE", root)

        for tree in ("agents", "skills", "commands"):
            d = os.path.join(codex_home, tree)
            os.makedirs(d)
            with open(os.path.join(d, "x.toml"), "w") as f:
                f.write("x\n")
        config_toml = os.path.join(codex_home, "config.toml")
        agents_md = os.path.join(codex_home, "AGENTS.md")
        with open(config_toml, "w") as f:
            f.write('api_key = "USER-SECRET"\n')
        with open(agents_md, "w") as f:
            f.write("user agents\n")

        # codex manifest, NO claude manifest -> a codex-only install
        manifest = {"plamen_home": plamen_home, "version": m.VERSION,
                    "installed": [], "copied": [], "copied_dirs": [], "shims": []}
        with open(os.path.join(codex_home, m._PLAMEN_MANIFEST), "w") as f:
            json.dump(manifest, f)

        monkeypatch.setenv("PLAMEN_UNINSTALL_YES", "1")
        m.run_uninstall()

        for tree in ("agents", "skills", "commands"):
            assert os.path.isdir(os.path.join(codex_home, tree)), tree
        # Shared config PRESERVED — deleting it would be user-data loss.
        assert os.path.isfile(config_toml)
        with open(config_toml) as f:
            assert f.read() == 'api_key = "USER-SECRET"\n'
        assert os.path.isfile(agents_md)
        assert not os.path.isfile(os.path.join(codex_home, m._PLAMEN_MANIFEST))


def test_uninstall_refuses_legacy_shim_outside_managed_launcher_dir(monkeypatch):
    """python3 shims recorded in the manifest must be removed by uninstall."""
    m = _load()
    with tempfile.TemporaryDirectory() as root:
        claude_home = os.path.join(root, ".claude")
        plamen_home = os.path.join(root, ".plamen")
        os.makedirs(claude_home)
        os.makedirs(plamen_home)
        monkeypatch.setattr(m, "CLAUDE_HOME", claude_home, raising=False)
        monkeypatch.setattr(m, "PLAMEN_HOME", plamen_home, raising=False)
        monkeypatch.setenv("HOME", root)
        monkeypatch.setenv("USERPROFILE", root)

        shim = os.path.join(plamen_home, "python3.bat")
        with open(shim, "w") as f:
            f.write("@echo off\n")
        manifest = {"plamen_home": plamen_home, "version": m.VERSION,
                    "installed": [], "copied": [], "copied_dirs": [], "shims": [shim]}
        with open(os.path.join(claude_home, m._PLAMEN_MANIFEST), "w") as f:
            json.dump(manifest, f)

        monkeypatch.setenv("PLAMEN_UNINSTALL_YES", "1")
        with pytest.raises(RuntimeError, match="outside managed namespaces"):
            m.run_uninstall()
        assert os.path.exists(shim)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
