"""Independent R3 blocker reproductions for CI/toolchain authority.

These fixtures preserve the reviewer counterexamples before production repair.
They assert closed workflow enumeration, conservative local dynamic-import
closure, extracted-stage execution, and alias-safe typed runtime assets.
"""

from __future__ import annotations

import ast
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

import pytest

import ci_dependency_authority as AUTH
import test_ci_dependency_authority_r2 as R2
import toolchain_control_authority as TOOLCHAIN


ROOT = Path(__file__).resolve().parents[1]


def _runtime_entry(
    root: Path,
    source: str,
) -> Path:
    scripts = root / "scripts"
    scripts.mkdir(parents=True)
    entry = scripts / "entry.py"
    entry.write_text(source, encoding="utf-8", newline="\n")
    return entry


def _snapshot_census(root: Path) -> str:
    rows = []
    for path in sorted(
        (path for path in root.rglob("*") if path.is_file()),
        key=lambda path: path.relative_to(root).as_posix(),
    ):
        relative = path.relative_to(root).as_posix()
        rows.append(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {relative}\n"
        )
    return hashlib.sha256("".join(rows).encode("utf-8")).hexdigest()


def _copy_runtime_snapshot(source_root: Path, snapshot: Path) -> str:
    """Copy the exact local-module universe and its literal runtime assets."""

    sources = [
        path
        for path in (source_root / "scripts").glob("*.py")
        if (
            not path.name.startswith("test_")
            and path.name not in TOOLCHAIN._RUNTIME_DENIED_BASENAMES
        )
    ]
    package = source_root / "plamen_l1"
    if package.is_dir():
        sources.extend(
            path
            for path in package.rglob("*.py")
            if not path.name.startswith("test_")
        )
    sources.append(source_root / "plamen.py")

    asset_paths: set[Path] = {
        TOOLCHAIN._RUNTIME_CLOSURE_PATH,
    }
    for source in sources:
        relative = source.relative_to(source_root).as_posix()
        tree = ast.parse(
            source.read_text(encoding="utf-8"),
            filename=relative,
        )
        for declaration in TOOLCHAIN._literal_runtime_asset_declarations(
            tree,
            importer_relative=relative,
        ):
            mode = declaration["mode"]
            if mode == "file":
                asset_paths.add(Path(declaration["path"]))
            elif mode == "named-files":
                base = Path(declaration["root"])
                asset_paths.update(
                    base / name for name in declaration["names"]
                )
            elif mode == "tree":
                base = Path(declaration["root"])
                asset_paths.update(
                    path.relative_to(source_root)
                    for path in (source_root / base).rglob(
                        declaration["pattern"]
                    )
                    if path.is_file()
                )
            else:  # pragma: no cover - production parser rejects this first
                raise AssertionError(f"unexpected runtime asset mode: {mode}")

    copied = {
        path.relative_to(source_root)
        for path in sources
    } | asset_paths
    for relative in sorted(copied, key=lambda path: path.as_posix()):
        source = source_root / relative
        destination = snapshot / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)

    return _snapshot_census(snapshot)


def test_workflow_directory_denominator_rejects_unreviewed_workflow(
    tmp_path: Path,
) -> None:
    repository = R2._copy_authority(tmp_path)
    workflow = repository / ".github" / "workflows" / "unreviewed.yml"
    workflow.write_text(
        "name: unreviewed\n"
        "on: [push]\n"
        "jobs:\n"
        "  unsafe:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - uses: unknown/action@main\n",
        encoding="utf-8",
        newline="\n",
    )

    with pytest.raises(
        AUTH.CIDependencyAuthorityError,
        match="workflow.*denominator|denominator.*workflow",
    ):
        AUTH.verify_static_bindings(repository)


@pytest.mark.parametrize(
    "name",
    [
        "benign.yml",
        "benign.yaml",
    ],
)
def test_workflow_directory_rejects_even_pinned_unreviewed_files(
    tmp_path: Path,
    name: str,
) -> None:
    repository = R2._copy_authority(tmp_path)
    policy = AUTH._load_policy(repository)
    checkout = next(
        row["commit_sha"]
        for row in policy["github_actions"]
        if row["name"] == "actions/checkout"
    )
    (repository / ".github" / "workflows" / name).write_text(
        "name: benign-but-unreviewed\n"
        "on: [push]\n"
        "jobs:\n"
        "  benign:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        f"      - uses: actions/checkout@{checkout}\n",
        encoding="utf-8",
        newline="\n",
    )

    with pytest.raises(
        AUTH.CIDependencyAuthorityError,
        match="workflow.*denominator|denominator.*workflow",
    ):
        AUTH.verify_workflow_action_bindings(repository)


def test_workflow_directory_rejects_missing_or_renamed_reviewed_file(
    tmp_path: Path,
) -> None:
    repository = R2._copy_authority(tmp_path)
    source = repository / ".github" / "workflows" / "tests.yml"
    source.rename(source.with_name("renamed.yml"))

    with pytest.raises(
        AUTH.CIDependencyAuthorityError,
        match="workflow.*denominator|denominator.*workflow",
    ):
        AUTH.verify_workflow_action_bindings(repository)


def test_nonliteral_dynamic_import_closes_over_local_module_universe_and_stage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    _runtime_entry(
        repository,
        "import importlib\n"
        'name = "dynamic_c"\n'
        "loaded = importlib.import_module(name)\n",
    )
    (repository / "scripts" / "dynamic_c.py").write_text(
        'VALUE = "dynamic-stage-pass"\n',
        encoding="utf-8",
        newline="\n",
    )
    monkeypatch.setattr(
        TOOLCHAIN,
        "_RUNTIME_ENTRYPOINTS",
        ("scripts/entry.py",),
    )

    closure = set(
        TOOLCHAIN.derive_runtime_dependency_closure(repository)
    )
    assert "scripts/dynamic_c.py" in closure

    stage = tmp_path / "stage"
    for relative in sorted(closure):
        source = repository / relative
        if not source.is_file():
            continue
        destination = stage / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            (
                "import sys;"
                f"sys.path.insert(0,{str(stage / 'scripts')!r});"
                "import entry;"
                "print(entry.loaded.VALUE)"
            ),
        ],
        cwd=stage,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "dynamic-stage-pass"


def test_keyword_alias_dynamic_import_also_closes_local_universe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    _runtime_entry(
        repository,
        "from importlib import import_module as load\n"
        'module_name = "dynamic_keyword"\n'
        "loaded = load(name=module_name)\n",
    )
    (repository / "scripts" / "dynamic_keyword.py").write_text(
        "VALUE = 1\n",
        encoding="utf-8",
        newline="\n",
    )
    monkeypatch.setattr(
        TOOLCHAIN,
        "_RUNTIME_ENTRYPOINTS",
        ("scripts/entry.py",),
    )

    closure = set(
        TOOLCHAIN.derive_runtime_dependency_closure(repository)
    )
    assert "scripts/dynamic_keyword.py" in closure


def test_literal_dynamic_import_remains_precise(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    _runtime_entry(
        repository,
        "import importlib\n"
        'loaded = importlib.import_module("selected")\n',
    )
    for name in ("selected", "unselected"):
        (repository / "scripts" / f"{name}.py").write_text(
            f'VALUE = "{name}"\n',
            encoding="utf-8",
            newline="\n",
        )
    monkeypatch.setattr(
        TOOLCHAIN,
        "_RUNTIME_ENTRYPOINTS",
        ("scripts/entry.py",),
    )

    closure = set(
        TOOLCHAIN.derive_runtime_dependency_closure(repository)
    )
    assert "scripts/selected.py" in closure
    assert "scripts/unselected.py" not in closure


def test_typed_runtime_asset_rejects_ancestor_link_escape(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "payload.json").write_text(
        "{}\n",
        encoding="utf-8",
        newline="\n",
    )
    _runtime_entry(
        repository,
        "PLAMEN_RUNTIME_ASSETS = (\n"
        "    {\n"
        '        "kind": "runtime-data",\n'
        '        "mode": "file",\n'
        '        "path": "linked/payload.json",\n'
        "    },\n"
        ")\n",
    )
    link = repository / "linked"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"directory symlink unavailable: {exc}")
    monkeypatch.setattr(
        TOOLCHAIN,
        "_RUNTIME_ENTRYPOINTS",
        ("scripts/entry.py",),
    )

    with pytest.raises(
        TOOLCHAIN.ToolchainControlError,
        match="ancestor|symlink|reparse|junction",
    ):
        TOOLCHAIN.derive_runtime_dependency_closure(repository)


def test_typed_runtime_assets_reject_casefold_collision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    upper = repository / "Data"
    upper.mkdir(parents=True)
    (upper / "payload.json").write_text(
        '{"case": "upper"}\n',
        encoding="utf-8",
        newline="\n",
    )
    if os.name != "nt":
        lower = repository / "data"
        lower.mkdir()
        (lower / "payload.json").write_text(
            '{"case": "lower"}\n',
            encoding="utf-8",
            newline="\n",
        )
    _runtime_entry(
        repository,
        "PLAMEN_RUNTIME_ASSETS = (\n"
        '    {"kind": "runtime-data", "mode": "file",\n'
        '     "path": "Data/payload.json"},\n'
        '    {"kind": "runtime-data", "mode": "file",\n'
        '     "path": "data/payload.json"},\n'
        ")\n",
    )
    monkeypatch.setattr(
        TOOLCHAIN,
        "_RUNTIME_ENTRYPOINTS",
        ("scripts/entry.py",),
    )

    with pytest.raises(
        TOOLCHAIN.ToolchainControlError,
        match="case|canonical|alias",
    ):
        TOOLCHAIN.derive_runtime_dependency_closure(repository)


def test_typed_runtime_assets_reject_native_identity_alias(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    data = repository / "data"
    data.mkdir(parents=True)
    payload = data / "payload.json"
    payload.write_text("{}\n", encoding="utf-8", newline="\n")
    alias = data / "payload-alias.json"
    try:
        os.link(payload, alias)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"hardlink unavailable: {exc}")
    _runtime_entry(
        repository,
        "PLAMEN_RUNTIME_ASSETS = (\n"
        '    {"kind": "runtime-data", "mode": "named-files",\n'
        '     "root": "data",\n'
        '     "names": ("payload.json", "payload-alias.json")},\n'
        ")\n",
    )
    monkeypatch.setattr(
        TOOLCHAIN,
        "_RUNTIME_ENTRYPOINTS",
        ("scripts/entry.py",),
    )

    with pytest.raises(
        TOOLCHAIN.ToolchainControlError,
        match="identity|alias|hardlink",
    ):
        TOOLCHAIN.derive_runtime_dependency_closure(repository)


@pytest.mark.skipif(
    os.name != "nt",
    reason="Windows canonical-spelling behavior",
)
def test_typed_runtime_asset_rejects_noncanonical_windows_spelling(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    data = repository / "Data"
    data.mkdir(parents=True)
    (data / "payload.json").write_text(
        "{}\n",
        encoding="utf-8",
        newline="\n",
    )
    _runtime_entry(
        repository,
        "PLAMEN_RUNTIME_ASSETS = (\n"
        '    {"kind": "runtime-data", "mode": "file",\n'
        '     "path": "data/payload.json"},\n'
        ")\n",
    )
    monkeypatch.setattr(
        TOOLCHAIN,
        "_RUNTIME_ENTRYPOINTS",
        ("scripts/entry.py",),
    )

    with pytest.raises(
        TOOLCHAIN.ToolchainControlError,
        match="case|canonical|spelling",
    ):
        TOOLCHAIN.derive_runtime_dependency_closure(repository)


def test_runtime_path_index_scans_once_then_rechecks_each_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    _runtime_entry(
        repository,
        "import importlib\n"
        'name = "module_0"\n'
        "importlib.import_module(name)\n",
    )
    for ordinal in range(12):
        (repository / "scripts" / f"module_{ordinal}.py").write_text(
            f"VALUE = {ordinal}\n",
            encoding="utf-8",
            newline="\n",
        )
    monkeypatch.setattr(
        TOOLCHAIN,
        "_RUNTIME_ENTRYPOINTS",
        ("scripts/entry.py",),
    )
    observed: dict[Path, int] = {}
    original_scandir = TOOLCHAIN.os.scandir

    def recorded_scandir(path):
        canonical = Path(path).absolute()
        if canonical in {
            repository.absolute(),
            (repository / "scripts").absolute(),
        }:
            observed[canonical] = observed.get(canonical, 0) + 1
        return original_scandir(path)

    monkeypatch.setattr(TOOLCHAIN.os, "scandir", recorded_scandir)
    TOOLCHAIN.derive_runtime_dependency_closure(repository)

    # Every relevant parent is enumerated once for the working index and once
    # for the final replay. Module-map enumeration consumes the same index.
    assert observed[repository.absolute()] == 2
    assert observed[(repository / "scripts").absolute()] == 2


def test_runtime_path_index_rejects_concurrent_asset_rename(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    data = repository / "data"
    data.mkdir(parents=True)
    payload = data / "payload.json"
    payload.write_text("{}\n", encoding="utf-8", newline="\n")
    _runtime_entry(
        repository,
        "PLAMEN_RUNTIME_ASSETS = (\n"
        '    {"kind": "runtime-data", "mode": "file",\n'
        '     "path": "data/payload.json"},\n'
        ")\n",
    )
    monkeypatch.setattr(
        TOOLCHAIN,
        "_RUNTIME_ENTRYPOINTS",
        ("scripts/entry.py",),
    )
    original_expand = TOOLCHAIN._expand_runtime_asset_declaration
    mutated = False

    def mutate_after_validation(*args, **kwargs):
        nonlocal mutated
        rows = original_expand(*args, **kwargs)
        if not mutated:
            payload.rename(payload.with_name("renamed.json"))
            mutated = True
        return rows

    monkeypatch.setattr(
        TOOLCHAIN,
        "_expand_runtime_asset_declaration",
        mutate_after_validation,
    )
    with pytest.raises(
        TOOLCHAIN.ToolchainControlError,
        match="changed|drift|canonical|rename",
    ):
        TOOLCHAIN.derive_runtime_dependency_closure(repository)


def test_runtime_path_index_rejects_concurrent_case_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    entry = _runtime_entry(repository, "VALUE = 1\n")
    monkeypatch.setattr(
        TOOLCHAIN,
        "_RUNTIME_ENTRYPOINTS",
        ("scripts/entry.py",),
    )
    original_targets = TOOLCHAIN._local_literal_file_targets
    mutated = False

    def mutate_after_validation(*args, **kwargs):
        nonlocal mutated
        targets = original_targets(*args, **kwargs)
        if not mutated:
            intermediate = entry.with_name("case-swap-intermediate.py")
            entry.rename(intermediate)
            intermediate.rename(entry.with_name("Entry.py"))
            mutated = True
        return targets

    monkeypatch.setattr(
        TOOLCHAIN,
        "_local_literal_file_targets",
        mutate_after_validation,
    )
    with pytest.raises(
        TOOLCHAIN.ToolchainControlError,
        match="changed|drift|case|canonical",
    ):
        TOOLCHAIN.derive_runtime_dependency_closure(repository)


def test_runtime_path_index_rejects_concurrent_ancestor_link_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    scripts = repository / "scripts"
    _runtime_entry(repository, "VALUE = 1\n")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "entry.py").write_text(
        "VALUE = 2\n",
        encoding="utf-8",
        newline="\n",
    )
    probe = tmp_path / "symlink-probe"
    try:
        probe.symlink_to(outside, target_is_directory=True)
        probe.unlink()
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"directory symlink unavailable: {exc}")
    monkeypatch.setattr(
        TOOLCHAIN,
        "_RUNTIME_ENTRYPOINTS",
        ("scripts/entry.py",),
    )
    original_targets = TOOLCHAIN._local_literal_file_targets
    mutated = False

    def mutate_after_validation(*args, **kwargs):
        nonlocal mutated
        targets = original_targets(*args, **kwargs)
        if not mutated:
            scripts.rename(repository / "scripts-original")
            scripts.symlink_to(outside, target_is_directory=True)
            mutated = True
        return targets

    monkeypatch.setattr(
        TOOLCHAIN,
        "_local_literal_file_targets",
        mutate_after_validation,
    )
    with pytest.raises(
        TOOLCHAIN.ToolchainControlError,
        match="changed|drift|ancestor|symlink|reparse|junction",
    ):
        TOOLCHAIN.derive_runtime_dependency_closure(repository)


def test_full_repository_runtime_snapshot_derivation_is_stable_and_bounded(
    tmp_path: Path,
) -> None:
    snapshot = tmp_path / "runtime-snapshot"
    source_census = _copy_runtime_snapshot(ROOT, snapshot)

    started = time.monotonic()
    cpu_started = time.process_time()
    first = TOOLCHAIN.derive_runtime_dependency_closure(snapshot)
    first_elapsed = time.monotonic() - started
    first_cpu = time.process_time() - cpu_started
    started = time.monotonic()
    cpu_started = time.process_time()
    second = TOOLCHAIN.derive_runtime_dependency_closure(snapshot)
    second_elapsed = time.monotonic() - started
    second_cpu = time.process_time() - cpu_started

    assert len(first) >= 200
    assert first == second
    assert _snapshot_census(snapshot) == source_census
    assert first_elapsed < 45.0, (
        "first runtime derivation exceeded bound: "
        f"wall={first_elapsed:.3f}s cpu={first_cpu:.3f}s"
    )
    assert second_elapsed < 45.0, (
        "second runtime derivation exceeded bound: "
        f"wall={second_elapsed:.3f}s cpu={second_cpu:.3f}s"
    )
    assert first_cpu < 45.0, (
        "first runtime derivation exceeded CPU bound: "
        f"wall={first_elapsed:.3f}s cpu={first_cpu:.3f}s"
    )
    assert second_cpu < 45.0, (
        "second runtime derivation exceeded CPU bound: "
        f"wall={second_elapsed:.3f}s cpu={second_cpu:.3f}s"
    )
    closure_sha256 = hashlib.sha256(
        "".join(f"{relative}\n" for relative in first).encode("utf-8")
    ).hexdigest()
    print(
        "R4_RUNTIME_DERIVATION "
        f"snapshot_sha256={source_census} "
        f"closure_sha256={closure_sha256} "
        f"files={len(first)} "
        f"first_wall={first_elapsed:.6f} "
        f"first_cpu={first_cpu:.6f} "
        f"second_wall={second_elapsed:.6f} "
        f"second_cpu={second_cpu:.6f}"
    )


def test_live_root_directory_drift_is_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    _runtime_entry(repository, "VALUE = 1\n")
    monkeypatch.setattr(
        TOOLCHAIN,
        "_RUNTIME_ENTRYPOINTS",
        ("scripts/entry.py",),
    )
    original_targets = TOOLCHAIN._local_literal_file_targets
    mutated = False

    def mutate_root_after_validation(*args, **kwargs):
        nonlocal mutated
        targets = original_targets(*args, **kwargs)
        if not mutated:
            (repository / "concurrent-writer.txt").write_text(
                "drift\n",
                encoding="utf-8",
                newline="\n",
            )
            mutated = True
        return targets

    monkeypatch.setattr(
        TOOLCHAIN,
        "_local_literal_file_targets",
        mutate_root_after_validation,
    )
    with pytest.raises(
        TOOLCHAIN.ToolchainControlError,
        match="changed|drift|index",
    ):
        TOOLCHAIN.derive_runtime_dependency_closure(repository)
