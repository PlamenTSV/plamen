"""Independent R2 blocker reproductions for CI/toolchain authority.

These fixtures begin red against the independently reviewed R2 boundary. They
must not be weakened into self-consistency checks over derived artifacts.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace
import tarfile

import pytest

import ci_dependency_authority as AUTH
import plamen as INSTALLER
import test_ci_dependency_authority_r2 as R2
import test_public_packaging_freeze as PUBLIC_PACKAGE
import toolchain_control_authority as TOOLCHAIN


ROOT = Path(__file__).resolve().parents[1]
def _validation_now() -> datetime:
    """Use a live aware clock so refreshed evidence reaches the intended seam."""

    return datetime.now(timezone.utc)


def _write_json(path: Path, payload: object) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _render_receipt(repository: Path) -> None:
    (repository / AUTH.RECEIPT_PATH).write_bytes(
        AUTH.render_receipt(repository)
    )


def _exact_resolver_distributions() -> list[SimpleNamespace]:
    return [
        SimpleNamespace(metadata={"Name": name}, version=row.version)
        for name, row in AUTH.parse_lock(
            ROOT / "requirements-ci-resolver.lock"
        ).items()
    ]


def _install_ambient_fake_piptools(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    lock_source: Path,
) -> Path:
    ambient = tmp_path / "ambient"
    package = ambient / "piptools"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text(
        '"""Uninstalled hostile fixture package."""\n',
        encoding="utf-8",
        newline="\n",
    )
    (package / "__main__.py").write_text(
        "from pathlib import Path\n"
        "import os\n"
        "import shutil\n"
        "import sys\n"
        "args = sys.argv[1:]\n"
        "index = args.index('--output-file')\n"
        "output = Path(args[index + 1])\n"
        "shutil.copy2(os.environ['PLAMEN_FAKE_LOCK_SOURCE'], output)\n"
        "Path(os.environ['PLAMEN_FAKE_PIPTOOLS_MARKER']).write_text(\n"
        "    'FAKE_PIPTOOLS_EXECUTED\\n', encoding='ascii'\n"
        ")\n",
        encoding="utf-8",
        newline="\n",
    )
    marker = tmp_path / "fake-piptools-executed.txt"
    monkeypatch.setenv("PYTHONPATH", str(ambient))
    monkeypatch.setenv(
        "PLAMEN_FAKE_LOCK_SOURCE", str(lock_source.resolve())
    )
    monkeypatch.setenv("PLAMEN_FAKE_PIPTOOLS_MARKER", str(marker))
    monkeypatch.setattr(
        AUTH.importlib.metadata,
        "distributions",
        _exact_resolver_distributions,
    )
    return marker


def test_resolver_never_executes_ambient_pythonpath_piptools(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = _install_ambient_fake_piptools(
        tmp_path,
        monkeypatch,
        lock_source=ROOT / "requirements-ci.lock",
    )
    try:
        regenerated = AUTH.regenerate_lock_bytes(ROOT)
    except AUTH.CIDependencyAuthorityError:
        assert not marker.exists(), (
            "ambient fake piptools executed before resolver rejection"
        )
        return
    assert regenerated == (ROOT / "requirements-ci.lock").read_bytes()
    assert not marker.exists(), (
        "FALSE_ACCEPTED_PYTHONPATH_RESOLVER: ambient fake piptools executed"
    )


def test_ambient_fake_resolver_cannot_authorize_marker_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = R2._copy_authority(tmp_path)
    lock = repository / "requirements-ci.lock"
    original = lock.read_text(encoding="utf-8")
    mutated = original.replace(
        'platform_system == "Windows"',
        'sys_platform == "win32"',
        1,
    )
    assert mutated != original
    lock.write_text(mutated, encoding="utf-8", newline="\n")
    _render_receipt(repository)
    marker = _install_ambient_fake_piptools(
        tmp_path,
        monkeypatch,
        lock_source=lock,
    )
    try:
        AUTH.verify_repository(repository, now=_validation_now())
    except AUTH.CIDependencyAuthorityError:
        assert not marker.exists(), (
            "ambient fake piptools executed before marker drift rejection"
        )
        return
    pytest.fail(
        "FALSE_ACCEPTED_INPUT_UNBOUND_MARKER_DRIFT: "
        f"fake_executed={marker.exists()}"
    )


def _assert_full_verifier_rejects(repository: Path, label: str) -> None:
    try:
        AUTH.verify_repository(
            repository,
            now=_validation_now(),
            regenerate_lock=False,
        )
    except AUTH.CIDependencyAuthorityError:
        return
    pytest.fail(f"FALSE_ACCEPTED_{label}")


def _rewrite_raw_release(
    repository: Path,
    project: str,
    mutate,
) -> None:
    evidence_path = repository / AUTH.RELEASE_EVIDENCE_PATH
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    response = evidence["responses"][project]
    raw_path = repository / response["raw_path"]
    payload = json.loads(raw_path.read_text(encoding="utf-8"))
    mutate(payload)
    raw = AUTH._compact_json_bytes(payload)
    raw_path.write_bytes(raw)
    response["raw_sha256"] = hashlib.sha256(raw).hexdigest()
    response["canonical_response_sha256"] = hashlib.sha256(
        AUTH._compact_json_bytes(payload)
    ).hexdigest()
    artifacts: dict[str, str] = {}
    metadata: dict[str, dict] = {}
    for row in payload["urls"]:
        if row.get("packagetype") != "bdist_wheel":
            continue
        filename = row["filename"]
        artifacts[filename] = row["digests"]["sha256"]
        metadata[filename] = {
            "requires_python": row.get("requires_python"),
            "url": row["url"],
            "yanked": row["yanked"],
        }
    evidence["releases"][project] = {
        "artifact_metadata": dict(sorted(metadata.items())),
        "artifacts": dict(sorted(artifacts.items())),
        "requires_python": payload["info"].get("requires_python") or "",
        "response_sha256": response["raw_sha256"],
        "version": response["version"],
    }
    evidence["response_set_sha256"] = hashlib.sha256(
        AUTH._canonical_json_bytes(evidence["responses"])
    ).hexdigest()
    _write_json(evidence_path, evidence)
    _render_receipt(repository)


def test_rejects_fabricated_compatible_filename_with_other_platform_digest(
    tmp_path: Path,
) -> None:
    repository = R2._copy_authority(tmp_path)
    policy_path = repository / AUTH.POLICY_PATH
    evidence_path = repository / AUTH.RELEASE_EVIDENCE_PATH
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    artifact = R2._target_artifact(policy)
    assert artifact["filename"].endswith(
        "manylinux_2_17_x86_64.manylinux2014_x86_64.whl"
    )
    windows_filename = (
        "pydantic_core-2.46.4-cp312-cp312-win_amd64.whl"
    )
    windows_digest = evidence["releases"]["pydantic-core"]["artifacts"][
        windows_filename
    ]
    assert windows_digest in AUTH.parse_lock(
        repository / "requirements-ci.lock"
    )["pydantic-core"].hashes
    artifact["sha256"] = windows_digest
    evidence["releases"]["pydantic-core"]["artifacts"][
        artifact["filename"]
    ] = windows_digest
    _write_json(policy_path, policy)
    _write_json(evidence_path, evidence)
    _render_receipt(repository)
    _assert_full_verifier_rejects(
        repository,
        "FABRICATED_WHEEL_FILENAME_DIGEST_PLATFORM_BINDING",
    )


def test_rejects_requires_python_changed_under_unchanged_response_digest(
    tmp_path: Path,
) -> None:
    repository = R2._copy_authority(tmp_path)
    evidence_path = repository / AUTH.RELEASE_EVIDENCE_PATH
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    before = evidence["releases"]["rich"]["response_sha256"]
    evidence["releases"]["rich"]["requires_python"] = ">=3.11"
    assert evidence["releases"]["rich"]["response_sha256"] == before
    _write_json(evidence_path, evidence)
    _render_receipt(repository)
    _assert_full_verifier_rejects(
        repository,
        "UNBOUND_REQUIRES_PYTHON",
    )


def test_rejects_recomputed_false_pypi_response_digest_graph(
    tmp_path: Path,
) -> None:
    repository = R2._copy_authority(tmp_path)
    evidence_path = repository / AUTH.RELEASE_EVIDENCE_PATH
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    evidence["responses"]["rich"] = "1" * 64
    evidence["releases"]["rich"]["response_sha256"] = "1" * 64
    evidence["response_set_sha256"] = hashlib.sha256(
        AUTH._canonical_json_bytes(evidence["responses"])
    ).hexdigest()
    _write_json(evidence_path, evidence)
    _render_receipt(repository)
    _assert_full_verifier_rejects(
        repository,
        "ARBITRARY_PYPI_RESPONSE_DIGEST",
    )


def test_rejects_arbitrary_osv_source_response_digest(
    tmp_path: Path,
) -> None:
    repository = R2._copy_authority(tmp_path)
    evidence_path = repository / AUTH.ADVISORY_EVIDENCE_PATH
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    evidence["source_response_sha256"] = "0" * 64
    _write_json(evidence_path, evidence)
    _render_receipt(repository)
    _assert_full_verifier_rejects(
        repository,
        "ARBITRARY_OSV_SOURCE_RESPONSE_DIGEST",
    )


@pytest.mark.parametrize(
    "url_factory",
    [
        lambda filename: f"https://example.invalid/{filename}",
        lambda filename: f"http://files.pythonhosted.org/{filename}",
        lambda filename: f"https://files.pythonhosted.org/{filename}.other",
        lambda filename: (
            f"https://files.pythonhosted.org/{filename}?mirror=1"
        ),
        lambda filename: (
            f"https://user@files.pythonhosted.org/{filename}"
        ),
        lambda filename: (
            f"https://files.pythonhosted.org:444/{filename}"
        ),
    ],
)
def test_raw_release_rejects_each_url_identity_drift(
    tmp_path: Path,
    url_factory,
) -> None:
    repository = R2._copy_authority(tmp_path)

    def mutate(payload: dict) -> None:
        wheel = next(
            row
            for row in payload["urls"]
            if row.get("packagetype") == "bdist_wheel"
        )
        wheel["url"] = url_factory(wheel["filename"])

    _rewrite_raw_release(repository, "rich", mutate)
    _assert_full_verifier_rejects(repository, "RAW_WHEEL_URL_IDENTITY")


def test_raw_release_rejects_duplicate_filename_before_normalization(
    tmp_path: Path,
) -> None:
    repository = R2._copy_authority(tmp_path)

    def mutate(payload: dict) -> None:
        wheel = next(
            row
            for row in payload["urls"]
            if row.get("packagetype") == "bdist_wheel"
        )
        payload["urls"].append(dict(wheel))

    _rewrite_raw_release(repository, "rich", mutate)
    _assert_full_verifier_rejects(repository, "DUPLICATE_RAW_WHEEL")


@pytest.mark.parametrize("axis", ["project", "file"])
def test_raw_release_rejects_invalid_requires_python(
    tmp_path: Path,
    axis: str,
) -> None:
    repository = R2._copy_authority(tmp_path)

    def mutate(payload: dict) -> None:
        if axis == "project":
            payload["info"]["requires_python"] = "=>3.12"
        else:
            wheel = next(
                row
                for row in payload["urls"]
                if row.get("packagetype") == "bdist_wheel"
            )
            wheel["requires_python"] = "=>3.12"

    _rewrite_raw_release(repository, "rich", mutate)
    _assert_full_verifier_rejects(
        repository,
        f"INVALID_{axis.upper()}_REQUIRES_PYTHON",
    )


@pytest.mark.parametrize("directory", ["pypi", "osv"])
def test_raw_response_directories_reject_extra_entries(
    tmp_path: Path,
    directory: str,
) -> None:
    repository = R2._copy_authority(tmp_path)
    target = (
        repository / AUTH.RELEASE_RESPONSE_DIR
        if directory == "pypi"
        else repository / AUTH.ADVISORY_REQUEST_PATH.parent
    )
    (target / "unreviewed.json").write_text(
        "{}\n",
        encoding="utf-8",
        newline="\n",
    )
    _render_receipt(repository)
    _assert_full_verifier_rejects(
        repository,
        f"EXTRA_{directory.upper()}_RAW_ENTRY",
    )


def test_semantic_workflow_scan_rejects_quoted_mutable_uses_key(
    tmp_path: Path,
) -> None:
    repository = R2._copy_authority(tmp_path)
    workflow = repository / ".github" / "workflows" / "tests.yml"
    original = workflow.read_text(encoding="utf-8")
    mutated = original.replace(
        (
            "- uses: actions/checkout@"
            "3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1"
        ),
        '- "uses": actions/checkout@v4',
        1,
    )
    assert mutated != original
    workflow.write_text(mutated, encoding="utf-8", newline="\n")
    with pytest.raises(
        AUTH.CIDependencyAuthorityError,
        match="workflow.*Action|Action.*workflow",
    ):
        AUTH.verify_static_bindings(repository)


def test_semantic_workflow_scan_accepts_quoted_inline_and_run_text(
    tmp_path: Path,
) -> None:
    repository = R2._copy_authority(tmp_path)
    policy = json.loads(
        (repository / AUTH.POLICY_PATH).read_text(encoding="utf-8")
    )
    actions = {
        row["name"]: row["commit_sha"]
        for row in policy["github_actions"]
    }
    workflow = repository / ".github" / "workflows" / "tests.yml"
    workflow.write_text(
        "name: semantic-fixture\n"
        "on: [push]\n"
        "jobs:\n"
        "  reusable-location:\n"
        f"    'uses': 'actions/checkout@{actions['actions/checkout']}'\n"
        "  steps-location:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        f"      - {{\"uses\": \"actions/setup-python@{actions['actions/setup-python']}\"}}\n"
        "      - run: |\n"
        "          echo 'uses: unreviewed/action@main'\n"
        f"      - 'uses': 'actions/dependency-review-action@{actions['actions/dependency-review-action']}'\n",
        encoding="utf-8",
        newline="\n",
    )
    AUTH.verify_workflow_action_bindings(repository)


@pytest.mark.parametrize("axis", ["duplicate", "merge", "alias"])
def test_semantic_workflow_scan_rejects_yaml_graph_ambiguity(
    tmp_path: Path,
    axis: str,
) -> None:
    repository = R2._copy_authority(tmp_path)
    workflow = repository / ".github" / "workflows" / "tests.yml"
    original = workflow.read_text(encoding="utf-8")
    if axis == "duplicate":
        mutated = original.replace(
            "name: tests",
            "name: tests\nname: duplicate",
            1,
        )
    elif axis == "merge":
        mutated = original.replace(
            "jobs:",
            "defaults: &defaults\n  runs-on: ubuntu-latest\n"
            "merged:\n  <<: *defaults\njobs:",
            1,
        )
    else:
        mutated = original.replace(
            "jobs:",
            "anchored: &shared\n  value: one\n"
            "aliased: *shared\njobs:",
            1,
        )
    workflow.write_text(mutated, encoding="utf-8", newline="\n")
    with pytest.raises(AUTH.CIDependencyAuthorityError):
        AUTH.verify_workflow_action_bindings(repository)


def test_bootstrap_child_environment_drops_all_python_and_pip_injection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    poisoned = {
        "PYTHONPATH": str(tmp_path / "pythonpath"),
        "PYTHONHOME": str(tmp_path / "pythonhome"),
        "PYTHONUSERBASE": str(tmp_path / "userbase"),
        "VIRTUAL_ENV": str(tmp_path / "ambient-venv"),
        "PIP_REQUIRE_VIRTUALENV": "0",
        "PIP_TOOLS_CACHE_DIR": str(tmp_path / "pip-tools-cache"),
        "CUSTOM_COMPILE_COMMAND": "hostile",
    }
    for key, value in poisoned.items():
        monkeypatch.setenv(key, value)
    child = AUTH._bootstrap_environment(
        tmp_path,
        "https://pypi.org/simple",
    )
    upper = {key.upper() for key in child}
    assert not (
        set(poisoned)
        & upper
    )
    assert child["PYTHONNOUSERSITE"] == "1"
    assert child["PIP_CONFIG_FILE"] == os.devnull


def test_governed_child_diagnostics_decode_non_ascii_as_utf8(
    tmp_path: Path,
) -> None:
    completed = AUTH._run_utf8_diagnostic(
        [
            sys.executable,
            "-I",
            "-c",
            "import os; os.write(2, b'diagnostic-\\xcf\\x80')",
        ],
        cwd=tmp_path,
        env=AUTH._bootstrap_environment(
            tmp_path,
            "https://pypi.org/simple",
        ),
    )
    assert completed.returncode == 0
    assert completed.stderr == "diagnostic-π"


def test_runtime_closure_includes_known_dynamic_code_and_data_consumers() -> None:
    required = set(TOOLCHAIN.derive_runtime_dependency_closure(ROOT))
    expected = {
        "scripts/spike_mechanical_poc.py",
        "rules/language-toolchain-registry.json",
        "requirements.txt",
    }
    assert expected <= required, (
        "generated oracle omits known runtime consumers: "
        f"{sorted(expected - required)}"
    )


def test_runtime_module_bound_applies_after_governed_candidate_filter(
    tmp_path: Path,
) -> None:
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    for ordinal in range(819):
        (scripts / f"test_fixture_{ordinal:04d}.py").write_text(
            "# excluded test fixture\n", encoding="utf-8", newline="\n"
        )
    for ordinal in range(219):
        (scripts / f"runtime_{ordinal:04d}.py").write_text(
            "VALUE = 1\n", encoding="utf-8", newline="\n"
        )
    index = TOOLCHAIN._RuntimePathIndex(tmp_path)
    modules = TOOLCHAIN._runtime_module_map(tmp_path, path_index=index)
    index.verify_unchanged()
    assert len(list(scripts.glob("*.py"))) == 1_038
    assert len({path for path in modules.values()}) == 219
    assert all(not Path(path).name.startswith("test_") for path in modules.values())


def test_runtime_module_bound_still_rejects_too_many_governed_candidates(
    tmp_path: Path,
) -> None:
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    for ordinal in range(1_025):
        (scripts / f"runtime_{ordinal:04d}.py").write_text(
            "VALUE = 1\n", encoding="utf-8", newline="\n"
        )
    with pytest.raises(
        TOOLCHAIN.ToolchainControlError,
        match="local module denominator exceeds its bound",
    ):
        TOOLCHAIN._runtime_module_map(
            tmp_path,
            path_index=TOOLCHAIN._RuntimePathIndex(tmp_path),
        )


def test_runtime_closure_resolves_literal_dynamic_import_calls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    literal_root = tmp_path / "literal"
    literal_scripts = literal_root / "scripts"
    literal_scripts.mkdir(parents=True)
    (literal_scripts / "entry.py").write_text(
        "import importlib\n"
        'importlib.import_module("selected")\n',
        encoding="utf-8",
        newline="\n",
    )
    for name in ("selected", "unselected"):
        (literal_scripts / f"{name}.py").write_text(
            f'NAME = "{name}"\n',
            encoding="utf-8",
            newline="\n",
        )
    monkeypatch.setattr(
        TOOLCHAIN,
        "_RUNTIME_ENTRYPOINTS",
        ("scripts/entry.py",),
    )
    literal = set(
        TOOLCHAIN.derive_runtime_dependency_closure(literal_root)
    )
    assert "scripts/selected.py" in literal
    assert "scripts/unselected.py" not in literal

    unresolved_root = tmp_path / "unresolved"
    unresolved_scripts = unresolved_root / "scripts"
    unresolved_scripts.mkdir(parents=True)
    (unresolved_scripts / "entry.py").write_text(
        "import importlib\n"
        'name = "dynamic_c"\n'
        "loaded = importlib.import_module(name)\n",
        encoding="utf-8",
        newline="\n",
    )
    (unresolved_scripts / "dynamic_c.py").write_text(
        'NAME = "dynamic-stage-pass"\n',
        encoding="utf-8",
        newline="\n",
    )
    external = unresolved_root / "unbounded-external-tree"
    external.mkdir()
    (external / "not_a_local_module.py").write_text(
        "RAISE_IF_PACKAGED = True\n",
        encoding="utf-8",
        newline="\n",
    )
    unresolved = set(
        TOOLCHAIN.derive_runtime_dependency_closure(unresolved_root)
    )
    assert "scripts/dynamic_c.py" in unresolved
    assert all(
        not relative.startswith("unbounded-external-tree/")
        for relative in unresolved
    )

    stage = tmp_path / "stage"
    for relative in sorted(unresolved):
        source = unresolved_root / relative
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
                "print(entry.loaded.NAME)"
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


def test_extracted_archive_doctor_names_each_known_outside_oracle_omission(
    tmp_path: Path,
) -> None:
    archive = PUBLIC_PACKAGE._temporary_public_archive(tmp_path)
    extracted = tmp_path / "extracted"
    extracted.mkdir()
    with tarfile.open(archive, "r") as package:
        package.extractall(extracted, filter="data")
    assert INSTALLER._toolchain_runtime_required_missing(extracted) == []

    for relative in (
        "scripts/spike_mechanical_poc.py",
        "rules/language-toolchain-registry.json",
        "requirements.txt",
    ):
        path = extracted / relative
        content = path.read_bytes()
        path.unlink()
        assert INSTALLER._toolchain_runtime_required_missing(extracted) == [
            relative
        ]
        path.write_bytes(content)
