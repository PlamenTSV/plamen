from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
import sys
import types
from unittest import mock

import pytest

import audit_snapshot as A


def _record_hash(path: Path) -> str:
    encoded = base64.urlsafe_b64encode(
        hashlib.sha256(path.read_bytes()).digest()
    ).decode("ascii").rstrip("=")
    return f"sha256={encoded}"


def _scheme_paths(data: Path, install: Path, scripts: Path) -> dict[str, str]:
    return {
        "data": str(data),
        "scripts": str(scripts),
        "purelib": str(install),
        "platlib": str(install),
    }


def _patch_scheme(
    monkeypatch: pytest.MonkeyPatch,
    data: Path,
    install: Path,
    scripts: Path,
) -> None:
    monkeypatch.setattr(A.sysconfig, "get_scheme_names", lambda: ("fixture",))
    monkeypatch.setattr(
        A.sysconfig,
        "get_paths",
        lambda *, scheme: _scheme_paths(data, install, scripts),
    )


class _FixtureDistribution:
    metadata = {"Name": "slither-analyzer"}

    def __init__(
        self,
        install: Path,
        files: tuple[Path, ...],
        *,
        retarget: Path | None = None,
    ) -> None:
        self._install = install
        self.files = files
        self.entry_points = (
            types.SimpleNamespace(
                group="console_scripts",
                name="slither",
                value="slither:main",
            ),
        )
        self._retarget = retarget

    def locate_file(self, relative: object) -> Path:
        normalized = str(relative).replace("\\", "/")
        if self._retarget is not None and normalized.startswith("../"):
            return self._retarget
        return Path(os.path.abspath(str(self._install / Path(normalized))))


def _fixture_tree(
    tmp_path: Path,
) -> tuple[Path, Path, Path, Path, _FixtureDistribution]:
    data = tmp_path / "private-runtime"
    install = data / "lib" / "python3.12" / "site-packages"
    scripts = data / ("Scripts" if os.name == "nt" else "bin")
    package = install / "slither"
    dist_info = install / "slither_analyzer-1.0.dist-info"
    package.mkdir(parents=True)
    dist_info.mkdir()
    scripts.mkdir()

    module = package / "__init__.py"
    metadata = dist_info / "METADATA"
    entry_points = dist_info / "entry_points.txt"
    script = scripts / ("slither.exe" if os.name == "nt" else "slither")
    module.write_bytes(b"VERSION = 'fixture'\n")
    metadata.write_bytes(b"Name: slither-analyzer\nVersion: 1.0\n")
    entry_points.write_bytes(b"[console_scripts]\nslither = slither:main\n")
    script.write_bytes(b"fixture console script\n")

    script_name = os.path.relpath(script, install).replace(os.sep, "/")
    names_and_paths = (
        ("slither/__init__.py", module),
        ("slither_analyzer-1.0.dist-info/METADATA", metadata),
        ("slither_analyzer-1.0.dist-info/entry_points.txt", entry_points),
        (script_name, script),
    )
    record_name = "slither_analyzer-1.0.dist-info/RECORD"
    record = dist_info / "RECORD"
    record.write_text(
        "".join(
            f"{name},{_record_hash(path)},{path.stat().st_size}\n"
            for name, path in names_and_paths
        )
        + f"{record_name},,\n",
        encoding="utf-8",
    )
    files = tuple(Path(name) for name, _path in names_and_paths) + (
        Path(record_name),
    )
    return data, install, scripts, module, _FixtureDistribution(install, files)


def test_exact_declared_scheme_script_is_in_full_record_closure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data, install, scripts, module, distribution = _fixture_tree(tmp_path)
    _patch_scheme(monkeypatch, data, install, scripts)
    A._PYTHON_DISTRIBUTION_CLOSURE_CACHE.clear()
    with mock.patch(
        "importlib.metadata.distributions", return_value=[distribution]
    ), mock.patch(
        "importlib.util.find_spec",
        return_value=types.SimpleNamespace(origin=str(module)),
    ):
        closure = A._python_distribution_closure(
            "slither-analyzer", "slither"
        )
    assert closure["record_member_file_count"] == len(distribution.files)
    assert closure["record_member_path_set_sha256"]


@pytest.mark.parametrize(
    "malicious",
    (
        "/tmp/slither",
        "C:/tmp/slither",
        "file:///tmp/slither",
        "https://example.invalid/slither",
        "../../../bin/%2e%2e/slither",
        "../../../bin/../outside/slither",
        "../../../../outside/slither",
        "../../../bin/SLITHER",
        "../../../bin/unlisted",
    ),
)
def test_parent_record_paths_are_not_general_traversal_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    malicious: str,
) -> None:
    data, install, scripts, _module, distribution = _fixture_tree(tmp_path)
    _patch_scheme(monkeypatch, data, install, scripts)
    with pytest.raises(A.SnapshotInputError):
        A._python_record_member_location(
            distribution,
            malicious,
            distribution="slither-analyzer",
            install_root=install,
            authority_root=data,
            scripts_root=scripts,
            declared_scripts=frozenset({"slither"}),
            lexical_validation_cache=set(),
            spelling_validation_cache=set(),
        )


def test_distribution_cannot_retarget_declared_script(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data, install, scripts, _module, distribution = _fixture_tree(tmp_path)
    _patch_scheme(monkeypatch, data, install, scripts)
    distribution._retarget = data / "other" / "slither"
    relative = os.path.relpath(
        scripts / ("slither.exe" if os.name == "nt" else "slither"), install
    ).replace(os.sep, "/")
    with pytest.raises(A.SnapshotInputError, match="retargeted"):
        A._python_record_member_location(
            distribution,
            relative,
            distribution="slither-analyzer",
            install_root=install,
            authority_root=data,
            scripts_root=scripts,
            declared_scripts=frozenset({"slither"}),
            lexical_validation_cache=set(),
            spelling_validation_cache=set(),
        )


def test_gui_api_entry_cannot_authorize_unrecorded_metadata_script(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data, install, scripts, module, distribution = _fixture_tree(tmp_path)
    _patch_scheme(monkeypatch, data, install, scripts)
    evil = scripts / ("evil.exe" if os.name == "nt" else "evil")
    evil.write_bytes(b"forged gui script\n")
    evil_name = os.path.relpath(evil, install).replace(os.sep, "/")
    record_name = "slither_analyzer-1.0.dist-info/RECORD"
    record = install / record_name
    record.write_text(
        record.read_text(encoding="utf-8").replace(
            f"{record_name},,\n",
            f"{evil_name},{_record_hash(evil)},{evil.stat().st_size}\n"
            f"{record_name},,\n",
        ),
        encoding="utf-8",
    )
    distribution.files = (
        *distribution.files[:-1],
        Path(evil_name),
        distribution.files[-1],
    )
    distribution.entry_points = (
        *distribution.entry_points,
        types.SimpleNamespace(
            group="gui_scripts",
            name="evil",
            value="attacker:main",
        ),
    )
    A._PYTHON_DISTRIBUTION_CLOSURE_CACHE.clear()
    with mock.patch(
        "importlib.metadata.distributions", return_value=[distribution]
    ), mock.patch(
        "importlib.util.find_spec",
        return_value=types.SimpleNamespace(origin=str(module)),
    ), pytest.raises(A.SnapshotInputError, match="exact declared script"):
        A._python_distribution_closure("slither-analyzer", "slither")


def test_windows_shaped_install_requires_an_exact_sysconfig_scheme(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install = tmp_path / "detached-runtime" / "Lib" / "site-packages"
    install.mkdir(parents=True)
    monkeypatch.setattr(A.sysconfig, "get_scheme_names", lambda: ())
    with pytest.raises(A.SnapshotInputError, match="one interpreter scheme"):
        A._python_distribution_install_namespace(install)


@pytest.mark.skipif(os.name == "nt", reason="POSIX hardlink rejection")
def test_full_closure_rejects_script_symlink_or_hardlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data, install, scripts, module, distribution = _fixture_tree(tmp_path)
    _patch_scheme(monkeypatch, data, install, scripts)
    script = scripts / "slither"
    original = script.read_bytes()
    script.unlink()
    target = data / "script-target"
    target.write_bytes(original)
    script.symlink_to(target)
    with mock.patch(
        "importlib.metadata.distributions", return_value=[distribution]
    ), mock.patch(
        "importlib.util.find_spec",
        return_value=types.SimpleNamespace(origin=str(module)),
    ), pytest.raises(A.SnapshotInputError, match="link"):
        A._python_distribution_closure("slither-analyzer", "slither")

    script.unlink()
    script.write_bytes(original)
    alias = data / "script-hardlink-alias"
    os.link(script, alias)
    with mock.patch(
        "importlib.metadata.distributions", return_value=[distribution]
    ), mock.patch(
        "importlib.util.find_spec",
        return_value=types.SimpleNamespace(origin=str(module)),
    ), pytest.raises(A.SnapshotInputError, match="hardlink"):
        A._python_distribution_closure("slither-analyzer", "slither")


def test_installed_packages_accepts_default_scheme_outside_sys_prefix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prefix = tmp_path / "opt" / "framework-python"
    data = tmp_path / "package-manager-prefix"
    purelib = data / "lib" / "python" / "site-packages"
    prefix.mkdir(parents=True)
    purelib.mkdir(parents=True)
    observed: list[tuple[str, ...]] = []

    def distributions(*, path: tuple[str, ...]) -> tuple[object, ...]:
        observed.append(path)
        return ()

    monkeypatch.setattr(sys, "prefix", str(prefix))
    monkeypatch.setattr(
        A.sysconfig,
        "get_paths",
        lambda: {
            "data": str(data),
            "purelib": str(purelib),
            "platlib": str(purelib),
        },
    )
    with mock.patch("importlib.metadata.distributions", distributions):
        assert A._installed_python_packages() == b"[]"
    assert observed == [(str(purelib),)]


def test_installed_packages_rejects_default_scheme_escape(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = tmp_path / "private-runtime"
    outside = tmp_path / "outside" / "site-packages"
    data.mkdir()
    outside.mkdir(parents=True)
    monkeypatch.setattr(
        A.sysconfig,
        "get_paths",
        lambda: {
            "data": str(data),
            "purelib": str(outside),
            "platlib": str(outside),
        },
    )
    with pytest.raises(A.SnapshotInputError, match="unreadable"):
        A._installed_python_packages()
