from __future__ import annotations

import platform
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

import claude_provider_preparation as P


_PRESERVE_UNAME = object()


def _unexpected_probe(*_args: object, **_kwargs: object) -> object:
    raise AssertionError("an unreviewed runtime host probe was called")


def _host(
    monkeypatch: pytest.MonkeyPatch,
    *,
    os_name: object,
    sys_platform: object,
    release: object = "6.8.0-generic",
) -> str:
    monkeypatch.setattr(P.os, "name", os_name)
    monkeypatch.setattr(P.sys, "platform", sys_platform)
    if release is not _PRESERVE_UNAME:
        monkeypatch.setattr(
            P.os,
            "uname",
            lambda: SimpleNamespace(release=release),
            raising=False,
        )
    monkeypatch.setattr(platform, "system", _unexpected_probe)
    monkeypatch.setattr(platform, "release", _unexpected_probe)
    return P._detect_host_family()


@pytest.mark.parametrize(
    ("os_name", "sys_platform", "release", "expected"),
    (
        ("nt", "win32", None, "windows"),
        ("posix", "darwin", None, "macos"),
        ("posix", "linux", "6.8.0-generic", "linux"),
        ("posix", "linux2", "6.6.87-linuxkit", "linux"),
        (
            "posix",
            "linux",
            "4.4.0-19041-Microsoft",
            "wsl2",
        ),
        (
            "posix",
            "linux",
            "5.15.153.1-MICROSOFT-standard-WSL2",
            "wsl2",
        ),
        ("posix", "linux", "6.1.0-wSl-custom", "wsl2"),
        ("posix", "linux", "6.8.0-Microsoft-standard", "wsl2"),
        ("posix", "linux", "6.8.0-WSL1-custom", "wsl2"),
        ("posix", "linux", "6.8.0-WSL2-custom", "wsl2"),
        ("posix", "linux", "6.8.0-newsletter", "linux"),
        ("posix", "linux", "6.8.0-microsoftish", "linux"),
        ("posix", "linux", "6.8.0-notwsl", "linux"),
        ("posix", "linux", "6.8.0-custom-native-linux", "linux"),
        ("posix", "linux", "6.8.0-prewsl2", "linux"),
        ("posix", "linux", "6.8.0-wsl2post", "linux"),
        ("posix", "linux", "6.8.0-WSL3-custom", "linux"),
        ("posix", "linux", "6.8.0-Microsoft2-custom", "linux"),
        ("posix", "linux", "6.8.0-xMicrosoft-custom", "linux"),
    ),
)
def test_supported_host_classification_uses_only_closed_world_inputs(
    monkeypatch: pytest.MonkeyPatch,
    os_name: object,
    sys_platform: object,
    release: object,
    expected: str,
) -> None:
    assert _host(
        monkeypatch,
        os_name=os_name,
        sys_platform=sys_platform,
        release=release,
    ) == expected


@pytest.mark.parametrize(
    ("os_name", "sys_platform"),
    (
        ("nt", "linux"),
        ("nt", "darwin"),
        ("posix", "win32"),
        ("java", "linux"),
        ("", "linux"),
        (None, "linux"),
        ("posix", None),
    ),
)
def test_contradictory_or_unknown_host_pair_fails_closed_without_linux_probe(
    monkeypatch: pytest.MonkeyPatch,
    os_name: object,
    sys_platform: object,
) -> None:
    monkeypatch.setattr(P.os, "name", os_name)
    monkeypatch.setattr(P.sys, "platform", sys_platform)
    monkeypatch.setattr(P.os, "uname", _unexpected_probe, raising=False)
    monkeypatch.setattr(P, "_read_linux_osrelease", _unexpected_probe)
    monkeypatch.setattr(platform, "system", _unexpected_probe)
    monkeypatch.setattr(platform, "release", _unexpected_probe)

    assert P._detect_host_family() == "unsupported"


@pytest.mark.parametrize(
    ("release", "expected"),
    (
        ("6.8.12-generic\n", "linux"),
        ("4.4.0-19041-Microsoft\n", "wsl2"),
        ("5.15.153.1-microsoft-standard-WSL2\n", "wsl2"),
    ),
)
def test_linux_uname_failure_uses_bounded_regular_proc_fallback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    release: str,
    expected: str,
) -> None:
    osrelease = tmp_path / "kernel-osrelease"
    osrelease.write_text(release, encoding="ascii", newline="")
    monkeypatch.setattr(P, "_LINUX_OSRELEASE_PATH", osrelease)
    monkeypatch.setattr(
        P.os,
        "uname",
        lambda: (_ for _ in ()).throw(OSError("unavailable")),
        raising=False,
    )

    assert _host(
        monkeypatch,
        os_name="posix",
        sys_platform="linux",
        release=_PRESERVE_UNAME,
    ) == expected


def test_linux_fallback_rejects_oversized_proc_value(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    osrelease = tmp_path / "oversized-osrelease"
    osrelease.write_bytes(b"x" * (P._MAX_LINUX_OSRELEASE_BYTES + 1))
    monkeypatch.setattr(P, "_LINUX_OSRELEASE_PATH", osrelease)
    monkeypatch.setattr(
        P.os,
        "uname",
        lambda: (_ for _ in ()).throw(OSError("unavailable")),
        raising=False,
    )

    assert _host(
        monkeypatch,
        os_name="posix",
        sys_platform="linux",
        release=_PRESERVE_UNAME,
    ) == "unsupported"


def test_linux_fallback_rejects_nonregular_proc_value(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(P, "_LINUX_OSRELEASE_PATH", tmp_path)
    monkeypatch.setattr(
        P.os,
        "uname",
        lambda: (_ for _ in ()).throw(OSError("unavailable")),
        raising=False,
    )

    assert _host(
        monkeypatch,
        os_name="posix",
        sys_platform="linux",
        release=_PRESERVE_UNAME,
    ) == "unsupported"


def test_linux_fallback_rejects_symlink_before_open(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    osrelease = tmp_path / "kernel-osrelease"
    osrelease.write_text("6.8.0-generic", encoding="ascii")
    monkeypatch.setattr(P, "_LINUX_OSRELEASE_PATH", osrelease)
    real_lstat = P.os.lstat

    def fake_lstat(path: object) -> object:
        observed = real_lstat(path)
        return SimpleNamespace(
            st_mode=stat.S_IFLNK | 0o777,
            st_dev=observed.st_dev,
            st_ino=observed.st_ino,
        )

    monkeypatch.setattr(P.os, "lstat", fake_lstat)
    monkeypatch.setattr(P.os, "open", _unexpected_probe)
    monkeypatch.setattr(
        P.os,
        "uname",
        lambda: (_ for _ in ()).throw(OSError("unavailable")),
        raising=False,
    )

    assert _host(
        monkeypatch,
        os_name="posix",
        sys_platform="linux",
        release=_PRESERVE_UNAME,
    ) == "unsupported"


def test_linux_invalid_uname_release_fails_closed_without_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(P, "_read_linux_osrelease", _unexpected_probe)
    assert _host(
        monkeypatch,
        os_name="posix",
        sys_platform="linux",
        release=None,
    ) == "unsupported"
