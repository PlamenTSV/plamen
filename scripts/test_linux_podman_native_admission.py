from __future__ import annotations

import ctypes
import hashlib
import json
from pathlib import Path
import platform
import subprocess

import pytest

try:
    from scripts import podman_linux_provider as provider_projection
    from scripts import podman_supervisor_adapter as adapter_projection
except ImportError:
    import podman_linux_provider as provider_projection
    import podman_supervisor_adapter as adapter_projection


ROOT = Path(__file__).resolve().parent.parent
MANIFEST = "sha256:" + "2" * 64
INDEX = "sha256:" + "3" * 64
CONFIG = "sha256:" + "4" * 64
REFERENCE = "localhost/plamen/runtime@" + MANIFEST


@pytest.fixture(scope="module")
def library(tmp_path_factory: pytest.TempPathFactory) -> ctypes.CDLL:
    suffix = ".dylib" if platform.system() == "Darwin" else ".so"
    output = tmp_path_factory.mktemp("podman-native-admission") / ("admission" + suffix)
    compiler = "/usr/bin/clang" if platform.system() == "Darwin" else "cc"
    command = [
        compiler,
        "-std=c11",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-DPLAMEN_BROKER_V2_PODMAN_ADMISSION_TEST_ONLY=1",
        "-I",
        str(ROOT / "native" / "linux"),
    ]
    if platform.system() == "Darwin":
        command.append("-dynamiclib")
    else:
        command.extend(["-shared", "-fPIC"])
    command.extend(
        [
            str(
                ROOT
                / "native"
                / "linux"
                / "plamen_broker_v2_podman_admission.c"
            ),
            str(ROOT / "native" / "posix" / "plamen_broker_v2_protocol.c"),
            "-o",
            str(output),
        ]
    )
    if platform.system() == "Linux":
        command.append("-lcrypto")
    subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
    )
    loaded = ctypes.CDLL(str(output))
    loaded.plamen_broker_v2_podman_test_validate_component_version.argtypes = [
        ctypes.c_uint32,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_void_p,
    ]
    loaded.plamen_broker_v2_podman_test_validate_image.argtypes = [
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    loaded.plamen_broker_v2_podman_test_render_read_command.argtypes = [
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_int),
        ctypes.POINTER(ctypes.c_int),
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    loaded.plamen_broker_v2_podman_admit.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    loaded.plamen_broker_v2_podman_open_beneath.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_uint,
    ]
    loaded.plamen_broker_v2_podman_test_relative_path_valid.argtypes = [
        ctypes.c_char_p
    ]
    loaded.plamen_broker_v2_podman_test_receipt_integrity.argtypes = []
    return loaded


def _digest(raw: bytes) -> ctypes.Array[ctypes.c_ubyte]:
    return (ctypes.c_ubyte * 32).from_buffer_copy(hashlib.sha256(raw).digest())


def _image(*, architecture: str = "arm64", reference: str = REFERENCE) -> bytes:
    return json.dumps(
        {
            "id": "sha256:" + "1" * 64,
            "digest": MANIFEST,
            "os": "linux",
            "architecture": architecture,
            "repo_digests": [reference],
        },
        separators=(",", ":"),
    ).encode("ascii")


@pytest.mark.parametrize(
    ("role", "line"),
    [
        (0, "podman version 6.1.1"),
        (1, "conmon version 2.2.1"),
        (2, "crun version 1.28"),
        (5, "fuse-overlayfs: version 1.17"),
        (6, "systemd 258"),
    ],
)
def test_exact_component_version_transcripts_are_digest_bound(
    library: ctypes.CDLL, role: int, line: str
) -> None:
    raw = (line + "\n").encode("ascii")
    assert (
        library.plamen_broker_v2_podman_test_validate_component_version(
            role, raw, len(raw), line.encode("ascii"), _digest(raw)
        )
        == 0
    )
    mutated = raw.replace(b"1", b"9", 1) if b"1" in raw else raw + b"x"
    assert (
        library.plamen_broker_v2_podman_test_validate_component_version(
            role, mutated, len(mutated), line.encode("ascii"), _digest(raw)
        )
        != 0
    )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda raw: raw + b"{}",
        lambda raw: raw.replace(b'"os":"linux"', b'"os":"darwin"'),
        lambda raw: raw.replace(b'"architecture":"arm64"', b'"architecture":"amd64"'),
        lambda raw: raw.replace(b'"digest":', b'"unknown":', 1),
        lambda raw: raw.replace(b'"repo_digests":[', b'"repo_digests":["other@sha256:' + b"5" * 64 + b'",'),
    ],
)
def test_image_inspect_parser_rejects_schema_platform_and_roster_drift(
    library: ctypes.CDLL, mutation
) -> None:
    raw = _image()
    changed = mutation(raw)
    assert (
        library.plamen_broker_v2_podman_test_validate_image(
            changed,
            len(changed),
            REFERENCE.encode("ascii"),
            MANIFEST.encode("ascii"),
            2,
            _digest(changed),
        )
        != 0
    )


def test_immutable_image_reference_and_exact_platform_are_admitted(
    library: ctypes.CDLL,
) -> None:
    raw = _image()
    validate = library.plamen_broker_v2_podman_test_validate_image
    assert validate(
        raw,
        len(raw),
        REFERENCE.encode("ascii"),
        MANIFEST.encode("ascii"),
        2,
        _digest(raw),
    ) == 0
    assert validate(
        raw,
        len(raw),
        b"localhost/plamen/runtime:latest",
        MANIFEST.encode("ascii"),
        2,
        _digest(raw),
    ) != 0
    wrong_hash = (ctypes.c_ubyte * 32)(*([0] * 32))
    assert validate(
        raw,
        len(raw),
        REFERENCE.encode("ascii"),
        MANIFEST.encode("ascii"),
        2,
        wrong_hash,
    ) != 0


def _render(library: ctypes.CDLL, operation: int) -> tuple[str, ...]:
    components = (ctypes.c_int * 7)(101, 102, 103, 104, 105, 106, 107)
    roots = (ctypes.c_int * 10)(201, 202, 203, 204, 205, 206, 207, 208, 209, 210)
    output = ctypes.create_string_buffer(32_768)
    size = ctypes.c_size_t()
    assert library.plamen_broker_v2_podman_test_render_read_command(
        operation,
        components,
        roots,
        REFERENCE.encode("ascii"),
        MANIFEST.encode("ascii"),
        output,
        len(output),
        ctypes.byref(size),
    ) == 0
    return tuple(output.raw[: size.value].rstrip(b"\0").decode().split("\0"))


def test_read_command_schema_is_closed_and_descriptor_addressed(
    library: ctypes.CDLL,
) -> None:
    assert _render(library, 16) == ("/proc/self/fd/101", "--version")
    assert _render(library, 22) == ("/proc/self/fd/107", "--version")
    inspect = _render(library, 32)
    assert inspect[0] == "/proc/self/fd/101"
    assert inspect[-5:] == ("image", "inspect", "--format", (
        '{"id":{{json .Id}},"digest":{{json .Digest}},'
        '"os":{{json .Os}},"architecture":{{json .Architecture}},'
        '"repo_digests":{{json .RepoDigests}}}'
    ), REFERENCE)
    assert "--remote=false" in inspect
    assert "--root" in inspect and "/proc/self/fd/201" in inspect
    assert "mount_program=/proc/self/fd/106" in inspect
    assert not any(value in inspect for value in ("pull", "build", "run", "exec"))


def test_unknown_read_operation_fails_closed(library: ctypes.CDLL) -> None:
    components = (ctypes.c_int * 7)(*range(101, 108))
    roots = (ctypes.c_int * 10)(*range(201, 211))
    output = ctypes.create_string_buffer(1024)
    size = ctypes.c_size_t()
    assert library.plamen_broker_v2_podman_test_render_read_command(
        999,
        components,
        roots,
        REFERENCE.encode(),
        MANIFEST.encode(),
        output,
        len(output),
        ctypes.byref(size),
    ) != 0


@pytest.mark.parametrize("operation", [19, 20])
def test_uidmap_tools_have_no_invented_version_command(
    library: ctypes.CDLL, operation: int
) -> None:
    components = (ctypes.c_int * 7)(*range(101, 108))
    roots = (ctypes.c_int * 10)(*range(201, 211))
    output = ctypes.create_string_buffer(1024)
    size = ctypes.c_size_t()
    assert library.plamen_broker_v2_podman_test_render_read_command(
        operation,
        components,
        roots,
        REFERENCE.encode(),
        MANIFEST.encode(),
        output,
        len(output),
        ctypes.byref(size),
    ) != 0


def test_componentwise_relative_path_grammar_rejects_escape_and_alias_syntax(
    library: ctypes.CDLL,
) -> None:
    validate = library.plamen_broker_v2_podman_test_relative_path_valid
    assert validate(b"usr/bin/podman") == 1
    for value in (
        b"",
        b"/usr/bin/podman",
        b"../podman",
        b"usr/../podman",
        b"usr//podman",
        b"usr/./podman",
        b"usr/bin/podman/",
        b"usr\\bin\\podman",
    ):
        assert validate(value) == 0


def test_receipt_integrity_rejects_bound_field_tampering(
    library: ctypes.CDLL,
) -> None:
    assert library.plamen_broker_v2_podman_test_receipt_integrity() == 0


@pytest.mark.skipif(platform.system() == "Linux", reason="non-Linux hard-stop gate")
def test_unsupported_host_hardstops_without_inspecting_spec(
    library: ctypes.CDLL,
) -> None:
    custody = ctypes.create_string_buffer(32_768)
    assert library.plamen_broker_v2_podman_admit(None, custody) == 78
    assert library.plamen_broker_v2_podman_open_beneath(-1, None, 0, 0) == -1


def test_native_admission_source_exposes_no_lifecycle_or_network_effect() -> None:
    source = (
        ROOT / "native" / "linux" / "plamen_broker_v2_podman_admission.c"
    ).read_text(encoding="utf-8")
    header = (
        ROOT / "native" / "linux" / "plamen_broker_v2_podman_admission.h"
    ).read_text(encoding="utf-8")
    for forbidden in (
        '"create"', '"start"', '"wait"', '"kill"', '"rm"',
        '"load"', '"pull"', '"build"', '"push"', '"login"',
    ):
        assert forbidden not in source
    assert "lifecycle_authority_granted" in header
    assert "receipt_requires_broker_authentication" in header
    assert "plamen_broker_v2_podman_process" not in header


def test_linux_only_kernel_gates_are_explicit_in_source() -> None:
    source = (
        ROOT / "native" / "linux" / "plamen_broker_v2_podman_admission.c"
    ).read_text(encoding="utf-8")
    for required in (
        "RESOLVE_BENEATH",
        "RESOLVE_NO_SYMLINKS",
        "RESOLVE_NO_MAGICLINKS",
        "RESOLVE_NO_XDEV",
        "CGROUP2_SUPER_MAGIC",
        '"cgroup.events"',
        '"cgroup.procs"',
        '"cgroup.type"',
        '"cgroup.stat"',
        '"cgroup.kill"',
        '"memory.swap.max"',
        "OVERLAYFS_SUPER_MAGIC",
        "F_DUPFD_CLOEXEC",
    ):
        assert required in source


def test_python_projection_names_the_native_slice_without_unlocking_lifecycle() -> None:
    assert provider_projection.NATIVE_ADMISSION_SCHEMA == (
        "plamen.podman-linux.native-admission.v1"
    )
    assert provider_projection.NATIVE_ADMISSION_COMPONENT_ROSTER == (
        ("podman", "6.1.1"),
        ("conmon", "2.2.1"),
        ("crun", "1.28"),
        ("newuidmap", "4.18.0"),
        ("newgidmap", "4.18.0"),
        ("fuse-overlayfs", "1.17"),
        ("systemd", "EXACT_NATIVE_PACKAGE_RECEIPT"),
    )
    assert provider_projection.NATIVE_ADMISSION_LIFECYCLE_AVAILABLE is False
    assert adapter_projection.NATIVE_ADMISSION_SCHEMA == (
        provider_projection.NATIVE_ADMISSION_SCHEMA
    )
    assert adapter_projection.NATIVE_ADMISSION_GRANTS_LIFECYCLE is False
    assert provider_projection.NATIVE_LIFECYCLE_AVAILABLE is False
    assert adapter_projection.NATIVE_LIFECYCLE_AVAILABLE is False
    assert provider_projection.NATIVE_LIFECYCLE_REQUIRED_RECEIPTS == (
        "compiled-native-identity",
        "native-admission",
        "native-lifecycle",
    )
    assert (
        adapter_projection.NATIVE_LIFECYCLE_REQUIRED_RECEIPTS
        == provider_projection.NATIVE_LIFECYCLE_REQUIRED_RECEIPTS
    )
    with pytest.raises(adapter_projection.AdapterUnavailableError):
        adapter_projection.open_podman_supervisor_adapter(object(), object())
