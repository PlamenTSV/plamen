from __future__ import annotations

import ctypes
import json
from pathlib import Path
import platform
import subprocess

import pytest


ROOT = Path(__file__).resolve().parent.parent
APPLE_COMMIT = "a9a62e28f6beb88940122a3d7b286f2d5ae8053a"
INDEX = "sha256:" + "1" * 64
MANIFEST = "sha256:" + "2" * 64
REFERENCE = "ghcr.io/plamen/runtime@" + INDEX


pytestmark = pytest.mark.skipif(
    platform.system() != "Darwin", reason="Darwin native admission only"
)


@pytest.fixture(scope="module")
def library(tmp_path_factory: pytest.TempPathFactory) -> ctypes.CDLL:
    output = tmp_path_factory.mktemp("apple-container-admission") / "admission.dylib"
    subprocess.run(
        [
            "/usr/bin/clang",
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fblocks",
            "-DPLAMEN_BROKER_V2_APPLE_CONTAINER_TEST_ONLY=1",
            "-I",
            str(ROOT / "native" / "darwin"),
            "-dynamiclib",
            str(ROOT / "native" / "darwin" / "plamen_broker_v2_apple_container.c"),
            str(ROOT / "native" / "darwin" / "plamen_broker_v2_process.c"),
            str(ROOT / "native" / "posix" / "plamen_broker_v2_protocol.c"),
            "-framework",
            "Security",
            "-framework",
            "CoreFoundation",
            "-o",
            str(output),
        ],
        cwd=ROOT,
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )
    loaded = ctypes.CDLL(str(output))
    loaded.plamen_broker_v2_apple_container_test_validate_version.argtypes = [
        ctypes.c_char_p,
        ctypes.c_size_t,
    ]
    loaded.plamen_broker_v2_apple_container_test_validate_status.argtypes = [
        ctypes.c_char_p,
        ctypes.c_size_t,
    ]
    loaded.plamen_broker_v2_apple_container_test_validate_image.argtypes = [
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
    ]
    loaded.plamen_broker_v2_apple_container_derive_id.argtypes = [
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.c_char_p,
    ]
    loaded.plamen_broker_v2_apple_container_id_validate.argtypes = [ctypes.c_char_p]
    loaded.plamen_broker_v2_apple_container_validate_state.argtypes = [
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_ubyte),
    ]
    return loaded


def _encoded(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _version() -> bytes:
    return _encoded(
        [
            {
                "appName": "container",
                "buildType": "release",
                "commit": APPLE_COMMIT,
                "version": "1.3.1",
            },
            {
                "appName": "container-apiserver",
                "buildType": "release",
                "commit": APPLE_COMMIT,
                "version": "container-apiserver version 1.3.1 "
                "(build: release, commit: a9a62e2)",
            },
        ]
    )


def _status() -> bytes:
    return _encoded(
        {
            "status": "running",
            "appRoot": "/Users/test/Library/Application Support/com.apple.container",
            "installRoot": "/usr/local/",
            "logRoot": "/Users/test/Library/Logs/com.apple.container",
            "apiServerVersion": "container-apiserver version 1.3.1 "
            "(build: release, commit: a9a62e2)",
            "apiServerCommit": APPLE_COMMIT,
            "apiServerBuild": "release",
            "apiServerAppName": "container-apiserver",
        }
    )


def _image(*, architecture: str = "arm64", name: str = REFERENCE) -> bytes:
    return _encoded(
        [
            {
                "id": INDEX.removeprefix("sha256:"),
                "configuration": {
                    "creationDate": "2026-09-08T00:00:00Z",
                    "name": name,
                    "descriptor": {
                        "digest": INDEX,
                        "mediaType": "application/vnd.oci.image.index.v1+json",
                        "size": 321,
                    },
                },
                "variants": [
                    {
                        "platform": {"os": "linux", "architecture": architecture},
                        "digest": MANIFEST,
                        "size": 123,
                        "config": {"architecture": "arm64", "os": "linux"},
                    }
                ],
            }
        ]
    )


def test_exact_131_and_running_server_documents_are_admitted(library: ctypes.CDLL) -> None:
    version = _version()
    status = _status()
    assert library.plamen_broker_v2_apple_container_test_validate_version(
        version, len(version)
    ) == 0


def test_newer_compatible_release_is_admitted_but_internal_drift_is_rejected(
    library: ctypes.CDLL,
) -> None:
    commit = "1" * 40
    version = _encoded([
        {"appName": "container", "buildType": "release", "commit": commit,
         "version": "1.4.0"},
        {"appName": "container-apiserver", "buildType": "release",
         "commit": commit,
         "version": "container-apiserver version 1.4.0 "
                    "(build: release, commit: 1111111)"},
    ])
    status = _encoded({
        "status": "running",
        "appRoot": "/Users/test/Library/Application Support/com.apple.container",
        "installRoot": "/usr/local/", "logRoot": "/tmp/container-log",
        "apiServerVersion": "container-apiserver version 1.4.0 "
                            "(build: release, commit: 1111111)",
        "apiServerCommit": commit, "apiServerBuild": "release",
        "apiServerAppName": "container-apiserver",
    })
    assert library.plamen_broker_v2_apple_container_test_validate_version(
        version, len(version)
    ) == 0
    assert library.plamen_broker_v2_apple_container_test_validate_status(
        status, len(status)
    ) == 0
    drifted = version.replace(commit.encode(), ("2" * 40).encode(), 1)
    assert library.plamen_broker_v2_apple_container_test_validate_version(
        drifted, len(drifted)
    ) != 0
    source = (
        ROOT / "native" / "darwin" / "plamen_broker_v2_apple_container.c"
    ).read_text(encoding="utf-8")
    assert "validate_status_identity(outputs[1], sizes[1]," in source
    assert "&provider_identity" in source
    assert library.plamen_broker_v2_apple_container_test_validate_status(
        status, len(status)
    ) == 0


@pytest.mark.parametrize(
    "mutation",
    [
        lambda raw: raw.replace(b'"1.3.1"', b'"1.3.0"', 1),
        lambda raw: raw.replace(b'},{', b'}{'),
        lambda raw: raw.replace(b'"commit":', b'"unknown":', 1),
        lambda raw: raw + b'{}',
    ],
)
def test_version_schema_and_json_grammar_fail_closed(
    library: ctypes.CDLL, mutation
) -> None:
    raw = mutation(_version())
    assert library.plamen_broker_v2_apple_container_test_validate_version(
        raw, len(raw)
    ) != 0


def test_preloaded_image_requires_immutable_reference_and_exact_arm64_variant(
    library: ctypes.CDLL,
) -> None:
    image = _image()
    validate = library.plamen_broker_v2_apple_container_test_validate_image
    assert validate(
        image,
        len(image),
        REFERENCE.encode(),
        INDEX.encode(),
        MANIFEST.encode(),
    ) == 0
    mutable = "ghcr.io/plamen/runtime:latest"
    assert validate(
        image, len(image), mutable.encode(), INDEX.encode(), MANIFEST.encode()
    ) != 0
    wrong_platform = _image(architecture="amd64")
    assert validate(
        wrong_platform,
        len(wrong_platform),
        REFERENCE.encode(),
        INDEX.encode(),
        MANIFEST.encode(),
    ) != 0


def test_ids_are_generated_fixed_format_and_reject_path_syntax(
    library: ctypes.CDLL,
) -> None:
    request = (ctypes.c_ubyte * 32)(*range(1, 33))
    operation = (ctypes.c_ubyte * 32)(*range(33, 65))
    output = ctypes.create_string_buffer(40)
    assert library.plamen_broker_v2_apple_container_derive_id(
        request, operation, output
    ) == 0
    assert output.value.startswith(b"plamen-")
    assert len(output.value) == 39
    assert library.plamen_broker_v2_apple_container_id_validate(output.value) == 0
    for unsafe in (b"../escape", b"plamen-deadbeef/../../x", b"plamen-ABCDEF"):
        assert library.plamen_broker_v2_apple_container_id_validate(unsafe) != 0


def test_lifecycle_state_proof_requires_exact_bound_stopped_zero_network_guest(
    library: ctypes.CDLL,
) -> None:
    container_id = "plamen-" + "a" * 32
    document = _encoded(
        [
            {
                "id": container_id,
                "configuration": {
                    "id": container_id,
                    "image": {"reference": REFERENCE},
                    "readOnly": True,
                    "useInit": True,
                    "networks": [],
                },
                "status": {"state": "stopped", "networks": []},
            }
        ]
    )
    digest = (ctypes.c_ubyte * 32)()
    validate = library.plamen_broker_v2_apple_container_validate_state
    assert validate(
        document,
        len(document),
        container_id.encode(),
        REFERENCE.encode(),
        b"stopped",
        digest,
    ) == 0
    for mutated in (
        document.replace(b'"stopped"', b'"running"'),
        document.replace(b'"networks":[]', b'"networks":[{}]', 1),
        document.replace(b'"readOnly":true', b'"readOnly":false'),
        document.replace(container_id.encode(), ("plamen-" + "b" * 32).encode(), 1),
    ):
        assert validate(
            mutated,
            len(mutated),
            container_id.encode(),
            REFERENCE.encode(),
            b"stopped",
            digest,
        ) != 0


def test_duplicate_optional_status_key_and_nonrelease_build_fail_closed(
    library: ctypes.CDLL,
) -> None:
    status = _status().replace(
        b'"logRoot":', b'"logRoot":"/tmp/duplicate","logRoot":', 1
    )
    assert library.plamen_broker_v2_apple_container_test_validate_status(
        status, len(status)
    ) != 0
    version = _version().replace(b'"buildType":"release"', b'"buildType":"debug"', 1)
    assert library.plamen_broker_v2_apple_container_test_validate_version(
        version, len(version)
    ) != 0


def test_source_has_no_mutating_apple_container_verb() -> None:
    source = (
        ROOT / "native" / "darwin" / "plamen_broker_v2_apple_container.c"
    ).read_text(encoding="utf-8")
    for forbidden in ('"build"', '"pull"', '"tag"', '"run"', '"exec"',
                      '"stop"', '"kill"', '"delete"'):
        assert forbidden not in source


def test_service_exposes_no_provider_authority_before_durable_admission() -> None:
    service = (
        ROOT / "native" / "darwin" / "plamen_broker_v2_service.c"
    ).read_text(encoding="utf-8")
    session = service[service.index("serve_session(void *opaque)") :]
    admission = session.index("admit_worker_apple_container")
    effects_create = session.index("plamen_broker_v2_effects_create")
    durable = session.index("plamen_broker_v2_effects_retain_provider_admission")
    operations = session.index("plamen_broker_v2_operations_session_open")
    exposed = session.index("PLAMEN_BROKER_V2_AUTH_ACCEPTED")
    assert admission < effects_create < durable < operations < exposed


def test_admission_receipt_is_request_bound_and_durable() -> None:
    header = (
        ROOT / "native" / "darwin" / "plamen_broker_v2_apple_container.h"
    ).read_text(encoding="utf-8")
    effects = (
        ROOT / "native" / "darwin" / "plamen_broker_v2_effects.c"
    ).read_text(encoding="utf-8")
    assert "request_fingerprint_sha256" in header
    assert 'PROVIDER_ADMISSION_FILE "provider-admission-v1.bin"' in effects
    assert "persist_provider_admission(context, receipt)" in effects
    assert effects.index("persist_provider_admission(context, receipt)") < effects.index(
        "context->provider_admission_present = 1"
    )


def test_service_acquires_only_fixed_apple_closure_paths() -> None:
    service = (
        ROOT / "native" / "darwin" / "plamen_broker_v2_service.c"
    ).read_text(encoding="utf-8")
    for expected in (
        "/usr/local/bin/container",
        "/usr/local/bin/container-apiserver",
        "/var/db/receipts/com.apple.container-installer.bom",
        "/var/db/receipts/com.apple.container-installer.plist",
        "/usr/local/libexec/container/plugins/container-runtime-linux/bin/",
        "/Library/Application Support/com.apple.container/kernels/",
    ):
        assert expected in service
    for forbidden in ("container build", "container pull", "container tag"):
        assert forbidden not in service
