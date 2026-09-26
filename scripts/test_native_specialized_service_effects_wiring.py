from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SERVICE = ROOT / "native/darwin/plamen_broker_v2_service.c"


def _function(source: str, name: str, next_marker: str) -> str:
    start = source.index(name)
    end = source.index(next_marker, start)
    return source[start:end]


def test_service_retains_installed_specialized_runtime_authority() -> None:
    source = SERVICE.read_text(encoding="utf-8")
    authority = source[source.index("struct plamen_service_authority {"):
                       source.index("struct plamen_pending_challenge {")]
    assert "int specialized_authority_fd;" in authority

    admission = _function(
        source, "admit_service_authority(", "\nstatic int\nauthority_xpc_key("
    )
    assert "authority->receipt.specialized_present != 1U" in admission
    assert "plamen_install_receipt_open_specialized_authority(" in admission
    assert "&authority->specialized_authority_fd" in admission

    close = _function(
        source, "close_service_authority(", "\nstatic int\nadmit_service_authority("
    )
    assert "close(authority->specialized_authority_fd);" in close


def test_service_passes_exact_runtime_and_session_authority_to_effects() -> None:
    source = SERVICE.read_text(encoding="utf-8")
    session = _function(
        source, "serve_session(void *opaque)",
        "\nstatic int\ngenerate_member_capabilities("
    )
    runtime_index = "PLAMEN_INSTALL_MEMBER_RUNTIME_MANIFEST - 1"
    assert (
        "effects_open.runtime_manifest_fd = service_authority.member_fds["
        in session
    )
    assert session.count(runtime_index) >= 2
    assert (
        "effects_open.image_member_receipt_fd =\n"
        "            service_authority.specialized_authority_fd;"
    ) in session
    assert (
        "effects_open.specialized_runtime_auxiliary =\n"
        "            &service_authority.receipt.specialized_authority;"
    ) in session

    specialized = _function(
        source, "serve_specialized_session(void *opaque)",
        "\nstatic void\ndestroy_session_worker_final("
    )
    call = specialized[specialized.index(
        "plamen_broker_v2_effects_dispatch_specialized("
    ):]
    assert "view.payload_size, request_sha256, worker->key,\n" in call
    assert "fds, fd_count" in call
