from __future__ import annotations

import copy
import base64
import hashlib
import json
import pickle
from pathlib import Path
import sys
import threading

import pytest


sys.path.insert(0, str(Path(__file__).resolve().parent))
import verified_backend_egress as V  # noqa: E402
import posix_backend_launch_policy as launch_policy  # noqa: E402


H1 = "1" * 64
H2 = "2" * 64
H3 = "3" * 64
H4 = "4" * 64
H5 = "5" * 64
H6 = "6" * 64
H7 = "7" * 64
H8 = "8" * 64


def install_generation(backend: str, version: str):
    return launch_policy.TEST_ONLY_issue_backend_install_generation(
        backend=backend, resolved_version=version,
        executable_sha256=H1, executable_size=1,
        runtime_closure_sha256=H2,
        publisher="OpenAI" if backend == "codex" else "Anthropic PBC",
        publisher_identity_sha256=H3, provenance="SIGNED_UPSTREAM_RELEASE",
        provenance_receipt_sha256=H4,
        latest_resolution_receipt_sha256=H5,
        cli_behavior_contract_sha256=(
            launch_policy.backend_cli_behavior_contract_sha256(backend)
        ),
        cli_conformance_sha256=H6,
        install_generation_id=f"{backend}-generation-1",
        producer_receipt_sha256=H7,
        acquisition_policy_sha256=H8,
        acquisition_validator_sha256="9" * 64,
        registry_latest_observation_sha256="a" * 64,
        upstream_integrity_sha256="b" * 64,
        signature_provenance_sha256="c" * 64,
        installed_manifest_sha256="d" * 64,
        coordinator_receipt_sha256="e" * 64,
    )


def expected(**changes: object) -> V.TrustedNetworkExpectation:
    values: dict[str, object] = {
        "provider_attempt_id": "attempt:A-1",
        "attempt_binding_sha256": H1,
        "backend_id": "codex",
        "auth_mode": "CHATGPT_OAUTH",
        "release_policy_id": "codex-egress-2026-09-v1",
        "provider_network_id": "plamen-net-a1",
        "network_generation": 7,
        "subnet_cidrs": ("10.70.0.0/24",),
        "guest_ip": "10.70.0.2",
        "primary_interface": "eth0",
        "proxy_ip": "10.70.0.1",
        "proxy_port": 9443,
        "listener_identity_sha256": H2,
        "nft_ruleset_sha256": H3,
        "nft_generation": 11,
        "nft_owner_uid": 1000,
        "seccomp_profile_sha256": H4,
        "backend_executable_sha256": H6,
        "backend_launch_policy_sha256": H7,
        "public_ca_bundle_sha256": H8,
    }
    values.update(changes)
    return V.TrustedNetworkExpectation(**values)  # type: ignore[arg-type]


def proof(exp: V.TrustedNetworkExpectation | None = None) -> dict[str, object]:
    exp = exp or expected()
    result: dict[str, object] = {
        "schema": V.NETWORK_PROOF_SCHEMA,
        "attempt": {
            "provider_attempt_id": exp.provider_attempt_id,
            "attempt_binding_sha256": exp.attempt_binding_sha256,
            "backend_id": exp.backend_id,
            "auth_mode": exp.auth_mode,
            "release_policy_id": exp.release_policy_id,
            "proxy_scope": V.NETWORK_MODE,
            "backend_executable_sha256": exp.backend_executable_sha256,
            "backend_launch_policy_sha256": exp.backend_launch_policy_sha256,
            "network_capable_process_count": 1,
            "network_capable_process_executable_sha256": exp.backend_executable_sha256,
            "authorization_recipient_executable_sha256": exp.backend_executable_sha256,
            "target_backend_policy_enabled": False,
            "target_backend_config_enabled": False,
            "model_generated_command_network": False,
            "tls_mode": V.TLS_MODE,
            "tls_termination": False,
            "public_ca_bundle_sha256": exp.public_ca_bundle_sha256,
            "opaque_tls_limitation": V.OPAQUE_TLS_LIMITATION,
            "domain_fronting_limitation": V.DOMAIN_FRONTING_LIMITATION,
        },
        "provider": {
            "topology_mode": (
                V.APPLE_TOPOLOGY_MODE
                if exp.proxy_transport == V.APPLE_ATTEMPT_NETWORK_TCP
                else V.LINUX_TOPOLOGY_MODE
            ),
            "effective_egress_mode": V.EFFECTIVE_EGRESS_MODE,
            "network_id": exp.provider_network_id,
            "network_generation": exp.network_generation,
            "subnet_cidrs": list(exp.subnet_cidrs),
            "attempt_unique": True,
            "default_network_attached": False,
            "alternate_network_ids": [],
            "interfaces": [
                {
                    "name": exp.primary_interface,
                    "address": exp.guest_ip,
                    "network_id": exp.provider_network_id,
                }
            ],
            "routes": [
                {"interface": exp.primary_interface, "destination": subnet, "kind": "LINK"}
                for subnet in exp.subnet_cidrs
            ],
            "default_routes": [],
            "dns_enabled": False,
            "dns_servers": [],
            "listener": {
                "address": exp.proxy_ip,
                "port": exp.proxy_port,
                "network_id": exp.provider_network_id,
                "network_generation": exp.network_generation,
                "identity_sha256": exp.listener_identity_sha256,
                "wildcard": False,
                "publicly_routable": False,
            },
            "published_ports": [],
            "published_sockets": [],
            "ssh_forwarding": False,
            "nested_virtualization": False,
            "host_devices": [],
            "proxy_transport": exp.proxy_transport,
            "transport": (
                {
                    "mode": V.APPLE_ATTEMPT_NETWORK_TCP,
                    "private_channel_identity_sha256": exp.channel_identity_sha256,
                    "private_channel_owner_uid": 0,
                    "private_channel_object_kind": "NETWORK_LISTENER",
                    "private_channel_mode": 0,
                    "bind_mount_count": 0,
                    "provider_network_disabled": False,
                    "guest_shim_identity_sha256": __import__("hashlib").sha256(b"plamen:not-applicable:v1").hexdigest(),
                    "guest_shim_owner_uid": 0,
                    "peer_credentials_verified": False,
                    "shim_loopback_initialized_before_cap_drop": False,
                    "shim_capabilities_dropped": True,
                }
                if exp.proxy_transport == V.APPLE_ATTEMPT_NETWORK_TCP
                else {
                    "mode": V.LINUX_NETWORK_NONE_UDS_SHIM,
                    "private_channel_identity_sha256": exp.channel_identity_sha256,
                    "private_channel_owner_uid": 0,
                    "private_channel_object_kind": "UNIX_STREAM_SOCKET",
                    "private_channel_mode": 0o600,
                    "bind_mount_count": 1,
                    "provider_network_disabled": True,
                    "guest_shim_identity_sha256": exp.shim_identity_sha256,
                    "guest_shim_owner_uid": 0,
                    "peer_credentials_verified": True,
                    "shim_loopback_initialized_before_cap_drop": True,
                    "shim_capabilities_dropped": True,
                }
            ),
        },
        "guest_firewall": {
            "engine": "NFTABLES",
            "ruleset_sha256": exp.nft_ruleset_sha256,
            "ruleset_generation": exp.nft_generation,
            "ruleset_owner_uid": exp.nft_owner_uid,
            "default_output": "DROP",
            "default_forward": "DROP",
            "output_allow_rules": [
                {
                    "kind": "LOOPBACK",
                    "interface": "lo",
                    "protocol": "ANY",
                    "destination_ip": "127.0.0.1",
                    "destination_port": 0,
                },
                {
                    "kind": "PROXY",
                    "interface": exp.primary_interface,
                    "protocol": "TCP",
                    "destination_ip": exp.proxy_ip,
                    "destination_port": exp.proxy_port,
                },
            ],
        },
        "guest_security": {
            "capability_sets": {
                "ambient": [],
                "bounding": [],
                "effective": [],
                "inheritable": [],
                "permitted": [],
            },
            "no_new_privileges": True,
            "seccomp": {
                "status": "ENFORCED",
                "profile_sha256": exp.seccomp_profile_sha256,
                "blocked_network_admin_syscalls": [
                    "bpf", "fsconfig", "fsmount", "fsopen", "mount", "move_mount",
                    "open_tree", "pivot_root", "setns", "umount2", "unshare",
                ],
                "denied_socket_families": ["AF_NETLINK", "AF_PACKET"],
                "denied_socket_types": ["SOCK_RAW"],
            },
            "raw_sockets_present": False,
            "packet_sockets_present": False,
            "network_admin_fds_present": False,
            "socket_census_sha256": H5,
        },
    }
    return result


def admit(exp: V.TrustedNetworkExpectation | None = None) -> V.NetworkAdmission:
    exp = exp or expected()
    return V.admit_network_proof(
        V.canonical_proof_bytes(proof(exp)),
        exp,
        authenticate_proof=proof_authenticator(exp.proof_authority_id),
    )


def proof_authenticator(authority_id: str):
    def authenticate(raw: bytes, digest: str) -> V.ProofAuthenticationEvidence:
        assert __import__("hashlib").sha256(raw).hexdigest() == digest
        return V.ProofAuthenticationEvidence(authority_id, digest, True, True)

    return authenticate


class ReplayStore:
    def __init__(self) -> None:
        self.keys: set[str] = set()

    def __call__(self, key: str, issuance: str) -> bool:
        assert len(key) == len(issuance) == 64
        if key in self.keys:
            return False
        self.keys.add(key)
        return True


class Harness:
    def __init__(self, *, answers: object = None, peer: V.PeerObservation | None = None) -> None:
        self.token = b""
        self.delivered_view: memoryview | None = None
        self.resolver_calls: list[str] = []
        self.connector_calls: list[tuple[str, int, tuple[str, ...]]] = []
        self.responses: list[bytes] = []
        self.answers = ["8.8.8.8"] if answers is None else answers
        self.peer = peer or V.PeerObservation("8.8.8.8", 443, "RAW_TCP", False)
        self.now = 10.0
        self.replay = ReplayStore()
        self.relay = self.good_relay
        self.finalizations: list[tuple[object, object | None]] = []
        self.finalization_evidence = V.ConnectionFinalizationEvidence(True, True, True, 0)
        self.cancel_wakeups = 0

    def deliver(self, view: memoryview) -> bool:
        self.delivered_view = view
        self.token = bytes(view)
        return True

    def resolve(self, hostname: str, maximum: int, timeout: float):
        self.resolver_calls.append(hostname)
        assert maximum == V.MAX_DNS_ANSWERS
        assert 0 < timeout <= 120
        return self.answers

    def connect(self, hostname: str, port: int, resolved: tuple[str, ...], timeout: float):
        self.connector_calls.append((hostname, port, resolved))
        assert 0 < timeout <= 120
        return object()

    def observe(self, _upstream: object, timeout: float) -> V.PeerObservation:
        assert 0 < timeout <= 120
        return self.peer

    def good_relay(self, _client: object, _upstream: object, controller: V.RelayController):
        controller.record_client_to_upstream(17)
        controller.record_upstream_to_client(23)
        controller.mark_client_eof_and_upstream_half_close()
        controller.mark_upstream_eof_and_client_half_close()
        return V.RelayRunnerEvidence(
            True, True, True, 0, controller.cancel_requested(), True, True
        )

    def clock(self) -> float:
        return self.now

    def finalize(self, client: object, upstream: object | None, timeout: float) -> V.ConnectionFinalizationEvidence:
        assert timeout == 120
        self.finalizations.append((client, upstream))
        return self.finalization_evidence

    def send(self, response: bytes, timeout: float) -> None:
        assert 0 < timeout <= 120
        self.responses.append(response)

    def wake_cancelled(self, timeout: float) -> bool:
        assert timeout == 120
        self.cancel_wakeups += 1
        return True

    def issue(self, admission: V.NetworkAdmission | None = None):
        return V.issue_attempt_proxy(
            admission or admit(),
            consume_replay_durably=self.replay,
            deliver_guest_authorization=self.deliver,
            entropy=lambda size: bytearray(b"x" * size),
            resolver=self.resolve,
            connector=self.connect,
            peer_observer=self.observe,
            relay_runner=lambda client, upstream, controller: self.relay(client, upstream, controller),
            connection_finalizer=self.finalize,
            cancel_wakeup=self.wake_cancelled,
            monotonic_clock=self.clock,
        )

    def request(self, hostname: str = "api.openai.com", **changes: object) -> bytes:
        token = changes.get("token", self.token)
        method = changes.get("method", "CONNECT")
        version = changes.get("version", "HTTP/1.1")
        authority = changes.get("authority", f"{hostname}:443")
        headers = changes.get(
            "headers",
            [
                f"Host: {authority}".encode(),
                b"Proxy-Authorization: Basic " + base64.b64encode(token),
            ],
        )
        return f"{method} {authority} {version}\r\n".encode() + b"\r\n".join(headers) + b"\r\n\r\n"

    def handle(
        self,
        proxy: V.AttemptProxy,
        raw: bytes | None = None,
        source: V.ConnectionSource | None = None,
    ):
        chunks = [raw or self.request()]

        def reader(_maximum: int, timeout: float) -> bytes:
            assert 0 <= timeout <= 120
            return chunks.pop(0) if chunks else b""

        return proxy.handle_connection(
            client=object(),
            source=source or V.ConnectionSource("10.70.0.2", "plamen-net-a1", 7),
            read_request=reader,
            send_response=self.send,
        )


def assert_code(code: str, call) -> None:
    with pytest.raises(V.VerifiedEgressError) as caught:
        call()
    assert caught.value.code == code
    assert str(caught.value) == code


def test_admits_exact_network_and_redacts_public_receipt() -> None:
    admission = admit()
    receipt = admission.public_receipt()
    assert receipt["result"] == "ADMITTED"
    assert receipt["network_mode"] == V.NETWORK_MODE
    assert receipt["network_mode"] == "VERIFIED_CONNECT_ALLOWLIST"
    assert receipt["topology_mode"] == "hostOnly"
    assert receipt["effective_egress_mode"] == "VERIFIED_CONNECT_ALLOWLIST"
    assert receipt["capability_scope"] == "TRUSTED_HOST_SUPERVISOR_PROCESS"
    assert receipt["tls_mode"] == "END_TO_END_PASSTHROUGH"
    assert receipt["opaque_tls_limitation"] == "ACKNOWLEDGED_PINNED_CLIENT_ONLY"
    assert receipt["domain_fronting_limitation"] == "NOT_INSPECTED_TRUST_PINNED_BACKEND_CLI"
    assert receipt["backend_executable_sha256"] == H6
    assert receipt["backend_launch_policy_sha256"] == H7
    assert receipt["public_ca_bundle_sha256"] == H8
    rendered = json.dumps(receipt, sort_keys=True)
    for forbidden in ("10.70.0.1", "10.70.0.2", "plamen-net-a1", "api.openai.com"):
        assert forbidden not in rendered
    assert receipt["domain_ids"] == [
        "CODEX_API_PRIMARY", "CODEX_CHATGPT_BACKEND", "CODEX_OAUTH_PRIMARY"
    ]


def test_linux_network_none_private_uds_shim_uses_same_connect_boundary() -> None:
    exp = expected(
        provider_network_id="linux-netns-a1",
        subnet_cidrs=("127.0.0.0/8",),
        guest_ip="127.0.0.1",
        primary_interface="lo",
        proxy_ip="127.0.0.1",
        proxy_port=9443,
        proxy_transport=V.LINUX_NETWORK_NONE_UDS_SHIM,
        private_channel_identity_sha256=H5,
        private_channel_mode=0o600,
        guest_shim_identity_sha256=H4,
        guest_shim_owner_uid=0,
    )
    admission = admit(exp)
    harness = Harness()
    proxy = harness.issue(admission)
    source = V.ConnectionSource(
        "127.0.0.1",
        "linux-netns-a1",
        7,
        V.LINUX_NETWORK_NONE_UDS_SHIM,
        H5,
        H4,
        True,
        0,
    )
    assert harness.handle(proxy, source=source)["result"] == "COMPLETED"
    receipts = [
        admission.public_receipt(),
        proxy.finish().public_receipt(),
    ]
    rendered = json.dumps(receipts)
    assert V.LINUX_NETWORK_NONE_UDS_SHIM in rendered
    assert "127.0.0.1" not in rendered
    assert "linux-netns-a1" not in rendered


def test_linux_shim_requires_loopback_network_none_shape_and_channel_identity() -> None:
    assert_code(
        "LINUX_SHIM_POLICY",
        lambda: expected(
            proxy_transport=V.LINUX_NETWORK_NONE_UDS_SHIM,
            private_channel_identity_sha256=H5,
            private_channel_mode=0o600,
            guest_shim_identity_sha256=H4,
            guest_shim_owner_uid=0,
        ),
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("private_channel_owner_uid", 501),
        ("private_channel_mode", 0o666),
        ("private_channel_object_kind", "REGULAR_FILE"),
        ("bind_mount_count", 2),
        ("provider_network_disabled", False),
        ("guest_shim_owner_uid", 1000),
        ("peer_credentials_verified", False),
        ("shim_loopback_initialized_before_cap_drop", False),
        ("shim_capabilities_dropped", False),
    ],
)
def test_linux_shim_rejects_nonprivate_nonroot_or_unproven_transport(field: str, value: object) -> None:
    exp = expected(
        provider_network_id="linux-netns-a1",
        subnet_cidrs=("127.0.0.0/8",),
        guest_ip="127.0.0.1",
        primary_interface="lo",
        proxy_ip="127.0.0.1",
        proxy_transport=V.LINUX_NETWORK_NONE_UDS_SHIM,
        private_channel_identity_sha256=H5,
        private_channel_mode=0o600,
        guest_shim_identity_sha256=H4,
        guest_shim_owner_uid=0,
    )
    value_proof = proof(exp)
    value_proof["provider"]["transport"][field] = value
    assert_code(
        "TRANSPORT_POLICY",
        lambda: V.admit_network_proof(
            V.canonical_proof_bytes(value_proof), exp,
            authenticate_proof=proof_authenticator(exp.proof_authority_id),
        ),
    )
    assert_code(
        "LINUX_SHIM_POLICY",
        lambda: expected(
            provider_network_id="linux-netns-a1",
            subnet_cidrs=("127.0.0.0/8",),
            guest_ip="127.0.0.1",
            primary_interface="lo",
            proxy_ip="127.0.0.1",
            proxy_transport=V.LINUX_NETWORK_NONE_UDS_SHIM,
            private_channel_mode=0o600,
            guest_shim_identity_sha256=H4,
            guest_shim_owner_uid=0,
        ),
    )


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (lambda p: p["provider"].__setitem__("topology_mode", "APPLE_INTERNAL"), "NETWORK_MODE"),
        (lambda p: p["provider"].__setitem__("effective_egress_mode", "hostOnly"), "NETWORK_MODE"),
        (lambda p: p["provider"].__setitem__("default_network_attached", True), "PROVIDER_POLICY"),
        (lambda p: p["provider"].__setitem__("alternate_network_ids", ["default"]), "PROVIDER_POLICY"),
        (lambda p: p["provider"].__setitem__("default_routes", ["0.0.0.0/0"]), "PROVIDER_POLICY"),
        (lambda p: p["provider"].__setitem__("dns_enabled", True), "PROVIDER_POLICY"),
        (lambda p: p["provider"].__setitem__("published_sockets", ["docker.sock"]), "PROVIDER_POLICY"),
        (lambda p: p["provider"].__setitem__("ssh_forwarding", True), "PROVIDER_POLICY"),
        (lambda p: p["provider"].__setitem__("nested_virtualization", True), "PROVIDER_POLICY"),
        (lambda p: p["provider"]["interfaces"].append({}), "INTERFACE_POLICY"),
        (lambda p: p["provider"]["routes"].append({}), "ROUTE_POLICY"),
        (lambda p: p["provider"]["listener"].__setitem__("wildcard", True), "LISTENER_POLICY"),
        (lambda p: p["provider"]["listener"].__setitem__("publicly_routable", True), "LISTENER_POLICY"),
        (lambda p: p["guest_firewall"].__setitem__("ruleset_sha256", H2), "FIREWALL_POLICY"),
        (lambda p: p["guest_firewall"].__setitem__("default_output", "ACCEPT"), "FIREWALL_POLICY"),
        (lambda p: p["guest_firewall"]["output_allow_rules"].append({}), "FIREWALL_RULES"),
        (lambda p: p["guest_security"]["capability_sets"]["effective"].append("CAP_NET_ADMIN"), "CAPABILITY_POLICY"),
        (lambda p: p["guest_security"].__setitem__("raw_sockets_present", True), "GUEST_SECURITY_POLICY"),
        (lambda p: p["guest_security"]["seccomp"]["blocked_network_admin_syscalls"].remove("bpf"), "GUEST_SECURITY_POLICY"),
        (lambda p: p["attempt"].__setitem__("proxy_scope", "ATTEMPT_OWNED_AUTHENTICATED_TLS_TERMINATING"), "CONNECT_SCOPE_POLICY"),
        (lambda p: p["attempt"].__setitem__("tls_termination", True), "CONNECT_SCOPE_POLICY"),
        (lambda p: p["attempt"].__setitem__("target_backend_policy_enabled", True), "CONNECT_SCOPE_POLICY"),
        (lambda p: p["attempt"].__setitem__("target_backend_config_enabled", True), "CONNECT_SCOPE_POLICY"),
        (lambda p: p["attempt"].__setitem__("model_generated_command_network", True), "CONNECT_SCOPE_POLICY"),
        (lambda p: p["attempt"].__setitem__("backend_executable_sha256", H1), "CONNECT_SCOPE_POLICY"),
        (lambda p: p["attempt"].__setitem__("public_ca_bundle_sha256", H1), "CONNECT_SCOPE_POLICY"),
        (lambda p: p["attempt"].__setitem__("opaque_tls_limitation", "DENIED"), "CONNECT_SCOPE_POLICY"),
        (lambda p: p["attempt"].__setitem__("domain_fronting_limitation", "INSPECTED"), "CONNECT_SCOPE_POLICY"),
    ],
)
def test_network_admission_rejects_bypasses(mutate, code: str) -> None:
    value = proof()
    mutate(value)
    assert_code(code, lambda: V.admit_network_proof(
        V.canonical_proof_bytes(value), expected(),
        authenticate_proof=proof_authenticator(V.PROVIDER_GUEST_PROOF_AUTHORITY),
    ))


def test_network_proof_parser_rejects_duplicates_noncanonical_and_flood() -> None:
    raw = V.canonical_proof_bytes(proof())
    duplicate = raw.replace(b'{"attempt":', b'{"schema":"x","attempt":', 1)
    auth = proof_authenticator(V.PROVIDER_GUEST_PROOF_AUTHORITY)
    assert_code("PROOF_DUPLICATE_KEY", lambda: V.admit_network_proof(duplicate, expected(), authenticate_proof=auth))
    assert_code("PROOF_CANONICAL", lambda: V.admit_network_proof(b" " + raw, expected(), authenticate_proof=auth))
    assert_code("PROOF_SIZE", lambda: V.admit_network_proof(b"x" * (V.MAX_PROOF_BYTES + 1), expected(), authenticate_proof=auth))


def test_network_proof_requires_independent_authenticated_source() -> None:
    raw = V.canonical_proof_bytes(proof())
    assert_code(
        "PROOF_AUTHENTICATION",
        lambda: V.admit_network_proof(
            raw,
            expected(),
            authenticate_proof=lambda _raw, digest: V.ProofAuthenticationEvidence(
                "UNTRUSTED", digest, True, True
            ),
        ),
    )

    def leaking(_raw: bytes, _digest: str):
        raise RuntimeError("SECRET provider path=/private/socket")

    assert_code(
        "PROOF_AUTHENTICATION_FAILURE",
        lambda: V.admit_network_proof(raw, expected(), authenticate_proof=leaking),
    )


def test_expectation_rejects_user_selected_policy_and_public_listener() -> None:
    assert_code("RELEASE_POLICY_UNKNOWN", lambda: expected(release_policy_id="target-selected"))
    assert_code("SUBNET_INVALID", lambda: expected(proxy_ip="8.8.8.8", subnet_cidrs=("8.8.8.0/24",), guest_ip="8.8.8.7"))
    assert_code("SUBNET_INVALID", lambda: expected(subnet_cidrs=("0.0.0.0/0",)))


def test_admission_and_proxy_capabilities_cannot_be_forged_copied_or_pickled() -> None:
    admission = admit()
    harness = Harness()
    with pytest.raises(TypeError):
        V.NetworkAdmission(object(), expected(), object(), H1, {})  # type: ignore[arg-type]
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(TypeError):
            operation(admission)
    proxy = harness.issue(admission)
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(TypeError):
            operation(proxy)
    forged_admission = object.__new__(V.NetworkAdmission)
    assert_code("ADMISSION_CAPABILITY", lambda: V.issue_attempt_proxy(
        forged_admission,
        consume_replay_durably=lambda _key, _issuance: True,
        deliver_guest_authorization=lambda _view: True,
        entropy=lambda size: bytearray(size),
        resolver=lambda _host, _maximum, _timeout: [],
        connector=lambda _host, _port, _addresses, _timeout: object(),
        peer_observer=lambda _upstream, _timeout: V.PeerObservation("8.8.8.8", 443, "RAW_TCP", False),
        relay_runner=harness.good_relay,
        connection_finalizer=harness.finalize,
        cancel_wakeup=harness.wake_cancelled,
        monotonic_clock=harness.clock,
    ))


def test_issue_consumes_stable_replay_key_before_secret_delivery_and_scrubs_view() -> None:
    harness = Harness()
    admission = admit()
    first = harness.issue(admission)
    assert harness.delivered_view is not None
    assert bytes(harness.delivered_view) == b"\x00" * 45
    first_receipt = first.public_issuance_receipt()
    delivered_count = 1

    def must_not_deliver(_view: memoryview) -> bool:
        nonlocal delivered_count
        delivered_count += 1
        return True

    assert_code(
        "REPLAY_NOT_CONSUMED",
        lambda: V.issue_attempt_proxy(
            admission,
            consume_replay_durably=harness.replay,
            deliver_guest_authorization=must_not_deliver,
            entropy=lambda size: bytearray(b"y" * size),
            resolver=harness.resolve,
            connector=harness.connect,
            peer_observer=harness.observe,
            relay_runner=harness.good_relay,
            connection_finalizer=harness.finalize,
            cancel_wakeup=harness.wake_cancelled,
            monotonic_clock=harness.clock,
        ),
    )
    assert delivered_count == 1
    rendered = json.dumps(first_receipt)
    assert first_receipt["domain_fronting_limitation"] == V.DOMAIN_FRONTING_LIMITATION
    assert harness.token.decode() not in rendered
    assert "api.openai.com" not in rendered


def test_replay_key_is_stable_across_changeable_observation_fields() -> None:
    exp = expected()
    one = proof(exp)
    two = proof(exp)
    two["guest_security"]["socket_census_sha256"] = "6" * 64
    admission_one = V.admit_network_proof(
        V.canonical_proof_bytes(one), exp,
        authenticate_proof=proof_authenticator(exp.proof_authority_id),
    )
    admission_two = V.admit_network_proof(
        V.canonical_proof_bytes(two), exp,
        authenticate_proof=proof_authenticator(exp.proof_authority_id),
    )
    harness = Harness()
    harness.issue(admission_one)
    assert_code("REPLAY_NOT_CONSUMED", lambda: harness.issue(admission_two))

    claude_exp = expected(
        backend_id="claude",
        auth_mode="CLAUDE_OAUTH",
        release_policy_id="claude-egress-2026-09-v1",
    )
    claude_admission = admit(claude_exp)
    assert_code("REPLAY_NOT_CONSUMED", lambda: harness.issue(claude_admission))


def test_exact_connect_success_binds_dns_set_peer_half_close_and_counters() -> None:
    harness = Harness(answers=["1.1.1.1", "8.8.8.8"])
    proxy = harness.issue()
    connection = harness.handle(proxy)
    assert connection["result"] == "COMPLETED"
    assert connection["domain_id"] == "CODEX_API_PRIMARY"
    assert connection["resolved_address_count"] == 2
    assert connection["domain_fronting_limitation"] == V.DOMAIN_FRONTING_LIMITATION
    assert harness.resolver_calls == ["api.openai.com"]
    assert harness.connector_calls == [("api.openai.com", 443, ("1.1.1.1", "8.8.8.8"))]
    assert harness.responses == [b"HTTP/1.1 200 Connection Established\r\n\r\n"]
    terminal = proxy.finish().public_receipt()
    assert terminal["domain_fronting_limitation"] == V.DOMAIN_FRONTING_LIMITATION
    assert terminal["counters"]["tunnels_completed"] == 1
    assert terminal["counters"]["total_bytes"] == 40
    rendered = json.dumps([connection, terminal])
    for forbidden in (harness.token.decode(), "api.openai.com", "1.1.1.1", "8.8.8.8"):
        assert forbidden not in rendered


@pytest.mark.parametrize(
    ("raw_factory", "code"),
    [
        (lambda h: h.request(method="GET"), "CONNECT_METHOD"),
        (lambda h: h.request(version="HTTP/1.0"), "CONNECT_METHOD"),
        (lambda h: h.request(authority="API.OPENAI.COM:443"), "CONNECT_AUTHORITY"),
        (lambda h: h.request(authority="api.openai.com.:443"), "CONNECT_AUTHORITY"),
        (lambda h: h.request(authority="user@api.openai.com:443"), "CONNECT_AUTHORITY"),
        (lambda h: h.request(authority="8.8.8.8:443"), "CONNECT_AUTHORITY"),
        (lambda h: h.request(authority="api.openai.com:0443"), "CONNECT_AUTHORITY"),
        (lambda h: h.request("evil.example"), "CONNECT_DOMAIN"),
        (lambda h: h.request(headers=[b"Host: api.openai.com:443", b"Host: api.openai.com:443", b"Proxy-Authorization: Basic " + base64.b64encode(h.token)]), "CONNECT_HEADERS"),
        (lambda h: h.request(headers=[b"Host: api.openai.com:443", b" Proxy-Authorization: Basic " + base64.b64encode(h.token)]), "CONNECT_FRAMING"),
        (lambda h: h.request(headers=[b"host: api.openai.com:443", b"Proxy-Authorization: Basic " + base64.b64encode(h.token)]), "CONNECT_HEADERS"),
        (lambda h: h.request(headers=[b"Host: api.openai.com:443", b"Proxy-Authorization: Basic " + base64.b64encode(h.token), b"Content-Length: 0"]), "CONNECT_HEADERS"),
        (lambda h: h.request(token=b"A" * 43), "CONNECT_AUTH"),
        (lambda h: h.request() + b"payload", "CONNECT_EXTRA_BYTES"),
        (lambda h: h.request(authority="api.openai.com:443/path"), "CONNECT_AUTHORITY"),
    ],
)
def test_connect_parser_rejects_alias_smuggling_and_unsupported_forms(raw_factory, code: str) -> None:
    harness = Harness()
    proxy = harness.issue()
    assert_code(code, lambda: harness.handle(proxy, raw_factory(harness)))
    assert harness.resolver_calls == []


def test_incremental_parser_rejects_early_tls_bytes_and_truncation() -> None:
    harness = Harness()
    proxy = harness.issue()
    raw = harness.request()
    chunks = [raw[:30], raw[30:] + b"\x16\x03\x01"]

    def reader(_maximum: int, _timeout: float) -> bytes:
        return chunks.pop(0)

    assert_code(
        "CONNECT_EXTRA_BYTES",
        lambda: proxy.handle_connection(
            client=object(),
            source=V.ConnectionSource("10.70.0.2", "plamen-net-a1", 7),
            read_request=reader,
            send_response=harness.send,
        ),
    )
    proxy2 = Harness().issue()
    assert_code(
        "CONNECT_TRUNCATED",
        lambda: proxy2.handle_connection(
            client=object(),
            source=V.ConnectionSource("10.70.0.2", "plamen-net-a1", 7),
            read_request=lambda _maximum, _timeout: b"",
            send_response=lambda _raw, _timeout: None,
        ),
    )
    assert len(harness.finalizations) == 1


def test_connect_rejects_early_tunnel_bytes_in_a_separate_queued_read() -> None:
    harness = Harness()
    proxy = harness.issue()
    chunks = [harness.request(), b"E"]

    def reader(_maximum: int, timeout: float) -> bytes:
        assert 0 <= timeout <= 120
        return chunks.pop(0) if chunks else b""

    assert_code(
        "CONNECT_EXTRA_BYTES",
        lambda: proxy.handle_connection(
            client=object(),
            source=V.ConnectionSource("10.70.0.2", "plamen-net-a1", 7),
            read_request=reader,
            send_response=harness.send,
        ),
    )
    assert harness.resolver_calls == []


def test_connect_rechecks_queued_bytes_at_the_response_boundary() -> None:
    harness = Harness()
    chunks: list[bytes] = []

    def reader(_maximum: int, timeout: float) -> bytes:
        assert 0 <= timeout <= 120
        return chunks.pop(0) if chunks else b""

    original_resolve = harness.resolve

    def resolver(hostname: str, maximum: int, timeout: float):
        answers = original_resolve(hostname, maximum, timeout)
        chunks.append(b"E")
        return answers

    harness.resolve = resolver  # type: ignore[method-assign]
    proxy = harness.issue()
    chunks.append(harness.request())
    assert_code(
        "CONNECT_EXTRA_BYTES",
        lambda: proxy.handle_connection(
            client=object(),
            source=V.ConnectionSource("10.70.0.2", "plamen-net-a1", 7),
            read_request=reader,
            send_response=harness.send,
        ),
    )
    assert harness.responses == []


def test_cancel_during_pending_byte_probe_aborts_before_dns() -> None:
    harness = Harness()
    proxy = harness.issue()
    calls = 0

    def reader(_maximum: int, timeout: float) -> bytes:
        nonlocal calls
        calls += 1
        if calls == 1:
            return harness.request()
        assert timeout == 0.0
        proxy.cancel()
        return b""

    assert_code(
        "PROXY_CANCELLED",
        lambda: proxy.handle_connection(
            client=object(),
            source=V.ConnectionSource("10.70.0.2", "plamen-net-a1", 7),
            read_request=reader,
            send_response=harness.send,
        ),
    )
    assert harness.resolver_calls == []


def test_every_failure_path_requires_cleanup_and_sanitizes_cleanup_failure() -> None:
    harness = Harness()
    proxy = harness.issue()
    assert_code("CONNECT_METHOD", lambda: harness.handle(proxy, harness.request(method="GET")))
    assert len(harness.finalizations) == 1

    harness2 = Harness()
    harness2.finalization_evidence = V.ConnectionFinalizationEvidence(True, False, True, 0)
    proxy2 = harness2.issue()
    assert_code("CONNECTION_CLEANUP", lambda: harness2.handle(proxy2, harness2.request(method="GET")))
    assert_code("CLEANUP_DEBT", proxy2.finish)

    harness3 = Harness()

    def bad_cleanup(_client: object, _upstream: object | None, _timeout: float):
        raise RuntimeError("SECRET /Users/private/socket")

    harness3.finalize = bad_cleanup  # type: ignore[method-assign]
    proxy3 = harness3.issue()
    with pytest.raises(V.VerifiedEgressError) as caught:
        harness3.handle(proxy3, harness3.request(method="GET"))
    assert str(caught.value) == "CONNECTION_CLEANUP"
    assert "SECRET" not in str(caught.value)


@pytest.mark.parametrize(
    ("answers", "code"),
    [
        (["127.0.0.1"], "ADDRESS_NOT_GLOBAL"),
        (["10.0.0.1"], "ADDRESS_NOT_GLOBAL"),
        (["169.254.1.1"], "ADDRESS_NOT_GLOBAL"),
        (["224.0.0.1"], "ADDRESS_NOT_GLOBAL"),
        (["fec0::1"], "ADDRESS_NOT_GLOBAL"),
        (["8.8.8.8", "10.0.0.1"], "ADDRESS_NOT_GLOBAL"),
        (["8.8.8.8", "8.8.8.8"], "DNS_DUPLICATE"),
        ([], "DNS_ANSWERS"),
        (["8.8.8.8"] * (V.MAX_DNS_ANSWERS + 1), "DNS_ANSWERS"),
        (["2001:4860:4860:0:0:0:0:8888"], "ADDRESS_ALIAS"),
    ],
)
def test_dns_ssrf_mixed_answers_aliases_and_caps_fail_closed(answers, code: str) -> None:
    harness = Harness(answers=answers)
    proxy = harness.issue()
    assert_code(code, lambda: harness.handle(proxy))
    assert harness.connector_calls == []


def test_dns_rebinding_and_tls_termination_are_rejected() -> None:
    harness = Harness(peer=V.PeerObservation("1.1.1.1", 443, "RAW_TCP", False))
    proxy = harness.issue()
    assert_code("DNS_REBINDING", lambda: harness.handle(proxy))
    harness2 = Harness(peer=V.PeerObservation("8.8.8.8", 443, "TLS", True))
    proxy2 = harness2.issue()
    assert_code("DNS_REBINDING", lambda: harness2.handle(proxy2))


def test_cancel_during_dns_aborts_before_connect_and_wakes_blocked_callbacks() -> None:
    harness = Harness()
    holder: dict[str, V.AttemptProxy] = {}

    def cancel_during_resolution(_hostname: str, _maximum: int, _timeout: float):
        holder["proxy"].cancel()
        return ["8.8.8.8"]

    harness.resolve = cancel_during_resolution  # type: ignore[method-assign]
    proxy = harness.issue()
    holder["proxy"] = proxy
    assert_code("PROXY_CANCELLED", lambda: harness.handle(proxy))
    assert harness.connector_calls == []
    assert harness.cancel_wakeups == 1


def test_cancel_wakeup_failure_creates_sticky_cleanup_debt() -> None:
    harness = Harness()

    def failed_wakeup(_timeout: float) -> bool:
        harness.cancel_wakeups += 1
        return False

    harness.wake_cancelled = failed_wakeup  # type: ignore[method-assign]
    proxy = harness.issue()
    assert_code("CANCEL_WAKEUP", proxy.cancel)
    assert harness.cancel_wakeups == 1
    assert_code("CLEANUP_DEBT", proxy.finish)


def test_exact_source_network_generation_and_attempt_auth_are_all_required() -> None:
    harness = Harness()
    proxy = harness.issue()

    def call(source: V.ConnectionSource) -> None:
        chunks = [harness.request()]
        proxy.handle_connection(
            client=object(), source=source,
            read_request=lambda _maximum, _timeout: chunks.pop(0),
            send_response=harness.send,
        )

    assert_code("SOURCE_BINDING", lambda: call(V.ConnectionSource("10.70.0.3", "plamen-net-a1", 7)))
    assert_code("SOURCE_BINDING", lambda: call(V.ConnectionSource("10.70.0.2", "other-net", 7)))
    assert_code("SOURCE_BINDING", lambda: call(V.ConnectionSource("10.70.0.2", "plamen-net-a1", 8)))
    assert_code(
        "INTEGER_INVALID",
        lambda: V.ConnectionSource("10.70.0.2", "plamen-net-a1", True),
    )


def test_quota_violation_cancels_attempt_and_runner_must_acknowledge_cancel() -> None:
    harness = Harness()

    def relay(_client, _upstream, controller: V.RelayController):
        controller.record_client_to_upstream(32 * 1024 * 1024 + 1)
        raise AssertionError("unreachable")

    harness.relay = relay
    proxy = harness.issue()
    assert_code("DIRECTION_BYTE_QUOTA", lambda: harness.handle(proxy))
    assert_code("PROXY_CLOSED", lambda: harness.handle(proxy))
    terminal = proxy.finish().public_receipt()
    assert terminal["cancelled"] is True
    assert terminal["counters"]["quota_rejections"] >= 1


def test_runner_cannot_swallow_latched_quota_failure() -> None:
    harness = Harness()

    def relay(_client, _upstream, controller: V.RelayController):
        with pytest.raises(V.VerifiedEgressError):
            controller.record_client_to_upstream(32 * 1024 * 1024 + 1)
        controller.mark_client_eof_and_upstream_half_close()
        controller.mark_upstream_eof_and_client_half_close()
        return V.RelayRunnerEvidence(True, True, True, 0, True, True, True)

    harness.relay = relay
    proxy = harness.issue()
    assert_code("DIRECTION_BYTE_QUOTA", lambda: harness.handle(proxy))


def test_same_direction_parallel_accounting_cannot_race_per_connection_quota() -> None:
    harness = Harness()

    def relay(_client, _upstream, controller: V.RelayController):
        barrier = threading.Barrier(3)
        failures: list[V.VerifiedEgressError] = []

        def record() -> None:
            barrier.wait(timeout=2)
            try:
                controller.record_client_to_upstream(20 * 1024 * 1024)
            except V.VerifiedEgressError as exc:
                failures.append(exc)

        threads = [threading.Thread(target=record) for _ in range(2)]
        for thread in threads:
            thread.start()
        barrier.wait(timeout=2)
        for thread in threads:
            thread.join(timeout=2)
        assert len(failures) == 1
        controller.mark_client_eof_and_upstream_half_close()
        controller.mark_upstream_eof_and_client_half_close()
        return V.RelayRunnerEvidence(True, True, True, 0, True, True, True)

    harness.relay = relay
    proxy = harness.issue()
    assert_code("DIRECTION_BYTE_QUOTA", lambda: harness.handle(proxy))


def test_half_close_fd_descendant_and_deadline_evidence_are_mandatory() -> None:
    bad_rows = [
        V.RelayRunnerEvidence(False, True, True, 0, False, True, True),
        V.RelayRunnerEvidence(True, False, True, 0, False, True, True),
        V.RelayRunnerEvidence(True, True, False, 0, False, True, True),
        V.RelayRunnerEvidence(True, True, True, 1, False, True, True),
        V.RelayRunnerEvidence(True, True, True, 0, False, False, True),
        V.RelayRunnerEvidence(True, True, True, 0, False, True, False),
    ]
    for evidence in bad_rows:
        harness = Harness()

        def relay(_client, _upstream, controller: V.RelayController, evidence=evidence):
            controller.mark_client_eof_and_upstream_half_close()
            controller.mark_upstream_eof_and_client_half_close()
            return evidence

        harness.relay = relay
        assert_code("RUNNER_EVIDENCE", lambda: harness.handle(harness.issue()))

    harness = Harness()

    def slow(_client, _upstream, controller: V.RelayController):
        controller.mark_client_eof_and_upstream_half_close()
        controller.mark_upstream_eof_and_client_half_close()
        harness.now += 121
        return V.RelayRunnerEvidence(True, True, True, 0, False, True, True)

    harness.relay = slow
    assert_code("CONNECTION_DEADLINE", lambda: harness.handle(harness.issue()))


def test_cancellation_is_observable_and_requires_runner_ack() -> None:
    harness = Harness()
    holder: dict[str, V.AttemptProxy] = {}

    def relay(_client, _upstream, controller: V.RelayController):
        holder["proxy"].cancel()
        assert controller.cancel_requested()
        controller.mark_client_eof_and_upstream_half_close()
        controller.mark_upstream_eof_and_client_half_close()
        return V.RelayRunnerEvidence(True, True, True, 0, True, True, True)

    harness.relay = relay
    proxy = harness.issue()
    holder["proxy"] = proxy
    assert harness.handle(proxy)["result"] == "COMPLETED"
    assert proxy.finish().public_receipt()["cancelled"] is True


def test_cancel_after_terminal_fails_without_wakeup_or_state_change() -> None:
    harness = Harness()
    proxy = harness.issue()
    terminal = proxy.finish()
    before = terminal.public_receipt()
    assert before["cancelled"] is False
    assert harness.cancel_wakeups == 0

    assert_code("PROXY_CLOSED", proxy.cancel)

    assert harness.cancel_wakeups == 0
    assert terminal.public_receipt() == before


def test_concurrency_quota_rejects_fifth_connection() -> None:
    harness = Harness()
    entered = threading.Barrier(5)
    release = threading.Event()

    def relay(_client, _upstream, controller: V.RelayController):
        entered.wait(timeout=3)
        release.wait(timeout=3)
        controller.mark_client_eof_and_upstream_half_close()
        controller.mark_upstream_eof_and_client_half_close()
        return V.RelayRunnerEvidence(True, True, True, 0, False, True, True)

    harness.relay = relay
    proxy = harness.issue()
    failures: list[BaseException] = []

    def run() -> None:
        try:
            harness.handle(proxy)
        except BaseException as exc:  # captured for the test thread
            failures.append(exc)

    threads = [threading.Thread(target=run) for _ in range(4)]
    for thread in threads:
        thread.start()
    entered.wait(timeout=3)
    assert_code("CONCURRENCY_QUOTA", lambda: harness.handle(proxy))
    release.set()
    for thread in threads:
        thread.join(timeout=3)
    assert failures == []
    assert proxy.finish().public_receipt()["counters"]["quota_rejections"] == 1


def terminal_proof(host: dict[str, object], exp: V.TrustedNetworkExpectation | None = None) -> dict[str, object]:
    exp = exp or expected()
    result: dict[str, object] = {
        "schema": V.TERMINAL_PROOF_SCHEMA,
        "attempt_binding_sha256": exp.attempt_binding_sha256,
        "tls_mode": V.TLS_MODE,
        "opaque_tls_limitation": V.OPAQUE_TLS_LIMITATION,
        "domain_fronting_limitation": V.DOMAIN_FRONTING_LIMITATION,
        "network": {
            "network_id_sha256": __import__("hashlib").sha256(exp.provider_network_id.encode()).hexdigest(),
            "network_generation": exp.network_generation,
            "network_removed": True,
            "guest_stopped": True,
            "cgroup_populated": 0,
            "private_channel_identity_sha256": exp.channel_identity_sha256,
            "private_channel_removed": True,
            "guest_shim_identity_sha256": exp.shim_identity_sha256,
            "guest_shim_descendant_count": 0,
            "guest_shim_fd_count": 0,
            "guest_shim_extinct": True,
        },
        "host_proxy": {
            "terminal_sha256": host["terminal_sha256"],
            "active_connections": 0,
            "resolution_set_count": host["resolution_set_count"],
            "resolution_sets_sha256": host["resolution_sets_sha256"],
            "counters": copy.deepcopy(host["counters"]),
        },
        "extinction": {
            "listener_closed": True,
            "listener_fd_count": 0,
            "relay_fd_count": 0,
            "runner_descendant_count": 0,
            "runner_descendants_extinct": True,
        },
    }
    return result


def test_terminal_reconciliation_binds_network_extinction_and_exact_counters() -> None:
    admission = admit()
    harness = Harness()
    proxy = harness.issue(admission)
    harness.handle(proxy)
    host_capability = proxy.finish()
    host = host_capability.public_receipt()
    value = terminal_proof(host)
    result = V.reconcile_terminal_proof(
        V.canonical_proof_bytes(value), admission, host_capability,
        authenticate_terminal_proof=proof_authenticator(V.PROVIDER_TERMINAL_PROOF_AUTHORITY),
    )
    assert result["result"] == "RECONCILED"
    assert result["connection_count"] == 1
    assert result["total_bytes"] == 40
    assert result["domain_fronting_limitation"] == V.DOMAIN_FRONTING_LIMITATION
    rendered = json.dumps(result)
    assert "10.70.0" not in rendered and "api.openai.com" not in rendered
    assert_code("TERMINAL_REPLAY", proxy.finish)
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(TypeError):
            operation(host_capability)


def test_terminal_proof_requires_authenticated_source_and_private_channel_extinction() -> None:
    admission = admit()
    terminal = Harness().issue(admission).finish()
    value = terminal_proof(terminal.public_receipt())
    raw = V.canonical_proof_bytes(value)
    assert_code(
        "TERMINAL_PROOF_AUTHENTICATION",
        lambda: V.reconcile_terminal_proof(
            raw, admission, terminal,
            authenticate_terminal_proof=lambda _raw, digest: V.ProofAuthenticationEvidence(
                "UNTRUSTED", digest, True, True
            ),
        ),
    )
    value["network"]["private_channel_removed"] = False
    assert_code(
        "TERMINAL_NETWORK",
        lambda: V.reconcile_terminal_proof(
            V.canonical_proof_bytes(value), admission, terminal,
            authenticate_terminal_proof=proof_authenticator(V.PROVIDER_TERMINAL_PROOF_AUTHORITY),
        ),
    )


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("tls_mode", "TLS_TERMINATED"),
        ("opaque_tls_limitation", "DENIED"),
        ("domain_fronting_limitation", "INSPECTED"),
    ],
)
def test_terminal_proof_rejects_tls_assurance_mutation(field: str, replacement: str) -> None:
    admission = admit()
    terminal = Harness().issue(admission).finish()
    value = terminal_proof(terminal.public_receipt())
    value[field] = replacement
    assert_code(
        "TERMINAL_SCHEMA",
        lambda: V.reconcile_terminal_proof(
            V.canonical_proof_bytes(value), admission, terminal,
            authenticate_terminal_proof=proof_authenticator(V.PROVIDER_TERMINAL_PROOF_AUTHORITY),
        ),
    )


def test_public_receipts_are_deep_copies() -> None:
    admission = admit()
    first = admission.public_receipt()
    first["domain_ids"].append("ATTACKER")
    assert "ATTACKER" not in admission.public_receipt()["domain_ids"]
    harness = Harness()
    proxy = harness.issue(admission)
    issued = proxy.public_issuance_receipt()
    issued["limits"]["maximum_connections"] = 10**9
    issued["domain_ids"].clear()
    replayed = proxy.public_issuance_receipt()
    assert replayed["limits"]["maximum_connections"] == 64
    assert replayed["domain_ids"]


def test_terminal_capability_cannot_be_swapped_for_equivalent_admission() -> None:
    first_admission = admit()
    second_admission = admit()
    harness = Harness()
    terminal = harness.issue(first_admission).finish()
    raw = V.canonical_proof_bytes(terminal_proof(terminal.public_receipt()))
    assert_code(
        "TERMINAL_AUTHORITY",
        lambda: V.reconcile_terminal_proof(
            raw, second_admission, terminal,
            authenticate_terminal_proof=proof_authenticator(V.PROVIDER_TERMINAL_PROOF_AUTHORITY),
        ),
    )


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (lambda p: p["network"].__setitem__("network_removed", False), "TERMINAL_NETWORK"),
        (lambda p: p["network"].__setitem__("cgroup_populated", 1), "TERMINAL_NETWORK"),
        (lambda p: p["host_proxy"]["counters"].__setitem__("total_bytes", 999), "TERMINAL_COUNTER_MISMATCH"),
        (lambda p: p["extinction"].__setitem__("listener_fd_count", 1), "TERMINAL_EXTINCTION"),
        (lambda p: p["extinction"].__setitem__("runner_descendant_count", 1), "TERMINAL_EXTINCTION"),
    ],
)
def test_terminal_reconciliation_rejects_counter_or_extinction_debt(mutate, code: str) -> None:
    admission = admit()
    harness = Harness()
    proxy = harness.issue(admission)
    host_capability = proxy.finish()
    host = host_capability.public_receipt()
    value = terminal_proof(host)
    mutate(value)
    assert_code(code, lambda: V.reconcile_terminal_proof(
        V.canonical_proof_bytes(value), admission, host_capability,
        authenticate_terminal_proof=proof_authenticator(V.PROVIDER_TERMINAL_PROOF_AUTHORITY),
    ))


def test_errors_and_public_receipts_do_not_leak_callback_values() -> None:
    harness = Harness()

    def resolver(_hostname: str, _maximum: int, _timeout: float):
        raise RuntimeError("SECRET-TOKEN host=/Users/name/.codex/auth.json")

    harness.resolve = resolver  # type: ignore[method-assign]
    proxy = harness.issue()
    with pytest.raises(V.VerifiedEgressError) as caught:
        harness.handle(proxy)
    assert str(caught.value) == "TRUSTED_CALLBACK_FAILURE"
    assert "SECRET" not in str(caught.value)
    assert "Users" not in json.dumps(proxy.finish().public_receipt())

    harness2 = Harness()

    def forged_internal_error(_hostname: str, _maximum: int, _timeout: float):
        raise V._error("secret_like_safe_id")

    harness2.resolve = forged_internal_error  # type: ignore[method-assign]
    proxy2 = harness2.issue()
    assert_code("TRUSTED_CALLBACK_FAILURE", lambda: harness2.handle(proxy2))
    with pytest.raises(TypeError):
        V.VerifiedEgressError("FORGED")


def test_release_policy_is_backend_specific_and_endpoint_names_are_not_enumerated() -> None:
    assert V.release_policy_ids() == (
        ("claude", "API_KEY", "claude-api-egress-2026-09-v2"),
        ("claude", "CLAUDE_OAUTH", "claude-egress-2026-09-v1"),
        ("codex", "API_KEY", "codex-api-egress-2026-09-v2"),
        ("codex", "CHATGPT_OAUTH", "codex-egress-2026-09-v1"),
    )
    assert all("." not in item for pair in V.release_policy_ids() for item in pair)


def v2_expectation(**changes: object) -> V.EgressV2Expectation:
    values: dict[str, object] = {
        "provider_attempt_id": "attempt:A-1",
        "attempt_binding_sha256": H1,
        "backend_id": "codex",
        "auth_mode": "CHATGPT_OAUTH",
        "release_policy_id": "codex-egress-2026-09-v1",
        "topology_mode": V.APPLE_TOPOLOGY_MODE,
        "effective_egress_mode": V.EFFECTIVE_EGRESS_MODE,
        "network_id_sha256": H2,
        "network_generation": 7,
        "ruleset_sha256": H3,
        "ruleset_generation": 11,
        "direct_public_ipv4": "1.1.1.1",
        "direct_public_ipv6": "2606:4700:4700::1111",
        "gateway_ipv4": "10.70.0.1",
        "proxy_port": 9443,
        "other_gateway_tcp_port": 9444,
        "allowlisted_domain_id": "CODEX_API_PRIMARY",
        "broker_authority_sha256": H4,
        "challenge_proxy_auth_generation": 41,
        "challenge_proxy_auth_binding_sha256": H5,
        "runtime_proxy_auth_generation": 42,
        "runtime_proxy_auth_binding_sha256": H6,
        "native_attestation_signature_sha256": H7,
    }
    values.update(changes)
    return V.EgressV2Expectation(**values)  # type: ignore[arg-type]


def v2_transcript(exp: V.EgressV2Expectation | None = None) -> dict[str, object]:
    exp = exp or v2_expectation()
    target_digests = V._v2_target_digests(exp)
    shapes = (
        ("DIRECT_PUBLIC_IPV4_DENIED", "TCP", "IPv4", "PUBLIC_IPV4", "NONE", "DENIED"),
        ("DIRECT_PUBLIC_IPV6_DENIED", "TCP", "IPv6", "PUBLIC_IPV6", "NONE", "DENIED"),
        ("GATEWAY_OTHER_TCP_DENIED", "TCP", "IPv4", "GATEWAY_OTHER_TCP", "NONE", "DENIED"),
        ("GATEWAY_UDP_DENIED", "UDP", "IPv4", "GATEWAY_UDP", "NONE", "DENIED"),
        ("GATEWAY_RAW_DENIED", "RAW_IP", "IPv4", "GATEWAY_RAW", "NONE", "DENIED"),
        ("PROXY_MISSING_AUTH_DENIED", "TCP", "IPv4", "PROXY", "MISSING", "DENIED"),
        ("PROXY_WRONG_AUTH_DENIED", "TCP", "IPv4", "PROXY", "WRONG", "DENIED"),
        ("PROXY_CROSS_ATTEMPT_AUTH_DENIED", "TCP", "IPv4", "PROXY", "OTHER_ATTEMPT", "DENIED"),
        ("PROXY_ALLOWLIST_CONNECT_SUCCEEDED", "CONNECT", "DOMAIN", "ALLOWLIST", "CHALLENGE_CURRENT", "CONNECTED"),
        ("PROXY_REPLAY_AUTH_DENIED", "CONNECT", "DOMAIN", "ALLOWLIST", "CHALLENGE_REPLAY", "DENIED"),
    )
    counters = {
        "connection_attempts": 0,
        "tunnels_established": 0,
        "tunnels_completed": 0,
        "requests_rejected": 0,
        "auth_rejections": 0,
    }
    challenges: list[dict[str, object]] = []
    for offset, shape in enumerate(shapes):
        challenge_id, transport, family, target_id, credential_case, outcome = shape
        before = dict(counters)
        if challenge_id.startswith("PROXY_"):
            counters["connection_attempts"] += 1
        if challenge_id in {
            "PROXY_MISSING_AUTH_DENIED", "PROXY_WRONG_AUTH_DENIED",
            "PROXY_CROSS_ATTEMPT_AUTH_DENIED", "PROXY_REPLAY_AUTH_DENIED",
        }:
            counters["requests_rejected"] += 1
            counters["auth_rejections"] += 1
        elif challenge_id == "PROXY_ALLOWLIST_CONNECT_SUCCEEDED":
            counters["tunnels_established"] += 1
            counters["tunnels_completed"] += 1
        challenges.append({
            "sequence": 3 + offset,
            "challenge_id": challenge_id,
            "transport": transport,
            "address_family": family,
            "target_id": target_id,
            "target_sha256": target_digests[target_id],
            "credential_case": credential_case,
            "proxy_auth_generation": (
                0 if credential_case in {"NONE", "MISSING"} else exp.challenge_proxy_auth_generation
            ),
            "observed_outcome": outcome,
            "backend_credential_released": False,
            "proxy_counters_before": before,
            "proxy_counters_after": dict(counters),
        })
    result: dict[str, object] = {
        "schema": V.EGRESS_V2_TRANSCRIPT_SCHEMA,
        "attempt": {
            "provider_attempt_id": exp.provider_attempt_id,
            "attempt_binding_sha256": exp.attempt_binding_sha256,
            "backend_id": exp.backend_id,
            "auth_mode": exp.auth_mode,
            "release_policy_id": exp.release_policy_id,
        },
        "network": {
            "topology_mode": exp.topology_mode,
            "effective_egress_mode": exp.effective_egress_mode,
            "network_id_sha256": exp.network_id_sha256,
            "network_generation": exp.network_generation,
            "ruleset_sha256": exp.ruleset_sha256,
            "ruleset_generation": exp.ruleset_generation,
        },
        "ordering": {
            "rules_installed_sequence": 1,
            "challenge_proxy_auth_minted_sequence": 2,
            "challenge_proxy_auth_revoked_sequence": 13,
            "runtime_proxy_auth_minted_sequence": 14,
            "admission_committed_sequence": 15,
            "backend_credential_release_sequence": 16,
            "backend_credential_released_before_admission": False,
        },
        "target_set_sha256": exp.target_set_sha256,
        "challenges": challenges,
        "proxy_auth_generations": {
            "challenge_generation": exp.challenge_proxy_auth_generation,
            "challenge_binding_sha256": exp.challenge_proxy_auth_binding_sha256,
            "challenge_one_shot": True,
            "challenge_success_sequence": 11,
            "challenge_replay_denied_sequence": 12,
            "challenge_revoked_sequence": 13,
            "runtime_generation": exp.runtime_proxy_auth_generation,
            "runtime_binding_sha256": exp.runtime_proxy_auth_binding_sha256,
            "runtime_reusable_within_attempt": True,
            "runtime_minted_sequence": 14,
            "credentials_distinct": True,
        },
    }
    statement = {
        key: result[key]
        for key in (
            "schema", "attempt", "network", "ordering", "target_set_sha256",
            "challenges", "proxy_auth_generations",
        )
    }
    result["native_attestation"] = {
        "authority_id": V.NATIVE_EGRESS_V2_AUTHORITY,
        "broker_authority_sha256": exp.broker_authority_sha256,
        "statement_sha256": hashlib.sha256(V.canonical_proof_bytes(statement)).hexdigest(),
        "signature_sha256": H7,
        "signature_algorithm": "NATIVE_BROKER_V2_OPAQUE_SHA256",
        "authenticated": True,
        "replay_safe": True,
    }
    return result


def validate_v2(
    value: dict[str, object], exp: V.EgressV2Expectation | None = None
) -> V.TEST_ONLY_EgressV2Validation:
    return V.TEST_ONLY_validate_egress_v2_transcript(
        V.canonical_proof_bytes(value), exp or v2_expectation()
    )


def test_v2_transcript_validates_full_ordered_challenge_set_but_is_not_authority() -> None:
    exp = v2_expectation()
    validation = validate_v2(v2_transcript(exp), exp)
    receipt = validation.public_receipt()
    assert receipt["result"] == "SEMANTICS_VALIDATED_NON_AUTHORITATIVE"
    assert receipt["authority_class"] == "TEST_ONLY_NON_AUTHORITY"
    assert receipt["native_authority_required"] == V.NATIVE_EGRESS_V2_AUTHORITY
    assert receipt["topology_mode"] == "hostOnly"
    assert receipt["effective_egress_mode"] == "VERIFIED_CONNECT_ALLOWLIST"
    assert receipt["challenge_count"] == 10
    assert receipt["last_challenge_sequence"] < receipt["admission_committed_sequence"]
    assert receipt["admission_committed_sequence"] < receipt["backend_credential_release_sequence"]
    assert receipt["final_proxy_counters"] == {
        "connection_attempts": 5,
        "tunnels_established": 1,
        "tunnels_completed": 1,
        "requests_rejected": 4,
        "auth_rejections": 4,
    }
    rendered = repr(validation) + json.dumps(receipt, sort_keys=True)
    for forbidden in (
        exp.direct_public_ipv4, exp.direct_public_ipv6, exp.gateway_ipv4,
        "api.openai.com", "Proxy-Authorization", "Basic ",
    ):
        assert forbidden not in rendered


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("direct_public_ipv4", "10.0.0.8"),
        ("direct_public_ipv4", "2001:4860:4860::8888"),
        ("direct_public_ipv6", "fd00::1"),
        ("direct_public_ipv6", "8.8.8.8"),
        ("direct_public_ipv6", "2606:4700:4700:0:0:0:0:1111"),
        ("gateway_ipv4", "8.8.8.8"),
        ("gateway_ipv4", "127.0.0.1"),
        ("other_gateway_tcp_port", 9443),
        ("effective_egress_mode", "hostOnly"),
        ("topology_mode", "VERIFIED_CONNECT_ALLOWLIST"),
    ],
)
def test_v2_expectation_rejects_private_global_alias_and_family_confusion(
    field: str, replacement: object
) -> None:
    assert_code("ADDRESS_NOT_GLOBAL" if field.startswith("direct_public") and replacement in {"10.0.0.8", "fd00::1"} else (
        "ADDRESS_ALIAS" if replacement == "2606:4700:4700:0:0:0:0:1111" else
        "CHALLENGE_ADDRESS_FAMILY" if field.startswith("direct_public") else
        "CHALLENGE_GATEWAY" if field in {"gateway_ipv4", "other_gateway_tcp_port"} else
        "NETWORK_MODE"
    ), lambda: v2_expectation(**{field: replacement}))


@pytest.mark.parametrize(
    ("section", "field", "replacement", "code"),
    [
        ("attempt", "attempt_binding_sha256", H8, "EGRESS_V2_ATTEMPT_BINDING"),
        ("attempt", "auth_mode", "API_KEY", "EGRESS_V2_ATTEMPT_BINDING"),
        ("network", "topology_mode", "VERIFIED_CONNECT_ALLOWLIST", "EGRESS_V2_NETWORK_BINDING"),
        ("network", "effective_egress_mode", "hostOnly", "EGRESS_V2_NETWORK_BINDING"),
        ("network", "network_generation", 8, "EGRESS_V2_NETWORK_BINDING"),
        ("network", "ruleset_generation", 12, "EGRESS_V2_NETWORK_BINDING"),
        ("ordering", "admission_committed_sequence", 12, "EGRESS_V2_ORDERING"),
        ("ordering", "backend_credential_release_sequence", 13, "EGRESS_V2_ORDERING"),
        ("ordering", "backend_credential_released_before_admission", True, "EGRESS_V2_ORDERING"),
    ],
)
def test_v2_transcript_mutations_fail_closed(
    section: str, field: str, replacement: object, code: str
) -> None:
    value = v2_transcript()
    value[section][field] = replacement  # type: ignore[index]
    assert_code(code, lambda: validate_v2(value))


@pytest.mark.parametrize(
    ("index", "field", "replacement"),
    [
        (0, "sequence", 4),
        (0, "target_sha256", H8),
        (0, "observed_outcome", "CONNECTED"),
        (1, "address_family", "IPv4"),
        (2, "transport", "UDP"),
        (5, "credential_case", "CHALLENGE_CURRENT"),
        (7, "credential_case", "CHALLENGE_CURRENT"),
        (8, "backend_credential_released", True),
        (9, "challenge_id", "PROXY_ALLOWLIST_CONNECT_SUCCEEDED"),
    ],
)
def test_v2_every_challenge_dimension_is_exact(
    index: int, field: str, replacement: object
) -> None:
    value = v2_transcript()
    value["challenges"][index][field] = replacement  # type: ignore[index]
    assert_code("EGRESS_V2_CHALLENGE_BINDING", lambda: validate_v2(value))


def test_v2_challenges_are_complete_ordered_and_counter_chained() -> None:
    for mutation in ("drop", "duplicate", "swap"):
        value = v2_transcript()
        rows = value["challenges"]  # type: ignore[assignment]
        if mutation == "drop":
            rows.pop()  # type: ignore[union-attr]
        elif mutation == "duplicate":
            rows.append(copy.deepcopy(rows[-1]))  # type: ignore[index,union-attr]
        else:
            rows[0], rows[1] = rows[1], rows[0]  # type: ignore[index]
        assert_code("EGRESS_V2_CHALLENGES" if mutation != "swap" else "EGRESS_V2_CHALLENGE_BINDING", lambda value=value: validate_v2(value))

    for index in range(10):
        for snapshot in ("proxy_counters_before", "proxy_counters_after"):
            value = v2_transcript()
            value["challenges"][index][snapshot]["connection_attempts"] += 1  # type: ignore[index,operator]
            assert_code("EGRESS_V2_CHALLENGE_BINDING", lambda value=value: validate_v2(value))


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("challenge_generation", 42),
        ("challenge_binding_sha256", H8),
        ("challenge_one_shot", False),
        ("challenge_success_sequence", 12),
        ("challenge_replay_denied_sequence", 11),
        ("challenge_revoked_sequence", 12),
        ("runtime_generation", 41),
        ("runtime_binding_sha256", H8),
        ("runtime_reusable_within_attempt", False),
        ("runtime_minted_sequence", 13),
        ("credentials_distinct", False),
    ],
)
def test_v2_one_shot_challenge_auth_rotates_to_distinct_reusable_runtime_auth(
    field: str, replacement: object
) -> None:
    value = v2_transcript()
    value["proxy_auth_generations"][field] = replacement  # type: ignore[index]
    assert_code("EGRESS_V2_AUTH_GENERATION", lambda: validate_v2(value))


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("authority_id", "PYTHON_STRUCTURAL"),
        ("broker_authority_sha256", H8),
        ("statement_sha256", H8),
        ("signature_sha256", H8),
        ("signature_algorithm", "HMAC-SHA256"),
        ("authenticated", False),
        ("replay_safe", False),
    ],
)
def test_v2_native_attestation_fields_and_statement_are_exact(
    field: str, replacement: object
) -> None:
    value = v2_transcript()
    value["native_attestation"][field] = replacement  # type: ignore[index]
    assert_code("EGRESS_V2_ATTESTATION", lambda: validate_v2(value))


def test_v2_auth_generations_are_consecutive_distinct_attempt_bindings() -> None:
    assert_code(
        "PROXY_AUTH_GENERATION",
        lambda: v2_expectation(runtime_proxy_auth_generation=43),
    )
    assert_code(
        "PROXY_AUTH_GENERATION",
        lambda: v2_expectation(runtime_proxy_auth_binding_sha256=H5),
    )


def test_v2_target_set_binds_raw_ip_gateway_proxy_and_backend_policy() -> None:
    value = v2_transcript()
    value["target_set_sha256"] = H8
    assert_code("EGRESS_V2_TARGET_SET", lambda: validate_v2(value))
    for changes in (
        {"direct_public_ipv4": "8.8.4.4"},
        {"direct_public_ipv6": "2001:4860:4860::8844"},
        {"other_gateway_tcp_port": 9445},
        {"allowlisted_domain_id": "CODEX_CHATGPT_BACKEND"},
    ):
        assert_code(
            "EGRESS_V2_TARGET_SET",
            lambda changes=changes: validate_v2(value=v2_transcript(), exp=v2_expectation(**changes)),
        )


def test_v2_policy_is_exactly_backend_and_auth_mode_specific() -> None:
    codex_api = v2_expectation(
        auth_mode="API_KEY",
        release_policy_id="codex-api-egress-2026-09-v2",
    )
    assert codex_api.allowlisted_domain_id == "CODEX_API_PRIMARY"
    assert_code(
        "CONNECT_DOMAIN",
        lambda: v2_expectation(
            auth_mode="API_KEY",
            release_policy_id="codex-api-egress-2026-09-v2",
            allowlisted_domain_id="CODEX_CHATGPT_BACKEND",
        ),
    )
    assert_code(
        "RELEASE_POLICY_UNKNOWN",
        lambda: v2_expectation(auth_mode="API_KEY"),
    )
    assert_code(
        "RELEASE_POLICY_UNKNOWN",
        lambda: v2_expectation(backend_id="claude", auth_mode="CHATGPT_OAUTH"),
    )


def test_generation_bound_cli_connect_bytes_are_typed_unsupported_not_inferred() -> None:
    rows = (
        V.TEST_ONLY_connect_fixture_compatibility(
            "codex", "CHATGPT_OAUTH",
            install_generation_authority=install_generation("codex", "0.154.0"),
        ),
        V.TEST_ONLY_connect_fixture_compatibility(
            "codex", "API_KEY",
            install_generation_authority=install_generation("codex", "0.154.0"),
        ),
        V.TEST_ONLY_connect_fixture_compatibility(
            "claude", "CLAUDE_OAUTH",
            install_generation_authority=install_generation("claude", "2.1.270"),
        ),
        V.TEST_ONLY_connect_fixture_compatibility(
            "claude", "API_KEY",
            install_generation_authority=install_generation("claude", "2.1.270"),
        ),
    )
    assert {(row.backend_id, row.cli_version) for row in rows} == {
        ("codex", "0.154.0"), ("claude", "2.1.270")
    }
    assert all(
        row.supported is False
        and row.reason_code == V.PINNED_FIXTURE_UNSUPPORTED
        and row.fixture_sha256 is None
        for row in rows
    )


def test_basic_proxy_auth_is_strict_standard_canonical_and_redacted() -> None:
    harness = Harness()
    proxy = harness.issue()
    assert harness.handle(proxy)["result"] == "COMPLETED"
    receipt = proxy.finish().public_receipt()
    encoded = base64.b64encode(harness.token)
    assert encoded not in json.dumps(receipt).encode()

    bad_headers = (
        b"Proxy-Authorization: Plamen " + harness.token,
        b"Proxy-Authorization: basic " + encoded,
        b"Proxy-Authorization: Basic " + encoded + b"=",
        b"Proxy-Authorization: Basic " + base64.b64encode(b"x" * 45),
        b"Proxy-Authorization: Basic " + base64.b64encode(b"x" * 22 + b"::" + b"y" * 21),
    )
    for auth_header in bad_headers:
        other = Harness()
        attempt = other.issue()
        raw = other.request(headers=[b"Host: api.openai.com:443", auth_header])
        assert_code("CONNECT_AUTH", lambda attempt=attempt, other=other, raw=raw: other.handle(attempt, raw))
        assert other.resolver_calls == []


def test_basic_proxy_credentials_are_attempt_random_and_cross_attempt_rejected() -> None:
    first = Harness()
    first_proxy = first.issue()
    first_credential = first.token

    second = Harness()
    second_proxy = V.issue_attempt_proxy(
        admit(),
        consume_replay_durably=second.replay,
        deliver_guest_authorization=second.deliver,
        entropy=lambda size: bytearray(b"y" * size),
        resolver=second.resolve,
        connector=second.connect,
        peer_observer=second.observe,
        relay_runner=second.good_relay,
        connection_finalizer=second.finalize,
        cancel_wakeup=second.wake_cancelled,
        monotonic_clock=second.clock,
    )
    assert first_credential != second.token
    cross_attempt = second.request(token=first_credential)
    assert_code(
        "CONNECT_AUTH",
        lambda: second.handle(second_proxy, cross_attempt),
    )
    assert second.resolver_calls == []
    assert first.handle(first_proxy)["result"] == "COMPLETED"


def test_dns_ipv6_global_resolution_and_rebinding_are_exact() -> None:
    global_v6 = "2606:4700:4700::1111"
    harness = Harness(
        answers=[global_v6],
        peer=V.PeerObservation(global_v6, 443, "RAW_TCP", False),
    )
    assert harness.handle(harness.issue())["result"] == "COMPLETED"

    for answer in ("::1", "fe80::1", "fd00::1", "ff02::1", "::"):
        rejected = Harness(answers=[answer])
        assert_code("ADDRESS_NOT_GLOBAL", lambda rejected=rejected: rejected.handle(rejected.issue()))
    rebound = Harness(
        answers=[global_v6],
        peer=V.PeerObservation("2001:4860:4860::8888", 443, "RAW_TCP", False),
    )
    assert_code("DNS_REBINDING", lambda: rebound.handle(rebound.issue()))


def test_v2_production_admission_hardstops_before_inspecting_structural_evidence() -> None:
    class Hostile:
        def __getattribute__(self, _name: str) -> object:
            raise AssertionError("production inspected Python structural evidence")

    assert_code(
        "NATIVE_EGRESS_AUTHORITY_REQUIRED",
        lambda: V.admit_verified_egress_v2(Hostile(), transcript=Hostile()),
    )
    assert all(not name.startswith("TEST_ONLY") for name in V.__all__)
