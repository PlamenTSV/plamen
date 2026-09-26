"""Verified, narrow egress for governed backend CLI attempts.

This module has no socket, DNS, process, filesystem, container, or credential
implementation.  It defines two fail-closed boundaries whose effects are
provided by trusted callbacks:

* :func:`admit_network_proof` validates the provider/guest network evidence
  against trusted expectations; and
* :func:`issue_attempt_proxy` creates one non-serializable, replay-consumed
  CONNECT proxy capability for that admitted attempt.

The proxy does not terminate TLS and never returns hostnames, IP addresses,
authorization bytes, payload bytes, socket handles, or host paths in a public
receipt.  A production adapter must obtain provider, nftables, seccomp, socket
census, and terminal observations independently of the confined guest.

Capability non-forgeability is scoped to the public API inside a trusted host
supervisor process.  The target and backend run out of process and never import
this module or receive these objects.  Arbitrary code execution/reflection in
the host supervisor is outside this module's boundary and must be prevented by
the provider/process architecture.
"""

from __future__ import annotations

from dataclasses import dataclass
import base64
import hashlib
import hmac
import ipaddress
import json
import math
import re
import threading
from types import MappingProxyType
from typing import Any, Callable, Mapping, Protocol, Sequence
import weakref


NETWORK_PROOF_SCHEMA = "plamen.verified_backend_network_proof.v1"
PUBLIC_ADMISSION_SCHEMA = "plamen.verified_backend_network_admission.v1"
PUBLIC_ISSUANCE_SCHEMA = "plamen.verified_backend_proxy_issuance.v1"
PUBLIC_CONNECTION_SCHEMA = "plamen.verified_backend_connection.v1"
PUBLIC_TERMINAL_SCHEMA = "plamen.verified_backend_proxy_terminal.v1"
TERMINAL_PROOF_SCHEMA = "plamen.verified_backend_network_terminal_proof.v1"
PUBLIC_RECONCILIATION_SCHEMA = "plamen.verified_backend_network_reconciliation.v1"

NETWORK_MODE = "VERIFIED_CONNECT_ALLOWLIST"
APPLE_TOPOLOGY_MODE = "hostOnly"
LINUX_TOPOLOGY_MODE = "networkNone"
EFFECTIVE_EGRESS_MODE = NETWORK_MODE
TLS_MODE = "END_TO_END_PASSTHROUGH"
OPAQUE_TLS_LIMITATION = "ACKNOWLEDGED_PINNED_CLIENT_ONLY"
DOMAIN_FRONTING_LIMITATION = "NOT_INSPECTED_TRUST_PINNED_BACKEND_CLI"
CAPABILITY_SCOPE = "TRUSTED_HOST_SUPERVISOR_PROCESS"
APPLE_ATTEMPT_NETWORK_TCP = "APPLE_ATTEMPT_NETWORK_TCP"
LINUX_NETWORK_NONE_UDS_SHIM = "LINUX_NETWORK_NONE_UDS_SHIM"
PROVIDER_GUEST_PROOF_AUTHORITY = "PROVIDER_GUEST_OBSERVER_V1"
PROVIDER_TERMINAL_PROOF_AUTHORITY = "PROVIDER_TERMINAL_OBSERVER_V1"
MAX_PROOF_BYTES = 64 * 1024
MAX_HEADER_BYTES = 8192
MAX_HEADER_LINES = 8
MAX_DNS_ANSWERS = 8
MAX_JSON_DEPTH = 12
MAX_JSON_ITEMS = 128
MAX_STRING_BYTES = 4096

_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_SAFE_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
_ATTEMPT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_DOMAIN_ID = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
_INTERFACE = re.compile(r"[a-z][a-z0-9_.-]{0,14}\Z")
_CANONICAL_HOST = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)
_AUTH_TOKEN = re.compile(rb"[A-Za-z0-9_-]{43}\Z")
_BASIC_TOKEN = re.compile(rb"[A-Za-z0-9+/]{60}\Z")
_BASIC_PART = re.compile(rb"[A-Za-z0-9_-]{22}\Z")
_NONE_DIGEST = hashlib.sha256(b"plamen:not-applicable:v1").hexdigest()

_CAPABILITY_SETS = (
    "ambient",
    "bounding",
    "effective",
    "inheritable",
    "permitted",
)
_BLOCKED_NETWORK_ADMIN_SYSCALLS = (
    "bpf",
    "fsconfig",
    "fsmount",
    "fsopen",
    "mount",
    "move_mount",
    "open_tree",
    "pivot_root",
    "setns",
    "umount2",
    "unshare",
)
_DENIED_SOCKET_FAMILIES = ("AF_NETLINK", "AF_PACKET")
_DENIED_SOCKET_TYPES = ("SOCK_RAW",)


class VerifiedEgressError(RuntimeError):
    """A sanitized, stable failure.  Values from untrusted input are omitted."""

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        raise TypeError("verified egress errors are created internally")


def _error(code: str) -> VerifiedEgressError:
    if type(code) is not str or _SAFE_ID.fullmatch(code.lower()) is None:
        code = "egress_error"
    result = RuntimeError.__new__(VerifiedEgressError)
    result.code = code.upper()
    RuntimeError.__init__(result, result.code)
    return result


def _public_copy(value: Mapping[str, Any]) -> dict[str, Any]:
    """Deep-copy an already bounded public JSON object."""

    return json.loads(_canonical_bytes(dict(value)).decode("ascii"))


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")


def _validate_json_bounds(value: Any, *, depth: int = 0) -> None:
    if depth > MAX_JSON_DEPTH:
        raise _error("proof_depth")
    if value is None or type(value) in {bool, int}:
        return
    if type(value) is str:
        try:
            raw = value.encode("utf-8", "strict")
        except UnicodeError as exc:
            raise _error("proof_text") from None
        if len(raw) > MAX_STRING_BYTES:
            raise _error("proof_text")
        return
    if type(value) is list:
        if len(value) > MAX_JSON_ITEMS:
            raise _error("proof_items")
        for item in value:
            _validate_json_bounds(item, depth=depth + 1)
        return
    if type(value) is dict:
        if len(value) > MAX_JSON_ITEMS:
            raise _error("proof_items")
        for key, item in value.items():
            if type(key) is not str:
                raise _error("proof_key")
            _validate_json_bounds(key, depth=depth + 1)
            _validate_json_bounds(item, depth=depth + 1)
        return
    raise _error("proof_type")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _error("proof_duplicate_key")
        result[key] = value
    return result


def _reject_float(_token: str) -> None:
    raise _error("proof_number")


def _bounded_int(token: str) -> int:
    if len(token) > 19:
        raise _error("proof_number")
    return int(token)


def _reject_constant(_token: str) -> None:
    raise _error("proof_number")


def _load_canonical(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or len(raw) > MAX_PROOF_BYTES:
        raise _error("proof_size")
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeError as exc:
        raise _error("proof_encoding") from None
    if text.startswith("\ufeff"):
        raise _error("proof_encoding")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_float=_reject_float,
            parse_int=_bounded_int,
            parse_constant=_reject_constant,
        )
    except VerifiedEgressError:
        raise
    except (ValueError, RecursionError, UnicodeError) as exc:
        raise _error("proof_json") from None
    _validate_json_bounds(value)
    if type(value) is not dict or raw != _canonical_bytes(value):
        raise _error("proof_canonical")
    return value


def canonical_proof_bytes(value: Mapping[str, Any]) -> bytes:
    """Render the sole admitted JSON representation for network proofs."""

    if type(value) is not dict:
        raise _error("proof_type")
    _validate_json_bounds(value)
    raw = _canonical_bytes(value)
    if len(raw) > MAX_PROOF_BYTES:
        raise _error("proof_size")
    return raw


def _exact(value: Any, keys: frozenset[str], code: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        raise _error(code)
    return value


def _text_id(value: Any, *, attempt: bool = False) -> str:
    pattern = _ATTEMPT_ID if attempt else _SAFE_ID
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise _error("identity_invalid")
    return value


def _digest(value: Any) -> str:
    if type(value) is not str or _HEX64.fullmatch(value) is None:
        raise _error("digest_invalid")
    return value


def _domain_int(value: Any, *, minimum: int = 0, maximum: int = 2**63 - 1) -> int:
    if type(value) is not int or isinstance(value, bool) or not minimum <= value <= maximum:
        raise _error("integer_invalid")
    return value


def _canonical_ip(value: Any, *, global_only: bool = False) -> str:
    if type(value) is not str or not value or "%" in value:
        raise _error("address_invalid")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise _error("address_invalid") from None
    if str(address) != value:
        raise _error("address_alias")
    if global_only and (
        not address.is_global
        or address.is_private
        or address.is_loopback
        or address.is_link_local
        or getattr(address, "is_site_local", False)
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
    ):
        raise _error("address_not_global")
    return value


def _canonical_network(value: Any) -> str:
    if type(value) is not str or not value or "%" in value:
        raise _error("subnet_invalid")
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        raise _error("subnet_invalid") from None
    if (
        str(network) != value
        or network.prefixlen == 0
        or not network.is_private
        or network.is_multicast
        or network.is_unspecified
    ):
        raise _error("subnet_invalid")
    return value


@dataclass(frozen=True, slots=True)
class ProxyLimits:
    maximum_connections: int
    maximum_concurrency: int
    maximum_bytes_each_direction: int
    maximum_total_bytes: int
    maximum_connection_seconds: int
    maximum_dns_answers: int


@dataclass(frozen=True, slots=True)
class _ReleasePolicy:
    backend_id: str
    auth_mode: str
    release_policy_id: str
    domains: tuple[tuple[str, str], ...]
    limits: ProxyLimits


_DEFAULT_LIMITS = ProxyLimits(
    maximum_connections=64,
    maximum_concurrency=4,
    maximum_bytes_each_direction=32 * 1024 * 1024,
    maximum_total_bytes=64 * 1024 * 1024,
    maximum_connection_seconds=120,
    maximum_dns_answers=MAX_DNS_ANSWERS,
)

# This is release authority, not audit target configuration.  New domains must
# arrive as a reviewed source change with a new policy identifier.
_RELEASE_POLICIES = MappingProxyType(
    {
        ("codex", "CHATGPT_OAUTH", "codex-egress-2026-09-v1"): _ReleasePolicy(
            backend_id="codex",
            auth_mode="CHATGPT_OAUTH",
            release_policy_id="codex-egress-2026-09-v1",
            domains=(
                ("CODEX_API_PRIMARY", "api.openai.com"),
                ("CODEX_CHATGPT_BACKEND", "chatgpt.com"),
                ("CODEX_OAUTH_PRIMARY", "auth.openai.com"),
            ),
            limits=_DEFAULT_LIMITS,
        ),
        ("codex", "API_KEY", "codex-api-egress-2026-09-v2"): _ReleasePolicy(
            backend_id="codex",
            auth_mode="API_KEY",
            release_policy_id="codex-api-egress-2026-09-v2",
            domains=(("CODEX_API_PRIMARY", "api.openai.com"),),
            limits=_DEFAULT_LIMITS,
        ),
        ("claude", "CLAUDE_OAUTH", "claude-egress-2026-09-v1"): _ReleasePolicy(
            backend_id="claude",
            auth_mode="CLAUDE_OAUTH",
            release_policy_id="claude-egress-2026-09-v1",
            domains=(("CLAUDE_API_PRIMARY", "api.anthropic.com"),),
            limits=_DEFAULT_LIMITS,
        ),
        ("claude", "API_KEY", "claude-api-egress-2026-09-v2"): _ReleasePolicy(
            backend_id="claude",
            auth_mode="API_KEY",
            release_policy_id="claude-api-egress-2026-09-v2",
            domains=(("CLAUDE_API_PRIMARY", "api.anthropic.com"),),
            limits=_DEFAULT_LIMITS,
        ),
    }
)


def release_policy_ids() -> tuple[tuple[str, str, str], ...]:
    """Return release identifiers only; endpoint hostnames remain private."""

    return tuple(sorted(_RELEASE_POLICIES))


@dataclass(frozen=True, slots=True)
class TrustedNetworkExpectation:
    """Values obtained from the trusted provider/guest launch authorities."""

    provider_attempt_id: str
    attempt_binding_sha256: str
    backend_id: str
    release_policy_id: str
    provider_network_id: str
    network_generation: int
    subnet_cidrs: tuple[str, ...]
    guest_ip: str
    primary_interface: str
    proxy_ip: str
    proxy_port: int
    listener_identity_sha256: str
    nft_ruleset_sha256: str
    nft_generation: int
    nft_owner_uid: int
    seccomp_profile_sha256: str
    backend_executable_sha256: str
    backend_launch_policy_sha256: str
    public_ca_bundle_sha256: str
    auth_mode: str = "CHATGPT_OAUTH"
    proxy_transport: str = APPLE_ATTEMPT_NETWORK_TCP
    private_channel_identity_sha256: str | None = None
    proof_authority_id: str = PROVIDER_GUEST_PROOF_AUTHORITY
    terminal_proof_authority_id: str = PROVIDER_TERMINAL_PROOF_AUTHORITY
    private_channel_owner_uid: int = 0
    private_channel_mode: int | None = None
    guest_shim_identity_sha256: str | None = None
    guest_shim_owner_uid: int | None = None

    def __post_init__(self) -> None:
        _text_id(self.provider_attempt_id, attempt=True)
        _digest(self.attempt_binding_sha256)
        policy = _RELEASE_POLICIES.get(
            (self.backend_id, self.auth_mode, self.release_policy_id)
        )
        if policy is None:
            raise _error("release_policy_unknown")
        _text_id(self.provider_network_id)
        _domain_int(self.network_generation, minimum=1)
        if (
            type(self.subnet_cidrs) is not tuple
            or not self.subnet_cidrs
            or len(self.subnet_cidrs) > 4
            or tuple(_canonical_network(item) for item in self.subnet_cidrs)
            != self.subnet_cidrs
            or len(set(self.subnet_cidrs)) != len(self.subnet_cidrs)
        ):
            raise _error("subnet_invalid")
        guest = ipaddress.ip_address(_canonical_ip(self.guest_ip))
        proxy = ipaddress.ip_address(_canonical_ip(self.proxy_ip))
        networks = tuple(ipaddress.ip_network(item) for item in self.subnet_cidrs)
        if not any(guest in item for item in networks) or not any(proxy in item for item in networks):
            raise _error("network_membership")
        if type(self.primary_interface) is not str or _INTERFACE.fullmatch(self.primary_interface) is None:
            raise _error("interface_invalid")
        _domain_int(self.proxy_port, minimum=1, maximum=65535)
        _digest(self.listener_identity_sha256)
        _digest(self.nft_ruleset_sha256)
        _domain_int(self.nft_generation, minimum=1)
        _domain_int(self.nft_owner_uid, minimum=1, maximum=2**31 - 1)
        _digest(self.seccomp_profile_sha256)
        _digest(self.backend_executable_sha256)
        _digest(self.backend_launch_policy_sha256)
        _digest(self.public_ca_bundle_sha256)
        if self.private_channel_identity_sha256 is not None:
            _digest(self.private_channel_identity_sha256)
        _domain_int(self.private_channel_owner_uid, maximum=2**31 - 1)
        if self.private_channel_owner_uid != 0:
            raise _error("private_channel_owner")
        if self.proxy_transport == APPLE_ATTEMPT_NETWORK_TCP:
            if (
                guest == proxy
                or self.primary_interface == "lo"
                or not guest.is_private
                or not proxy.is_private
                or guest.is_loopback
                or proxy.is_loopback
                or guest.is_link_local
                or proxy.is_link_local
                or guest.is_multicast
                or proxy.is_multicast
                or guest.is_unspecified
                or proxy.is_unspecified
                or self.private_channel_mode is not None
                or self.guest_shim_identity_sha256 is not None
                or self.guest_shim_owner_uid is not None
            ):
                raise _error("listener_policy")
        elif self.proxy_transport == LINUX_NETWORK_NONE_UDS_SHIM:
            _domain_int(self.guest_shim_owner_uid, maximum=2**31 - 1)
            if (
                self.subnet_cidrs != ("127.0.0.0/8",)
                or self.guest_ip != "127.0.0.1"
                or self.proxy_ip != "127.0.0.1"
                or self.primary_interface != "lo"
                or self.private_channel_identity_sha256 is None
                or self.private_channel_mode != 0o600
                or self.guest_shim_identity_sha256 is None
                or self.guest_shim_owner_uid != 0
            ):
                raise _error("linux_shim_policy")
            _digest(self.guest_shim_identity_sha256)
        else:
            raise _error("proxy_transport")
        if (
            self.proof_authority_id != PROVIDER_GUEST_PROOF_AUTHORITY
            or self.terminal_proof_authority_id != PROVIDER_TERMINAL_PROOF_AUTHORITY
        ):
            raise _error("proof_authority")

    @property
    def channel_identity_sha256(self) -> str:
        return self.private_channel_identity_sha256 or self.listener_identity_sha256

    @property
    def shim_identity_sha256(self) -> str:
        return self.guest_shim_identity_sha256 or _NONE_DIGEST


_CONTROLLER_SEAL = object()
_CAPABILITY_LOCK = threading.RLock()
_ADMISSIONS: weakref.WeakSet[NetworkAdmission]
_PROXIES: weakref.WeakSet[AttemptProxy]
_TERMINALS: weakref.WeakSet[ProxyTerminal]


def _deny_capability_copy(_self: Any, _memo: Any = None) -> None:
    raise TypeError("capability copying is disabled")


class NetworkAdmission:
    """Opaque, in-process admission capability bound to exact proof bytes."""

    __slots__ = ("_expectation", "_policy", "_proof_sha256", "_public", "__weakref__")

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        raise TypeError("network admission capabilities are issued internally")

    __copy__ = _deny_capability_copy
    __deepcopy__ = _deny_capability_copy

    def __reduce__(self) -> None:
        raise TypeError("network admission capabilities are not serializable")

    def public_receipt(self) -> dict[str, Any]:
        _require_admission(self)
        return _public_copy(self._public)


class ProxyTerminal:
    """Opaque terminal authority; its public receipt is informational only."""

    __slots__ = ("_admission", "_receipt", "__weakref__")

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        raise TypeError("proxy terminal capabilities are issued internally")

    __copy__ = _deny_capability_copy
    __deepcopy__ = _deny_capability_copy

    def __reduce__(self) -> None:
        raise TypeError("proxy terminal capabilities are not serializable")

    def public_receipt(self) -> dict[str, Any]:
        _require_terminal(self)
        return _public_copy(self._receipt)


_ADMISSIONS = weakref.WeakSet()
_PROXIES = weakref.WeakSet()
_TERMINALS = weakref.WeakSet()


def _require_admission(value: Any) -> NetworkAdmission:
    with _CAPABILITY_LOCK:
        if type(value) is not NetworkAdmission or value not in _ADMISSIONS:
            raise _error("admission_capability")
    return value


def _require_proxy(value: Any) -> AttemptProxy:
    with _CAPABILITY_LOCK:
        if type(value) is not AttemptProxy or value not in _PROXIES:
            raise _error("proxy_capability")
    return value


def _require_terminal(value: Any) -> ProxyTerminal:
    with _CAPABILITY_LOCK:
        if type(value) is not ProxyTerminal or value not in _TERMINALS:
            raise _error("terminal_authority")
    return value


def _new_admission(
    expectation: TrustedNetworkExpectation,
    policy: _ReleasePolicy,
    proof_sha256: str,
    public: Mapping[str, Any],
) -> NetworkAdmission:
    result = object.__new__(NetworkAdmission)
    object.__setattr__(result, "_expectation", expectation)
    object.__setattr__(result, "_policy", policy)
    object.__setattr__(result, "_proof_sha256", proof_sha256)
    object.__setattr__(result, "_public", MappingProxyType(dict(public)))
    with _CAPABILITY_LOCK:
        _ADMISSIONS.add(result)
    return result


def _new_terminal(admission: NetworkAdmission, receipt: Mapping[str, Any]) -> ProxyTerminal:
    _require_admission(admission)
    result = object.__new__(ProxyTerminal)
    object.__setattr__(result, "_admission", admission)
    object.__setattr__(result, "_receipt", MappingProxyType(dict(receipt)))
    with _CAPABILITY_LOCK:
        _TERMINALS.add(result)
    return result


_TOP_KEYS = frozenset({"schema", "attempt", "provider", "guest_firewall", "guest_security"})
_ATTEMPT_KEYS = frozenset(
    {
        "provider_attempt_id", "attempt_binding_sha256", "backend_id",
        "auth_mode", "release_policy_id", "proxy_scope", "backend_executable_sha256",
        "backend_launch_policy_sha256", "network_capable_process_count",
        "network_capable_process_executable_sha256",
        "authorization_recipient_executable_sha256",
        "target_backend_policy_enabled", "target_backend_config_enabled",
        "model_generated_command_network", "tls_mode", "tls_termination",
        "public_ca_bundle_sha256", "opaque_tls_limitation",
        "domain_fronting_limitation",
    }
)
_PROVIDER_KEYS = frozenset(
    {
        "topology_mode", "effective_egress_mode", "network_id", "network_generation", "subnet_cidrs",
        "attempt_unique", "default_network_attached", "alternate_network_ids",
        "interfaces", "routes", "default_routes", "dns_enabled", "dns_servers",
        "listener", "published_ports", "published_sockets", "ssh_forwarding",
        "nested_virtualization", "host_devices", "proxy_transport", "transport",
    }
)
_INTERFACE_KEYS = frozenset({"name", "address", "network_id"})
_ROUTE_KEYS = frozenset({"interface", "destination", "kind"})
_LISTENER_KEYS = frozenset(
    {"address", "port", "network_id", "network_generation", "identity_sha256", "wildcard", "publicly_routable"}
)
_FIREWALL_KEYS = frozenset(
    {"engine", "ruleset_sha256", "ruleset_generation", "ruleset_owner_uid", "default_output", "default_forward", "output_allow_rules"}
)
_RULE_KEYS = frozenset({"kind", "interface", "protocol", "destination_ip", "destination_port"})
_SECURITY_KEYS = frozenset(
    {"capability_sets", "no_new_privileges", "seccomp", "raw_sockets_present", "packet_sockets_present", "network_admin_fds_present", "socket_census_sha256"}
)


@dataclass(frozen=True, slots=True)
class ProofAuthenticationEvidence:
    authority_id: str
    proof_sha256: str
    authenticated: bool
    replay_safe: bool


class ProofAuthenticator(Protocol):
    """Authenticate bytes obtained independently of the confined guest."""

    def __call__(self, raw: bytes, proof_sha256: str) -> ProofAuthenticationEvidence: ...
_SECCOMP_KEYS = frozenset(
    {"status", "profile_sha256", "blocked_network_admin_syscalls", "denied_socket_families", "denied_socket_types"}
)
_TRANSPORT_KEYS = frozenset(
    {
        "mode", "private_channel_identity_sha256", "private_channel_owner_uid",
        "private_channel_object_kind", "private_channel_mode", "bind_mount_count",
        "provider_network_disabled", "guest_shim_identity_sha256",
        "guest_shim_owner_uid", "peer_credentials_verified",
        "shim_loopback_initialized_before_cap_drop", "shim_capabilities_dropped",
    }
)


def admit_network_proof(
    raw: bytes,
    expected: TrustedNetworkExpectation,
    *,
    authenticate_proof: ProofAuthenticator,
) -> NetworkAdmission:
    """Validate canonical provider+guest evidence and issue an opaque capability."""

    if type(expected) is not TrustedNetworkExpectation:
        raise _error("expectation_type")
    value = _exact(_load_canonical(raw), _TOP_KEYS, "proof_fields")
    proof_sha256 = _sha256(raw)
    try:
        authentication = authenticate_proof(raw, proof_sha256)
    except Exception:
        raise _error("proof_authentication_failure") from None
    if type(authentication) is not ProofAuthenticationEvidence or authentication != ProofAuthenticationEvidence(
        authority_id=expected.proof_authority_id,
        proof_sha256=proof_sha256,
        authenticated=True,
        replay_safe=True,
    ):
        raise _error("proof_authentication")
    if value["schema"] != NETWORK_PROOF_SCHEMA:
        raise _error("proof_schema")

    attempt = _exact(value["attempt"], _ATTEMPT_KEYS, "attempt_fields")
    if (
        attempt["provider_attempt_id"] != expected.provider_attempt_id
        or attempt["attempt_binding_sha256"] != expected.attempt_binding_sha256
        or attempt["backend_id"] != expected.backend_id
        or attempt["auth_mode"] != expected.auth_mode
        or attempt["release_policy_id"] != expected.release_policy_id
    ):
        raise _error("attempt_binding")
    _domain_int(attempt["network_capable_process_count"], minimum=1, maximum=1)
    if (
        attempt["proxy_scope"] != NETWORK_MODE
        or attempt["backend_executable_sha256"] != expected.backend_executable_sha256
        or attempt["backend_launch_policy_sha256"] != expected.backend_launch_policy_sha256
        or attempt["network_capable_process_count"] != 1
        or attempt["network_capable_process_executable_sha256"] != expected.backend_executable_sha256
        or attempt["authorization_recipient_executable_sha256"] != expected.backend_executable_sha256
        or attempt["target_backend_policy_enabled"] is not False
        or attempt["target_backend_config_enabled"] is not False
        or attempt["model_generated_command_network"] is not False
        or attempt["tls_mode"] != TLS_MODE
        or attempt["tls_termination"] is not False
        or attempt["public_ca_bundle_sha256"] != expected.public_ca_bundle_sha256
        or attempt["opaque_tls_limitation"] != OPAQUE_TLS_LIMITATION
        or attempt["domain_fronting_limitation"] != DOMAIN_FRONTING_LIMITATION
    ):
        raise _error("connect_scope_policy")

    provider = _exact(value["provider"], _PROVIDER_KEYS, "provider_fields")
    expected_topology = (
        APPLE_TOPOLOGY_MODE
        if expected.proxy_transport == APPLE_ATTEMPT_NETWORK_TCP
        else LINUX_TOPOLOGY_MODE
    )
    if (
        provider["topology_mode"] != expected_topology
        or provider["effective_egress_mode"] != EFFECTIVE_EGRESS_MODE
    ):
        # Topology and the independently enforced effective policy are never
        # aliases.  In particular, Apple hostOnly is not itself egress proof.
        raise _error("network_mode")
    _domain_int(provider["network_generation"], minimum=1)
    if (
        provider["network_id"] != expected.provider_network_id
        or provider["network_generation"] != expected.network_generation
        or provider["subnet_cidrs"] != list(expected.subnet_cidrs)
        or provider["attempt_unique"] is not True
        or provider["default_network_attached"] is not False
        or provider["alternate_network_ids"] != []
        or provider["default_routes"] != []
        or provider["dns_enabled"] is not False
        or provider["dns_servers"] != []
        or provider["published_ports"] != []
        or provider["published_sockets"] != []
        or provider["ssh_forwarding"] is not False
        or provider["nested_virtualization"] is not False
        or provider["host_devices"] != []
        or provider["proxy_transport"] != expected.proxy_transport
    ):
        raise _error("provider_policy")
    transport = _exact(provider["transport"], _TRANSPORT_KEYS, "transport_fields")
    for field, maximum in (
        ("private_channel_owner_uid", 2**31 - 1),
        ("private_channel_mode", 0o7777),
        ("bind_mount_count", 64),
        ("guest_shim_owner_uid", 2**31 - 1),
    ):
        _domain_int(transport[field], maximum=maximum)
    for field in (
        "provider_network_disabled", "peer_credentials_verified",
        "shim_loopback_initialized_before_cap_drop", "shim_capabilities_dropped",
    ):
        if type(transport[field]) is not bool:
            raise _error("transport_policy")
    if expected.proxy_transport == APPLE_ATTEMPT_NETWORK_TCP:
        wanted_transport = {
            "mode": APPLE_ATTEMPT_NETWORK_TCP,
            "private_channel_identity_sha256": expected.channel_identity_sha256,
            "private_channel_owner_uid": 0,
            "private_channel_object_kind": "NETWORK_LISTENER",
            "private_channel_mode": 0,
            "bind_mount_count": 0,
            "provider_network_disabled": False,
            "guest_shim_identity_sha256": _NONE_DIGEST,
            "guest_shim_owner_uid": 0,
            "peer_credentials_verified": False,
            "shim_loopback_initialized_before_cap_drop": False,
            "shim_capabilities_dropped": True,
        }
    else:
        wanted_transport = {
            "mode": LINUX_NETWORK_NONE_UDS_SHIM,
            "private_channel_identity_sha256": expected.channel_identity_sha256,
            "private_channel_owner_uid": 0,
            "private_channel_object_kind": "UNIX_STREAM_SOCKET",
            "private_channel_mode": 0o600,
            "bind_mount_count": 1,
            "provider_network_disabled": True,
            "guest_shim_identity_sha256": expected.shim_identity_sha256,
            "guest_shim_owner_uid": 0,
            "peer_credentials_verified": True,
            "shim_loopback_initialized_before_cap_drop": True,
            "shim_capabilities_dropped": True,
        }
    if transport != wanted_transport:
        raise _error("transport_policy")

    interfaces = provider["interfaces"]
    if type(interfaces) is not list or len(interfaces) != 1:
        raise _error("interface_policy")
    interface = _exact(interfaces[0], _INTERFACE_KEYS, "interface_fields")
    if interface != {
        "name": expected.primary_interface,
        "address": expected.guest_ip,
        "network_id": expected.provider_network_id,
    }:
        raise _error("interface_policy")

    routes = provider["routes"]
    wanted_routes = [
        {"interface": expected.primary_interface, "destination": subnet, "kind": "LINK"}
        for subnet in expected.subnet_cidrs
    ]
    if routes != wanted_routes:
        raise _error("route_policy")

    listener = _exact(provider["listener"], _LISTENER_KEYS, "listener_fields")
    _domain_int(listener["port"], minimum=1, maximum=65535)
    _domain_int(listener["network_generation"], minimum=1)
    if listener != {
        "address": expected.proxy_ip,
        "port": expected.proxy_port,
        "network_id": expected.provider_network_id,
        "network_generation": expected.network_generation,
        "identity_sha256": expected.listener_identity_sha256,
        "wildcard": False,
        "publicly_routable": False,
    }:
        raise _error("listener_policy")
    proxy_address = ipaddress.ip_address(expected.proxy_ip)
    if proxy_address.is_global or proxy_address.is_multicast or proxy_address.is_unspecified:
        raise _error("listener_policy")

    firewall = _exact(value["guest_firewall"], _FIREWALL_KEYS, "firewall_fields")
    wanted_rules = [
        {
            "kind": "LOOPBACK",
            "interface": "lo",
            "protocol": "ANY",
            "destination_ip": "127.0.0.1" if proxy_address.version == 4 else "::1",
            "destination_port": 0,
        },
        {
            "kind": "PROXY",
            "interface": expected.primary_interface,
            "protocol": "TCP",
            "destination_ip": expected.proxy_ip,
            "destination_port": expected.proxy_port,
        },
    ]
    rules = firewall.get("output_allow_rules")
    if type(rules) is not list or any(type(item) is not dict or set(item) != _RULE_KEYS for item in rules):
        raise _error("firewall_rules")
    _domain_int(firewall["ruleset_generation"], minimum=1)
    _domain_int(firewall["ruleset_owner_uid"], minimum=1, maximum=2**31 - 1)
    for rule in rules:
        _domain_int(rule["destination_port"], maximum=65535)
    if (
        firewall["engine"] != "NFTABLES"
        or firewall["ruleset_sha256"] != expected.nft_ruleset_sha256
        or firewall["ruleset_generation"] != expected.nft_generation
        or firewall["ruleset_owner_uid"] != expected.nft_owner_uid
        or firewall["default_output"] != "DROP"
        or firewall["default_forward"] != "DROP"
        or rules != wanted_rules
    ):
        raise _error("firewall_policy")

    security = _exact(value["guest_security"], _SECURITY_KEYS, "security_fields")
    capabilities = security["capability_sets"]
    if (
        type(capabilities) is not dict
        or set(capabilities) != set(_CAPABILITY_SETS)
        or any(capabilities[name] != [] for name in _CAPABILITY_SETS)
    ):
        raise _error("capability_policy")
    seccomp = _exact(security["seccomp"], _SECCOMP_KEYS, "seccomp_fields")
    if (
        security["no_new_privileges"] is not True
        or security["raw_sockets_present"] is not False
        or security["packet_sockets_present"] is not False
        or security["network_admin_fds_present"] is not False
        or type(security["socket_census_sha256"]) is not str
        or _HEX64.fullmatch(security["socket_census_sha256"]) is None
        or seccomp["status"] != "ENFORCED"
        or seccomp["profile_sha256"] != expected.seccomp_profile_sha256
        or seccomp["blocked_network_admin_syscalls"] != list(_BLOCKED_NETWORK_ADMIN_SYSCALLS)
        or seccomp["denied_socket_families"] != list(_DENIED_SOCKET_FAMILIES)
        or seccomp["denied_socket_types"] != list(_DENIED_SOCKET_TYPES)
    ):
        raise _error("guest_security_policy")

    policy = _RELEASE_POLICIES[
        (expected.backend_id, expected.auth_mode, expected.release_policy_id)
    ]
    public = {
        "schema": PUBLIC_ADMISSION_SCHEMA,
        "result": "ADMITTED",
        "topology_mode": expected_topology,
        "effective_egress_mode": EFFECTIVE_EGRESS_MODE,
        "network_mode": NETWORK_MODE,
        "capability_scope": CAPABILITY_SCOPE,
        "proxy_transport": expected.proxy_transport,
        "backend_id": policy.backend_id,
        "auth_mode": policy.auth_mode,
        "release_policy_id": policy.release_policy_id,
        "attempt_binding_sha256": expected.attempt_binding_sha256,
        "proof_sha256": proof_sha256,
        "proof_authority_id": expected.proof_authority_id,
        "private_channel_identity_sha256": expected.channel_identity_sha256,
        "guest_shim_identity_sha256": expected.shim_identity_sha256,
        "backend_executable_sha256": expected.backend_executable_sha256,
        "backend_launch_policy_sha256": expected.backend_launch_policy_sha256,
        "public_ca_bundle_sha256": expected.public_ca_bundle_sha256,
        "tls_mode": TLS_MODE,
        "opaque_tls_limitation": OPAQUE_TLS_LIMITATION,
        "domain_fronting_limitation": DOMAIN_FRONTING_LIMITATION,
        "network_id_sha256": _sha256(expected.provider_network_id.encode("ascii")),
        "network_generation": expected.network_generation,
        "subnet_count": len(expected.subnet_cidrs),
        "interface_count": 1,
        "route_count": len(expected.subnet_cidrs),
        "domain_ids": [item[0] for item in policy.domains],
        "domain_count": len(policy.domains),
        "nft_ruleset_sha256": expected.nft_ruleset_sha256,
        "nft_generation": expected.nft_generation,
        "seccomp_profile_sha256": expected.seccomp_profile_sha256,
        "socket_census_sha256": security["socket_census_sha256"],
    }
    return _new_admission(expected, policy, proof_sha256, public)


class DurableReplayConsumer(Protocol):
    """Persist a never-before-consumed key before returning literal ``True``."""

    def __call__(self, replay_key_sha256: str, issuance_sha256: str) -> bool: ...


class SecretDeliverer(Protocol):
    """Synchronously copy a secret view into a private guest channel."""

    def __call__(self, authorization: memoryview) -> bool: ...


class Reader(Protocol):
    """Read CONNECT bytes.

    Positive timeouts are bounded blocking reads.  A zero timeout is a single
    non-blocking read of bytes already queued by the transport; it MUST return
    immediately and return ``b""`` only when no byte is pending at that
    instant.  The host adapter must serialize this check with its response
    write so early tunnel bytes cannot cross the CONNECT admission boundary.
    """

    def __call__(self, maximum_bytes: int, timeout_seconds: float) -> bytes: ...


class Sender(Protocol):
    def __call__(self, response: bytes, timeout_seconds: float) -> None: ...


class Resolver(Protocol):
    def __call__(self, hostname: str, maximum_answers: int, timeout_seconds: float) -> Sequence[str]: ...


class Connector(Protocol):
    def __call__(self, hostname: str, port: int, resolved_addresses: tuple[str, ...], timeout_seconds: float) -> Any: ...


class PeerObserver(Protocol):
    def __call__(self, upstream: Any, timeout_seconds: float) -> "PeerObservation": ...


@dataclass(frozen=True, slots=True)
class PeerObservation:
    """Kernel-derived observation of the opaque upstream descriptor."""

    address: str
    port: int
    transport_mode: str
    tls_terminated: bool


@dataclass(frozen=True, slots=True)
class RelayRunnerEvidence:
    descendants_extinct: bool
    client_fd_closed: bool
    upstream_fd_closed: bool
    runner_fd_delta: int
    cancel_acknowledged: bool
    deadline_watchdog_armed: bool
    cancel_wakeup_registered: bool


@dataclass(frozen=True, slots=True)
class ConnectionFinalizationEvidence:
    """Post-cleanup observation produced by the injected process/FD owner."""

    client_fd_closed: bool
    upstream_fd_closed: bool
    runner_descendants_extinct: bool
    runner_fd_delta: int


class RelayRunner(Protocol):
    def __call__(self, client: Any, upstream: Any, controller: "RelayController") -> RelayRunnerEvidence: ...


class ConnectionFinalizer(Protocol):
    def __call__(self, client: Any, upstream: Any | None, timeout_seconds: float) -> ConnectionFinalizationEvidence: ...


class CancelWakeup(Protocol):
    """Wake/interrupt all blocked connection callbacks for this attempt."""

    def __call__(self, timeout_seconds: float) -> bool: ...


class RelayController:
    """Atomic quota/cancellation surface used by the trusted relay runner."""

    __slots__ = (
        "_proxy", "_started", "_client_bytes", "_upstream_bytes",
        "_client_half_closed", "_upstream_half_closed", "_terminal",
        "_failure_code",
    )

    def __init__(self, seal: object, proxy: "AttemptProxy", started: float) -> None:
        if seal is not _CONTROLLER_SEAL:
            raise TypeError("relay controllers are issued internally")
        self._proxy = proxy
        self._started = started
        self._client_bytes = 0
        self._upstream_bytes = 0
        self._client_half_closed = False
        self._upstream_half_closed = False
        self._terminal = False
        self._failure_code: str | None = None

    __copy__ = _deny_capability_copy
    __deepcopy__ = _deny_capability_copy

    def __reduce__(self) -> None:
        raise TypeError("relay controllers are not serializable")

    def cancel_requested(self) -> bool:
        return self._proxy._cancelled.is_set()

    def remaining_seconds(self) -> float:
        """Return the trusted clock budget available to the relay runner."""

        try:
            return self._proxy._remaining(self._started, fail_if_expired=False)
        except VerifiedEgressError as exc:
            self._raise(exc.code)

    def _record(self, count: int, *, client_to_upstream: bool) -> None:
        if self._terminal:
            self._raise("relay_terminal")
        try:
            _domain_int(count, maximum=2**63 - 1)
        except VerifiedEgressError as exc:
            self._raise(exc.code)
        if count == 0:
            return
        try:
            self._proxy._claim_bytes(self, count, client_to_upstream=client_to_upstream)
        except VerifiedEgressError as exc:
            self._raise(exc.code)

    def record_client_to_upstream(self, count: int) -> None:
        self._record(count, client_to_upstream=True)

    def record_upstream_to_client(self, count: int) -> None:
        self._record(count, client_to_upstream=False)

    def mark_client_eof_and_upstream_half_close(self) -> None:
        if self._terminal or self._client_half_closed:
            self._raise("half_close_state")
        self._client_half_closed = True

    def mark_upstream_eof_and_client_half_close(self) -> None:
        if self._terminal or self._upstream_half_closed:
            self._raise("half_close_state")
        self._upstream_half_closed = True

    def _raise(self, code: str) -> None:
        with self._proxy._lock:
            if self._failure_code is None:
                self._failure_code = code
        raise _error(code)

    def _finish(self, evidence: RelayRunnerEvidence) -> tuple[int, int, int]:
        if self._terminal:
            raise _error("relay_terminal")
        self._terminal = True
        if self._failure_code is not None:
            raise _error(self._failure_code)
        if type(evidence) is not RelayRunnerEvidence:
            raise _error("runner_evidence")
        if (
            evidence.descendants_extinct is not True
            or evidence.client_fd_closed is not True
            or evidence.upstream_fd_closed is not True
            or evidence.runner_fd_delta != 0
            or evidence.deadline_watchdog_armed is not True
            or evidence.cancel_wakeup_registered is not True
            or not self._client_half_closed
            or not self._upstream_half_closed
            or (self.cancel_requested() and evidence.cancel_acknowledged is not True)
            or (not self.cancel_requested() and evidence.cancel_acknowledged is not False)
        ):
            raise _error("runner_evidence")
        elapsed = self._proxy._now() - self._started
        if elapsed < 0 or elapsed > self._proxy._policy.limits.maximum_connection_seconds:
            with self._proxy._lock:
                self._proxy._counters["quota_rejections"] += 1
            raise _error("connection_deadline")
        return self._client_bytes, self._upstream_bytes, max(0, int(elapsed * 1000))


@dataclass(frozen=True, slots=True)
class ConnectionSource:
    guest_ip: str
    provider_network_id: str
    network_generation: int
    proxy_transport: str = APPLE_ATTEMPT_NETWORK_TCP
    private_channel_identity_sha256: str | None = None
    guest_shim_identity_sha256: str | None = None
    peer_credentials_verified: bool = False
    peer_uid: int | None = None

    def __post_init__(self) -> None:
        _canonical_ip(self.guest_ip)
        _text_id(self.provider_network_id)
        _domain_int(self.network_generation, minimum=1)
        if self.proxy_transport not in {
            APPLE_ATTEMPT_NETWORK_TCP,
            LINUX_NETWORK_NONE_UDS_SHIM,
        }:
            raise _error("source_binding")
        if self.private_channel_identity_sha256 is not None:
            _digest(self.private_channel_identity_sha256)
        if self.guest_shim_identity_sha256 is not None:
            _digest(self.guest_shim_identity_sha256)
        if type(self.peer_credentials_verified) is not bool:
            raise _error("source_binding")
        if self.peer_uid is not None:
            _domain_int(self.peer_uid, maximum=2**31 - 1)


def _validate_connection_source(
    source: Any,
    expected: TrustedNetworkExpectation,
) -> None:
    if type(source) is not ConnectionSource:
        raise _error("source_binding")
    # Revalidate even frozen instances because the accept adapter, not a target
    # object constructor, is the source authority.
    try:
        _canonical_ip(source.guest_ip)
        _text_id(source.provider_network_id)
        _domain_int(source.network_generation, minimum=1)
        if source.private_channel_identity_sha256 is not None:
            _digest(source.private_channel_identity_sha256)
        if source.guest_shim_identity_sha256 is not None:
            _digest(source.guest_shim_identity_sha256)
        if type(source.peer_credentials_verified) is not bool:
            raise _error("source_binding")
        if source.peer_uid is not None:
            _domain_int(source.peer_uid, maximum=2**31 - 1)
    except (AttributeError, VerifiedEgressError):
        raise _error("source_binding") from None
    source_channel = (
        expected.listener_identity_sha256
        if source.private_channel_identity_sha256 is None
        else source.private_channel_identity_sha256
    )
    source_shim = (
        _NONE_DIGEST
        if source.guest_shim_identity_sha256 is None
        else source.guest_shim_identity_sha256
    )
    expected_peer_verified = expected.proxy_transport == LINUX_NETWORK_NONE_UDS_SHIM
    expected_peer_uid = 0 if expected_peer_verified else None
    if (
        source.guest_ip != expected.guest_ip
        or source.provider_network_id != expected.provider_network_id
        or source.network_generation != expected.network_generation
        or source.proxy_transport != expected.proxy_transport
        or source_channel != expected.channel_identity_sha256
        or source_shim != expected.shim_identity_sha256
        or source.peer_credentials_verified is not expected_peer_verified
        or source.peer_uid != expected_peer_uid
    ):
        raise _error("source_binding")


class _ConnectParser:
    __slots__ = ("_buffer", "_done")

    def __init__(self) -> None:
        self._buffer = bytearray()
        self._done = False

    def _scrub(self) -> None:
        for index in range(len(self._buffer)):
            self._buffer[index] = 0
        self._buffer.clear()

    def feed(self, chunk: bytes) -> bytes | None:
        if self._done or type(chunk) is not bytes:
            raise _error("connect_state")
        if not chunk:
            self._scrub()
            raise _error("connect_truncated")
        if len(self._buffer) + len(chunk) > MAX_HEADER_BYTES:
            self._scrub()
            raise _error("connect_oversized")
        self._buffer.extend(chunk)
        marker = self._buffer.find(b"\r\n\r\n")
        if marker < 0:
            if b"\n\n" in self._buffer or b"\r\r" in self._buffer:
                self._scrub()
                raise _error("connect_framing")
            return None
        end = marker + 4
        if end != len(self._buffer):
            self._scrub()
            raise _error("connect_extra_bytes")
        self._done = True
        return bytes(self._buffer)

    def close(self) -> None:
        self._scrub()


def _parse_connect(raw: bytes, expected_auth_sha256: bytes, policy: _ReleasePolicy) -> tuple[str, str]:
    if b"\x00" in raw or b"\r\n " in raw or b"\r\n\t" in raw:
        raise _error("connect_framing")
    lines = raw[:-4].split(b"\r\n")
    if not 3 <= len(lines) <= MAX_HEADER_LINES:
        raise _error("connect_headers")
    if any(not line or len(line) > 2048 for line in lines):
        raise _error("connect_headers")
    try:
        request_line = lines[0].decode("ascii", "strict")
    except UnicodeError as exc:
        raise _error("connect_ascii") from None
    pieces = request_line.split(" ")
    if len(pieces) != 3 or pieces[0] != "CONNECT" or pieces[2] != "HTTP/1.1":
        raise _error("connect_method")
    authority = pieces[1]
    if authority.count(":") != 1 or any(item in authority for item in ("@", "/", "?", "#", "[", "]")):
        raise _error("connect_authority")
    hostname, port = authority.split(":", 1)
    if port != "443" or hostname != hostname.lower() or hostname.endswith(".") or _CANONICAL_HOST.fullmatch(hostname) is None:
        raise _error("connect_authority")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise _error("connect_ip_literal")

    headers: dict[bytes, bytes] = {}
    for line in lines[1:]:
        if b":" not in line:
            raise _error("connect_headers")
        name, value = line.split(b":", 1)
        if not name or value[:1] != b" " or value != value.rstrip(b" \t") or b"\t" in value:
            raise _error("connect_headers")
        lowered = name.lower()
        if name not in {b"Host", b"Proxy-Authorization"} or lowered in headers:
            raise _error("connect_headers")
        headers[lowered] = value[1:]
    if set(headers) != {b"host", b"proxy-authorization"}:
        raise _error("connect_headers")
    if headers[b"host"] != authority.encode("ascii"):
        raise _error("connect_host")
    auth = headers[b"proxy-authorization"]
    prefix = b"Basic "
    if not auth.startswith(prefix):
        raise _error("connect_auth")
    token = auth[len(prefix):]
    if _BASIC_TOKEN.fullmatch(token) is None:
        raise _error("connect_auth")
    decoded = bytearray()
    try:
        decoded = bytearray(base64.b64decode(token, validate=True))
        if (
            len(decoded) != 45
            or decoded[22] != 0x3A
            or decoded.count(b":") != 1
            or _BASIC_PART.fullmatch(decoded, 0, 22) is None
            or _BASIC_PART.fullmatch(decoded, 23, 45) is None
            or base64.b64encode(decoded) != token
            or not hmac.compare_digest(
                hashlib.sha256(decoded).digest(), expected_auth_sha256
            )
        ):
            raise _error("connect_auth")
    except VerifiedEgressError:
        raise
    except (ValueError, TypeError):
        raise _error("connect_auth") from None
    finally:
        for index in range(len(decoded)):
            decoded[index] = 0
    match = next(((domain_id, host) for domain_id, host in policy.domains if host == hostname), None)
    if match is None:
        raise _error("connect_domain")
    return match


class AttemptProxy:
    """One attempt-bound proxy authority.  Instances cannot be forged or copied."""

    __slots__ = (
        "_admission", "_policy", "_auth_sha256", "_resolver", "_connector",
        "_peer_observer", "_relay_runner", "_clock", "_lock", "_cancelled",
        "_connection_finalizer",
        "_cancel_wakeup", "_cancel_wakeup_sent", "_cleanup_debt",
        "_closed", "_active", "_counters", "_resolution_digests",
        "_replay_key_sha256", "_issuance_sha256", "_public_issuance",
        "__weakref__",
    )

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        raise TypeError("attempt proxy capabilities are issued internally")

    __copy__ = _deny_capability_copy
    __deepcopy__ = _deny_capability_copy

    def __reduce__(self) -> None:
        raise TypeError("attempt proxy capabilities are not serializable")

    def public_issuance_receipt(self) -> dict[str, Any]:
        _require_proxy(self)
        return _public_copy(self._public_issuance)

    def cancel(self) -> None:
        _require_proxy(self)
        self._signal_cancel()

    def _signal_cancel(self) -> None:
        with self._lock:
            if self._closed:
                raise _error("proxy_closed")
            self._cancelled.set()
            notify = not self._cancel_wakeup_sent
            self._cancel_wakeup_sent = True
        if not notify:
            return
        try:
            acknowledged = self._cancel_wakeup(
                float(self._policy.limits.maximum_connection_seconds)
            )
        except Exception:
            with self._lock:
                self._cleanup_debt = True
            raise _error("cancel_wakeup") from None
        if acknowledged is not True:
            with self._lock:
                self._cleanup_debt = True
            raise _error("cancel_wakeup")

    def _acquire_connection(self) -> None:
        with self._lock:
            self._counters["connection_attempts"] += 1
            if self._closed or self._cancelled.is_set():
                self._counters["requests_rejected"] += 1
                raise _error("proxy_closed")
            if self._counters["connection_attempts"] > self._policy.limits.maximum_connections:
                self._counters["requests_rejected"] += 1
                self._counters["quota_rejections"] += 1
                raise _error("connection_quota")
            if self._active >= self._policy.limits.maximum_concurrency:
                self._counters["requests_rejected"] += 1
                self._counters["quota_rejections"] += 1
                raise _error("concurrency_quota")
            self._active += 1

    def _release_connection(self) -> None:
        with self._lock:
            self._active -= 1
            if self._active < 0:
                self._active = 0
                raise _error("counter_state")

    def _record_rejection(self, code: str) -> None:
        with self._lock:
            self._counters["requests_rejected"] += 1
            if code == "CONNECT_AUTH":
                self._counters["auth_rejections"] += 1
            if code.startswith("DNS_") or code.startswith("ADDRESS_"):
                self._counters["dns_rejections"] += 1
            if code.endswith("QUOTA") or code == "CONNECTION_DEADLINE":
                self._counters["quota_rejections"] += 1

    def _claim_bytes(self, controller: RelayController, count: int, *, client_to_upstream: bool) -> None:
        self._remaining(controller._started)
        if self._cancelled.is_set():
            raise _error("proxy_cancelled")
        violation: str | None = None
        with self._lock:
            key = "client_to_upstream_bytes" if client_to_upstream else "upstream_to_client_bytes"
            per_connection = controller._client_bytes if client_to_upstream else controller._upstream_bytes
            limits = self._policy.limits
            if per_connection + count > limits.maximum_bytes_each_direction:
                self._counters["quota_rejections"] += 1
                violation = "direction_byte_quota"
            total = self._counters["client_to_upstream_bytes"] + self._counters["upstream_to_client_bytes"]
            if violation is None and total + count > limits.maximum_total_bytes:
                self._counters["quota_rejections"] += 1
                violation = "total_byte_quota"
            if violation is None:
                self._counters[key] += count
                if client_to_upstream:
                    controller._client_bytes += count
                else:
                    controller._upstream_bytes += count
        if violation is not None:
            self._signal_cancel()
            raise _error(violation)

    def _now(self) -> float:
        try:
            value = self._clock()
        except Exception:
            raise _error("clock_invalid") from None
        if type(value) not in {int, float} or isinstance(value, bool) or not math.isfinite(float(value)):
            raise _error("clock_invalid")
        return float(value)

    def _remaining(self, started: float, *, fail_if_expired: bool = True) -> float:
        elapsed = self._now() - started
        maximum = float(self._policy.limits.maximum_connection_seconds)
        if elapsed < 0:
            raise _error("clock_invalid")
        remaining = maximum - elapsed
        if fail_if_expired and remaining <= 0:
            with self._lock:
                self._counters["quota_rejections"] += 1
            raise _error("connection_deadline")
        return max(0.0, remaining)

    def _finalize_connection(self, client: Any, upstream: Any | None) -> None:
        try:
            evidence = self._connection_finalizer(
                client,
                upstream,
                float(self._policy.limits.maximum_connection_seconds),
            )
        except Exception:
            with self._lock:
                self._cleanup_debt = True
            raise _error("connection_cleanup") from None
        if type(evidence) is not ConnectionFinalizationEvidence or (
            evidence.client_fd_closed is not True
            or evidence.upstream_fd_closed is not True
            or evidence.runner_descendants_extinct is not True
            or evidence.runner_fd_delta != 0
        ):
            with self._lock:
                self._cleanup_debt = True
            raise _error("connection_cleanup")

    @staticmethod
    def _invoke_callback(callback: Callable[..., Any], *args: Any) -> Any:
        try:
            return callback(*args)
        except Exception:
            raise _error("trusted_callback_failure") from None

    def handle_connection(
        self,
        *,
        client: Any,
        source: ConnectionSource,
        read_request: Reader,
        send_response: Sender,
    ) -> dict[str, Any]:
        """Authenticate and relay one CONNECT stream through injected effects."""

        _require_proxy(self)
        try:
            self._acquire_connection()
        except VerifiedEgressError:
            self._finalize_connection(client, None)
            raise
        parser = _ConnectParser()
        established = False
        upstream: Any | None = None
        finalized = False
        try:
            started = self._now()
            expected = self._admission._expectation
            _validate_connection_source(source, expected)
            raw: bytes | None = None
            while raw is None:
                chunk = self._invoke_callback(
                    read_request,
                    min(2048, MAX_HEADER_BYTES),
                    self._remaining(started),
                )
                self._remaining(started)
                if self._cancelled.is_set():
                    raise _error("proxy_cancelled")
                raw = parser.feed(chunk)
            domain_id, hostname = _parse_connect(raw, self._auth_sha256, self._policy)
            raw = b""
            parser.close()

            # CONNECT has no request body.  Require an immediate transport
            # buffer probe after the complete header and before any DNS or
            # response.  This closes the chunk-boundary variant where early
            # tunnel/body bytes arrive in a separate queued read.
            pending = self._invoke_callback(read_request, 1, 0.0)
            self._remaining(started)
            if self._cancelled.is_set():
                raise _error("proxy_cancelled")
            if type(pending) is not bytes or pending:
                raise _error("connect_extra_bytes")

            answers = self._invoke_callback(
                self._resolver,
                hostname,
                self._policy.limits.maximum_dns_answers,
                self._remaining(started),
            )
            self._remaining(started)
            if self._cancelled.is_set():
                raise _error("proxy_cancelled")
            if type(answers) not in {list, tuple} or not 1 <= len(answers) <= self._policy.limits.maximum_dns_answers:
                raise _error("dns_answers")
            canonical = tuple(_canonical_ip(item, global_only=True) for item in answers)
            if len(set(canonical)) != len(canonical):
                raise _error("dns_duplicate")
            resolved = tuple(sorted(canonical, key=lambda item: ipaddress.ip_address(item).packed))
            resolution_sha256 = _sha256(_canonical_bytes(list(resolved)))
            with self._lock:
                self._resolution_digests.append(resolution_sha256)

            upstream = self._invoke_callback(
                self._connector,
                hostname,
                443,
                resolved,
                self._remaining(started),
            )
            self._remaining(started)
            if self._cancelled.is_set():
                raise _error("proxy_cancelled")
            if upstream is None:
                raise _error("upstream_handle")
            observed_peer = self._invoke_callback(
                self._peer_observer,
                upstream,
                self._remaining(started),
            )
            self._remaining(started)
            if self._cancelled.is_set():
                raise _error("proxy_cancelled")
            if type(observed_peer) is not PeerObservation:
                raise _error("peer_observation")
            peer_ip = observed_peer.address
            if (
                _canonical_ip(peer_ip, global_only=True) not in resolved
                or observed_peer.port != 443
                or observed_peer.transport_mode != "RAW_TCP"
                or observed_peer.tls_terminated is not False
            ):
                raise _error("dns_rebinding")

            # DNS and connect can take most of the admission deadline.  Probe
            # again at the serialized response boundary so bytes queued while
            # those operations ran cannot become tunnel payload.
            pending = self._invoke_callback(read_request, 1, 0.0)
            self._remaining(started)
            if self._cancelled.is_set():
                raise _error("proxy_cancelled")
            if type(pending) is not bytes or pending:
                raise _error("connect_extra_bytes")

            self._invoke_callback(
                send_response,
                b"HTTP/1.1 200 Connection Established\r\n\r\n",
                self._remaining(started),
            )
            self._remaining(started)
            if self._cancelled.is_set():
                raise _error("proxy_cancelled")
            with self._lock:
                self._counters["tunnels_established"] += 1
            established = True
            controller = RelayController(_CONTROLLER_SEAL, self, started)
            try:
                evidence = self._relay_runner(client, upstream, controller)
            except Exception:
                if controller._failure_code is not None:
                    raise _error(controller._failure_code) from None
                raise _error("trusted_callback_failure") from None
            client_bytes, upstream_bytes, elapsed_ms = controller._finish(evidence)
            self._finalize_connection(client, upstream)
            finalized = True
            with self._lock:
                self._counters["tunnels_completed"] += 1
            return {
                "schema": PUBLIC_CONNECTION_SCHEMA,
                "result": "COMPLETED",
                "tls_mode": TLS_MODE,
                "opaque_tls_limitation": OPAQUE_TLS_LIMITATION,
                "domain_fronting_limitation": DOMAIN_FRONTING_LIMITATION,
                "domain_id": domain_id,
                "resolved_address_count": len(resolved),
                "resolution_set_sha256": resolution_sha256,
                "selected_address_sha256": _sha256(peer_ip.encode("ascii")),
                "client_to_upstream_bytes": client_bytes,
                "upstream_to_client_bytes": upstream_bytes,
                "elapsed_milliseconds": elapsed_ms,
            }
        except VerifiedEgressError as exc:
            cleanup_failed = False
            if not finalized:
                try:
                    self._finalize_connection(client, upstream)
                except VerifiedEgressError:
                    cleanup_failed = True
            if established:
                with self._lock:
                    self._counters["tunnels_failed"] += 1
            else:
                self._record_rejection(exc.code)
            if cleanup_failed:
                raise _error("connection_cleanup") from None
            raise
        except Exception:
            cleanup_failed = False
            if not finalized:
                try:
                    self._finalize_connection(client, upstream)
                except VerifiedEgressError:
                    cleanup_failed = True
            if established:
                with self._lock:
                    self._counters["tunnels_failed"] += 1
            else:
                self._record_rejection("CALLBACK_FAILURE")
            if cleanup_failed:
                raise _error("connection_cleanup") from None
            raise _error("trusted_callback_failure") from None
        finally:
            parser.close()
            self._release_connection()

    def finish(self) -> ProxyTerminal:
        """Close issuance and return counters only after all relays are extinct."""

        _require_proxy(self)
        with self._lock:
            if self._closed:
                raise _error("terminal_replay")
            if self._active != 0:
                raise _error("active_connections")
            if self._cleanup_debt:
                raise _error("cleanup_debt")
            self._closed = True
            counters = dict(self._counters)
            resolution_digests = tuple(sorted(self._resolution_digests))
        counters["total_bytes"] = counters["client_to_upstream_bytes"] + counters["upstream_to_client_bytes"]
        receipt = {
            "schema": PUBLIC_TERMINAL_SCHEMA,
            "result": "TERMINAL",
            "network_mode": NETWORK_MODE,
            "capability_scope": CAPABILITY_SCOPE,
            "proxy_transport": self._admission._expectation.proxy_transport,
            "tls_mode": TLS_MODE,
            "opaque_tls_limitation": OPAQUE_TLS_LIMITATION,
            "domain_fronting_limitation": DOMAIN_FRONTING_LIMITATION,
            "backend_executable_sha256": self._admission._expectation.backend_executable_sha256,
            "backend_launch_policy_sha256": self._admission._expectation.backend_launch_policy_sha256,
            "public_ca_bundle_sha256": self._admission._expectation.public_ca_bundle_sha256,
            "backend_id": self._policy.backend_id,
            "auth_mode": self._policy.auth_mode,
            "release_policy_id": self._policy.release_policy_id,
            "attempt_binding_sha256": self._admission._expectation.attempt_binding_sha256,
            "admission_proof_sha256": self._admission._proof_sha256,
            "issuance_sha256": self._issuance_sha256,
            "replay_key_sha256": self._replay_key_sha256,
            "cancelled": self._cancelled.is_set(),
            "active_connections": 0,
            "resolution_set_count": len(resolution_digests),
            "resolution_sets_sha256": _sha256(_canonical_bytes(list(resolution_digests))),
            "counters": counters,
        }
        receipt["terminal_sha256"] = _sha256(_canonical_bytes(receipt))
        return _new_terminal(self._admission, receipt)


def _new_proxy(
    admission: NetworkAdmission,
    auth_sha256: bytes,
    replay_key_sha256: str,
    issuance_sha256: str,
    public_issuance: Mapping[str, Any],
    resolver: Resolver,
    connector: Connector,
    peer_observer: PeerObserver,
    relay_runner: RelayRunner,
    connection_finalizer: ConnectionFinalizer,
    cancel_wakeup: CancelWakeup,
    clock: Callable[[], float],
) -> AttemptProxy:
    _require_admission(admission)
    result = object.__new__(AttemptProxy)
    for name, value in (
        ("_admission", admission),
        ("_policy", admission._policy),
        ("_auth_sha256", auth_sha256),
        ("_resolver", resolver),
        ("_connector", connector),
        ("_peer_observer", peer_observer),
        ("_relay_runner", relay_runner),
        ("_connection_finalizer", connection_finalizer),
        ("_cancel_wakeup", cancel_wakeup),
        ("_cancel_wakeup_sent", False),
        ("_cleanup_debt", False),
        ("_clock", clock),
        ("_lock", threading.RLock()),
        ("_cancelled", threading.Event()),
        ("_closed", False),
        ("_active", 0),
        (
            "_counters",
            {
                "connection_attempts": 0,
                "tunnels_established": 0,
                "tunnels_completed": 0,
                "tunnels_failed": 0,
                "requests_rejected": 0,
                "auth_rejections": 0,
                "dns_rejections": 0,
                "quota_rejections": 0,
                "client_to_upstream_bytes": 0,
                "upstream_to_client_bytes": 0,
            },
        ),
        ("_resolution_digests", []),
        ("_replay_key_sha256", replay_key_sha256),
        ("_issuance_sha256", issuance_sha256),
        ("_public_issuance", MappingProxyType(dict(public_issuance))),
    ):
        object.__setattr__(result, name, value)
    with _CAPABILITY_LOCK:
        _PROXIES.add(result)
    return result


def issue_attempt_proxy(
    admission: NetworkAdmission,
    *,
    consume_replay_durably: DurableReplayConsumer,
    deliver_guest_authorization: SecretDeliverer,
    entropy: Callable[[int], bytearray],
    resolver: Resolver,
    connector: Connector,
    peer_observer: PeerObserver,
    relay_runner: RelayRunner,
    connection_finalizer: ConnectionFinalizer,
    cancel_wakeup: CancelWakeup,
    monotonic_clock: Callable[[], float],
) -> AttemptProxy:
    """Durably consume attempt issuance, deliver one secret, and issue proxy."""

    _require_admission(admission)
    expected = admission._expectation
    replay_material = {
        "attempt_binding_sha256": expected.attempt_binding_sha256,
    }
    replay_key_sha256 = _sha256(b"plamen-egress-replay-v1\x00" + _canonical_bytes(replay_material))
    issuance_unsigned = {
        "schema": PUBLIC_ISSUANCE_SCHEMA,
        "result": "ISSUED",
        "network_mode": NETWORK_MODE,
        "capability_scope": CAPABILITY_SCOPE,
        "proxy_transport": expected.proxy_transport,
        "tls_mode": TLS_MODE,
        "opaque_tls_limitation": OPAQUE_TLS_LIMITATION,
        "domain_fronting_limitation": DOMAIN_FRONTING_LIMITATION,
        "backend_executable_sha256": expected.backend_executable_sha256,
        "backend_launch_policy_sha256": expected.backend_launch_policy_sha256,
        "public_ca_bundle_sha256": expected.public_ca_bundle_sha256,
        "backend_id": admission._policy.backend_id,
        "auth_mode": admission._policy.auth_mode,
        "release_policy_id": admission._policy.release_policy_id,
        "attempt_binding_sha256": expected.attempt_binding_sha256,
        "admission_proof_sha256": admission._proof_sha256,
        "replay_key_sha256": replay_key_sha256,
        "domain_ids": [item[0] for item in admission._policy.domains],
        "domain_count": len(admission._policy.domains),
        "limits": {
            "maximum_connections": admission._policy.limits.maximum_connections,
            "maximum_concurrency": admission._policy.limits.maximum_concurrency,
            "maximum_bytes_each_direction": admission._policy.limits.maximum_bytes_each_direction,
            "maximum_total_bytes": admission._policy.limits.maximum_total_bytes,
            "maximum_connection_seconds": admission._policy.limits.maximum_connection_seconds,
            "maximum_dns_answers": admission._policy.limits.maximum_dns_answers,
        },
    }
    issuance_sha256 = _sha256(_canonical_bytes(issuance_unsigned))
    try:
        consumed = consume_replay_durably(replay_key_sha256, issuance_sha256)
    except Exception as exc:
        raise _error("replay_consumer_failure") from None
    if consumed is not True:
        raise _error("replay_not_consumed")

    try:
        secret = entropy(32)
    except Exception as exc:
        raise _error("entropy_failure") from None
    if type(secret) is not bytearray or len(secret) != 32:
        if type(secret) is bytearray:
            for index in range(len(secret)):
                secret[index] = 0
        raise _error("entropy_invalid")
    username = base64.urlsafe_b64encode(secret[:16]).rstrip(b"=")
    password = base64.urlsafe_b64encode(secret[16:]).rstrip(b"=")
    encoded = bytearray(username + b":" + password)
    for index in range(len(secret)):
        secret[index] = 0
    if (
        len(encoded) != 45
        or _BASIC_PART.fullmatch(username) is None
        or _BASIC_PART.fullmatch(password) is None
    ):
        for index in range(len(encoded)):
            encoded[index] = 0
        raise _error("entropy_invalid")
    auth_sha256 = hashlib.sha256(encoded).digest()
    try:
        delivered = deliver_guest_authorization(memoryview(encoded))
    except Exception:
        raise _error("secret_delivery_failure") from None
    finally:
        for index in range(len(encoded)):
            encoded[index] = 0
    if delivered is not True:
        raise _error("secret_not_delivered")

    public = dict(issuance_unsigned)
    public["issuance_sha256"] = issuance_sha256
    return _new_proxy(
        admission,
        auth_sha256,
        replay_key_sha256,
        issuance_sha256,
        public,
        resolver,
        connector,
        peer_observer,
        relay_runner,
        connection_finalizer,
        cancel_wakeup,
        monotonic_clock,
    )


_TERMINAL_TOP_KEYS = frozenset(
    {
        "schema", "attempt_binding_sha256", "tls_mode",
        "opaque_tls_limitation", "domain_fronting_limitation",
        "network", "host_proxy", "extinction",
    }
)
_TERMINAL_NETWORK_KEYS = frozenset(
    {
        "network_id_sha256", "network_generation", "network_removed",
        "guest_stopped", "cgroup_populated", "private_channel_identity_sha256",
        "private_channel_removed", "guest_shim_identity_sha256",
        "guest_shim_descendant_count", "guest_shim_fd_count", "guest_shim_extinct",
    }
)
_TERMINAL_HOST_KEYS = frozenset({"terminal_sha256", "active_connections", "resolution_set_count", "resolution_sets_sha256", "counters"})
_TERMINAL_EXTINCTION_KEYS = frozenset({"listener_closed", "listener_fd_count", "relay_fd_count", "runner_descendant_count", "runner_descendants_extinct"})
_COUNTER_KEYS = frozenset(
    {
        "connection_attempts", "tunnels_established", "tunnels_completed",
        "tunnels_failed", "requests_rejected", "auth_rejections",
        "dns_rejections", "quota_rejections", "client_to_upstream_bytes",
        "upstream_to_client_bytes", "total_bytes",
    }
)


def reconcile_terminal_proof(
    raw: bytes,
    admission: NetworkAdmission,
    host_terminal: ProxyTerminal,
    *,
    authenticate_terminal_proof: ProofAuthenticator,
) -> dict[str, Any]:
    """Reconcile provider extinction/counters with the host proxy terminal."""

    _require_admission(admission)
    _require_terminal(host_terminal)
    if host_terminal._admission is not admission:
        raise _error("terminal_authority")
    host_receipt = host_terminal._receipt
    expected = admission._expectation
    if host_receipt.get("schema") != PUBLIC_TERMINAL_SCHEMA:
        raise _error("terminal_host_schema")
    terminal_copy = dict(host_receipt)
    terminal_digest = terminal_copy.pop("terminal_sha256", None)
    if _digest(terminal_digest) != _sha256(_canonical_bytes(terminal_copy)):
        raise _error("terminal_host_digest")
    if (
        host_receipt.get("attempt_binding_sha256") != expected.attempt_binding_sha256
        or host_receipt.get("admission_proof_sha256") != admission._proof_sha256
        or host_receipt.get("tls_mode") != TLS_MODE
        or host_receipt.get("opaque_tls_limitation") != OPAQUE_TLS_LIMITATION
        or host_receipt.get("domain_fronting_limitation") != DOMAIN_FRONTING_LIMITATION
        or host_receipt.get("active_connections") != 0
        or type(host_receipt.get("counters")) is not dict
        or set(host_receipt["counters"]) != _COUNTER_KEYS
    ):
        raise _error("terminal_host_binding")
    for value in host_receipt["counters"].values():
        _domain_int(value)
    if host_receipt["counters"]["total_bytes"] != (
        host_receipt["counters"]["client_to_upstream_bytes"]
        + host_receipt["counters"]["upstream_to_client_bytes"]
    ):
        raise _error("terminal_counter_math")

    value = _exact(_load_canonical(raw), _TERMINAL_TOP_KEYS, "terminal_fields")
    terminal_proof_sha256 = _sha256(raw)
    try:
        authentication = authenticate_terminal_proof(raw, terminal_proof_sha256)
    except Exception:
        raise _error("terminal_proof_authentication_failure") from None
    if type(authentication) is not ProofAuthenticationEvidence or authentication != ProofAuthenticationEvidence(
        authority_id=expected.terminal_proof_authority_id,
        proof_sha256=terminal_proof_sha256,
        authenticated=True,
        replay_safe=True,
    ):
        raise _error("terminal_proof_authentication")
    if (
        value["schema"] != TERMINAL_PROOF_SCHEMA
        or value["attempt_binding_sha256"] != expected.attempt_binding_sha256
        or value["tls_mode"] != TLS_MODE
        or value["opaque_tls_limitation"] != OPAQUE_TLS_LIMITATION
        or value["domain_fronting_limitation"] != DOMAIN_FRONTING_LIMITATION
    ):
        raise _error("terminal_schema")
    network = _exact(value["network"], _TERMINAL_NETWORK_KEYS, "terminal_network_fields")
    _domain_int(network["network_generation"], minimum=1)
    _domain_int(network["cgroup_populated"], maximum=2**31 - 1)
    _domain_int(network["guest_shim_descendant_count"], maximum=2**31 - 1)
    _domain_int(network["guest_shim_fd_count"], maximum=2**31 - 1)
    for field in ("network_removed", "guest_stopped", "private_channel_removed", "guest_shim_extinct"):
        if type(network[field]) is not bool:
            raise _error("terminal_network")
    if network != {
        "network_id_sha256": _sha256(expected.provider_network_id.encode("ascii")),
        "network_generation": expected.network_generation,
        "network_removed": True,
        "guest_stopped": True,
        "cgroup_populated": 0,
        "private_channel_identity_sha256": expected.channel_identity_sha256,
        "private_channel_removed": True,
        "guest_shim_identity_sha256": expected.shim_identity_sha256,
        "guest_shim_descendant_count": 0,
        "guest_shim_fd_count": 0,
        "guest_shim_extinct": True,
    }:
        raise _error("terminal_network")
    observed = _exact(value["host_proxy"], _TERMINAL_HOST_KEYS, "terminal_proxy_fields")
    _domain_int(observed["active_connections"], maximum=2**31 - 1)
    _domain_int(observed["resolution_set_count"], maximum=2**31 - 1)
    _digest(observed["terminal_sha256"])
    _digest(observed["resolution_sets_sha256"])
    if type(observed["counters"]) is not dict or set(observed["counters"]) != _COUNTER_KEYS:
        raise _error("terminal_counter_mismatch")
    for counter in observed["counters"].values():
        _domain_int(counter)
    if observed != {
        "terminal_sha256": terminal_digest,
        "active_connections": 0,
        "resolution_set_count": host_receipt["resolution_set_count"],
        "resolution_sets_sha256": host_receipt["resolution_sets_sha256"],
        "counters": host_receipt["counters"],
    }:
        raise _error("terminal_counter_mismatch")
    extinction = _exact(value["extinction"], _TERMINAL_EXTINCTION_KEYS, "terminal_extinction_fields")
    _domain_int(extinction["listener_fd_count"], maximum=2**31 - 1)
    _domain_int(extinction["relay_fd_count"], maximum=2**31 - 1)
    _domain_int(extinction["runner_descendant_count"], maximum=2**31 - 1)
    if type(extinction["listener_closed"]) is not bool or type(extinction["runner_descendants_extinct"]) is not bool:
        raise _error("terminal_extinction")
    if extinction != {
        "listener_closed": True,
        "listener_fd_count": 0,
        "relay_fd_count": 0,
        "runner_descendant_count": 0,
        "runner_descendants_extinct": True,
    }:
        raise _error("terminal_extinction")
    result = {
        "schema": PUBLIC_RECONCILIATION_SCHEMA,
        "result": "RECONCILED",
        "network_mode": NETWORK_MODE,
        "capability_scope": CAPABILITY_SCOPE,
        "tls_mode": TLS_MODE,
        "opaque_tls_limitation": OPAQUE_TLS_LIMITATION,
        "domain_fronting_limitation": DOMAIN_FRONTING_LIMITATION,
        "backend_executable_sha256": expected.backend_executable_sha256,
        "backend_launch_policy_sha256": expected.backend_launch_policy_sha256,
        "public_ca_bundle_sha256": expected.public_ca_bundle_sha256,
        "proxy_transport": expected.proxy_transport,
        "backend_id": admission._policy.backend_id,
        "auth_mode": admission._policy.auth_mode,
        "release_policy_id": admission._policy.release_policy_id,
        "attempt_binding_sha256": expected.attempt_binding_sha256,
        "admission_proof_sha256": admission._proof_sha256,
        "host_terminal_sha256": terminal_digest,
        "terminal_proof_sha256": terminal_proof_sha256,
        "terminal_proof_authority_id": expected.terminal_proof_authority_id,
        "network_id_sha256": network["network_id_sha256"],
        "network_generation": expected.network_generation,
        "connection_count": host_receipt["counters"]["connection_attempts"],
        "completed_tunnel_count": host_receipt["counters"]["tunnels_completed"],
        "rejected_request_count": host_receipt["counters"]["requests_rejected"],
        "total_bytes": host_receipt["counters"]["total_bytes"],
    }
    result["reconciliation_sha256"] = _sha256(_canonical_bytes(result))
    return result


# ---------------------------------------------------------------------------
# Verified egress v2 semantic transcript
# ---------------------------------------------------------------------------

EGRESS_V2_TRANSCRIPT_SCHEMA = "plamen.verified_backend_egress_transcript.v2"
PUBLIC_EGRESS_V2_VALIDATION_SCHEMA = "plamen.verified_backend_egress_validation.v2"
NATIVE_EGRESS_V2_AUTHORITY = "NATIVE_BROKER_V2_ATTEMPT_BOUND"
TEST_ONLY_EGRESS_V2_AUTHORITY = "TEST_ONLY_NON_AUTHORITY"
PINNED_FIXTURE_UNSUPPORTED = "PINNED_CONNECT_BYTES_NOT_CAPTURED"

_CHALLENGE_COUNTER_KEYS = frozenset(
    {
        "connection_attempts",
        "tunnels_established",
        "tunnels_completed",
        "requests_rejected",
        "auth_rejections",
    }
)
_V2_TOP_KEYS = frozenset(
    {
        "schema", "attempt", "network", "ordering", "target_set_sha256",
        "challenges", "proxy_auth_generations", "native_attestation",
    }
)
_V2_ATTEMPT_KEYS = frozenset(
    {
        "provider_attempt_id", "attempt_binding_sha256", "backend_id",
        "auth_mode", "release_policy_id",
    }
)
_V2_NETWORK_KEYS = frozenset(
    {
        "topology_mode", "effective_egress_mode", "network_id_sha256",
        "network_generation", "ruleset_sha256", "ruleset_generation",
    }
)
_V2_ORDERING_KEYS = frozenset(
    {
        "rules_installed_sequence", "challenge_proxy_auth_minted_sequence",
        "challenge_proxy_auth_revoked_sequence",
        "runtime_proxy_auth_minted_sequence",
        "admission_committed_sequence", "backend_credential_release_sequence",
        "backend_credential_released_before_admission",
    }
)
_V2_CHALLENGE_KEYS = frozenset(
    {
        "sequence", "challenge_id", "transport", "address_family",
        "target_id", "target_sha256", "credential_case", "observed_outcome",
        "proxy_auth_generation",
        "backend_credential_released", "proxy_counters_before",
        "proxy_counters_after",
    }
)
_V2_AUTH_GENERATION_KEYS = frozenset(
    {
        "challenge_generation", "challenge_binding_sha256", "challenge_one_shot",
        "challenge_success_sequence", "challenge_replay_denied_sequence",
        "challenge_revoked_sequence", "runtime_generation",
        "runtime_binding_sha256", "runtime_reusable_within_attempt",
        "runtime_minted_sequence", "credentials_distinct",
    }
)
_V2_ATTESTATION_KEYS = frozenset(
    {
        "authority_id", "broker_authority_sha256", "statement_sha256",
        "signature_sha256", "signature_algorithm", "authenticated",
        "replay_safe",
    }
)

_CHALLENGE_SHAPES = (
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


@dataclass(frozen=True, slots=True)
class ConnectFixtureCompatibility:
    """Typed disposition for generation-bound CLI CONNECT compatibility.

    No CONNECT bytes are asserted until they have been captured from and bound
    to the pinned executable.  A generic HTTP-library assumption is not a CLI
    fixture.
    """

    backend_id: str
    cli_version: str
    auth_mode: str
    supported: bool
    reason_code: str
    fixture_sha256: str | None


def _connect_fixture_compatibility(
    backend_id: str, auth_mode: str, install_generation_authority: object,
    *, test_only: bool,
) -> ConnectFixtureCompatibility:
    from posix_backend_launch_policy import (  # local: avoid authority cycle
        TEST_ONLY_project_backend_install_generation,
        require_backend_install_generation,
    )

    projection = (
        TEST_ONLY_project_backend_install_generation(install_generation_authority)
        if test_only
        else require_backend_install_generation(install_generation_authority)
    )
    if projection.backend != backend_id or not any(
        key[0] == backend_id and key[1] == auth_mode for key in _RELEASE_POLICIES
    ):
        raise _error("release_policy_unknown")
    return ConnectFixtureCompatibility(
        backend_id=backend_id,
        cli_version=projection.resolved_version,
        auth_mode=auth_mode,
        supported=False,
        reason_code=PINNED_FIXTURE_UNSUPPORTED,
        fixture_sha256=None,
    )


def connect_fixture_compatibility(
    backend_id: str, auth_mode: str, *, install_generation_authority: object,
) -> ConnectFixtureCompatibility:
    """Return a disposition bound to one authenticated install generation."""

    return _connect_fixture_compatibility(
        backend_id, auth_mode, install_generation_authority, test_only=False,
    )


def TEST_ONLY_connect_fixture_compatibility(
    backend_id: str, auth_mode: str, *, install_generation_authority: object,
) -> ConnectFixtureCompatibility:
    return _connect_fixture_compatibility(
        backend_id, auth_mode, install_generation_authority, test_only=True,
    )


@dataclass(frozen=True, slots=True)
class EgressV2Expectation:
    """Trusted inputs against which a native challenge transcript is checked.

    This value is configuration, not admission authority.  In particular, a
    caller constructing it cannot release a backend credential.
    """

    provider_attempt_id: str
    attempt_binding_sha256: str
    backend_id: str
    auth_mode: str
    release_policy_id: str
    topology_mode: str
    effective_egress_mode: str
    network_id_sha256: str
    network_generation: int
    ruleset_sha256: str
    ruleset_generation: int
    direct_public_ipv4: str
    direct_public_ipv6: str
    gateway_ipv4: str
    proxy_port: int
    other_gateway_tcp_port: int
    allowlisted_domain_id: str
    broker_authority_sha256: str
    challenge_proxy_auth_generation: int
    challenge_proxy_auth_binding_sha256: str
    runtime_proxy_auth_generation: int
    runtime_proxy_auth_binding_sha256: str
    native_attestation_signature_sha256: str

    def __post_init__(self) -> None:
        _text_id(self.provider_attempt_id, attempt=True)
        _digest(self.attempt_binding_sha256)
        policy = _RELEASE_POLICIES.get(
            (self.backend_id, self.auth_mode, self.release_policy_id)
        )
        if policy is None:
            raise _error("release_policy_unknown")
        if self.topology_mode not in {APPLE_TOPOLOGY_MODE, LINUX_TOPOLOGY_MODE}:
            raise _error("network_mode")
        if self.effective_egress_mode != EFFECTIVE_EGRESS_MODE:
            raise _error("network_mode")
        _digest(self.network_id_sha256)
        _domain_int(self.network_generation, minimum=1)
        _digest(self.ruleset_sha256)
        _domain_int(self.ruleset_generation, minimum=1)
        address4 = ipaddress.ip_address(_canonical_ip(self.direct_public_ipv4, global_only=True))
        address6 = ipaddress.ip_address(_canonical_ip(self.direct_public_ipv6, global_only=True))
        gateway = ipaddress.ip_address(_canonical_ip(self.gateway_ipv4))
        if address4.version != 4 or address6.version != 6:
            raise _error("challenge_address_family")
        if (
            gateway.version != 4
            or not gateway.is_private
            or gateway.is_loopback
            or gateway.is_link_local
            or gateway.is_multicast
            or gateway.is_unspecified
        ):
            raise _error("challenge_gateway")
        _domain_int(self.proxy_port, minimum=1, maximum=65535)
        _domain_int(self.other_gateway_tcp_port, minimum=1, maximum=65535)
        if self.other_gateway_tcp_port == self.proxy_port:
            raise _error("challenge_gateway")
        if (
            type(self.allowlisted_domain_id) is not str
            or _DOMAIN_ID.fullmatch(self.allowlisted_domain_id) is None
        ):
            raise _error("identity_invalid")
        if self.allowlisted_domain_id not in {item[0] for item in policy.domains}:
            raise _error("connect_domain")
        _digest(self.broker_authority_sha256)
        _domain_int(self.challenge_proxy_auth_generation, minimum=1)
        _digest(self.challenge_proxy_auth_binding_sha256)
        _domain_int(self.runtime_proxy_auth_generation, minimum=2)
        _digest(self.runtime_proxy_auth_binding_sha256)
        _digest(self.native_attestation_signature_sha256)
        if (
            self.runtime_proxy_auth_generation != self.challenge_proxy_auth_generation + 1
            or self.runtime_proxy_auth_binding_sha256
            == self.challenge_proxy_auth_binding_sha256
        ):
            raise _error("proxy_auth_generation")

    @property
    def target_set_sha256(self) -> str:
        return _sha256(_canonical_bytes(_v2_target_documents(self)))


def _v2_policy(expectation: EgressV2Expectation) -> _ReleasePolicy:
    policy = _RELEASE_POLICIES.get(
        (expectation.backend_id, expectation.auth_mode, expectation.release_policy_id)
    )
    if policy is None:
        raise _error("release_policy_unknown")
    return policy


def _v2_target_documents(expectation: EgressV2Expectation) -> list[dict[str, Any]]:
    policy = _v2_policy(expectation)
    hostname = dict(policy.domains)[expectation.allowlisted_domain_id]
    values = {
        "PUBLIC_IPV4": ("TCP", expectation.direct_public_ipv4, 443),
        "PUBLIC_IPV6": ("TCP", expectation.direct_public_ipv6, 443),
        "GATEWAY_OTHER_TCP": ("TCP", expectation.gateway_ipv4, expectation.other_gateway_tcp_port),
        "GATEWAY_UDP": ("UDP", expectation.gateway_ipv4, expectation.proxy_port),
        "GATEWAY_RAW": ("RAW_IP", expectation.gateway_ipv4, 0),
        "PROXY": ("TCP", expectation.gateway_ipv4, expectation.proxy_port),
        "ALLOWLIST": ("CONNECT", hostname, 443),
    }
    return [
        {
            "target_id": target_id,
            "transport": transport,
            "destination": destination,
            "port": port,
        }
        for target_id, (transport, destination, port) in values.items()
    ]


def _v2_target_digests(expectation: EgressV2Expectation) -> dict[str, str]:
    return {
        item["target_id"]: _sha256(_canonical_bytes(item))
        for item in _v2_target_documents(expectation)
    }


def _challenge_counters(value: Any) -> dict[str, int]:
    value = _exact(value, _CHALLENGE_COUNTER_KEYS, "challenge_counter_fields")
    for counter in value.values():
        _domain_int(counter, maximum=2**31 - 1)
    return value


def _next_challenge_counters(
    current: Mapping[str, int], challenge_id: str
) -> dict[str, int]:
    result = dict(current)
    if challenge_id.startswith("PROXY_"):
        result["connection_attempts"] += 1
    if challenge_id in {
        "PROXY_MISSING_AUTH_DENIED", "PROXY_WRONG_AUTH_DENIED",
        "PROXY_CROSS_ATTEMPT_AUTH_DENIED", "PROXY_REPLAY_AUTH_DENIED",
    }:
        result["requests_rejected"] += 1
        result["auth_rejections"] += 1
    elif challenge_id == "PROXY_ALLOWLIST_CONNECT_SUCCEEDED":
        result["tunnels_established"] += 1
        result["tunnels_completed"] += 1
    return result


@dataclass(frozen=True, slots=True)
class TEST_ONLY_EgressV2Validation:
    """Inert semantic result which is explicitly not release authority."""

    receipt: Mapping[str, Any]
    authority_class: str = TEST_ONLY_EGRESS_V2_AUTHORITY

    def __post_init__(self) -> None:
        if self.authority_class != TEST_ONLY_EGRESS_V2_AUTHORITY:
            raise _error("test_authority")

    def public_receipt(self) -> dict[str, Any]:
        return _public_copy(self.receipt)


def TEST_ONLY_validate_egress_v2_transcript(
    raw: bytes, expectation: EgressV2Expectation
) -> TEST_ONLY_EgressV2Validation:
    """Exercise v2 semantics without creating production authority."""

    if type(expectation) is not EgressV2Expectation:
        raise _error("expectation_type")
    # Reconstruct after possible object.__new__/object.__setattr__ forgery.
    try:
        expectation = EgressV2Expectation(
            **{
                field: object.__getattribute__(expectation, field)
                for field in EgressV2Expectation.__dataclass_fields__
            }
        )
    except (AttributeError, TypeError, VerifiedEgressError):
        raise _error("expectation_type") from None
    value = _exact(_load_canonical(raw), _V2_TOP_KEYS, "egress_v2_fields")
    if value["schema"] != EGRESS_V2_TRANSCRIPT_SCHEMA:
        raise _error("egress_v2_schema")
    attempt = _exact(value["attempt"], _V2_ATTEMPT_KEYS, "egress_v2_attempt_fields")
    if attempt != {
        "provider_attempt_id": expectation.provider_attempt_id,
        "attempt_binding_sha256": expectation.attempt_binding_sha256,
        "backend_id": expectation.backend_id,
        "auth_mode": expectation.auth_mode,
        "release_policy_id": expectation.release_policy_id,
    }:
        raise _error("egress_v2_attempt_binding")
    network = _exact(value["network"], _V2_NETWORK_KEYS, "egress_v2_network_fields")
    _domain_int(network["network_generation"], minimum=1)
    _domain_int(network["ruleset_generation"], minimum=1)
    if network != {
        "topology_mode": expectation.topology_mode,
        "effective_egress_mode": expectation.effective_egress_mode,
        "network_id_sha256": expectation.network_id_sha256,
        "network_generation": expectation.network_generation,
        "ruleset_sha256": expectation.ruleset_sha256,
        "ruleset_generation": expectation.ruleset_generation,
    }:
        raise _error("egress_v2_network_binding")
    if value["target_set_sha256"] != expectation.target_set_sha256:
        raise _error("egress_v2_target_set")
    ordering = _exact(value["ordering"], _V2_ORDERING_KEYS, "egress_v2_ordering_fields")
    for field in (
        "rules_installed_sequence", "challenge_proxy_auth_minted_sequence",
        "challenge_proxy_auth_revoked_sequence",
        "runtime_proxy_auth_minted_sequence",
        "admission_committed_sequence", "backend_credential_release_sequence",
    ):
        _domain_int(ordering[field], minimum=1)
    challenge_start = 3
    challenge_end = challenge_start + len(_CHALLENGE_SHAPES) - 1
    if ordering != {
        "rules_installed_sequence": 1,
        "challenge_proxy_auth_minted_sequence": 2,
        "challenge_proxy_auth_revoked_sequence": challenge_end + 1,
        "runtime_proxy_auth_minted_sequence": challenge_end + 2,
        "admission_committed_sequence": challenge_end + 3,
        "backend_credential_release_sequence": challenge_end + 4,
        "backend_credential_released_before_admission": False,
    }:
        raise _error("egress_v2_ordering")
    challenges = value["challenges"]
    if type(challenges) is not list or len(challenges) != len(_CHALLENGE_SHAPES):
        raise _error("egress_v2_challenges")
    target_digests = _v2_target_digests(expectation)
    challenge_success_sequence = challenge_start + next(
        index
        for index, shape in enumerate(_CHALLENGE_SHAPES)
        if shape[0] == "PROXY_ALLOWLIST_CONNECT_SUCCEEDED"
    )
    challenge_replay_sequence = challenge_start + next(
        index
        for index, shape in enumerate(_CHALLENGE_SHAPES)
        if shape[0] == "PROXY_REPLAY_AUTH_DENIED"
    )
    auth_generations = _exact(
        value["proxy_auth_generations"],
        _V2_AUTH_GENERATION_KEYS,
        "egress_v2_auth_generation_fields",
    )
    for field in (
        "challenge_generation", "challenge_success_sequence",
        "challenge_replay_denied_sequence", "challenge_revoked_sequence",
        "runtime_generation", "runtime_minted_sequence",
    ):
        _domain_int(auth_generations[field], minimum=1)
    if auth_generations != {
        "challenge_generation": expectation.challenge_proxy_auth_generation,
        "challenge_binding_sha256": expectation.challenge_proxy_auth_binding_sha256,
        "challenge_one_shot": True,
        "challenge_success_sequence": challenge_success_sequence,
        "challenge_replay_denied_sequence": challenge_replay_sequence,
        "challenge_revoked_sequence": challenge_end + 1,
        "runtime_generation": expectation.runtime_proxy_auth_generation,
        "runtime_binding_sha256": expectation.runtime_proxy_auth_binding_sha256,
        "runtime_reusable_within_attempt": True,
        "runtime_minted_sequence": challenge_end + 2,
        "credentials_distinct": True,
    }:
        raise _error("egress_v2_auth_generation")
    counters = {
        "connection_attempts": 0,
        "tunnels_established": 0,
        "tunnels_completed": 0,
        "requests_rejected": 0,
        "auth_rejections": 0,
    }
    for offset, shape in enumerate(_CHALLENGE_SHAPES):
        challenge = _exact(
            challenges[offset], _V2_CHALLENGE_KEYS, "egress_v2_challenge_fields"
        )
        sequence = challenge_start + offset
        challenge_id, transport, family, target_id, credential_case, outcome = shape
        auth_generation = (
            0
            if credential_case in {"NONE", "MISSING"}
            else expectation.challenge_proxy_auth_generation
        )
        before = _challenge_counters(challenge["proxy_counters_before"])
        after = _challenge_counters(challenge["proxy_counters_after"])
        _domain_int(challenge["proxy_auth_generation"], maximum=2**31 - 1)
        expected_after = _next_challenge_counters(counters, challenge_id)
        if challenge != {
            "sequence": sequence,
            "challenge_id": challenge_id,
            "transport": transport,
            "address_family": family,
            "target_id": target_id,
            "target_sha256": target_digests[target_id],
            "credential_case": credential_case,
            "proxy_auth_generation": auth_generation,
            "observed_outcome": outcome,
            "backend_credential_released": False,
            "proxy_counters_before": counters,
            "proxy_counters_after": expected_after,
        } or before != counters or after != expected_after:
            raise _error("egress_v2_challenge_binding")
        counters = expected_after
    statement = {
        key: value[key]
        for key in (
            "schema", "attempt", "network", "ordering", "target_set_sha256",
            "challenges", "proxy_auth_generations",
        )
    }
    statement_sha256 = _sha256(_canonical_bytes(statement))
    attestation = _exact(
        value["native_attestation"],
        _V2_ATTESTATION_KEYS,
        "egress_v2_attestation_fields",
    )
    _digest(attestation["broker_authority_sha256"])
    _digest(attestation["statement_sha256"])
    _digest(attestation["signature_sha256"])
    if attestation != {
        "authority_id": NATIVE_EGRESS_V2_AUTHORITY,
        "broker_authority_sha256": expectation.broker_authority_sha256,
        "statement_sha256": statement_sha256,
        "signature_sha256": expectation.native_attestation_signature_sha256,
        "signature_algorithm": "NATIVE_BROKER_V2_OPAQUE_SHA256",
        "authenticated": True,
        "replay_safe": True,
    }:
        raise _error("egress_v2_attestation")
    transcript_sha256 = _sha256(raw)
    receipt = {
        "schema": PUBLIC_EGRESS_V2_VALIDATION_SCHEMA,
        "result": "SEMANTICS_VALIDATED_NON_AUTHORITATIVE",
        "authority_class": TEST_ONLY_EGRESS_V2_AUTHORITY,
        "native_authority_required": NATIVE_EGRESS_V2_AUTHORITY,
        "attempt_binding_sha256": expectation.attempt_binding_sha256,
        "backend_id": expectation.backend_id,
        "auth_mode": expectation.auth_mode,
        "release_policy_id": expectation.release_policy_id,
        "topology_mode": expectation.topology_mode,
        "effective_egress_mode": expectation.effective_egress_mode,
        "network_id_sha256": expectation.network_id_sha256,
        "network_generation": expectation.network_generation,
        "ruleset_sha256": expectation.ruleset_sha256,
        "ruleset_generation": expectation.ruleset_generation,
        "target_set_sha256": expectation.target_set_sha256,
        "challenge_count": len(challenges),
        "last_challenge_sequence": challenge_end,
        "challenge_proxy_auth_generation": expectation.challenge_proxy_auth_generation,
        "runtime_proxy_auth_generation": expectation.runtime_proxy_auth_generation,
        "admission_committed_sequence": challenge_end + 3,
        "backend_credential_release_sequence": challenge_end + 4,
        "final_proxy_counters": counters,
        "transcript_sha256": transcript_sha256,
        "statement_sha256": statement_sha256,
        "signature_sha256": attestation["signature_sha256"],
        "broker_authority_sha256": expectation.broker_authority_sha256,
    }
    return TEST_ONLY_EgressV2Validation(MappingProxyType(receipt))


def admit_verified_egress_v2(*_args: Any, **_kwargs: Any) -> None:
    """Production entry point; native broker-v2 authority is not integrated."""

    raise _error("native_egress_authority_required")


__all__ = [
    "AttemptProxy",
    "ConnectionSource",
    "CAPABILITY_SCOPE",
    "ConnectionFinalizationEvidence",
    "DOMAIN_FRONTING_LIMITATION",
    "APPLE_ATTEMPT_NETWORK_TCP",
    "APPLE_TOPOLOGY_MODE",
    "EFFECTIVE_EGRESS_MODE",
    "EGRESS_V2_TRANSCRIPT_SCHEMA",
    "EgressV2Expectation",
    "LINUX_NETWORK_NONE_UDS_SHIM",
    "LINUX_TOPOLOGY_MODE",
    "NETWORK_MODE",
    "TLS_MODE",
    "OPAQUE_TLS_LIMITATION",
    "NETWORK_PROOF_SCHEMA",
    "NetworkAdmission",
    "PUBLIC_ADMISSION_SCHEMA",
    "PUBLIC_CONNECTION_SCHEMA",
    "PUBLIC_ISSUANCE_SCHEMA",
    "PUBLIC_RECONCILIATION_SCHEMA",
    "PUBLIC_TERMINAL_SCHEMA",
    "PeerObservation",
    "PINNED_FIXTURE_UNSUPPORTED",
    "ConnectFixtureCompatibility",
    "ProxyTerminal",
    "ProxyLimits",
    "ProofAuthenticationEvidence",
    "PROVIDER_GUEST_PROOF_AUTHORITY",
    "PROVIDER_TERMINAL_PROOF_AUTHORITY",
    "RelayController",
    "RelayRunnerEvidence",
    "TERMINAL_PROOF_SCHEMA",
    "TrustedNetworkExpectation",
    "VerifiedEgressError",
    "admit_network_proof",
    "admit_verified_egress_v2",
    "canonical_proof_bytes",
    "issue_attempt_proxy",
    "connect_fixture_compatibility",
    "reconcile_terminal_proof",
    "release_policy_ids",
]
