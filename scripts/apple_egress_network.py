"""Closed Apple Container 1.3.1 egress-network contract.

The module is intentionally inert at import time.  It renders and validates the
finite network lifecycle needed by the Apple provider, but production effects
are available only through an already-loaded, static native broker-v2 extension.
No Python object in this module is an authority or an authenticated receipt.

Apple ``container network create --internal`` selects a host-only topology.  It
does *not* prove credential isolation or complete egress denial: the guest can
reach the host gateway and affected releases have permitted raw-IP TCP egress.
Consequently an internal network is accepted only together with independent,
attempt-bound native enforcement and revocation evidence for the narrow proxy.
"""
from __future__ import annotations

from dataclasses import dataclass, fields
from enum import Enum, IntEnum
import hashlib
import importlib.machinery
import ipaddress
import json
import os
import re
import sys
import threading
import types
from typing import Any


SCHEMA = "plamen.apple-egress-network.v1"
SUPPORTED_APPLE_CONTAINER_VERSION = "1.3.1"
APPLE_CONTAINER_EXECUTABLE = "/usr/local/bin/container"
NETWORK_PLUGIN = "container-network-vmnet"
NETWORK_MODE = "hostOnly"
PROXY_KIND = "VERIFIED_CONNECT_ALLOWLIST"
NATIVE_MODULE_NAME = "_plamen_native_supervisor"
NATIVE_ABI_SCHEMA = "plamen.native-broker.v2"
NATIVE_CALL_AUTHORITY = "PROCESS_THREAD_FORK_BOUND_ONE_SHOT"
NATIVE_PRODUCTION_ACQUISITION = (
    "HARD_STOP_PENDING_NATIVE_LAUNCHER_AND_DURABLE_BROKER_SERVICE"
)
TEST_ONLY_AUTHORITY_CLASS = "TEST_ONLY_NON_AUTHORITY"

# Exact numeric values from native/include/plamen_broker_v2.h.  These constants
# are protocol descriptions, not an execution or authority lane.
BROKER_V2_PROTOCOL_VERSION = 2
BROKER_V2_FRAME_HEADER_SIZE = 196
BROKER_V2_MAX_SCM_RIGHTS_FDS = 16
BROKER_V2_FD_APPLE_CLI_EXECUTABLE = 0x0001
BROKER_V2_FD_JOURNAL_DIRECTORY = 0x0002
NATIVE_PROJECTION_MISSING_COMMITMENTS = (
    "backend_admission_sha256",
    "image_closure_sha256",
)

_HEX64 = re.compile(r"[0-9a-f]{64}")
_HEX32 = re.compile(r"[0-9a-f]{32}")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_NETWORK_ID = re.compile(r"[a-z0-9](?:[a-z0-9_.-]{0,61}[a-z0-9])?")
_NATIVE_EXTENSION_SUFFIXES = tuple(importlib.machinery.EXTENSION_SUFFIXES)

_OWNER_LABEL = "io.plamen.provider"
_OWNER_VALUE = "apple-container-v3"
_SCHEMA_LABEL = "io.plamen.network-schema"
_ATTEMPT_LABEL = "io.plamen.audit-attempt"
_RUN_LABEL = "io.plamen.run"
_POLICY_LABEL = "io.plamen.network-sha256"
_CLOSURE_LABEL = "io.plamen.network-closure-sha256"
_EGRESS_LABEL = "io.plamen.egress-admission-sha256"
_ROLE_LABEL = "io.plamen.network-role"
_ROLE_VALUE = "governed-egress"


class AppleEgressNetworkError(RuntimeError):
    """Base error; messages contain no caller data, paths, or native output."""


class NetworkConfigurationError(AppleEgressNetworkError, ValueError):
    pass


class NetworkCollisionError(AppleEgressNetworkError):
    pass


class NetworkProtocolError(AppleEgressNetworkError):
    pass


class NetworkAmbiguousError(AppleEgressNetworkError):
    pass


class NativeBrokerUnavailable(AppleEgressNetworkError):
    pass


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _json_digest(value: object) -> str:
    try:
        raw = json.dumps(
            value, allow_nan=False, ensure_ascii=True, sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        raise NetworkConfigurationError("canonical network input is invalid") from None
    return _digest(raw)


def _exact_text(value: object, label: str, maximum: int = 128) -> str:
    if (type(value) is not str or not value or len(value) > maximum
            or "\x00" in value or "\n" in value or "\r" in value
            or not value.isascii()):
        raise NetworkConfigurationError(f"{label} is invalid")
    return value


def _exact_id(value: object, label: str) -> str:
    value = _exact_text(value, label)
    if _ID.fullmatch(value) is None:
        raise NetworkConfigurationError(f"{label} is invalid")
    return value


def _hex64(value: object, label: str) -> str:
    if type(value) is not str or _HEX64.fullmatch(value) is None:
        raise NetworkConfigurationError(f"{label} is invalid")
    return value


def _hex32(value: object, label: str) -> str:
    if type(value) is not str or _HEX32.fullmatch(value) is None:
        raise NetworkConfigurationError(f"{label} is invalid")
    return value


def _exact_bool(value: object, expected: bool, label: str) -> None:
    if value is not expected:
        raise NetworkConfigurationError(f"{label} is invalid")


def _expected_labels(closure: "NetworkClosure") -> tuple[tuple[str, str], ...]:
    return tuple(sorted({
        _OWNER_LABEL: _OWNER_VALUE,
        _SCHEMA_LABEL: SCHEMA,
        _ATTEMPT_LABEL: closure.attempt_id,
        _RUN_LABEL: closure.run_identity,
        _POLICY_LABEL: closure.egress_policy_sha256,
        _CLOSURE_LABEL: closure.digest,
        _EGRESS_LABEL: closure.egress_admission_sha256,
        _ROLE_LABEL: _ROLE_VALUE,
    }.items()))


def _derived_network_name(closure_digest: str) -> str:
    return "plamen-egress-" + closure_digest[:24]


def _derived_subnet(closure_digest: str) -> str:
    # A deterministic /28 in 10/8. Collisions remain possible and are handled
    # by exact label/identity reconciliation, never by adopting an existing net.
    octet2 = 64 + int(closure_digest[24:26], 16) % 128
    octet3 = int(closure_digest[26:28], 16)
    block = (int(closure_digest[28:30], 16) % 16) * 16
    return f"10.{octet2}.{octet3}.{block}/28"


@dataclass(frozen=True)
class NetworkClosure:
    attempt_id: str
    run_identity: str
    request_fingerprint_sha256: str
    config_sha256: str
    runtime_closure_sha256: str
    provider_provenance_sha256: str
    egress_policy_sha256: str
    egress_admission_sha256: str
    proxy_endpoint_sha256: str
    credential_isolation_sha256: str
    broker_authority_sha256: str

    def __post_init__(self) -> None:
        _exact_id(self.attempt_id, "attempt identity")
        _exact_id(self.run_identity, "run identity")
        for label, value in (
            ("request fingerprint", self.request_fingerprint_sha256),
            ("configuration digest", self.config_sha256),
            ("runtime closure digest", self.runtime_closure_sha256),
            ("provider provenance digest", self.provider_provenance_sha256),
            ("egress policy digest", self.egress_policy_sha256),
            ("egress admission digest", self.egress_admission_sha256),
            ("proxy endpoint digest", self.proxy_endpoint_sha256),
            ("credential isolation digest", self.credential_isolation_sha256),
            ("broker authority digest", self.broker_authority_sha256),
        ):
            _hex64(value, label)

    @property
    def digest(self) -> str:
        return _json_digest({
            "attempt_id": self.attempt_id,
            "broker_authority_sha256": self.broker_authority_sha256,
            "config_sha256": self.config_sha256,
            "credential_isolation_sha256": self.credential_isolation_sha256,
            "egress_admission_sha256": self.egress_admission_sha256,
            "egress_policy_sha256": self.egress_policy_sha256,
            "provider_provenance_sha256": self.provider_provenance_sha256,
            "proxy_endpoint_sha256": self.proxy_endpoint_sha256,
            "request_fingerprint_sha256": self.request_fingerprint_sha256,
            "run_identity": self.run_identity,
            "runtime_closure_sha256": self.runtime_closure_sha256,
            "schema": SCHEMA + ".closure",
        })


def _closure(value: object) -> NetworkClosure:
    if type(value) is not NetworkClosure:
        raise NetworkConfigurationError("network closure type is invalid")
    # Reconstruct to force every exact field check after object.__new__ forgery.
    return NetworkClosure(
        object.__getattribute__(value, "attempt_id"),
        object.__getattribute__(value, "run_identity"),
        object.__getattribute__(value, "request_fingerprint_sha256"),
        object.__getattribute__(value, "config_sha256"),
        object.__getattribute__(value, "runtime_closure_sha256"),
        object.__getattribute__(value, "provider_provenance_sha256"),
        object.__getattribute__(value, "egress_policy_sha256"),
        object.__getattribute__(value, "egress_admission_sha256"),
        object.__getattribute__(value, "proxy_endpoint_sha256"),
        object.__getattribute__(value, "credential_isolation_sha256"),
        object.__getattribute__(value, "broker_authority_sha256"),
    )


@dataclass(frozen=True)
class NetworkPlan:
    closure_sha256: str
    network_name: str
    ipv4_subnet: str
    ipv4_gateway: str
    plugin: str
    mode: str
    labels: tuple[tuple[str, str], ...]
    internal: bool
    internal_isolation_sufficient: bool
    create_argv: tuple[str, ...]
    inspect_argv: tuple[str, ...]
    delete_argv: tuple[str, ...]
    fingerprint_sha256: str

    def __post_init__(self) -> None:
        _hex64(self.closure_sha256, "closure digest")
        if type(self.network_name) is not str or _NETWORK_ID.fullmatch(self.network_name) is None:
            raise NetworkConfigurationError("network name is invalid")
        try:
            subnet = ipaddress.IPv4Network(self.ipv4_subnet, strict=True)
            gateway = ipaddress.IPv4Address(self.ipv4_gateway)
        except (ValueError, TypeError):
            raise NetworkConfigurationError("network subnet is invalid") from None
        if (not subnet.subnet_of(ipaddress.IPv4Network("10.0.0.0/8"))
                or subnet.prefixlen != 28 or gateway != subnet.network_address + 1):
            raise NetworkConfigurationError("network subnet is invalid")
        if (type(self.plugin) is not str or type(self.mode) is not str
                or self.plugin != NETWORK_PLUGIN or self.mode != NETWORK_MODE):
            raise NetworkConfigurationError("network topology is invalid")
        _exact_bool(self.internal, True, "internal topology")
        _exact_bool(
            self.internal_isolation_sufficient, False,
            "internal isolation claim",
        )
        _validate_label_tuple(self.labels)
        for argv in (self.create_argv, self.inspect_argv, self.delete_argv):
            _validate_argv(argv)
        _hex64(self.fingerprint_sha256, "network plan digest")

    @property
    def document(self) -> dict[str, object]:
        return {
            "closure_sha256": self.closure_sha256,
            "create_argv": list(self.create_argv),
            "delete_argv": list(self.delete_argv),
            "inspect_argv": list(self.inspect_argv),
            "internal": self.internal,
            "internal_isolation_sufficient": self.internal_isolation_sufficient,
            "ipv4_gateway": self.ipv4_gateway,
            "ipv4_subnet": self.ipv4_subnet,
            "labels": [list(item) for item in self.labels],
            "mode": self.mode,
            "network_name": self.network_name,
            "plugin": self.plugin,
            "schema": SCHEMA + ".plan",
        }


def _validate_label_tuple(value: object) -> tuple[tuple[str, str], ...]:
    if type(value) is not tuple or not value:
        raise NetworkConfigurationError("network labels are invalid")
    checked: list[tuple[str, str]] = []
    for row in value:
        if type(row) is not tuple or len(row) != 2:
            raise NetworkConfigurationError("network labels are invalid")
        key, item = row
        key = _exact_text(key, "network label", 128)
        item = _exact_text(item, "network label", 256)
        checked.append((key, item))
    result = tuple(checked)
    if result != tuple(sorted(result)) or len({key for key, _ in result}) != len(result):
        raise NetworkConfigurationError("network labels are invalid")
    return result


def _validate_argv(value: object) -> tuple[str, ...]:
    if type(value) is not tuple or not 4 <= len(value) <= 32:
        raise NetworkConfigurationError("network command is invalid")
    result: list[str] = []
    total = 0
    for item in value:
        item = _exact_text(item, "network command", 512)
        total += len(item.encode("ascii")) + 1
        result.append(item)
    if total > 8192:
        raise NetworkConfigurationError("network command is invalid")
    return tuple(result)


def render_network_plan(closure: NetworkClosure) -> NetworkPlan:
    closure = _closure(closure)
    name = _derived_network_name(closure.digest)
    subnet = _derived_subnet(closure.digest)
    gateway = str(ipaddress.IPv4Network(subnet).network_address + 1)
    labels = _expected_labels(closure)
    create: list[str] = [
        APPLE_CONTAINER_EXECUTABLE, "network", "create", "--internal",
        "--subnet", subnet,
    ]
    for key, value in labels:
        create.extend(("--label", key + "=" + value))
    create.extend(("--plugin", NETWORK_PLUGIN, name))
    inspect = (APPLE_CONTAINER_EXECUTABLE, "network", "inspect", name)
    delete = (APPLE_CONTAINER_EXECUTABLE, "network", "delete", name)
    partial = NetworkPlan(
        closure.digest, name, subnet, gateway, NETWORK_PLUGIN, NETWORK_MODE,
        labels, True, False, tuple(create), inspect, delete, "0" * 64,
    )
    return NetworkPlan(
        partial.closure_sha256, partial.network_name, partial.ipv4_subnet,
        partial.ipv4_gateway, partial.plugin, partial.mode, partial.labels,
        partial.internal, partial.internal_isolation_sufficient,
        partial.create_argv, partial.inspect_argv, partial.delete_argv,
        _json_digest(partial.document),
    )


def _plan(value: object, closure: NetworkClosure) -> NetworkPlan:
    if type(value) is not NetworkPlan:
        raise NetworkConfigurationError("network plan type is invalid")
    expected = render_network_plan(closure)
    try:
        checked = NetworkPlan(*(
            object.__getattribute__(value, name) for name in (
                "closure_sha256", "network_name", "ipv4_subnet",
                "ipv4_gateway", "plugin", "mode", "labels", "internal",
                "internal_isolation_sufficient", "create_argv", "inspect_argv",
                "delete_argv", "fingerprint_sha256",
            )
        ))
    except (NetworkConfigurationError, AttributeError):
        raise NetworkConfigurationError("network plan is invalid") from None
    if checked != expected:
        raise NetworkConfigurationError("network plan differs")
    return expected


@dataclass(frozen=True)
class NetworkObservation:
    present: bool
    network_name: str | None
    network_id: str | None
    mode: str | None
    plugin: str | None
    ipv4_subnet: str | None
    ipv4_gateway: str | None
    ipv6_subnet: str | None
    labels: tuple[tuple[str, str], ...]
    attached_container_ids: tuple[str, ...]
    inspection_sha256: str

    def __post_init__(self) -> None:
        if type(self.present) is not bool:
            raise NetworkConfigurationError("network presence is invalid")
        if not self.present:
            if (type(self.labels) is not tuple
                    or type(self.attached_container_ids) is not tuple
                    or self.network_name is not None or self.network_id is not None
                    or self.mode is not None or self.plugin is not None
                    or self.ipv4_subnet is not None or self.ipv4_gateway is not None
                    or self.ipv6_subnet is not None
                    or self.labels != () or self.attached_container_ids != ()):
                raise NetworkConfigurationError("absent network observation is invalid")
        else:
            if (type(self.network_name) is not str
                    or _NETWORK_ID.fullmatch(self.network_name) is None
                    or type(self.network_id) is not str
                    or _NETWORK_ID.fullmatch(self.network_id) is None
                    or type(self.mode) is not str or type(self.plugin) is not str
                    or self.mode != NETWORK_MODE or self.plugin != NETWORK_PLUGIN):
                raise NetworkConfigurationError("network inspection identity is invalid")
            _validate_label_tuple(self.labels)
            if type(self.attached_container_ids) is not tuple or any(
                type(item) is not str or _NETWORK_ID.fullmatch(item) is None
                for item in self.attached_container_ids
            ) or len(set(self.attached_container_ids)) != len(self.attached_container_ids):
                raise NetworkConfigurationError("network attachments are invalid")
            try:
                if (type(self.ipv4_subnet) is not str
                        or type(self.ipv4_gateway) is not str
                        or type(self.ipv6_subnet) is not str):
                    raise ValueError
                subnet = ipaddress.IPv4Network(self.ipv4_subnet, strict=True)
                gateway = ipaddress.IPv4Address(self.ipv4_gateway)
                ipv6 = ipaddress.IPv6Network(self.ipv6_subnet, strict=True)
            except (ValueError, TypeError):
                raise NetworkConfigurationError("network inspection subnet is invalid") from None
            if (gateway != subnet.network_address + 1 or ipv6.prefixlen != 64
                    or not ipv6.subnet_of(ipaddress.IPv6Network("fc00::/7"))):
                raise NetworkConfigurationError("network inspection subnet is invalid")
        _hex64(self.inspection_sha256, "inspection digest")
        if self.inspection_sha256 != _json_digest(self.document):
            raise NetworkConfigurationError("inspection digest differs")

    @property
    def document(self) -> dict[str, object]:
        return {
            "attached_container_ids": list(self.attached_container_ids),
            "ipv4_gateway": self.ipv4_gateway,
            "ipv4_subnet": self.ipv4_subnet,
            "ipv6_subnet": self.ipv6_subnet,
            "labels": [list(item) for item in self.labels],
            "mode": self.mode,
            "network_id": self.network_id,
            "network_name": self.network_name,
            "plugin": self.plugin,
            "present": self.present,
            "schema": SCHEMA + ".observation",
        }


def TEST_ONLY_observation(
    plan: NetworkPlan, *, network_id: str = "plamen-network-object-001",
    attached_container_ids: tuple[str, ...] = (), present: bool = True,
    ipv6_subnet: str = "fd12:3456:789a:1::/64",
) -> NetworkObservation:
    """Build inert inspect data. Never authenticates an Apple observation."""
    if type(plan) is not NetworkPlan:
        raise NetworkConfigurationError("network plan type is invalid")
    document: dict[str, object]
    if present:
        document = {
            "attached_container_ids": list(attached_container_ids),
            "ipv4_gateway": plan.ipv4_gateway,
            "ipv4_subnet": plan.ipv4_subnet,
            "ipv6_subnet": ipv6_subnet,
            "labels": [list(item) for item in plan.labels],
            "mode": plan.mode,
            "network_id": network_id,
            "network_name": plan.network_name,
            "plugin": plan.plugin,
            "present": True,
            "schema": SCHEMA + ".observation",
        }
        return NetworkObservation(
            True, plan.network_name, network_id, plan.mode, plan.plugin,
            plan.ipv4_subnet, plan.ipv4_gateway, ipv6_subnet, plan.labels,
            attached_container_ids, _json_digest(document),
        )
    document = {
        "attached_container_ids": [], "ipv4_gateway": None,
        "ipv4_subnet": None, "labels": [], "mode": None,
        "ipv6_subnet": None,
        "network_id": None, "network_name": None, "plugin": None,
        "present": False, "schema": SCHEMA + ".observation",
    }
    return NetworkObservation(
        False, None, None, None, None, None, None, None, (), (),
        _json_digest(document),
    )


def validate_inspection(
    closure: NetworkClosure, plan: NetworkPlan, observation: NetworkObservation,
    *, expected_network_id: str | None,
) -> NetworkObservation:
    closure = _closure(closure)
    plan = _plan(plan, closure)
    if type(observation) is not NetworkObservation:
        raise NetworkProtocolError("network inspection type is invalid")
    # Rebuild to catch object.__new__ substitution and recompute the digest.
    try:
        checked = NetworkObservation(
            object.__getattribute__(observation, "present"),
            object.__getattribute__(observation, "network_name"),
            object.__getattribute__(observation, "network_id"),
            object.__getattribute__(observation, "mode"),
            object.__getattribute__(observation, "plugin"),
            object.__getattribute__(observation, "ipv4_subnet"),
            object.__getattribute__(observation, "ipv4_gateway"),
            object.__getattribute__(observation, "ipv6_subnet"),
            object.__getattribute__(observation, "labels"),
            object.__getattribute__(observation, "attached_container_ids"),
            object.__getattribute__(observation, "inspection_sha256"),
        )
    except (NetworkConfigurationError, AttributeError):
        raise NetworkProtocolError("network inspection is invalid") from None
    if not checked.present:
        return checked
    if (checked.network_name != plan.network_name
            or checked.mode != NETWORK_MODE or checked.plugin != NETWORK_PLUGIN
            or checked.ipv4_subnet != plan.ipv4_subnet
            or checked.ipv4_gateway != plan.ipv4_gateway
            or checked.labels != plan.labels):
        raise NetworkCollisionError("network belongs to another closure")
    if expected_network_id is not None:
        expected_network_id = _exact_text(expected_network_id, "network identity", 63)
        if _NETWORK_ID.fullmatch(expected_network_id) is None:
            raise NetworkProtocolError("network identity is invalid")
        if checked.network_id != expected_network_id:
            raise NetworkCollisionError("network identity changed")
    return checked


class EgressState(str, Enum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"


@dataclass(frozen=True)
class EgressEvidence:
    attempt_id: str
    closure_sha256: str
    network_name: str
    egress_admission_sha256: str
    proxy_endpoint_sha256: str
    proxy_kind: str
    state: EgressState
    sequence: int
    prior_checkpoint_sha256: str
    checkpoint_sha256: str
    native_enforced: bool
    direct_ip_egress_denied: bool
    host_gateway_bypass_denied: bool
    proxy_attempt_authenticated: bool
    internal_alone_sufficient: bool
    authority_class: str = TEST_ONLY_AUTHORITY_CLASS

    def __post_init__(self) -> None:
        _exact_id(self.attempt_id, "attempt identity")
        _hex64(self.closure_sha256, "closure digest")
        if type(self.network_name) is not str or _NETWORK_ID.fullmatch(self.network_name) is None:
            raise NetworkConfigurationError("network name is invalid")
        _hex64(self.egress_admission_sha256, "egress admission digest")
        _hex64(self.proxy_endpoint_sha256, "proxy endpoint digest")
        if (type(self.proxy_kind) is not str or self.proxy_kind != PROXY_KIND
                or type(self.state) is not EgressState):
            raise NetworkConfigurationError("egress authority is invalid")
        if type(self.sequence) is not int or isinstance(self.sequence, bool) or self.sequence < 1:
            raise NetworkConfigurationError("egress sequence is invalid")
        _hex64(self.prior_checkpoint_sha256, "prior egress checkpoint")
        _hex64(self.checkpoint_sha256, "egress checkpoint")
        for label, value in (
            ("native egress enforcement", self.native_enforced),
            ("direct IP egress", self.direct_ip_egress_denied),
            ("host gateway bypass", self.host_gateway_bypass_denied),
            ("proxy attempt authentication", self.proxy_attempt_authenticated),
        ):
            _exact_bool(value, True, label)
        _exact_bool(self.internal_alone_sufficient, False, "internal isolation claim")
        if (type(self.authority_class) is not str
                or self.authority_class != TEST_ONLY_AUTHORITY_CLASS):
            raise NetworkConfigurationError("Python egress evidence claims authority")
        if self.checkpoint_sha256 != _json_digest(self.document):
            raise NetworkConfigurationError("egress checkpoint differs")

    @property
    def document(self) -> dict[str, object]:
        return {
            "attempt_id": self.attempt_id,
            "authority_class": self.authority_class,
            "closure_sha256": self.closure_sha256,
            "direct_ip_egress_denied": self.direct_ip_egress_denied,
            "egress_admission_sha256": self.egress_admission_sha256,
            "host_gateway_bypass_denied": self.host_gateway_bypass_denied,
            "internal_alone_sufficient": self.internal_alone_sufficient,
            "native_enforced": self.native_enforced,
            "network_name": self.network_name,
            "prior_checkpoint_sha256": self.prior_checkpoint_sha256,
            "proxy_attempt_authenticated": self.proxy_attempt_authenticated,
            "proxy_endpoint_sha256": self.proxy_endpoint_sha256,
            "proxy_kind": self.proxy_kind,
            "schema": SCHEMA + ".egress.TEST_ONLY",
            "sequence": self.sequence,
            "state": self.state.value,
        }


def TEST_ONLY_egress_evidence(
    closure: NetworkClosure, plan: NetworkPlan, state: EgressState,
    *, sequence: int, prior_checkpoint_sha256: str = "0" * 64,
) -> EgressEvidence:
    """Build inert structural evidence; it is deliberately non-authoritative."""
    closure = _closure(closure)
    plan = _plan(plan, closure)
    values = dict(
        attempt_id=closure.attempt_id, closure_sha256=closure.digest,
        network_name=plan.network_name,
        egress_admission_sha256=closure.egress_admission_sha256,
        proxy_endpoint_sha256=closure.proxy_endpoint_sha256,
        proxy_kind=PROXY_KIND, state=state, sequence=sequence,
        prior_checkpoint_sha256=prior_checkpoint_sha256,
        native_enforced=True, direct_ip_egress_denied=True,
        host_gateway_bypass_denied=True, proxy_attempt_authenticated=True,
        internal_alone_sufficient=False,
        authority_class=TEST_ONLY_AUTHORITY_CLASS,
    )
    draft = object.__new__(EgressEvidence)
    for name, value in values.items():
        object.__setattr__(draft, name, value)
    object.__setattr__(draft, "checkpoint_sha256", "0" * 64)
    return EgressEvidence(checkpoint_sha256=_json_digest(draft.document), **values)


def _egress(
    closure: NetworkClosure, plan: NetworkPlan, value: object,
    state: EgressState,
) -> EgressEvidence:
    if type(value) is not EgressEvidence:
        raise NetworkProtocolError("egress evidence type is invalid")
    try:
        checked = EgressEvidence(*(
            object.__getattribute__(value, name) for name in (
                "attempt_id", "closure_sha256", "network_name",
                "egress_admission_sha256", "proxy_endpoint_sha256",
                "proxy_kind", "state", "sequence", "prior_checkpoint_sha256",
                "checkpoint_sha256", "native_enforced",
                "direct_ip_egress_denied", "host_gateway_bypass_denied",
                "proxy_attempt_authenticated", "internal_alone_sufficient",
                "authority_class",
            )
        ))
    except (NetworkConfigurationError, AttributeError):
        raise NetworkProtocolError("egress evidence is invalid") from None
    if (checked.attempt_id != closure.attempt_id
            or checked.closure_sha256 != closure.digest
            or checked.network_name != plan.network_name
            or checked.egress_admission_sha256 != closure.egress_admission_sha256
            or checked.proxy_endpoint_sha256 != closure.proxy_endpoint_sha256
            or checked.state is not state):
        raise NetworkProtocolError("egress evidence differs")
    return checked


class Operation(str, Enum):
    CREATE = "CREATE"
    DELETE = "DELETE"


class RecordState(str, Enum):
    PREPARED = "PREPARED"
    CREATED = "CREATED"
    ABORTED = "ABORTED"
    DELETED = "DELETED"


class BrokerV2FrameType(IntEnum):
    """Apple-network lifecycle subset of the immutable broker-v2 ABI."""

    CLI_PREPARE = 0x0010
    CLI_COMMITTED = 0x0011
    REVOKE_PREPARE = 0x0040
    REVOKED = 0x0041


_VALID_JOURNAL_PREFIXES = frozenset({
    (),
    ((Operation.CREATE, RecordState.PREPARED),),
    ((Operation.CREATE, RecordState.PREPARED),
     (Operation.CREATE, RecordState.CREATED)),
    ((Operation.CREATE, RecordState.PREPARED),
     (Operation.CREATE, RecordState.ABORTED)),
    ((Operation.CREATE, RecordState.PREPARED),
     (Operation.CREATE, RecordState.CREATED),
     (Operation.DELETE, RecordState.PREPARED)),
    ((Operation.CREATE, RecordState.PREPARED),
     (Operation.CREATE, RecordState.CREATED),
     (Operation.DELETE, RecordState.PREPARED),
     (Operation.DELETE, RecordState.DELETED)),
})


@dataclass(frozen=True)
class TEST_ONLY_MutationClaim:
    operation: Operation
    attempt_id: str
    closure_sha256: str
    network_name: str
    plan_sha256: str
    operation_nonce: str
    sequence: int
    prior_checkpoint_sha256: str
    creator_pid: int
    creator_thread: int
    durable_pre_effect: bool
    authority_class: str = TEST_ONLY_AUTHORITY_CLASS

    def __post_init__(self) -> None:
        if type(self.operation) is not Operation:
            raise NetworkConfigurationError("mutation operation is invalid")
        _exact_id(self.attempt_id, "attempt identity")
        _hex64(self.closure_sha256, "closure digest")
        if type(self.network_name) is not str or _NETWORK_ID.fullmatch(self.network_name) is None:
            raise NetworkConfigurationError("network name is invalid")
        _hex64(self.plan_sha256, "plan digest")
        _hex32(self.operation_nonce, "operation nonce")
        if type(self.sequence) is not int or isinstance(self.sequence, bool) or self.sequence < 1:
            raise NetworkConfigurationError("mutation sequence is invalid")
        _hex64(self.prior_checkpoint_sha256, "prior journal checkpoint")
        if (type(self.creator_pid) is not int or self.creator_pid <= 0
                or type(self.creator_thread) is not int or self.creator_thread <= 0):
            raise NetworkConfigurationError("mutation owner is invalid")
        _exact_bool(self.durable_pre_effect, True, "pre-effect durability")
        if (type(self.authority_class) is not str
                or self.authority_class != TEST_ONLY_AUTHORITY_CLASS):
            raise NetworkConfigurationError("Python mutation claim claims authority")

    @property
    def digest(self) -> str:
        return _json_digest({
            "attempt_id": self.attempt_id, "authority_class": self.authority_class,
            "closure_sha256": self.closure_sha256,
            "creator_pid": self.creator_pid, "creator_thread": self.creator_thread,
            "durable_pre_effect": self.durable_pre_effect,
            "network_name": self.network_name, "operation": self.operation.value,
            "operation_nonce": self.operation_nonce,
            "plan_sha256": self.plan_sha256,
            "prior_checkpoint_sha256": self.prior_checkpoint_sha256,
            "sequence": self.sequence, "schema": SCHEMA + ".claim.TEST_ONLY",
        })


@dataclass(frozen=True)
class TEST_ONLY_JournalRecord:
    operation: Operation
    state: RecordState
    attempt_id: str
    closure_sha256: str
    network_name: str
    network_id: str | None
    plan_sha256: str
    claim_sha256: str
    operation_nonce: str
    observation_sha256: str | None
    egress_checkpoint_sha256: str
    egress_sequence: int
    sequence: int
    prior_checkpoint_sha256: str
    checkpoint_sha256: str
    durable: bool
    authority_class: str = TEST_ONLY_AUTHORITY_CLASS

    def __post_init__(self) -> None:
        if type(self.operation) is not Operation or type(self.state) is not RecordState:
            raise NetworkConfigurationError("test journal state is invalid")
        _exact_id(self.attempt_id, "attempt identity")
        _hex64(self.closure_sha256, "closure digest")
        if type(self.network_name) is not str or _NETWORK_ID.fullmatch(self.network_name) is None:
            raise NetworkConfigurationError("test journal network is invalid")
        if (self.network_id is not None and (
            type(self.network_id) is not str
            or _NETWORK_ID.fullmatch(self.network_id) is None
        )):
            raise NetworkConfigurationError("test journal network identity is invalid")
        _hex64(self.plan_sha256, "plan digest")
        _hex64(self.claim_sha256, "claim digest")
        _hex32(self.operation_nonce, "operation nonce")
        if self.observation_sha256 is not None:
            _hex64(self.observation_sha256, "observation digest")
        _hex64(self.egress_checkpoint_sha256, "egress checkpoint")
        if (type(self.egress_sequence) is not int
                or isinstance(self.egress_sequence, bool)
                or self.egress_sequence < 1):
            raise NetworkConfigurationError("test journal egress sequence is invalid")
        if type(self.sequence) is not int or isinstance(self.sequence, bool) or self.sequence < 1:
            raise NetworkConfigurationError("test journal sequence is invalid")
        _hex64(self.prior_checkpoint_sha256, "prior journal checkpoint")
        _hex64(self.checkpoint_sha256, "journal checkpoint")
        _exact_bool(self.durable, True, "journal durability")
        if (type(self.authority_class) is not str
                or self.authority_class != TEST_ONLY_AUTHORITY_CLASS):
            raise NetworkConfigurationError("test journal claims authority")
        valid_shape = (
            (self.operation is Operation.CREATE
             and self.state is RecordState.PREPARED
             and self.network_id is None and self.observation_sha256 is not None),
            (self.operation is Operation.CREATE
             and self.state is RecordState.CREATED
             and self.network_id is not None and self.observation_sha256 is not None),
            (self.operation is Operation.CREATE
             and self.state is RecordState.ABORTED
             and self.network_id is None and self.observation_sha256 is not None),
            (self.operation is Operation.DELETE
             and self.state is RecordState.PREPARED
             and self.network_id is not None and self.observation_sha256 is not None),
            (self.operation is Operation.DELETE
             and self.state is RecordState.DELETED
             and self.network_id is not None and self.observation_sha256 is not None),
        )
        if not any(valid_shape):
            raise NetworkConfigurationError("test journal record shape is invalid")

    @property
    def document(self) -> dict[str, object]:
        return {
            "attempt_id": self.attempt_id, "authority_class": self.authority_class,
            "claim_sha256": self.claim_sha256,
            "closure_sha256": self.closure_sha256,
            "durable": self.durable,
            "egress_checkpoint_sha256": self.egress_checkpoint_sha256,
            "egress_sequence": self.egress_sequence,
            "network_id": self.network_id, "network_name": self.network_name,
            "observation_sha256": self.observation_sha256,
            "operation": self.operation.value, "plan_sha256": self.plan_sha256,
            "operation_nonce": self.operation_nonce,
            "prior_checkpoint_sha256": self.prior_checkpoint_sha256,
            "schema": SCHEMA + ".journal-record.TEST_ONLY",
            "sequence": self.sequence, "state": self.state.value,
        }


@dataclass(frozen=True)
class TEST_ONLY_Journal:
    attempt_id: str
    closure_sha256: str
    records: tuple[TEST_ONLY_JournalRecord, ...] = ()
    authority_class: str = TEST_ONLY_AUTHORITY_CLASS

    def __post_init__(self) -> None:
        _exact_id(self.attempt_id, "attempt identity")
        _hex64(self.closure_sha256, "closure digest")
        if (type(self.records) is not tuple
                or type(self.authority_class) is not str
                or self.authority_class != TEST_ONLY_AUTHORITY_CLASS):
            raise NetworkConfigurationError("test journal is invalid")
        previous = "0" * 64
        checked_records: list[TEST_ONLY_JournalRecord] = []
        for index, record in enumerate(self.records, 1):
            if type(record) is not TEST_ONLY_JournalRecord:
                raise NetworkConfigurationError("test journal record is invalid")
            try:
                checked = TEST_ONLY_JournalRecord(*(
                    object.__getattribute__(record, name) for name in (
                        "operation", "state", "attempt_id", "closure_sha256",
                        "network_name", "network_id", "plan_sha256",
                        "claim_sha256", "operation_nonce", "observation_sha256",
                        "egress_checkpoint_sha256", "egress_sequence", "sequence",
                        "prior_checkpoint_sha256", "checkpoint_sha256",
                        "durable", "authority_class",
                    )
                ))
            except (NetworkConfigurationError, AttributeError):
                raise NetworkConfigurationError("test journal record is invalid") from None
            if (checked.attempt_id != self.attempt_id
                    or checked.closure_sha256 != self.closure_sha256
                    or checked.sequence != index
                    or checked.prior_checkpoint_sha256 != previous
                    or checked.checkpoint_sha256 != _json_digest(checked.document)):
                raise NetworkConfigurationError("test journal chain is invalid")
            previous = checked.checkpoint_sha256
            checked_records.append(checked)
        history = tuple((item.operation, item.state) for item in checked_records)
        if history not in _VALID_JOURNAL_PREFIXES:
            raise NetworkConfigurationError("test journal lifecycle is invalid")
        for prepared, terminal in zip(checked_records[::2], checked_records[1::2]):
            if (terminal.claim_sha256 != prepared.claim_sha256
                    or terminal.operation_nonce != prepared.operation_nonce
                    or terminal.operation is not prepared.operation
                    or terminal.egress_checkpoint_sha256
                       != prepared.egress_checkpoint_sha256
                    or terminal.egress_sequence != prepared.egress_sequence):
                raise NetworkConfigurationError("test journal operation binding is invalid")
        if len(checked_records) >= 3:
            created, delete_prepared = checked_records[1:3]
            if (created.state is not RecordState.CREATED
                    or created.network_id != delete_prepared.network_id
                    or delete_prepared.egress_sequence <= created.egress_sequence):
                raise NetworkConfigurationError("test journal deletion binding is invalid")

    @property
    def checkpoint(self) -> str:
        return self.records[-1].checkpoint_sha256 if self.records else "0" * 64


@dataclass(frozen=True)
class TEST_ONLY_ExtinctionEvidence:
    attempt_id: str
    closure_sha256: str
    network_name: str
    network_id: str
    absence_inspection_sha256: str
    egress_revocation_checkpoint_sha256: str
    attachments_absent: bool
    network_object_absent: bool
    plugin_process_extinct: bool
    native_cleanup_complete: bool
    sequence: int
    prior_checkpoint_sha256: str
    checkpoint_sha256: str
    authority_class: str = TEST_ONLY_AUTHORITY_CLASS

    def __post_init__(self) -> None:
        _exact_id(self.attempt_id, "attempt identity")
        _hex64(self.closure_sha256, "closure digest")
        if (type(self.network_name) is not str
                or _NETWORK_ID.fullmatch(self.network_name) is None
                or type(self.network_id) is not str
                or _NETWORK_ID.fullmatch(self.network_id) is None):
            raise NetworkConfigurationError("network extinction identity is invalid")
        _hex64(self.absence_inspection_sha256, "absence inspection digest")
        _hex64(self.egress_revocation_checkpoint_sha256, "egress revocation checkpoint")
        for label, value in (
            ("attachment extinction", self.attachments_absent),
            ("network extinction", self.network_object_absent),
            ("plugin extinction", self.plugin_process_extinct),
            ("native cleanup", self.native_cleanup_complete),
        ):
            _exact_bool(value, True, label)
        if type(self.sequence) is not int or isinstance(self.sequence, bool) or self.sequence < 1:
            raise NetworkConfigurationError("extinction sequence is invalid")
        _hex64(self.prior_checkpoint_sha256, "prior extinction checkpoint")
        _hex64(self.checkpoint_sha256, "extinction checkpoint")
        if (type(self.authority_class) is not str
                or self.authority_class != TEST_ONLY_AUTHORITY_CLASS):
            raise NetworkConfigurationError("Python extinction evidence claims authority")
        if self.checkpoint_sha256 != _json_digest(self.document):
            raise NetworkConfigurationError("extinction checkpoint differs")

    @property
    def document(self) -> dict[str, object]:
        return {
            "absence_inspection_sha256": self.absence_inspection_sha256,
            "attachments_absent": self.attachments_absent,
            "attempt_id": self.attempt_id,
            "authority_class": self.authority_class,
            "closure_sha256": self.closure_sha256,
            "egress_revocation_checkpoint_sha256": self.egress_revocation_checkpoint_sha256,
            "native_cleanup_complete": self.native_cleanup_complete,
            "network_id": self.network_id,
            "network_name": self.network_name,
            "network_object_absent": self.network_object_absent,
            "plugin_process_extinct": self.plugin_process_extinct,
            "prior_checkpoint_sha256": self.prior_checkpoint_sha256,
            "schema": SCHEMA + ".extinction.TEST_ONLY",
            "sequence": self.sequence,
        }


def TEST_ONLY_extinction_evidence(
    closure: NetworkClosure, plan: NetworkPlan, network_id: str,
    absence: NetworkObservation, revoked_egress: EgressEvidence,
    *, sequence: int, prior_checkpoint_sha256: str,
) -> TEST_ONLY_ExtinctionEvidence:
    closure = _closure(closure)
    plan = _plan(plan, closure)
    absence = validate_inspection(closure, plan, absence, expected_network_id=None)
    if absence.present:
        raise NetworkConfigurationError("network extinction requires absence")
    revoked = _egress(closure, plan, revoked_egress, EgressState.REVOKED)
    values = dict(
        attempt_id=closure.attempt_id, closure_sha256=closure.digest,
        network_name=plan.network_name, network_id=network_id,
        absence_inspection_sha256=absence.inspection_sha256,
        egress_revocation_checkpoint_sha256=revoked.checkpoint_sha256,
        attachments_absent=True, network_object_absent=True,
        plugin_process_extinct=True, native_cleanup_complete=True,
        sequence=sequence, prior_checkpoint_sha256=prior_checkpoint_sha256,
        authority_class=TEST_ONLY_AUTHORITY_CLASS,
    )
    draft = object.__new__(TEST_ONLY_ExtinctionEvidence)
    for name, value in values.items():
        object.__setattr__(draft, name, value)
    object.__setattr__(draft, "checkpoint_sha256", "0" * 64)
    return TEST_ONLY_ExtinctionEvidence(
        checkpoint_sha256=_json_digest(draft.document), **values
    )


def TEST_ONLY_new_journal(closure: NetworkClosure) -> TEST_ONLY_Journal:
    closure = _closure(closure)
    return TEST_ONLY_Journal(closure.attempt_id, closure.digest)


def TEST_ONLY_claim(
    journal: TEST_ONLY_Journal, closure: NetworkClosure, plan: NetworkPlan,
    operation: Operation, nonce: str,
) -> TEST_ONLY_MutationClaim:
    closure = _closure(closure)
    plan = _plan(plan, closure)
    _journal(journal, closure, plan)
    return TEST_ONLY_MutationClaim(
        operation, closure.attempt_id, closure.digest, plan.network_name,
        plan.fingerprint_sha256, _hex32(nonce, "operation nonce"),
        len(journal.records) + 1, journal.checkpoint, os.getpid(),
        threading.get_ident(), True,
    )


def _journal(
    value: object, closure: NetworkClosure, plan: NetworkPlan | None = None,
) -> TEST_ONLY_Journal:
    if type(value) is not TEST_ONLY_Journal:
        raise NetworkProtocolError("test journal type is invalid")
    try:
        checked = TEST_ONLY_Journal(
            object.__getattribute__(value, "attempt_id"),
            object.__getattribute__(value, "closure_sha256"),
            object.__getattribute__(value, "records"),
            object.__getattribute__(value, "authority_class"),
        )
    except (NetworkConfigurationError, AttributeError):
        raise NetworkProtocolError("test journal is invalid") from None
    if checked.attempt_id != closure.attempt_id or checked.closure_sha256 != closure.digest:
        raise NetworkProtocolError("test journal belongs to another attempt")
    if plan is not None and any(
        record.network_name != plan.network_name
        or record.plan_sha256 != plan.fingerprint_sha256
        for record in checked.records
    ):
        raise NetworkProtocolError("test journal belongs to another network plan")
    return checked


def _claim(
    value: object, journal: TEST_ONLY_Journal, closure: NetworkClosure,
    plan: NetworkPlan, operation: Operation,
) -> TEST_ONLY_MutationClaim:
    if type(value) is not TEST_ONLY_MutationClaim:
        raise NetworkProtocolError("mutation claim type is invalid")
    try:
        checked = TEST_ONLY_MutationClaim(*(
            object.__getattribute__(value, name) for name in (
                "operation", "attempt_id", "closure_sha256", "network_name",
                "plan_sha256", "operation_nonce", "sequence",
                "prior_checkpoint_sha256", "creator_pid", "creator_thread",
                "durable_pre_effect", "authority_class",
            )
        ))
    except (NetworkConfigurationError, AttributeError):
        raise NetworkProtocolError("mutation claim is invalid") from None
    if (checked.operation is not operation
            or checked.attempt_id != closure.attempt_id
            or checked.closure_sha256 != closure.digest
            or checked.network_name != plan.network_name
            or checked.plan_sha256 != plan.fingerprint_sha256
            or checked.sequence != len(journal.records) + 1
            or checked.prior_checkpoint_sha256 != journal.checkpoint
            or checked.creator_pid != os.getpid()
            or checked.creator_thread != threading.get_ident()):
        raise NetworkProtocolError("mutation claim differs or was replayed")
    return checked


def _append(
    journal: TEST_ONLY_Journal, operation: Operation, state: RecordState,
    closure: NetworkClosure, plan: NetworkPlan, claim_sha256: str,
    operation_nonce: str, egress_checkpoint: str, egress_sequence: int,
    network_id: str | None, observation_sha256: str | None,
) -> TEST_ONLY_Journal:
    values = dict(
        operation=operation, state=state, attempt_id=closure.attempt_id,
        closure_sha256=closure.digest, network_name=plan.network_name,
        network_id=network_id, plan_sha256=plan.fingerprint_sha256,
        claim_sha256=claim_sha256, operation_nonce=operation_nonce,
        observation_sha256=observation_sha256,
        egress_checkpoint_sha256=egress_checkpoint,
        egress_sequence=egress_sequence,
        sequence=len(journal.records) + 1,
        prior_checkpoint_sha256=journal.checkpoint,
        durable=True, authority_class=TEST_ONLY_AUTHORITY_CLASS,
    )
    draft = TEST_ONLY_JournalRecord(checkpoint_sha256="0" * 64, **values)
    record = TEST_ONLY_JournalRecord(
        checkpoint_sha256=_json_digest(draft.document), **values
    )
    return TEST_ONLY_Journal(
        closure.attempt_id, closure.digest, journal.records + (record,)
    )


def TEST_ONLY_prepare_create(
    journal: TEST_ONLY_Journal, closure: NetworkClosure, plan: NetworkPlan,
    claim: TEST_ONLY_MutationClaim, active_egress: EgressEvidence,
    initial_observation: NetworkObservation,
) -> TEST_ONLY_Journal:
    closure = _closure(closure)
    plan = _plan(plan, closure)
    journal = _journal(journal, closure, plan)
    checked_claim = _claim(claim, journal, closure, plan, Operation.CREATE)
    egress = _egress(closure, plan, active_egress, EgressState.ACTIVE)
    initial = validate_inspection(
        closure, plan, initial_observation, expected_network_id=None
    )
    if initial.present:
        raise NetworkCollisionError("network name or subnet is already allocated")
    if journal.records:
        raise NetworkAmbiguousError("network create already has durable history")
    return _append(
        journal, Operation.CREATE, RecordState.PREPARED, closure, plan,
        checked_claim.digest, checked_claim.operation_nonce,
        egress.checkpoint_sha256, egress.sequence, None, initial.inspection_sha256,
    )


def TEST_ONLY_commit_create(
    journal: TEST_ONLY_Journal, closure: NetworkClosure, plan: NetworkPlan,
    observation: NetworkObservation, active_egress: EgressEvidence,
) -> TEST_ONLY_Journal:
    closure = _closure(closure)
    plan = _plan(plan, closure)
    journal = _journal(journal, closure, plan)
    egress = _egress(closure, plan, active_egress, EgressState.ACTIVE)
    if not journal.records:
        raise NetworkAmbiguousError("network create lacks durable preparation")
    prior = journal.records[-1]
    if prior.operation is not Operation.CREATE or prior.state is not RecordState.PREPARED:
        raise NetworkAmbiguousError("network create state is not reconcilable")
    if egress.checkpoint_sha256 != prior.egress_checkpoint_sha256:
        raise NetworkProtocolError("active egress authority changed during create")
    observation = validate_inspection(
        closure, plan, observation, expected_network_id=None
    )
    if not observation.present or observation.attached_container_ids:
        raise NetworkProtocolError("created network inspection differs")
    return _append(
        journal, Operation.CREATE, RecordState.CREATED, closure, plan,
        prior.claim_sha256, prior.operation_nonce, egress.checkpoint_sha256,
        egress.sequence, observation.network_id,
        observation.inspection_sha256,
    )


def TEST_ONLY_prepare_delete(
    journal: TEST_ONLY_Journal, closure: NetworkClosure, plan: NetworkPlan,
    claim: TEST_ONLY_MutationClaim, revoked_egress: EgressEvidence,
    observation: NetworkObservation,
) -> TEST_ONLY_Journal:
    closure = _closure(closure)
    plan = _plan(plan, closure)
    journal = _journal(journal, closure, plan)
    checked_claim = _claim(claim, journal, closure, plan, Operation.DELETE)
    egress = _egress(closure, plan, revoked_egress, EgressState.REVOKED)
    if not journal.records or journal.records[-1].state is not RecordState.CREATED:
        raise NetworkAmbiguousError("network deletion lacks created state")
    created = journal.records[-1]
    observation = validate_inspection(
        closure, plan, observation, expected_network_id=created.network_id
    )
    if not observation.present or observation.attached_container_ids:
        raise NetworkProtocolError("network is not ready for deletion")
    if egress.sequence <= len(journal.records):
        raise NetworkProtocolError("egress revocation is stale")
    if egress.prior_checkpoint_sha256 != created.egress_checkpoint_sha256:
        raise NetworkProtocolError("egress revocation does not follow admission")
    return _append(
        journal, Operation.DELETE, RecordState.PREPARED, closure, plan,
        checked_claim.digest, checked_claim.operation_nonce,
        egress.checkpoint_sha256, egress.sequence, created.network_id,
        observation.inspection_sha256,
    )


def TEST_ONLY_commit_delete(
    journal: TEST_ONLY_Journal, closure: NetworkClosure, plan: NetworkPlan,
    absent_observation: NetworkObservation, revoked_egress: EgressEvidence,
    extinction: TEST_ONLY_ExtinctionEvidence,
) -> TEST_ONLY_Journal:
    closure = _closure(closure)
    plan = _plan(plan, closure)
    journal = _journal(journal, closure, plan)
    egress = _egress(closure, plan, revoked_egress, EgressState.REVOKED)
    if not journal.records:
        raise NetworkAmbiguousError("network deletion lacks durable preparation")
    prior = journal.records[-1]
    if prior.operation is not Operation.DELETE or prior.state is not RecordState.PREPARED:
        raise NetworkAmbiguousError("network deletion state is not reconcilable")
    if egress.checkpoint_sha256 != prior.egress_checkpoint_sha256:
        raise NetworkProtocolError("egress revocation changed during deletion")
    absent = validate_inspection(
        closure, plan, absent_observation, expected_network_id=None
    )
    if absent.present:
        raise NetworkAmbiguousError("network deletion is not extinct")
    if type(extinction) is not TEST_ONLY_ExtinctionEvidence:
        raise NetworkProtocolError("network extinction type is invalid")
    try:
        extinction = TEST_ONLY_ExtinctionEvidence(*(
            object.__getattribute__(extinction, name) for name in (
                "attempt_id", "closure_sha256", "network_name", "network_id",
                "absence_inspection_sha256", "egress_revocation_checkpoint_sha256",
                "attachments_absent", "network_object_absent",
                "plugin_process_extinct", "native_cleanup_complete", "sequence",
                "prior_checkpoint_sha256", "checkpoint_sha256", "authority_class",
            )
        ))
    except (NetworkConfigurationError, AttributeError):
        raise NetworkProtocolError("network extinction evidence is invalid") from None
    if (extinction.attempt_id != closure.attempt_id
            or extinction.closure_sha256 != closure.digest
            or extinction.network_name != plan.network_name
            or extinction.network_id != prior.network_id
            or extinction.absence_inspection_sha256 != absent.inspection_sha256
            or extinction.egress_revocation_checkpoint_sha256 != egress.checkpoint_sha256
            or extinction.prior_checkpoint_sha256 != prior.checkpoint_sha256
            or extinction.sequence <= prior.sequence):
        raise NetworkProtocolError("network extinction evidence differs")
    return _append(
        journal, Operation.DELETE, RecordState.DELETED, closure, plan,
        prior.claim_sha256, prior.operation_nonce, egress.checkpoint_sha256,
        egress.sequence, prior.network_id,
        extinction.checkpoint_sha256,
    )


def TEST_ONLY_recover(
    journal: TEST_ONLY_Journal, closure: NetworkClosure, plan: NetworkPlan,
    observation: NetworkObservation, egress: EgressEvidence,
    *, extinction: TEST_ONLY_ExtinctionEvidence | None = None,
) -> TEST_ONLY_Journal:
    """Reconcile a durable prefix without ever repeating an effect."""
    closure = _closure(closure)
    plan = _plan(plan, closure)
    journal = _journal(journal, closure, plan)
    if not journal.records:
        checked = validate_inspection(
            closure, plan, observation, expected_network_id=None
        )
        if checked.present:
            raise NetworkCollisionError("unowned network exists without journal authority")
        return journal
    prior = journal.records[-1]
    if prior.state is RecordState.CREATED:
        checked = validate_inspection(
            closure, plan, observation,
            expected_network_id=prior.network_id,
        )
        if not checked.present:
            raise NetworkAmbiguousError("committed network state differs")
        if checked.inspection_sha256 != prior.observation_sha256:
            raise NetworkAmbiguousError("committed network inspection changed")
        fresh = _egress(closure, plan, egress, EgressState.ACTIVE)
        if (fresh.prior_checkpoint_sha256 != prior.egress_checkpoint_sha256
                or fresh.sequence <= prior.egress_sequence):
            raise NetworkProtocolError("active egress recovery evidence is stale")
        return journal
    if prior.state is RecordState.DELETED:
        checked = validate_inspection(
            closure, plan, observation, expected_network_id=None
        )
        if checked.present:
            raise NetworkAmbiguousError("deleted network has reappeared")
        fresh = _egress(closure, plan, egress, EgressState.REVOKED)
        if (fresh.prior_checkpoint_sha256 != prior.egress_checkpoint_sha256
                or fresh.sequence <= prior.egress_sequence):
            raise NetworkProtocolError("egress revocation recovery evidence is stale")
        if type(extinction) is not TEST_ONLY_ExtinctionEvidence:
            raise NetworkProtocolError("stored extinction evidence is unavailable")
        try:
            stored_extinction = TEST_ONLY_ExtinctionEvidence(*(
                object.__getattribute__(extinction, name) for name in (
                    "attempt_id", "closure_sha256", "network_name", "network_id",
                    "absence_inspection_sha256",
                    "egress_revocation_checkpoint_sha256", "attachments_absent",
                    "network_object_absent", "plugin_process_extinct",
                    "native_cleanup_complete", "sequence",
                    "prior_checkpoint_sha256", "checkpoint_sha256",
                    "authority_class",
                )
            ))
        except (NetworkConfigurationError, AttributeError):
            raise NetworkProtocolError("stored extinction evidence is invalid") from None
        if (stored_extinction.attempt_id != closure.attempt_id
                or stored_extinction.closure_sha256 != closure.digest
                or stored_extinction.network_name != plan.network_name
                or stored_extinction.network_id != prior.network_id
                or stored_extinction.absence_inspection_sha256
                   != checked.inspection_sha256
                or stored_extinction.egress_revocation_checkpoint_sha256
                   != prior.egress_checkpoint_sha256
                or stored_extinction.prior_checkpoint_sha256
                   != prior.prior_checkpoint_sha256
                or stored_extinction.checkpoint_sha256
                   != prior.observation_sha256):
            raise NetworkProtocolError("stored extinction evidence differs")
        return journal
    if prior.state is RecordState.ABORTED:
        checked = validate_inspection(
            closure, plan, observation, expected_network_id=None
        )
        if (checked.present or prior.operation is not Operation.CREATE
                or prior.network_id is not None
                or checked.inspection_sha256 != prior.observation_sha256):
            raise NetworkAmbiguousError("aborted network state differs")
        fresh = _egress(closure, plan, egress, EgressState.ACTIVE)
        if (fresh.prior_checkpoint_sha256 != prior.egress_checkpoint_sha256
                or fresh.sequence <= prior.egress_sequence):
            raise NetworkProtocolError("aborted recovery evidence is stale")
        return journal
    if prior.operation is Operation.CREATE:
        active = _egress(closure, plan, egress, EgressState.ACTIVE)
        checked = validate_inspection(
            closure, plan, observation, expected_network_id=None
        )
        if checked.present:
            return TEST_ONLY_commit_create(journal, closure, plan, checked, active)
        return _append(
            journal, Operation.CREATE, RecordState.ABORTED, closure, plan,
            prior.claim_sha256, prior.operation_nonce,
            active.checkpoint_sha256, active.sequence, None, checked.inspection_sha256,
        )
    revoked = _egress(closure, plan, egress, EgressState.REVOKED)
    checked = validate_inspection(
        closure, plan, observation, expected_network_id=prior.network_id
        if observation.present else None,
    )
    if checked.present:
        raise NetworkAmbiguousError("prepared deletion still has a live network")
    if extinction is None:
        raise NetworkAmbiguousError("network extinction evidence is unavailable")
    return TEST_ONLY_commit_delete(
        journal, closure, plan, checked, revoked, extinction
    )


_NATIVE_FRAME_BY_RECORD = {
    (Operation.CREATE, RecordState.PREPARED): BrokerV2FrameType.CLI_PREPARE,
    (Operation.CREATE, RecordState.CREATED): BrokerV2FrameType.CLI_COMMITTED,
    (Operation.CREATE, RecordState.ABORTED): BrokerV2FrameType.CLI_COMMITTED,
    (Operation.DELETE, RecordState.PREPARED): BrokerV2FrameType.REVOKE_PREPARE,
    (Operation.DELETE, RecordState.DELETED): BrokerV2FrameType.REVOKED,
}
_NATIVE_REQUEST_FRAMES = frozenset({
    BrokerV2FrameType.CLI_PREPARE,
    BrokerV2FrameType.REVOKE_PREPARE,
})


@dataclass(frozen=True)
class TEST_ONLY_NativeLifecycleProjection:
    """Inert semantic projection of one journal record onto broker-v2.

    This type deliberately records the two commitments missing from the current
    Apple closure.  It can therefore test lifecycle alignment without being
    mistaken for an encodable native request or an authenticated receipt.
    """

    abi_schema: str
    protocol_version: int
    frame_type: BrokerV2FrameType
    frame_name: str
    direction: str
    operation: Operation
    state: RecordState
    attempt_id: str
    closure_sha256: str
    network_name: str
    network_id: str | None
    plan_sha256: str
    claim_sha256: str
    operation_nonce: str
    observation_sha256: str
    egress_checkpoint_sha256: str
    egress_sequence: int
    journal_sequence: int
    prior_journal_checkpoint_sha256: str
    journal_checkpoint_sha256: str
    fd_purposes: tuple[int, ...]
    missing_commitments: tuple[str, ...]
    native_dispatch_supported: bool
    projection_sha256: str
    authority_class: str = TEST_ONLY_AUTHORITY_CLASS

    def __post_init__(self) -> None:
        if type(self.abi_schema) is not str or self.abi_schema != NATIVE_ABI_SCHEMA:
            raise NetworkConfigurationError("native lifecycle ABI is invalid")
        if (type(self.protocol_version) is not int
                or isinstance(self.protocol_version, bool)
                or self.protocol_version != BROKER_V2_PROTOCOL_VERSION
                or type(self.frame_type) is not BrokerV2FrameType
                or type(self.frame_name) is not str
                or self.frame_name != self.frame_type.name
                or type(self.operation) is not Operation
                or type(self.state) is not RecordState):
            raise NetworkConfigurationError("native lifecycle frame is invalid")
        expected_frame = _NATIVE_FRAME_BY_RECORD.get((self.operation, self.state))
        if self.frame_type is not expected_frame:
            raise NetworkConfigurationError("native lifecycle transition is invalid")
        request = self.frame_type in _NATIVE_REQUEST_FRAMES
        expected_direction = "EXTENSION_TO_BROKER" if request else "BROKER_TO_EXTENSION"
        expected_fds = (
            BROKER_V2_FD_APPLE_CLI_EXECUTABLE,
            BROKER_V2_FD_JOURNAL_DIRECTORY,
        ) if request else ()
        if (type(self.direction) is not str
                or type(self.fd_purposes) is not tuple
                or any(type(item) is not int or isinstance(item, bool)
                       for item in self.fd_purposes)
                or self.direction != expected_direction
                or self.fd_purposes != expected_fds):
            raise NetworkConfigurationError("native lifecycle direction is invalid")
        _exact_id(self.attempt_id, "attempt identity")
        _hex64(self.closure_sha256, "closure digest")
        if (type(self.network_name) is not str
                or _NETWORK_ID.fullmatch(self.network_name) is None):
            raise NetworkConfigurationError("native lifecycle network is invalid")
        if (self.network_id is not None and (
            type(self.network_id) is not str
            or _NETWORK_ID.fullmatch(self.network_id) is None
        )):
            raise NetworkConfigurationError("native lifecycle network identity is invalid")
        _hex64(self.plan_sha256, "plan digest")
        _hex64(self.claim_sha256, "claim digest")
        _hex32(self.operation_nonce, "operation nonce")
        _hex64(self.observation_sha256, "observation digest")
        _hex64(self.egress_checkpoint_sha256, "egress checkpoint")
        for label, value in (
            ("egress sequence", self.egress_sequence),
            ("journal sequence", self.journal_sequence),
        ):
            if type(value) is not int or isinstance(value, bool) or value < 1:
                raise NetworkConfigurationError(f"native lifecycle {label} is invalid")
        _hex64(self.prior_journal_checkpoint_sha256, "prior journal checkpoint")
        _hex64(self.journal_checkpoint_sha256, "journal checkpoint")
        if (type(self.missing_commitments) is not tuple
                or any(type(item) is not str for item in self.missing_commitments)
                or self.missing_commitments != NATIVE_PROJECTION_MISSING_COMMITMENTS
                or self.native_dispatch_supported is not False
                or type(self.authority_class) is not str
                or self.authority_class != TEST_ONLY_AUTHORITY_CLASS):
            raise NetworkConfigurationError("native lifecycle projection claims authority")
        _hex64(self.projection_sha256, "native lifecycle projection digest")
        if self.projection_sha256 != _json_digest(self.document):
            raise NetworkConfigurationError("native lifecycle projection digest differs")

    @property
    def document(self) -> dict[str, object]:
        return {
            "abi_schema": self.abi_schema,
            "attempt_id": self.attempt_id,
            "authority_class": self.authority_class,
            "claim_sha256": self.claim_sha256,
            "closure_sha256": self.closure_sha256,
            "direction": self.direction,
            "egress_checkpoint_sha256": self.egress_checkpoint_sha256,
            "egress_sequence": self.egress_sequence,
            "fd_purposes": list(self.fd_purposes),
            "frame_name": self.frame_name,
            "frame_type": int(self.frame_type),
            "journal_checkpoint_sha256": self.journal_checkpoint_sha256,
            "journal_sequence": self.journal_sequence,
            "missing_commitments": list(self.missing_commitments),
            "native_dispatch_supported": self.native_dispatch_supported,
            "network_id": self.network_id,
            "network_name": self.network_name,
            "observation_sha256": self.observation_sha256,
            "operation": self.operation.value,
            "operation_nonce": self.operation_nonce,
            "plan_sha256": self.plan_sha256,
            "prior_journal_checkpoint_sha256": self.prior_journal_checkpoint_sha256,
            "protocol_version": self.protocol_version,
            "schema": SCHEMA + ".native-lifecycle-projection.TEST_ONLY",
            "state": self.state.value,
        }


def _native_lifecycle_projection(
    value: object,
) -> TEST_ONLY_NativeLifecycleProjection:
    if type(value) is not TEST_ONLY_NativeLifecycleProjection:
        raise NetworkProtocolError("native lifecycle projection type is invalid")
    try:
        return TEST_ONLY_NativeLifecycleProjection(**{
            item.name: object.__getattribute__(value, item.name)
            for item in fields(TEST_ONLY_NativeLifecycleProjection)
        })
    except (AttributeError, TypeError, NetworkConfigurationError):
        raise NetworkProtocolError("native lifecycle projection is invalid") from None


def TEST_ONLY_native_lifecycle_projections(
    journal: TEST_ONLY_Journal, closure: NetworkClosure, plan: NetworkPlan,
) -> tuple[TEST_ONLY_NativeLifecycleProjection, ...]:
    """Project a validated inert journal; never encode or send a native frame."""
    closure = _closure(closure)
    plan = _plan(plan, closure)
    journal = _journal(journal, closure, plan)
    result: list[TEST_ONLY_NativeLifecycleProjection] = []
    for record in journal.records:
        frame = _NATIVE_FRAME_BY_RECORD[(record.operation, record.state)]
        request = frame in _NATIVE_REQUEST_FRAMES
        values = dict(
            abi_schema=NATIVE_ABI_SCHEMA,
            protocol_version=BROKER_V2_PROTOCOL_VERSION,
            frame_type=frame,
            frame_name=frame.name,
            direction="EXTENSION_TO_BROKER" if request else "BROKER_TO_EXTENSION",
            operation=record.operation,
            state=record.state,
            attempt_id=record.attempt_id,
            closure_sha256=record.closure_sha256,
            network_name=record.network_name,
            network_id=record.network_id,
            plan_sha256=record.plan_sha256,
            claim_sha256=record.claim_sha256,
            operation_nonce=record.operation_nonce,
            observation_sha256=record.observation_sha256,
            egress_checkpoint_sha256=record.egress_checkpoint_sha256,
            egress_sequence=record.egress_sequence,
            journal_sequence=record.sequence,
            prior_journal_checkpoint_sha256=record.prior_checkpoint_sha256,
            journal_checkpoint_sha256=record.checkpoint_sha256,
            fd_purposes=(
                BROKER_V2_FD_APPLE_CLI_EXECUTABLE,
                BROKER_V2_FD_JOURNAL_DIRECTORY,
            ) if request else (),
            missing_commitments=NATIVE_PROJECTION_MISSING_COMMITMENTS,
            native_dispatch_supported=False,
            authority_class=TEST_ONLY_AUTHORITY_CLASS,
        )
        draft = object.__new__(TEST_ONLY_NativeLifecycleProjection)
        for name, item in values.items():
            object.__setattr__(draft, name, item)
        object.__setattr__(draft, "projection_sha256", "0" * 64)
        result.append(TEST_ONLY_NativeLifecycleProjection(
            projection_sha256=_json_digest(draft.document), **values
        ))
    return tuple(result)


def TEST_ONLY_validate_native_lifecycle_projections(
    journal: TEST_ONLY_Journal, closure: NetworkClosure, plan: NetworkPlan,
    projections: object,
) -> tuple[TEST_ONLY_NativeLifecycleProjection, ...]:
    closure = _closure(closure)
    plan = _plan(plan, closure)
    expected = TEST_ONLY_native_lifecycle_projections(journal, closure, plan)
    if type(projections) is not tuple:
        raise NetworkProtocolError("native lifecycle projection set is invalid")
    checked = tuple(_native_lifecycle_projection(item) for item in projections)
    if checked != expected:
        raise NetworkProtocolError("native lifecycle projection set differs")
    return checked


class AppleEgressNetwork:
    """Thin projection wrapper; the native capability owns every effect."""

    __slots__ = ("_closure", "_capability")

    def __new__(cls, *_args: object, **_kwargs: object) -> "AppleEgressNetwork":
        raise NativeBrokerUnavailable("native Apple egress broker is unavailable")

    def create(self, plan: NetworkPlan) -> object:
        return _production_call(self, "create", plan)

    def inspect(self, plan: NetworkPlan) -> object:
        return _production_call(self, "inspect", plan)

    def delete(self, plan: NetworkPlan) -> object:
        return _production_call(self, "delete", plan)

    def recover(self, plan: NetworkPlan) -> object:
        return _production_call(self, "recover", plan)


_NATIVE_TYPE_NAMES = (
    "BrokerV2AuthorityConsumer",
    "SupervisorAuthorities",
    "ProviderAuthority",
    "NetworkReceiptProjection",
)


def _native_types() -> tuple[type[Any], type[Any], type[Any], type[Any]]:
    # Already-loaded only: importing by name could execute attacker Python.
    system_namespace = types.ModuleType.__getattribute__(sys, "__dict__")
    module_table = system_namespace.get("modules")
    if type(module_table) is not dict:
        raise NativeBrokerUnavailable("native Apple egress broker is unavailable")
    module = module_table.get(NATIVE_MODULE_NAME)
    if type(module) is not types.ModuleType:
        raise NativeBrokerUnavailable("native Apple egress broker is unavailable")
    namespace = types.ModuleType.__getattribute__(module, "__dict__")
    if type(namespace) is not dict:
        raise NativeBrokerUnavailable("native Apple egress broker is unavailable")
    spec = namespace.get("__spec__")
    if type(spec) is not importlib.machinery.ModuleSpec:
        raise NativeBrokerUnavailable("native Apple egress broker is unavailable")
    spec_ns = object.__getattribute__(spec, "__dict__")
    if type(spec_ns) is not dict:
        raise NativeBrokerUnavailable("native Apple egress broker is unavailable")
    loader = spec_ns.get("loader")
    if type(loader) is not importlib.machinery.ExtensionFileLoader:
        raise NativeBrokerUnavailable("native Apple egress broker is unavailable")
    loader_ns = object.__getattribute__(loader, "__dict__")
    if type(loader_ns) is not dict:
        raise NativeBrokerUnavailable("native Apple egress broker is unavailable")
    native_types = tuple(namespace.get(name) for name in _NATIVE_TYPE_NAMES)
    text_metadata = (
        namespace.get("__name__"), namespace.get("__file__"),
        namespace.get("BROKER_V2_ABI_SCHEMA"),
        namespace.get("BROKER_V2_PRODUCTION_ACQUISITION"),
        spec_ns.get("name"), spec_ns.get("origin"), loader_ns.get("name"),
        loader_ns.get("path"),
    )
    # Exact built-in checks precede all equality, suffix and length operations.
    if any(type(item) is not str for item in text_metadata):
        raise NativeBrokerUnavailable("native Apple egress broker is unavailable")
    if any(not item or len(item) > 4096 or "\x00" in item for item in text_metadata):
        raise NativeBrokerUnavailable("native Apple egress broker is unavailable")
    (name, module_file, abi, acquisition, spec_name, origin, loader_name,
     loader_path) = text_metadata
    integer_metadata = (
        namespace.get("BROKER_V2_PROTOCOL_VERSION"),
        namespace.get("BROKER_V2_FRAME_HEADER_SIZE"),
        namespace.get("BROKER_V2_MAX_SCM_RIGHTS_FDS"),
    )
    if any(type(item) is not int or isinstance(item, bool) for item in integer_metadata):
        raise NativeBrokerUnavailable("native Apple egress broker is unavailable")
    suffixes = _NATIVE_EXTENSION_SUFFIXES
    if (type(suffixes) is not tuple or not suffixes
            or any(type(item) is not str or not item or len(item) > 256 for item in suffixes)):
        raise NativeBrokerUnavailable("native Apple egress broker is unavailable")
    if (name != NATIVE_MODULE_NAME or spec_name != NATIVE_MODULE_NAME
            or loader_name != NATIVE_MODULE_NAME or module_file != origin
            or loader_path != origin or abi != NATIVE_ABI_SCHEMA
            or acquisition != NATIVE_PRODUCTION_ACQUISITION
            or integer_metadata != (
                BROKER_V2_PROTOCOL_VERSION,
                BROKER_V2_FRAME_HEADER_SIZE,
                BROKER_V2_MAX_SCM_RIGHTS_FDS,
            )
            or namespace.get("TEST_ONLY_BUILD") is not False
            or not any(origin.endswith(item) for item in suffixes)):
        raise NativeBrokerUnavailable("native Apple egress broker is unavailable")
    if any(type(item) is not type for item in native_types):
        raise NativeBrokerUnavailable("native Apple egress broker is unavailable")
    if any(type.__getattribute__(item, "__flags__") & (1 << 9) for item in native_types):
        raise NativeBrokerUnavailable("native Apple egress broker is unavailable")
    modules = tuple(type.__getattribute__(item, "__module__") for item in native_types)
    if (any(type(item) is not str for item in modules)
            or modules != (NATIVE_MODULE_NAME,) * len(native_types)):
        raise NativeBrokerUnavailable("native Apple egress broker is unavailable")
    for native_type in native_types:
        type_namespace = type.__getattribute__(native_type, "__dict__")
        if (type(type_namespace) is not types.MappingProxyType
                or type(type_namespace.get("consume_once"))
                   is not types.MethodDescriptorType):
            raise NativeBrokerUnavailable("native Apple egress broker is unavailable")
    return native_types


def _production_call(_wrapper: object, _operation: str, _plan: object) -> object:
    # Authenticate the final shared ABI before touching any caller object.  The
    # shared extension intentionally exposes no Apple-network execution method
    # until the native launcher/service and durable CLI adapter are integrated.
    _native_types()
    raise NativeBrokerUnavailable("native Apple egress lifecycle adapter is unavailable")


def open_apple_egress_network(
    closure: NetworkClosure, native_consumer: object,
) -> AppleEgressNetwork:
    """Fail closed until the unified native service issues Apple authority."""
    # Literal first action: do not inspect either caller object before hardstop.
    consumer_type, _bundle_type, _provider_type, _network_type = _native_types()
    if type(native_consumer) is not consumer_type:
        raise NativeBrokerUnavailable("native Apple egress consumer is unavailable")
    raise NativeBrokerUnavailable("native Apple egress lifecycle adapter is unavailable")


__all__ = [
    "APPLE_CONTAINER_EXECUTABLE", "AppleEgressNetwork",
    "AppleEgressNetworkError", "BROKER_V2_FD_APPLE_CLI_EXECUTABLE",
    "BROKER_V2_FD_JOURNAL_DIRECTORY", "BROKER_V2_FRAME_HEADER_SIZE",
    "BROKER_V2_MAX_SCM_RIGHTS_FDS", "BROKER_V2_PROTOCOL_VERSION",
    "BrokerV2FrameType", "EgressEvidence", "EgressState",
    "NATIVE_ABI_SCHEMA", "NATIVE_CALL_AUTHORITY", "NATIVE_MODULE_NAME",
    "NATIVE_PRODUCTION_ACQUISITION", "NATIVE_PROJECTION_MISSING_COMMITMENTS",
    "NETWORK_MODE", "NETWORK_PLUGIN", "NativeBrokerUnavailable",
    "NetworkAmbiguousError", "NetworkClosure", "NetworkCollisionError",
    "NetworkConfigurationError", "NetworkObservation", "NetworkPlan",
    "NetworkProtocolError", "Operation", "PROXY_KIND", "RecordState",
    "SCHEMA", "SUPPORTED_APPLE_CONTAINER_VERSION",
    "open_apple_egress_network", "render_network_plan", "validate_inspection",
]
