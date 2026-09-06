"""Redacted, replayable Claude CLI authentication-route authority.

The provider's authentication precedence is security and billing authority.
This module observes route *presence*, compiles one selected route and exact
endpoint policy, and emits receipts that contain neither credential values nor
credential-content hashes.  Credential-value equality is deliberately a
short-lived, in-memory concern of the child-environment/process transaction.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import threading
from typing import Any, Mapping
from urllib.parse import urlsplit
import weakref


AUTH_ROUTE_SCHEMA = "plamen.claude_auth_route.v1"
AUTH_SOURCE_OBSERVATION_SCHEMA = (
    "plamen.claude_auth_source_observation.v1"
)
STORED_SUBSCRIPTION_SOURCE_SCHEMA = (
    "plamen.claude_stored_subscription_source.v1"
)
AUTH_ENDPOINT_POLICY_SCHEMA = "plamen.claude_auth_endpoint_policy.v1"
AUTH_ENVIRONMENT_SCHEMA = "plamen.claude_auth_environment.v1"
AUTH_ROUTE_POLICY_SCHEMA = "plamen.claude_auth_route_policy.v1"

_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_VERSION_RE = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
)
_SOURCE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_ROUTE_ORDER = (
    "CLOUD_BEDROCK",
    "CLOUD_VERTEX",
    "CLOUD_FOUNDRY",
    "AUTH_TOKEN",
    "API_KEY",
    "API_KEY_HELPER",
    "OAUTH_TOKEN",
    "STORED_SUBSCRIPTION_OAUTH",
)
_CLOUD_SELECTORS = {
    "CLOUD_BEDROCK": "CLAUDE_CODE_USE_BEDROCK",
    "CLOUD_VERTEX": "CLAUDE_CODE_USE_VERTEX",
    "CLOUD_FOUNDRY": "CLAUDE_CODE_USE_FOUNDRY",
}
_DIRECT_ROUTE_SOURCES = {
    "AUTH_TOKEN": "ANTHROPIC_AUTH_TOKEN",
    "API_KEY": "ANTHROPIC_API_KEY",
    "OAUTH_TOKEN": "CLAUDE_CODE_OAUTH_TOKEN",
}
_ENDPOINT_ENV_BY_ROUTE = {
    "CLOUD_BEDROCK": frozenset({"ANTHROPIC_BEDROCK_BASE_URL"}),
    "CLOUD_VERTEX": frozenset({"ANTHROPIC_VERTEX_BASE_URL"}),
    "CLOUD_FOUNDRY": frozenset(
        {
            "ANTHROPIC_FOUNDRY_BASE_URL",
            "ANTHROPIC_FOUNDRY_RESOURCE",
        }
    ),
}
_ALL_ENDPOINT_ENV = frozenset(
    {
        "ANTHROPIC_BASE_URL",
        *(
            name
            for names in _ENDPOINT_ENV_BY_ROUTE.values()
            for name in names
        ),
    }
)
_ROUTE_AFFECTING_ENV = frozenset(
    {
        *_CLOUD_SELECTORS.values(),
        *_DIRECT_ROUTE_SOURCES.values(),
        *_ALL_ENDPOINT_ENV,
    }
)
_TRUTHY = {"1", "true", "yes", "on"}
_STORED_SOURCE_CLASSES = {
    "FILE_BACKED",
    "OS_KEYCHAIN",
    "EXPLICIT_PROFILE",
    "SETUP_TOKEN",
}
_ENDPOINT_MODES = {
    "OFFICIAL_DEFAULT",
    "CUSTOM_BASE_URL",
    "CLOUD_PROVIDER",
}
_CUSTOM_ENDPOINT_ROUTES = {"AUTH_TOKEN", "API_KEY", "API_KEY_HELPER"}

# Exact stream-json ``system/init.apiKeySource`` vocabulary pinned for the
# reviewed legacy CLI protocol from the recorded protocol evidence.  A CLI
# update is intentionally a code/config change, not a permissive semver range;
# the controlled official-CLI checkpoint still has to confirm this table
# before cutover.
_API_KEY_SOURCE_BY_VERSION_ROUTE: dict[
    str, dict[str, tuple[str, ...]]
] = {
    "2.1.220": {
        "CLOUD_BEDROCK": ("none",),
        "CLOUD_VERTEX": ("none",),
        "CLOUD_FOUNDRY": ("none",),
        "AUTH_TOKEN": ("ANTHROPIC_AUTH_TOKEN",),
        "API_KEY": ("ANTHROPIC_API_KEY",),
        "API_KEY_HELPER": ("apiKeyHelper",),
        "OAUTH_TOKEN": ("none",),
        "STORED_SUBSCRIPTION_OAUTH": ("none",),
    },
    "2.1.250": {
        "CLOUD_BEDROCK": ("none",),
        "CLOUD_VERTEX": ("none",),
        "CLOUD_FOUNDRY": ("none",),
        "AUTH_TOKEN": ("ANTHROPIC_AUTH_TOKEN",),
        "API_KEY": ("ANTHROPIC_API_KEY",),
        "API_KEY_HELPER": ("apiKeyHelper",),
        "OAUTH_TOKEN": ("none",),
        "STORED_SUBSCRIPTION_OAUTH": ("none",),
    },
    "2.1.252": {
        "CLOUD_BEDROCK": ("none",),
        "CLOUD_VERTEX": ("none",),
        "CLOUD_FOUNDRY": ("none",),
        "AUTH_TOKEN": ("ANTHROPIC_AUTH_TOKEN",),
        "API_KEY": ("ANTHROPIC_API_KEY",),
        "API_KEY_HELPER": ("apiKeyHelper",),
        "OAUTH_TOKEN": ("none",),
        "STORED_SUBSCRIPTION_OAUTH": ("none",),
    },
}


class ClaudeAuthRouteError(RuntimeError):
    """The requested Claude authentication route is unavailable or ambiguous."""


_PROMOTION_TOKEN = object()
_SOURCE_PROMOTION_LOCK = threading.RLock()
_SOURCE_PROMOTION_PENDING: dict[str, tuple[dict[str, Any], str]] = {}
_SOURCE_PROMOTION_ISSUED: dict[
    int, tuple[weakref.ReferenceType[Any], dict[str, Any]]
] = {}
_AUTH_CAPABILITY_LOCK = threading.RLock()
_SETTINGS_HELPER_PENDING: dict[str, dict[str, Any]] = {}
_SETTINGS_HELPER_ISSUED: dict[
    int, tuple[weakref.ReferenceType[Any], dict[str, Any]]
] = {}
_AUTH_SOURCE_PENDING: dict[str, dict[str, Any]] = {}
_AUTH_SOURCE_ISSUED: dict[
    int, tuple[weakref.ReferenceType[Any], dict[str, Any]]
] = {}
_AUTH_ENVIRONMENT_PENDING: dict[str, dict[str, Any]] = {}
_AUTH_ENVIRONMENT_ISSUED: dict[
    int, tuple[weakref.ReferenceType[Any], dict[str, Any]]
] = {}


def _register_auth_capability(
    registry: dict[
        int, tuple[weakref.ReferenceType[Any], dict[str, Any]]
    ],
    value: Any,
    state: dict[str, Any],
) -> None:
    key = id(value)

    def retire(reference: weakref.ReferenceType[Any]) -> None:
        with _AUTH_CAPABILITY_LOCK:
            current = registry.get(key)
            if current is not None and current[0] is reference:
                registry.pop(key, None)

    reference = weakref.ref(value, retire)
    registry[key] = (
        reference,
        {**state, "issuer_pid": os.getpid()},
    )


def _auth_capability_state(
    registry: Mapping[
        int, tuple[weakref.ReferenceType[Any], dict[str, Any]]
    ],
    value: Any,
    *,
    label: str,
) -> dict[str, Any]:
    issued = registry.get(id(value))
    if issued is None or issued[0]() is not value:
        raise ClaudeAuthRouteError(
            f"{label} was not issued by its validator"
        )
    if issued[1].get("issuer_pid") != os.getpid():
        raise ClaudeAuthRouteError(
            f"{label} cannot cross a process boundary"
        )
    return issued[1]


class PromotedStoredSubscriptionSourceEvidence(dict):
    """Opaque live promotion of neutral credential-store evidence.

    Its mapping surface is the redacted durable receipt. The keyed live
    promotion is deliberately absent from serialization and is consumed once
    when auth-source observation begins.
    """

    def __init__(
        self,
        value: Mapping[str, Any],
        *,
        provider_authority_sha256: str,
        _token: object,
        _issuance_id: str | None = None,
    ) -> None:
        if (
            type(self) is not PromotedStoredSubscriptionSourceEvidence
            or _token is not _PROMOTION_TOKEN
            or not isinstance(_issuance_id, str)
        ):
            raise TypeError("stored-source promotion is provider-owned")
        replayed = replay_stored_subscription_source_evidence(value)
        with _SOURCE_PROMOTION_LOCK:
            pending = _SOURCE_PROMOTION_PENDING.pop(
                _issuance_id,
                None,
            )
        if (
            pending is None
            or pending[0] != replayed
            or pending[1] != provider_authority_sha256
            or not replayed["available"]
            or replayed["observation_authority_sha256"]
            != provider_authority_sha256
        ):
            raise ClaudeAuthRouteError(
                "stored-source promotion authority disagrees with evidence"
            )
        super().__init__(replayed)
        self.__key = bytearray(secrets.token_bytes(32))
        self.__tag = bytearray(
            hmac.digest(
                self.__key,
                _canonical_json(replayed),
                "sha256",
            )
        )
        self.__provider_authority_sha256 = provider_authority_sha256
        self.__active = True
        self.__lock = threading.Lock()
        state = {
            "receipt_sha256": replayed["receipt_sha256"],
            "provider_authority_sha256": provider_authority_sha256,
            "consumed": False,
            "issuer_pid": os.getpid(),
        }
        key = id(self)

        def retire(reference: weakref.ReferenceType[Any]) -> None:
            with _SOURCE_PROMOTION_LOCK:
                current = _SOURCE_PROMOTION_ISSUED.get(key)
                if current is not None and current[0] is reference:
                    _SOURCE_PROMOTION_ISSUED.pop(key, None)

        reference = weakref.ref(self, retire)
        with _SOURCE_PROMOTION_LOCK:
            _SOURCE_PROMOTION_ISSUED[key] = (reference, state)

    def __repr__(self) -> str:
        return "<PromotedStoredSubscriptionSourceEvidence redacted>"

    def __copy__(self) -> None:
        raise TypeError("stored-source promotion cannot be copied")

    def __deepcopy__(self, _memo: object) -> None:
        raise TypeError("stored-source promotion cannot be copied")

    def __reduce__(self) -> None:
        raise TypeError("stored-source promotion cannot be serialized")

    def _consume_for_auth_observation(self) -> dict[str, Any]:
        with _SOURCE_PROMOTION_LOCK:
            issued = _SOURCE_PROMOTION_ISSUED.get(id(self))
            if (
                issued is None
                or issued[0]() is not self
                or issued[1]["consumed"]
                or issued[1]["issuer_pid"] != os.getpid()
            ):
                raise ClaudeAuthRouteError(
                    "stored-source promotion is stale or already consumed"
                )
            replayed = replay_stored_subscription_source_evidence(self)
            expected = hmac.digest(
                self.__key,
                _canonical_json(replayed),
                "sha256",
            )
            if (
                not hmac.compare_digest(expected, self.__tag)
                or replayed["observation_authority_sha256"]
                != self.__provider_authority_sha256
                or replayed["receipt_sha256"]
                != issued[1]["receipt_sha256"]
                or self.__provider_authority_sha256
                != issued[1]["provider_authority_sha256"]
            ):
                raise ClaudeAuthRouteError(
                    "stored-source promotion was rebound or mutated"
                )
            issued[1]["consumed"] = True
            self.__active = False
            _zeroize(self.__key)
            _zeroize(self.__tag)
            return replayed

    def _invalidate(self) -> None:
        with _SOURCE_PROMOTION_LOCK:
            issued = _SOURCE_PROMOTION_ISSUED.get(id(self))
            if issued is None or issued[0]() is not self:
                return
            if issued[1]["issuer_pid"] != os.getpid():
                return
            issued[1]["consumed"] = True
            if not self.__active:
                return
            self.__active = False
            _zeroize(self.__key)
            _zeroize(self.__tag)


def _promote_stored_subscription_source_evidence(
    value: Mapping[str, Any],
    *,
    provider_authority_sha256: str,
) -> PromotedStoredSubscriptionSourceEvidence:
    """Provider-only bridge from store inspection to auth observation."""

    replayed = replay_stored_subscription_source_evidence(value)
    issuance_id = secrets.token_hex(32)
    with _SOURCE_PROMOTION_LOCK:
        _SOURCE_PROMOTION_PENDING[issuance_id] = (
            replayed,
            provider_authority_sha256,
        )
    try:
        return PromotedStoredSubscriptionSourceEvidence(
            replayed,
            provider_authority_sha256=provider_authority_sha256,
            _token=_PROMOTION_TOKEN,
            _issuance_id=issuance_id,
        )
    finally:
        with _SOURCE_PROMOTION_LOCK:
            _SOURCE_PROMOTION_PENDING.pop(issuance_id, None)


class ClaudeSettingsHelperAuthority:
    """Opaque exact settings-byte observation for apiKeyHelper."""

    __slots__ = (
        "__authority_sha256",
        "__settings_json",
        "__weakref__",
    )

    def __init__(
        self,
        *,
        settings: Mapping[str, Any],
        authority_sha256: str,
        _token: object,
        _issuance_id: str | None = None,
    ) -> None:
        settings_json = _canonical_json(dict(settings))
        if (
            type(self) is not ClaudeSettingsHelperAuthority
            or _token is not _PROMOTION_TOKEN
            or not isinstance(_issuance_id, str)
        ):
            raise TypeError("settings-helper authority is compiler-owned")
        with _AUTH_CAPABILITY_LOCK:
            pending = _SETTINGS_HELPER_PENDING.pop(
                _issuance_id,
                None,
            )
        if (
            pending is None
            or pending["settings_json"] != settings_json
            or pending["authority_sha256"] != authority_sha256
        ):
            raise TypeError(
                "settings-helper authority requires validator issuance"
            )
        self.__settings_json = settings_json
        self.__authority_sha256 = authority_sha256
        with _AUTH_CAPABILITY_LOCK:
            _register_auth_capability(
                _SETTINGS_HELPER_ISSUED,
                self,
                {
                    "settings_json": settings_json,
                    "authority_sha256": authority_sha256,
                },
            )

    def __repr__(self) -> str:
        return "<ClaudeSettingsHelperAuthority opaque>"

    def __copy__(self) -> None:
        raise TypeError("settings-helper authority cannot be copied")

    def __deepcopy__(self, _memo: object) -> None:
        raise TypeError("settings-helper authority cannot be copied")

    def __reduce__(self) -> None:
        raise TypeError("settings-helper authority cannot be serialized")

    def _assert_matches(
        self,
        settings: Mapping[str, Any],
        *,
        authority_sha256: str | None,
    ) -> None:
        with _AUTH_CAPABILITY_LOCK:
            state = _auth_capability_state(
                _SETTINGS_HELPER_ISSUED,
                self,
                label="settings-helper authority",
            )
            if (
                state["authority_sha256"] != self.__authority_sha256
                or state["settings_json"] != self.__settings_json
                or authority_sha256 != self.__authority_sha256
                or _canonical_json(dict(settings))
                != self.__settings_json
            ):
                raise ClaudeAuthRouteError(
                    "settings-helper authority was rebound"
                )


class ClaudeAuthSourceCapability(dict):
    """Redacted observation plus one-shot keyed ambient value identity."""

    def __init__(
        self,
        receipt: Mapping[str, Any],
        *,
        environment: Mapping[str, str],
        _token: object,
        _issuance_id: str | None = None,
    ) -> None:
        if (
            type(self) is not ClaudeAuthSourceCapability
            or _token is not _PROMOTION_TOKEN
            or not isinstance(_issuance_id, str)
        ):
            raise TypeError("auth-source capability is observer-owned")
        replayed = replay_claude_auth_source_observation(receipt)
        source, _names = _normalize_environment(environment)
        with _AUTH_CAPABILITY_LOCK:
            pending = _AUTH_SOURCE_PENDING.pop(_issuance_id, None)
        if (
            pending is None
            or pending["receipt"] != replayed
            or pending["environment"] != source
        ):
            raise TypeError(
                "auth-source capability requires observer issuance"
            )
        super().__init__(replayed)
        self.__key = bytearray(secrets.token_bytes(32))
        self.__tag = bytearray(
            hmac.digest(
                self.__key,
                _auth_environment_integrity_material(source),
                "sha256",
            )
        )
        self.__active = True
        self.__lock = threading.Lock()
        with _AUTH_CAPABILITY_LOCK:
            _register_auth_capability(
                _AUTH_SOURCE_ISSUED,
                self,
                {
                    "receipt_sha256": replayed["receipt_sha256"],
                    "consumed": False,
                },
            )

    def __repr__(self) -> str:
        return (
            "<ClaudeAuthSourceCapability "
            f"receipt_sha256={self.get('receipt_sha256')!r}>"
        )

    def __copy__(self) -> None:
        raise TypeError("auth-source capability cannot be copied")

    def __deepcopy__(self, _memo: object) -> None:
        raise TypeError("auth-source capability cannot be copied")

    def __reduce__(self) -> None:
        raise TypeError("auth-source capability cannot be serialized")

    def _assert_environment(
        self,
        environment: Mapping[str, str],
    ) -> dict[str, str]:
        with _AUTH_CAPABILITY_LOCK:
            state = _auth_capability_state(
                _AUTH_SOURCE_ISSUED,
                self,
                label="auth-source capability",
            )
            if state["consumed"] or not self.__active:
                raise ClaudeAuthRouteError(
                    "auth-source capability is stale or already consumed"
                )
            replayed = replay_claude_auth_source_observation(self)
            if replayed["receipt_sha256"] != state["receipt_sha256"]:
                raise ClaudeAuthRouteError(
                    "Claude auth-source observation receipt was rebound"
                )
            source, _names = _normalize_environment(environment)
            actual = hmac.digest(
                self.__key,
                _auth_environment_integrity_material(source),
                "sha256",
            )
            if not hmac.compare_digest(actual, self.__tag):
                raise ClaudeAuthRouteError(
                    "Claude auth-source observation value identity was rebound"
                )
            return source

    def _consume_environment(
        self,
        environment: Mapping[str, str],
    ) -> dict[str, str]:
        with _AUTH_CAPABILITY_LOCK:
            state = _auth_capability_state(
                _AUTH_SOURCE_ISSUED,
                self,
                label="auth-source capability",
            )
            if state["consumed"]:
                raise ClaudeAuthRouteError(
                    "auth-source capability is stale or already consumed"
                )
            source = self._assert_environment_unlocked(environment)
            state["consumed"] = True
            self.__active = False
            _zeroize(self.__key)
            _zeroize(self.__tag)
            return source

    def _assert_environment_unlocked(
        self,
        environment: Mapping[str, str],
    ) -> dict[str, str]:
        state = _auth_capability_state(
            _AUTH_SOURCE_ISSUED,
            self,
            label="auth-source capability",
        )
        if state["consumed"] or not self.__active:
            raise ClaudeAuthRouteError(
                "auth-source capability is stale or already consumed"
            )
        replayed = replay_claude_auth_source_observation(self)
        if replayed["receipt_sha256"] != state["receipt_sha256"]:
            raise ClaudeAuthRouteError(
                "Claude auth-source observation receipt was rebound"
            )
        source, _names = _normalize_environment(environment)
        actual = hmac.digest(
            self.__key,
            _auth_environment_integrity_material(source),
            "sha256",
        )
        if not hmac.compare_digest(actual, self.__tag):
            raise ClaudeAuthRouteError(
                "Claude auth-source observation value identity was rebound"
            )
        return source


class ClaudeAuthEnvironmentCapability(dict):
    """One-shot exact filtered auth environment for final child compilation."""

    def __init__(
        self,
        environment: Mapping[str, str],
        *,
        receipt_sha256: str,
        _token: object,
        _issuance_id: str | None = None,
    ) -> None:
        if (
            type(self) is not ClaudeAuthEnvironmentCapability
            or _token is not _PROMOTION_TOKEN
            or not isinstance(_issuance_id, str)
        ):
            raise TypeError("auth environment capability is compiler-owned")
        source, _names = _normalize_environment(environment)
        with _AUTH_CAPABILITY_LOCK:
            pending = _AUTH_ENVIRONMENT_PENDING.pop(
                _issuance_id,
                None,
            )
        if (
            pending is None
            or pending["environment"] != source
            or pending["receipt_sha256"] != receipt_sha256
        ):
            raise TypeError(
                "auth environment capability requires compiler issuance"
            )
        super().__init__(source)
        self.__key = bytearray(secrets.token_bytes(32))
        self.__tag = bytearray(
            hmac.digest(
                self.__key,
                _auth_environment_integrity_material(source),
                "sha256",
            )
        )
        self.__receipt_sha256 = receipt_sha256
        self.__active = True
        self.__lock = threading.Lock()
        with _AUTH_CAPABILITY_LOCK:
            _register_auth_capability(
                _AUTH_ENVIRONMENT_ISSUED,
                self,
                {
                    "receipt_sha256": receipt_sha256,
                    "consumed": False,
                },
            )

    def __repr__(self) -> str:
        return "<ClaudeAuthEnvironmentCapability opaque>"

    def __copy__(self) -> None:
        raise TypeError("auth environment capability cannot be copied")

    def __deepcopy__(self, _memo: object) -> None:
        raise TypeError("auth environment capability cannot be copied")

    def __reduce__(self) -> None:
        raise TypeError("auth environment capability cannot be serialized")

    def _verified_environment(
        self,
        *,
        receipt_sha256: str,
    ) -> dict[str, str]:
        with _AUTH_CAPABILITY_LOCK:
            state = _auth_capability_state(
                _AUTH_ENVIRONMENT_ISSUED,
                self,
                label="auth environment capability",
            )
            if (
                state["consumed"]
                or not self.__active
                or receipt_sha256 != self.__receipt_sha256
                or state["receipt_sha256"] != self.__receipt_sha256
            ):
                raise ClaudeAuthRouteError(
                    "auth environment capability is stale or rebound"
                )
            source, _names = _normalize_environment(self)
            actual = hmac.digest(
                self.__key,
                _auth_environment_integrity_material(source),
                "sha256",
            )
            if not hmac.compare_digest(actual, self.__tag):
                raise ClaudeAuthRouteError(
                    "auth environment value identity drifted"
                )
            return source

    def _consume_verified_environment(
        self,
        *,
        receipt_sha256: str,
    ) -> dict[str, str]:
        """Atomically verify, transfer, and revoke the one-shot values.

        A separate verify-then-invalidate sequence permits two concurrent
        child compilers to observe the capability as active.  The transfer
        and revocation therefore share the same lock and linearization point.
        """

        with _AUTH_CAPABILITY_LOCK:
            state = _auth_capability_state(
                _AUTH_ENVIRONMENT_ISSUED,
                self,
                label="auth environment capability",
            )
            if (
                state["consumed"]
                or not self.__active
                or receipt_sha256 != self.__receipt_sha256
                or state["receipt_sha256"] != self.__receipt_sha256
            ):
                raise ClaudeAuthRouteError(
                    "auth environment capability is stale or rebound"
                )
            source, _names = _normalize_environment(self)
            actual = hmac.digest(
                self.__key,
                _auth_environment_integrity_material(source),
                "sha256",
            )
            if not hmac.compare_digest(actual, self.__tag):
                raise ClaudeAuthRouteError(
                    "auth environment value identity drifted"
                )
            state["consumed"] = True
            self.__active = False
            _zeroize(self.__key)
            _zeroize(self.__tag)
            dict.clear(self)
            return source

    def _invalidate_private_values(self) -> None:
        with _AUTH_CAPABILITY_LOCK:
            state = _auth_capability_state(
                _AUTH_ENVIRONMENT_ISSUED,
                self,
                label="auth environment capability",
            )
            if state["consumed"] or not self.__active:
                return
            state["consumed"] = True
            self.__active = False
            _zeroize(self.__key)
            _zeroize(self.__tag)
            # Drop the capability's last direct references to credential
            # strings after the final child environment has taken ownership.
            # Python strings cannot be overwritten in place, so clearing the
            # private container is the strongest honest in-process zeroization
            # this representation can provide.
            dict.clear(self)


def _zeroize(value: bytearray) -> None:
    for index in range(len(value)):
        value[index] = 0


def _auth_environment_integrity_material(
    environment: Mapping[str, str],
) -> bytes:
    return "\0".join(
        f"{name.casefold()}={environment[name]}"
        for name in sorted(environment, key=str.casefold)
    ).encode("utf-8")


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ClaudeAuthRouteError(
            "Claude auth authority is not canonical JSON"
        ) from exc


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _valid_sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None


def _normalize_environment(
    environment: Mapping[str, str],
) -> tuple[dict[str, str], dict[str, str]]:
    if not isinstance(environment, Mapping):
        raise ClaudeAuthRouteError("environment must be a mapping")
    normalized: dict[str, str] = {}
    canonical_names: dict[str, str] = {}
    for raw_name, raw_value in environment.items():
        if (
            not isinstance(raw_name, str)
            or not raw_name
            or "=" in raw_name
            or "\x00" in raw_name
            or not isinstance(raw_value, str)
            or "\x00" in raw_value
        ):
            raise ClaudeAuthRouteError("environment contains malformed text")
        folded = raw_name.casefold()
        if folded in canonical_names:
            raise ClaudeAuthRouteError(
                "environment has case-ambiguous variable names"
            )
        canonical_names[folded] = raw_name
        normalized[raw_name] = raw_value
    return normalized, canonical_names


def _key_set_digest(environment: Mapping[str, str]) -> str:
    # Environment names are normalized case-insensitively at every boundary.
    return hashlib.sha256(
        "\0".join(
            sorted((name.casefold() for name in environment), key=str.casefold)
        ).encode("utf-8")
    ).hexdigest()


def _lookup(
    environment: Mapping[str, str],
    canonical_names: Mapping[str, str],
    name: str,
) -> str | None:
    actual = canonical_names.get(name.casefold())
    return None if actual is None else environment[actual]


def _actual_name(
    canonical_names: Mapping[str, str],
    source: str,
) -> str | None:
    return canonical_names.get(source.casefold())


def _truthy(value: str | None) -> bool:
    return value is not None and value.strip().casefold() in _TRUTHY


def _environment_route_sources(
    environment: Mapping[str, str],
    canonical_names: Mapping[str, str],
) -> list[str]:
    result: list[str] = []
    for route, source in _CLOUD_SELECTORS.items():
        if _truthy(_lookup(environment, canonical_names, source)):
            result.append(source)
    for route in ("AUTH_TOKEN", "API_KEY", "OAUTH_TOKEN"):
        source = _DIRECT_ROUTE_SOURCES[route]
        value = _lookup(environment, canonical_names, source)
        if value is not None and bool(value):
            result.append(source)
    return sorted(result)


def replay_stored_subscription_source_evidence(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Strictly replay evidence emitted by a credential-store provider.

    The provider owns actual store inspection.  This receipt is intentionally
    limited to store metadata and an external observation authority; it never
    carries raw bytes or a digest of credential content.
    """

    if not isinstance(value, Mapping):
        raise ClaudeAuthRouteError(
            "stored-subscription source evidence must be an object"
        )
    clone = dict(value)
    expected_fields = {
        "schema",
        "store_class",
        "source_identity",
        "source_size",
        "available",
        "observation_authority_sha256",
        "credential_values_recorded",
        "credential_content_hashes_recorded",
        "receipt_sha256",
    }
    if set(clone) != expected_fields:
        raise ClaudeAuthRouteError(
            "stored-subscription source evidence fields drifted"
        )
    digest = clone.pop("receipt_sha256")
    if (
        clone.get("schema") != STORED_SUBSCRIPTION_SOURCE_SCHEMA
        or clone.get("store_class") not in _STORED_SOURCE_CLASSES
        or not isinstance(clone.get("source_identity"), str)
        or _SOURCE_ID_RE.fullmatch(clone["source_identity"]) is None
        or isinstance(clone.get("source_size"), bool)
        or not isinstance(clone.get("source_size"), int)
        or clone["source_size"] < 0
        or not isinstance(clone.get("available"), bool)
        or not _valid_sha256(clone.get("observation_authority_sha256"))
        or clone.get("credential_values_recorded") is not False
        or clone.get("credential_content_hashes_recorded") is not False
        or not _valid_sha256(digest)
        or digest != _digest(clone)
    ):
        raise ClaudeAuthRouteError(
            "stored-subscription source evidence does not replay"
        )
    return {**clone, "receipt_sha256": digest}


def _normalize_settings(
    settings: Mapping[str, Any],
) -> tuple[dict[str, Any], bool]:
    if not isinstance(settings, Mapping):
        raise ClaudeAuthRouteError("Claude settings evidence must be an object")
    clone = dict(settings)
    if any(
        not isinstance(name, str) or not name or "\x00" in name
        for name in clone
    ):
        raise ClaudeAuthRouteError("Claude settings names are malformed")
    folded: set[str] = set()
    for name in clone:
        name_folded = name.casefold()
        if name_folded in folded:
            raise ClaudeAuthRouteError(
                "Claude settings have case-ambiguous keys"
            )
        folded.add(name_folded)
    helper_names = [
        name for name in clone if name.casefold() == "apikeyhelper"
    ]
    helper_configured = False
    if helper_names:
        helper = clone[helper_names[0]]
        if (
            not isinstance(helper, str)
            or not helper
            or "\x00" in helper
        ):
            raise ClaudeAuthRouteError(
                "apiKeyHelper settings evidence is malformed"
            )
        helper_configured = True
    return clone, helper_configured


def compile_claude_settings_helper_authority(
    *,
    settings_bytes: bytes,
    settings_authority: Mapping[str, Any],
) -> ClaudeSettingsHelperAuthority:
    """Observe exact bound settings bytes and promote apiKeyHelper presence."""

    if not isinstance(settings_bytes, bytes):
        raise ClaudeAuthRouteError(
            "settings-helper source must be exact immutable bytes"
        )
    try:
        settings = json.loads(
            settings_bytes.decode("utf-8", errors="strict"),
        )
    except (UnicodeError, json.JSONDecodeError):
        raise ClaudeAuthRouteError(
            "settings-helper source is not strict JSON"
        ) from None
    normalized, helper = _normalize_settings(settings)
    authority = dict(settings_authority)
    expected_fields = {
        "schema",
        "mode",
        "settings_sha256",
        "external_policy_sha256",
        "authority_sha256",
    }
    if set(authority) != expected_fields:
        raise ClaudeAuthRouteError(
            "settings-helper authority fields drifted"
        )
    digest = authority.pop("authority_sha256")
    if (
        not helper
        or authority.get("schema")
        != "plamen.claude_settings_authority.v1"
        or authority.get("mode") != "BOUND_SETTINGS"
        or authority.get("settings_sha256")
        != hashlib.sha256(settings_bytes).hexdigest()
        or not _valid_sha256(authority.get("external_policy_sha256"))
        or not _valid_sha256(digest)
        or digest != _digest(authority)
    ):
        raise ClaudeAuthRouteError(
            "settings-helper exact byte authority does not replay"
        )
    issuance_id = secrets.token_hex(32)
    pending = {
        "settings_json": _canonical_json(dict(normalized)),
        "authority_sha256": digest,
    }
    with _AUTH_CAPABILITY_LOCK:
        _SETTINGS_HELPER_PENDING[issuance_id] = pending
    try:
        return ClaudeSettingsHelperAuthority(
            settings=normalized,
            authority_sha256=digest,
            _token=_PROMOTION_TOKEN,
            _issuance_id=issuance_id,
        )
    finally:
        with _AUTH_CAPABILITY_LOCK:
            _SETTINGS_HELPER_PENDING.pop(issuance_id, None)


def observe_claude_auth_sources(
    environment: Mapping[str, str],
    *,
    settings: Mapping[str, Any],
    settings_authority_sha256: str | None,
    stored_subscription_evidence: Mapping[str, Any],
    settings_helper_authority: ClaudeSettingsHelperAuthority | None = None,
) -> ClaudeAuthSourceCapability:
    """Observe environment/settings sources and bind external store evidence.

    This replaces caller-trusted ``helper=True`` / ``stored=True`` switches.
    Direct credentials are observed from the environment, helper availability
    is derived from the settings object, and stored OAuth availability comes
    from a separately owned credential-store observation receipt.
    """

    source, names = _normalize_environment(environment)
    normalized_settings, helper_configured = _normalize_settings(settings)
    if helper_configured:
        if not _valid_sha256(settings_authority_sha256):
            raise ClaudeAuthRouteError(
                "apiKeyHelper requires bound settings authority"
            )
        if not isinstance(
            settings_helper_authority,
            ClaudeSettingsHelperAuthority,
        ):
            raise ClaudeAuthRouteError(
                "apiKeyHelper requires promoted neutral settings authority"
            )
        settings_helper_authority._assert_matches(
            normalized_settings,
            authority_sha256=settings_authority_sha256,
        )
    elif settings_authority_sha256 is not None:
        raise ClaudeAuthRouteError(
            "settings authority cannot imply an absent apiKeyHelper"
        )
    elif settings_helper_authority is not None:
        raise ClaudeAuthRouteError(
            "settings-helper authority cannot imply an absent apiKeyHelper"
        )
    stored = replay_stored_subscription_source_evidence(
        stored_subscription_evidence
    )
    if stored["available"]:
        if type(stored_subscription_evidence) is not (
            PromotedStoredSubscriptionSourceEvidence
        ):
            raise ClaudeAuthRouteError(
                "available stored subscription requires promoted neutral "
                "source authority"
            )
        stored = (
            stored_subscription_evidence
            ._consume_for_auth_observation()
        )
    core = {
        "schema": AUTH_SOURCE_OBSERVATION_SCHEMA,
        "environment_key_set_sha256": _key_set_digest(source),
        "environment_route_sources": _environment_route_sources(
            source,
            names,
        ),
        "api_key_helper_configured": helper_configured,
        "settings_authority_sha256": settings_authority_sha256,
        "stored_subscription_evidence": stored,
        "credential_values_recorded": False,
        "credential_content_hashes_recorded": False,
    }
    receipt = {**core, "receipt_sha256": _digest(core)}
    issuance_id = secrets.token_hex(32)
    with _AUTH_CAPABILITY_LOCK:
        _AUTH_SOURCE_PENDING[issuance_id] = {
            "receipt": receipt,
            "environment": source,
        }
    try:
        return ClaudeAuthSourceCapability(
            receipt,
            environment=source,
            _token=_PROMOTION_TOKEN,
            _issuance_id=issuance_id,
        )
    finally:
        with _AUTH_CAPABILITY_LOCK:
            _AUTH_SOURCE_PENDING.pop(issuance_id, None)


def replay_claude_auth_source_observation(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ClaudeAuthRouteError(
            "Claude auth source observation must be an object"
        )
    clone = dict(value)
    expected_fields = {
        "schema",
        "environment_key_set_sha256",
        "environment_route_sources",
        "api_key_helper_configured",
        "settings_authority_sha256",
        "stored_subscription_evidence",
        "credential_values_recorded",
        "credential_content_hashes_recorded",
        "receipt_sha256",
    }
    if set(clone) != expected_fields:
        raise ClaudeAuthRouteError(
            "Claude auth source observation fields drifted"
        )
    digest = clone.pop("receipt_sha256")
    sources = clone.get("environment_route_sources")
    helper = clone.get("api_key_helper_configured")
    settings_digest = clone.get("settings_authority_sha256")
    try:
        stored = replay_stored_subscription_source_evidence(
            clone.get("stored_subscription_evidence")
        )
    except ClaudeAuthRouteError as exc:
        raise ClaudeAuthRouteError(
            f"Claude auth source observation does not replay: {exc}"
        ) from exc
    allowed_sources = set(_CLOUD_SELECTORS.values()) | set(
        _DIRECT_ROUTE_SOURCES.values()
    )
    if (
        clone.get("schema") != AUTH_SOURCE_OBSERVATION_SCHEMA
        or not _valid_sha256(clone.get("environment_key_set_sha256"))
        or not isinstance(sources, list)
        or any(source not in allowed_sources for source in sources)
        or sources != sorted(set(sources))
        or not isinstance(helper, bool)
        or (
            helper
            and not _valid_sha256(settings_digest)
        )
        or (not helper and settings_digest is not None)
        or clone.get("credential_values_recorded") is not False
        or clone.get("credential_content_hashes_recorded") is not False
        or not _valid_sha256(digest)
    ):
        raise ClaudeAuthRouteError(
            "Claude auth source observation does not replay"
        )
    clone["stored_subscription_evidence"] = stored
    if digest != _digest(clone):
        raise ClaudeAuthRouteError(
            "Claude auth source observation digest drifted"
        )
    return {**clone, "receipt_sha256": digest}


def _present_route_rows(
    environment: Mapping[str, str],
    canonical_names: Mapping[str, str],
    *,
    api_key_helper_configured: bool,
    stored_subscription_available: bool,
) -> tuple[list[str], list[str]]:
    cloud = [
        route
        for route, source in _CLOUD_SELECTORS.items()
        if _truthy(_lookup(environment, canonical_names, source))
    ]
    present: list[str] = list(cloud)
    source_names = [_CLOUD_SELECTORS[route] for route in cloud]
    for route in ("AUTH_TOKEN", "API_KEY"):
        source = _DIRECT_ROUTE_SOURCES[route]
        value = _lookup(environment, canonical_names, source)
        if value is not None and bool(value):
            present.append(route)
            source_names.append(source)
    if api_key_helper_configured:
        present.append("API_KEY_HELPER")
        source_names.append("SETTINGS_API_KEY_HELPER")
    oauth_source = _DIRECT_ROUTE_SOURCES["OAUTH_TOKEN"]
    oauth_value = _lookup(environment, canonical_names, oauth_source)
    if oauth_value is not None and bool(oauth_value):
        present.append("OAUTH_TOKEN")
        source_names.append(oauth_source)
    if stored_subscription_available:
        present.append("STORED_SUBSCRIPTION_OAUTH")
        source_names.append("STORED_SUBSCRIPTION_CREDENTIAL")
    present.sort(key=_ROUTE_ORDER.index)
    return present, sorted(source_names)


def _selected_route(present: list[str]) -> str:
    clouds = [route for route in present if route.startswith("CLOUD_")]
    if len(clouds) > 1:
        return "AMBIGUOUS_CLOUD_PROVIDER"
    return present[0] if present else "UNAVAILABLE"


def _reconcile_observation_environment(
    environment: Mapping[str, str],
    observation: Mapping[str, Any],
) -> tuple[dict[str, str], dict[str, str], dict[str, Any]]:
    if type(observation) is not ClaudeAuthSourceCapability:
        raise ClaudeAuthRouteError(
            "live promoted Claude auth-source capability is required"
        )
    source = observation._assert_environment(environment)
    source, names = _normalize_environment(source)
    replayed = replay_claude_auth_source_observation(observation)
    if (
        replayed["environment_key_set_sha256"] != _key_set_digest(source)
        or replayed["environment_route_sources"]
        != _environment_route_sources(source, names)
    ):
        raise ClaudeAuthRouteError(
            "Claude auth source observation does not match environment"
        )
    return source, names, observation


def classify_claude_auth_route(
    environment: Mapping[str, str],
    *,
    source_observation: Mapping[str, Any],
) -> dict[str, Any]:
    """Classify official precedence from replayed source observations."""

    source, names, observation = _reconcile_observation_environment(
        environment,
        source_observation,
    )
    stored = observation["stored_subscription_evidence"]
    present, source_names = _present_route_rows(
        source,
        names,
        api_key_helper_configured=observation[
            "api_key_helper_configured"
        ],
        stored_subscription_available=stored["available"],
    )
    selected = _selected_route(present)
    shadowed = (
        present[1:]
        if selected not in {"AMBIGUOUS_CLOUD_PROVIDER", "UNAVAILABLE"}
        else list(present)
    )
    core = {
        "schema": AUTH_ROUTE_SCHEMA,
        "source_observation_sha256": observation["receipt_sha256"],
        "selected_route": selected,
        "present_routes": present,
        "shadowed_routes": shadowed,
        "source_names": source_names,
        "credential_values_recorded": False,
        "credential_content_hashes_recorded": False,
    }
    return {**core, "receipt_sha256": _digest(core)}


def replay_claude_auth_route(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Replay a redacted classification receipt without ambient credentials."""

    if not isinstance(value, Mapping):
        raise ClaudeAuthRouteError("auth route receipt must be an object")
    expected_fields = {
        "schema",
        "source_observation_sha256",
        "selected_route",
        "present_routes",
        "shadowed_routes",
        "source_names",
        "credential_values_recorded",
        "credential_content_hashes_recorded",
        "receipt_sha256",
    }
    clone = dict(value)
    if set(clone) != expected_fields:
        raise ClaudeAuthRouteError("auth route receipt fields drifted")
    digest = clone.pop("receipt_sha256")
    present = clone.get("present_routes")
    shadowed = clone.get("shadowed_routes")
    source_names = clone.get("source_names")
    expected_source_names: list[str] = []
    if isinstance(present, list) and all(
        route in _ROUTE_ORDER for route in present
    ):
        for route in present:
            if route in _CLOUD_SELECTORS:
                expected_source_names.append(_CLOUD_SELECTORS[route])
            elif route in _DIRECT_ROUTE_SOURCES:
                expected_source_names.append(_DIRECT_ROUTE_SOURCES[route])
            elif route == "API_KEY_HELPER":
                expected_source_names.append("SETTINGS_API_KEY_HELPER")
            elif route == "STORED_SUBSCRIPTION_OAUTH":
                expected_source_names.append(
                    "STORED_SUBSCRIPTION_CREDENTIAL"
                )
        expected_source_names.sort()
    if (
        clone.get("schema") != AUTH_ROUTE_SCHEMA
        or not _valid_sha256(clone.get("source_observation_sha256"))
        or clone.get("credential_values_recorded") is not False
        or clone.get("credential_content_hashes_recorded") is not False
        or not isinstance(present, list)
        or any(route not in _ROUTE_ORDER for route in present)
        or present != sorted(set(present), key=_ROUTE_ORDER.index)
        or not isinstance(shadowed, list)
        or any(route not in present for route in shadowed)
        or not isinstance(source_names, list)
        or any(
            not isinstance(name, str) or not name
            for name in source_names
        )
        or source_names != sorted(set(source_names))
        or source_names != expected_source_names
        or clone.get("selected_route") != _selected_route(present)
        or shadowed
        != (
            present[1:]
            if clone["selected_route"]
            not in {"AMBIGUOUS_CLOUD_PROVIDER", "UNAVAILABLE"}
            else present
        )
        or not _valid_sha256(digest)
        or digest != _digest(clone)
    ):
        raise ClaudeAuthRouteError("auth route receipt does not replay")
    return {**clone, "receipt_sha256": digest}


def expected_init_api_key_sources(
    *,
    claude_code_version: str,
    desired_route: str,
) -> tuple[str, ...]:
    """Return the exact pinned init vocabulary for one route/version."""

    if (
        not isinstance(claude_code_version, str)
        or _VERSION_RE.fullmatch(claude_code_version) is None
        or desired_route not in _ROUTE_ORDER
    ):
        raise ClaudeAuthRouteError(
            "Claude version or auth route is malformed"
        )
    route_map = _API_KEY_SOURCE_BY_VERSION_ROUTE.get(claude_code_version)
    if route_map is None or desired_route not in route_map:
        raise ClaudeAuthRouteError(
            "Claude auth/init protocol version is unsupported"
        )
    return route_map[desired_route]


def _validate_endpoint_url(name: str, value: str) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 2048
        or "\x00" in value
        or any(ord(char) < 0x20 for char in value)
    ):
        raise ClaudeAuthRouteError(
            f"Claude endpoint value for {name} is malformed"
        )
    if name.endswith("BASE_URL"):
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise ClaudeAuthRouteError(
                "Claude endpoint URL must be credential-free canonical HTTPS"
            )


def compile_claude_endpoint_policy(
    *,
    desired_route: str,
    endpoint_mode: str,
    endpoint_environment: Mapping[str, str],
) -> dict[str, Any]:
    """Compile exact, non-credential endpoint semantics for one route."""

    if desired_route not in _ROUTE_ORDER:
        raise ClaudeAuthRouteError("desired auth route is unsupported")
    if endpoint_mode not in _ENDPOINT_MODES:
        raise ClaudeAuthRouteError("Claude endpoint mode is unsupported")
    endpoint, endpoint_names = _normalize_environment(endpoint_environment)
    canonical: dict[str, str] = {}
    for name, value in endpoint.items():
        expected_name = next(
            (
                candidate
                for candidate in _ALL_ENDPOINT_ENV
                if candidate.casefold() == name.casefold()
            ),
            None,
        )
        if expected_name is None:
            raise ClaudeAuthRouteError(
                "Claude endpoint policy contains an unsupported variable"
            )
        _validate_endpoint_url(expected_name, value)
        canonical[expected_name] = value

    if endpoint_mode == "OFFICIAL_DEFAULT":
        if canonical:
            raise ClaudeAuthRouteError(
                "official Claude endpoint policy cannot carry overrides"
            )
    elif endpoint_mode == "CUSTOM_BASE_URL":
        if (
            desired_route not in _CUSTOM_ENDPOINT_ROUTES
            or set(canonical) != {"ANTHROPIC_BASE_URL"}
        ):
            raise ClaudeAuthRouteError(
                "custom endpoint requires an explicit non-subscription route"
            )
    elif endpoint_mode == "CLOUD_PROVIDER":
        if (
            desired_route not in _CLOUD_SELECTORS
            or not set(canonical).issubset(
                _ENDPOINT_ENV_BY_ROUTE[desired_route]
            )
        ):
            raise ClaudeAuthRouteError(
                "cloud endpoint policy disagrees with selected route"
            )

    core = {
        "schema": AUTH_ENDPOINT_POLICY_SCHEMA,
        "desired_route": desired_route,
        "endpoint_mode": endpoint_mode,
        # Values here are endpoints/resources only.  URL userinfo/query
        # credentials are rejected above.
        "endpoint_environment": dict(sorted(canonical.items())),
        "credential_values_recorded": False,
    }
    return {**core, "receipt_sha256": _digest(core)}


def replay_claude_endpoint_policy(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ClaudeAuthRouteError("Claude endpoint policy must be an object")
    clone = dict(value)
    expected_fields = {
        "schema",
        "desired_route",
        "endpoint_mode",
        "endpoint_environment",
        "credential_values_recorded",
        "receipt_sha256",
    }
    if set(clone) != expected_fields:
        raise ClaudeAuthRouteError("Claude endpoint policy fields drifted")
    digest = clone.pop("receipt_sha256")
    try:
        rebuilt = compile_claude_endpoint_policy(
            desired_route=clone.get("desired_route"),
            endpoint_mode=clone.get("endpoint_mode"),
            endpoint_environment=clone.get("endpoint_environment"),
        )
    except (ClaudeAuthRouteError, TypeError) as exc:
        raise ClaudeAuthRouteError(
            f"Claude endpoint policy does not replay: {exc}"
        ) from exc
    if (
        clone.get("schema") != AUTH_ENDPOINT_POLICY_SCHEMA
        or clone.get("credential_values_recorded") is not False
        or not _valid_sha256(digest)
        or rebuilt != {**clone, "receipt_sha256": digest}
    ):
        raise ClaudeAuthRouteError(
            "Claude endpoint policy does not replay"
        )
    return rebuilt


def compile_claude_auth_route_policy(
    *,
    claude_code_version: str,
    desired_route: str,
    endpoint_policy: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Compile one attempt-independent auth and init-source authority."""

    expected_sources = list(
        expected_init_api_key_sources(
            claude_code_version=claude_code_version,
            desired_route=desired_route,
        )
    )
    endpoint = (
        compile_claude_endpoint_policy(
            desired_route=desired_route,
            endpoint_mode="OFFICIAL_DEFAULT",
            endpoint_environment={},
        )
        if endpoint_policy is None
        else replay_claude_endpoint_policy(endpoint_policy)
    )
    if endpoint["desired_route"] != desired_route:
        raise ClaudeAuthRouteError(
            "Claude endpoint and auth-route policies differ"
        )
    core = {
        "schema": AUTH_ROUTE_POLICY_SCHEMA,
        "claude_code_version": claude_code_version,
        "desired_route": desired_route,
        "expected_init_api_key_sources": expected_sources,
        "endpoint_policy": endpoint,
    }
    return {**core, "policy_sha256": _digest(core)}


def replay_claude_auth_route_policy(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Replay the exact route-to-init mapping without credential evidence."""

    if not isinstance(value, Mapping):
        raise ClaudeAuthRouteError(
            "Claude auth-route policy must be an object"
        )
    clone = dict(value)
    if set(clone) != {
        "schema",
        "claude_code_version",
        "desired_route",
        "expected_init_api_key_sources",
        "endpoint_policy",
        "policy_sha256",
    }:
        raise ClaudeAuthRouteError(
            "Claude auth-route policy fields drifted"
        )
    digest = clone.pop("policy_sha256")
    try:
        rebuilt = compile_claude_auth_route_policy(
            claude_code_version=clone.get("claude_code_version"),
            desired_route=clone.get("desired_route"),
            endpoint_policy=clone.get("endpoint_policy"),
        )
    except (ClaudeAuthRouteError, TypeError) as exc:
        raise ClaudeAuthRouteError(
            f"Claude auth-route policy does not replay: {exc}"
        ) from exc
    if (
        clone.get("schema") != AUTH_ROUTE_POLICY_SCHEMA
        or not _valid_sha256(digest)
        or rebuilt != {**clone, "policy_sha256": digest}
    ):
        raise ClaudeAuthRouteError(
            "Claude auth-route policy mapping does not replay"
        )
    return rebuilt


def _selected_route_source(desired_route: str) -> str | None:
    if desired_route in _CLOUD_SELECTORS:
        return _CLOUD_SELECTORS[desired_route]
    if desired_route in _DIRECT_ROUTE_SOURCES:
        return _DIRECT_ROUTE_SOURCES[desired_route]
    return None


def compile_claude_auth_environment(
    environment: Mapping[str, str],
    *,
    desired_route: str,
    source_observation: Mapping[str, Any],
    claude_code_version: str,
    endpoint_policy: Mapping[str, Any],
) -> tuple[ClaudeAuthEnvironmentCapability, dict[str, Any]]:
    """Remove competitors and retain one exact route and endpoint policy."""

    if desired_route not in _ROUTE_ORDER:
        raise ClaudeAuthRouteError("desired auth route is unsupported")
    source, names, observation = _reconcile_observation_environment(
        environment,
        source_observation,
    )
    ambient = classify_claude_auth_route(
        source,
        source_observation=observation,
    )
    present = set(ambient["present_routes"])
    clouds = {route for route in present if route.startswith("CLOUD_")}
    if len(clouds) > 1:
        raise ClaudeAuthRouteError(
            "conflicting cloud provider selectors are ambiguous"
        )
    if desired_route not in present:
        raise ClaudeAuthRouteError(
            f"desired Claude auth route is unavailable: {desired_route}"
        )
    expected_sources = expected_init_api_key_sources(
        claude_code_version=claude_code_version,
        desired_route=desired_route,
    )
    endpoint = replay_claude_endpoint_policy(endpoint_policy)
    if endpoint["desired_route"] != desired_route:
        raise ClaudeAuthRouteError(
            "Claude endpoint policy route does not match auth route"
        )

    child = dict(source)
    removed: set[str] = set()
    preserved: set[str] = set()
    for route_source in sorted(_ROUTE_AFFECTING_ENV):
        actual = _actual_name(names, route_source)
        if actual is not None:
            child.pop(actual, None)
            removed.add(route_source)
    if observation["api_key_helper_configured"]:
        removed.add("SETTINGS_API_KEY_HELPER")

    keep_source = _selected_route_source(desired_route)
    if keep_source is not None:
        actual = _actual_name(names, keep_source)
        if actual is None:
            raise ClaudeAuthRouteError(
                "desired auth route source disappeared"
            )
        child[keep_source] = (
            "1"
            if desired_route in _CLOUD_SELECTORS
            else source[actual]
        )
        removed.discard(keep_source)
        preserved.add(keep_source)
    elif desired_route == "API_KEY_HELPER":
        removed.discard("SETTINGS_API_KEY_HELPER")
        preserved.add("SETTINGS_API_KEY_HELPER")
    elif desired_route == "STORED_SUBSCRIPTION_OAUTH":
        preserved.add("STORED_SUBSCRIPTION_CREDENTIAL")

    for endpoint_name, endpoint_value in endpoint[
        "endpoint_environment"
    ].items():
        child[endpoint_name] = endpoint_value
        removed.discard(endpoint_name)

    core = {
        "schema": AUTH_ENVIRONMENT_SCHEMA,
        "claude_code_version": claude_code_version,
        "source_observation_sha256": observation["receipt_sha256"],
        "ambient_selected_route": ambient["selected_route"],
        "ambient_route_receipt_sha256": ambient["receipt_sha256"],
        "selected_route": desired_route,
        "expected_init_api_key_sources": list(expected_sources),
        "endpoint_policy": endpoint,
        "removed_route_sources": sorted(removed),
        "preserved_route_sources": sorted(preserved),
        "preserved_endpoint_sources": sorted(
            endpoint["endpoint_environment"]
        ),
        "child_environment_key_set_sha256": _key_set_digest(child),
        "credential_values_recorded": False,
        "credential_content_hashes_recorded": False,
    }
    receipt = {**core, "receipt_sha256": _digest(core)}
    if type(source_observation) is not ClaudeAuthSourceCapability:
        raise ClaudeAuthRouteError(
            "live promoted Claude auth-source capability is required"
        )
    source_observation._consume_environment(environment)
    issuance_id = secrets.token_hex(32)
    with _AUTH_CAPABILITY_LOCK:
        _AUTH_ENVIRONMENT_PENDING[issuance_id] = {
            "environment": dict(child),
            "receipt_sha256": receipt["receipt_sha256"],
        }
    try:
        capability = ClaudeAuthEnvironmentCapability(
            child,
            receipt_sha256=receipt["receipt_sha256"],
            _token=_PROMOTION_TOKEN,
            _issuance_id=issuance_id,
        )
    finally:
        with _AUTH_CAPABILITY_LOCK:
            _AUTH_ENVIRONMENT_PENDING.pop(issuance_id, None)
    return capability, receipt


def replay_claude_auth_environment(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Strict replay for ``AUTH_ENVIRONMENT_SCHEMA``."""

    if not isinstance(value, Mapping):
        raise ClaudeAuthRouteError(
            "Claude auth environment receipt must be an object"
        )
    clone = dict(value)
    expected_fields = {
        "schema",
        "claude_code_version",
        "source_observation_sha256",
        "ambient_selected_route",
        "ambient_route_receipt_sha256",
        "selected_route",
        "expected_init_api_key_sources",
        "endpoint_policy",
        "removed_route_sources",
        "preserved_route_sources",
        "preserved_endpoint_sources",
        "child_environment_key_set_sha256",
        "credential_values_recorded",
        "credential_content_hashes_recorded",
        "receipt_sha256",
    }
    if set(clone) != expected_fields:
        raise ClaudeAuthRouteError(
            "Claude auth environment receipt fields drifted"
        )
    digest = clone.pop("receipt_sha256")
    desired_route = clone.get("selected_route")
    expected_sources = clone.get("expected_init_api_key_sources")
    removed = clone.get("removed_route_sources")
    preserved = clone.get("preserved_route_sources")
    endpoint_sources = clone.get("preserved_endpoint_sources")
    try:
        endpoint = replay_claude_endpoint_policy(
            clone.get("endpoint_policy")
        )
        derived_sources = list(
            expected_init_api_key_sources(
                claude_code_version=clone.get("claude_code_version"),
                desired_route=desired_route,
            )
        )
    except (ClaudeAuthRouteError, TypeError) as exc:
        raise ClaudeAuthRouteError(
            f"Claude auth environment receipt does not replay: {exc}"
        ) from exc
    expected_preserved: list[str]
    keep_source = _selected_route_source(str(desired_route))
    if keep_source is not None:
        expected_preserved = [keep_source]
    elif desired_route == "API_KEY_HELPER":
        expected_preserved = ["SETTINGS_API_KEY_HELPER"]
    elif desired_route == "STORED_SUBSCRIPTION_OAUTH":
        expected_preserved = ["STORED_SUBSCRIPTION_CREDENTIAL"]
    else:
        expected_preserved = []
    allowed_removed = set(_ROUTE_AFFECTING_ENV) | {
        "SETTINGS_API_KEY_HELPER"
    }
    if (
        clone.get("schema") != AUTH_ENVIRONMENT_SCHEMA
        or not _valid_sha256(clone.get("source_observation_sha256"))
        or not _valid_sha256(clone.get("ambient_route_receipt_sha256"))
        or clone.get("ambient_selected_route")
        not in {*_ROUTE_ORDER, "AMBIGUOUS_CLOUD_PROVIDER", "UNAVAILABLE"}
        or desired_route not in _ROUTE_ORDER
        or expected_sources != derived_sources
        or not isinstance(removed, list)
        or any(item not in allowed_removed for item in removed)
        or removed != sorted(set(removed))
        or preserved != expected_preserved
        or endpoint["desired_route"] != desired_route
        or endpoint_sources
        != sorted(endpoint["endpoint_environment"])
        or not _valid_sha256(
            clone.get("child_environment_key_set_sha256")
        )
        or clone.get("credential_values_recorded") is not False
        or clone.get("credential_content_hashes_recorded") is not False
        or not _valid_sha256(digest)
    ):
        raise ClaudeAuthRouteError(
            "Claude auth environment receipt does not replay"
        )
    clone["endpoint_policy"] = endpoint
    if digest != _digest(clone):
        raise ClaudeAuthRouteError(
            "Claude auth environment receipt digest drifted"
        )
    return {**clone, "receipt_sha256": digest}


def reconcile_claude_auth_environment(
    environment: Mapping[str, str],
    receipt: Mapping[str, Any],
    *,
    source_observation: Mapping[str, Any],
) -> dict[str, Any]:
    """Reconcile a concrete in-memory environment against durable authority."""

    replayed = replay_claude_auth_environment(receipt)
    observation = replay_claude_auth_source_observation(
        source_observation
    )
    if (
        replayed["source_observation_sha256"]
        != observation["receipt_sha256"]
    ):
        raise ClaudeAuthRouteError(
            "Claude auth source observation binding drifted"
        )
    if type(environment) is not ClaudeAuthEnvironmentCapability:
        raise ClaudeAuthRouteError(
            "live compiled Claude auth-environment capability is required"
        )
    source = environment._verified_environment(
        receipt_sha256=replayed["receipt_sha256"],
    )
    source, names = _normalize_environment(source)
    if (
        _key_set_digest(source)
        != replayed["child_environment_key_set_sha256"]
    ):
        raise ClaudeAuthRouteError(
            "Claude auth environment key denominator drifted"
        )
    desired_route = replayed["selected_route"]
    stored_available = (
        desired_route == "STORED_SUBSCRIPTION_OAUTH"
        and observation["stored_subscription_evidence"]["available"]
    )
    helper_configured = (
        desired_route == "API_KEY_HELPER"
        and observation["api_key_helper_configured"]
    )
    present, _ = _present_route_rows(
        source,
        names,
        api_key_helper_configured=helper_configured,
        stored_subscription_available=stored_available,
    )
    if present != [desired_route] or _selected_route(present) != desired_route:
        raise ClaudeAuthRouteError(
            "Claude selected auth route was not preserved"
        )

    endpoint = replayed["endpoint_policy"]
    expected_endpoint = endpoint["endpoint_environment"]
    for endpoint_name in _ALL_ENDPOINT_ENV:
        actual = _lookup(source, names, endpoint_name)
        if endpoint_name in expected_endpoint:
            if actual != expected_endpoint[endpoint_name]:
                raise ClaudeAuthRouteError(
                    "Claude auth endpoint environment drifted"
                )
        elif actual is not None:
            raise ClaudeAuthRouteError(
                "unselected Claude endpoint source survived"
            )
    return replayed


__all__ = [
    "AUTH_ENDPOINT_POLICY_SCHEMA",
    "AUTH_ENVIRONMENT_SCHEMA",
    "AUTH_ROUTE_SCHEMA",
    "AUTH_ROUTE_POLICY_SCHEMA",
    "AUTH_SOURCE_OBSERVATION_SCHEMA",
    "STORED_SUBSCRIPTION_SOURCE_SCHEMA",
    "ClaudeAuthEnvironmentCapability",
    "ClaudeAuthRouteError",
    "ClaudeAuthSourceCapability",
    "ClaudeSettingsHelperAuthority",
    "PromotedStoredSubscriptionSourceEvidence",
    "classify_claude_auth_route",
    "compile_claude_auth_environment",
    "compile_claude_auth_route_policy",
    "compile_claude_endpoint_policy",
    "compile_claude_settings_helper_authority",
    "expected_init_api_key_sources",
    "observe_claude_auth_sources",
    "reconcile_claude_auth_environment",
    "replay_claude_auth_environment",
    "replay_claude_auth_route",
    "replay_claude_auth_route_policy",
    "replay_claude_auth_source_observation",
    "replay_claude_endpoint_policy",
    "replay_stored_subscription_source_evidence",
]
