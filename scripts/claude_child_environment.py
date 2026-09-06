"""Compile one minimal Claude worker environment.

The compiler starts from an empty mapping.  It re-adds only:

* a selected, replayed Claude authentication route;
* an attempt-private Claude config/temp overlay;
* reviewed functional controls; and
* explicitly named OS/toolchain environment policies.

``HOME`` and the platform toolchain discovery roots are preserved by default.
Credential-bearing values are protected only by a per-object random-key HMAC.
No unkeyed secret-derived digest is retained or placed in a durable receipt.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import threading
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from claude_auth_route import (
    ClaudeAuthEnvironmentCapability,
    ClaudeAuthRouteError,
    reconcile_claude_auth_environment,
    replay_claude_auth_environment,
    replay_claude_auth_source_observation,
)


CHILD_ENVIRONMENT_SCHEMA = "plamen.claude_child_environment.v2"
PRIVATE_HOME_OVERLAY_AUTHORITY_SCHEMA = (
    "plamen.claude_private_home_overlay_authority.v1"
)
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_POSITIVE_INTEGER_RE = re.compile(r"[1-9][0-9]{0,11}")

_POLICY_ENVIRONMENT_NAMES: dict[str, frozenset[str]] = {
    # Platform process and tool discovery.  Deliberately includes the user's
    # actual home/config roots: replacing these with an empty profile breaks
    # compiler, package-manager, Git, certificate, and keychain discovery.
    "base": frozenset(
        {
            "PATH",
            "PATHEXT",
            "SYSTEMROOT",
            "WINDIR",
            "COMSPEC",
            "SYSTEMDRIVE",
            "HOME",
            "USERPROFILE",
            "HOMEDRIVE",
            "HOMEPATH",
            "APPDATA",
            "LOCALAPPDATA",
            "XDG_CONFIG_HOME",
            "XDG_CACHE_HOME",
            "XDG_DATA_HOME",
            "TMP",
            "TEMP",
            "TMPDIR",
            "LANG",
            "LC_ALL",
            "LC_CTYPE",
        }
    ),
    "certificates": frozenset(
        {
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
            "REQUESTS_CA_BUNDLE",
            "CURL_CA_BUNDLE",
            "NODE_EXTRA_CA_CERTS",
        }
    ),
    "git": frozenset(
        {
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_SYSTEM",
            "GIT_CONFIG_NOSYSTEM",
            "GIT_EXEC_PATH",
            "GIT_TEMPLATE_DIR",
            "GIT_CEILING_DIRECTORIES",
        }
    ),
    "node": frozenset(
        {
            "NPM_CONFIG_USERCONFIG",
            "NPM_CONFIG_CACHE",
            "COREPACK_HOME",
            "PNPM_HOME",
            "YARN_CACHE_FOLDER",
        }
    ),
    "rust": frozenset(
        {
            "CARGO_HOME",
            "RUSTUP_HOME",
            "CARGO_TARGET_DIR",
            "RUST_BACKTRACE",
        }
    ),
    "go": frozenset(
        {
            "GOROOT",
            "GOPATH",
            "GOMODCACHE",
            "GOCACHE",
            "GOENV",
            "GOPROXY",
            "GONOPROXY",
            "GONOSUMDB",
            "GOPRIVATE",
            "GOTOOLCHAIN",
            "CGO_ENABLED",
        }
    ),
    "evm": frozenset(
        {
            "FOUNDRY_PROFILE",
            "FOUNDRY_CACHE_PATH",
            "FOUNDRY_OUT",
            "DAPP_BUILD_OPTIMIZE",
        }
    ),
    "solana": frozenset(
        {
            "SOLANA_CONFIG_FILE",
            "ANCHOR_HOME",
            "AVM_HOME",
        }
    ),
    "aptos": frozenset({"APTOS_HOME"}),
    "sui": frozenset({"SUI_CONFIG_DIR"}),
    "soroban": frozenset(
        {
            "STELLAR_CONFIG_DIR",
            "SOROBAN_RPC_URL",
            "SOROBAN_NETWORK_PASSPHRASE",
        }
    ),
    "l1-native": frozenset(
        {
            "CMAKE_PREFIX_PATH",
            "CMAKE_GENERATOR",
            "MAKEFLAGS",
            "PKG_CONFIG_PATH",
            "LIBRARY_PATH",
            "LD_LIBRARY_PATH",
            "DYLD_LIBRARY_PATH",
            "INCLUDE",
            "LIB",
        }
    ),
    "plamen": frozenset(
        {
            "PLAMEN_SCRATCHPAD",
            "PLAMEN_AUDIT_ROOT",
            "PLAMEN_RUN_ID",
        }
    ),
}

_ATTEMPT_PROFILE_KEYS = frozenset(
    {
        "CLAUDE_CONFIG_DIR",
        "CLAUDE_CODE_TMPDIR",
        "TMP",
        "TEMP",
        "TMPDIR",
    }
)
_TOOLCHAIN_HOME_KEYS = frozenset(
    {
        "HOME",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "XDG_CONFIG_HOME",
        "XDG_CACHE_HOME",
        "XDG_DATA_HOME",
    }
)
_PRIVATE_HOME_REQUIRED_KEYS = frozenset(
    {
        "HOME",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "XDG_CONFIG_HOME",
        "XDG_CACHE_HOME",
        "XDG_DATA_HOME",
    }
)
_BOOLEAN_FUNCTIONAL_CONTROLS = frozenset(
    {
        "CLAUDE_CODE_DISABLE_AUTO_MEMORY",
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
        "CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL",
        "CLAUDE_CODE_SKIP_PROMPT_HISTORY",
        "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB",
        "DISABLE_AUTOUPDATER",
        "DISABLE_TELEMETRY",
        "DISABLE_ERROR_REPORTING",
        "DISABLE_UPDATES",
    }
)
_FALSE_FUNCTIONAL_CONTROLS = frozenset({"ENABLE_CLAUDEAI_MCP_SERVERS"})
_NUMERIC_FUNCTIONAL_CONTROLS = frozenset()
_REVIEWED_FUNCTIONAL_CONTROLS = (
    _BOOLEAN_FUNCTIONAL_CONTROLS
    | _FALSE_FUNCTIONAL_CONTROLS
    | _NUMERIC_FUNCTIONAL_CONTROLS
)
_FUNCTIONAL_CONTROLS_BY_VERSION = {
    "2.1.220": _REVIEWED_FUNCTIONAL_CONTROLS,
    "2.1.250": _REVIEWED_FUNCTIONAL_CONTROLS,
    "2.1.252": _REVIEWED_FUNCTIONAL_CONTROLS,
}
_REQUIRED_FUNCTIONAL_CONTROLS_BY_VERSION = {
    "2.1.220": {
        "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1",
        "CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL": "1",
        "DISABLE_AUTOUPDATER": "1",
        "DISABLE_UPDATES": "1",
        "ENABLE_CLAUDEAI_MCP_SERVERS": "false",
    },
    "2.1.250": {
        "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1",
        "CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL": "1",
        "DISABLE_AUTOUPDATER": "1",
        "DISABLE_UPDATES": "1",
        "ENABLE_CLAUDEAI_MCP_SERVERS": "false",
    },
    "2.1.252": {
        "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1",
        "CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL": "1",
        "DISABLE_AUTOUPDATER": "1",
        "DISABLE_UPDATES": "1",
        "ENABLE_CLAUDEAI_MCP_SERVERS": "false",
    },
}
_CLOUD_CREDENTIAL_ENV = {
    "CLOUD_BEDROCK": frozenset(
        {
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "AWS_PROFILE",
            "AWS_REGION",
            "AWS_DEFAULT_REGION",
            "AWS_BEARER_TOKEN_BEDROCK",
        }
    ),
    "CLOUD_VERTEX": frozenset(
        {
            "GOOGLE_APPLICATION_CREDENTIALS",
            "GOOGLE_CLOUD_PROJECT",
            "CLOUD_ML_REGION",
        }
    ),
    "CLOUD_FOUNDRY": frozenset(
        {
            "AZURE_CLIENT_ID",
            "AZURE_CLIENT_SECRET",
            "AZURE_TENANT_ID",
            "AZURE_FEDERATED_TOKEN_FILE",
        }
    ),
}
_SELECTED_ROUTE_ENV = {
    "CLOUD_BEDROCK": frozenset({"CLAUDE_CODE_USE_BEDROCK"}),
    "CLOUD_VERTEX": frozenset({"CLAUDE_CODE_USE_VERTEX"}),
    "CLOUD_FOUNDRY": frozenset({"CLAUDE_CODE_USE_FOUNDRY"}),
    "AUTH_TOKEN": frozenset({"ANTHROPIC_AUTH_TOKEN"}),
    "API_KEY": frozenset({"ANTHROPIC_API_KEY"}),
    "API_KEY_HELPER": frozenset(),
    "OAUTH_TOKEN": frozenset({"CLAUDE_CODE_OAUTH_TOKEN"}),
    "STORED_SUBSCRIPTION_OAUTH": frozenset(),
}
_SENSITIVE_EXACT_NAMES = {
    "SSH_AUTH_SOCK",
    "SSH_AGENT_PID",
    "KUBECONFIG",
    "DOCKER_CONFIG",
    "NETRC",
}
_SENSITIVE_PREFIXES = (
    "AWS_",
    "AZURE_",
    "GOOGLE_",
    "GITHUB_",
    "GITLAB_",
)
_SENSITIVE_SUFFIXES = (
    "_TOKEN",
    "_KEY",
    "_SECRET",
    "_PASSWORD",
    "_CREDENTIAL",
    "_CREDENTIALS",
)


class ClaudeChildEnvironmentError(RuntimeError):
    """A child environment layer is ambiguous, unreviewed, or drifted."""


_PRIVATE_HOME_OVERLAY_TOKEN = object()


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
        raise ClaudeChildEnvironmentError(
            "Claude child environment receipt is not canonical JSON"
        ) from exc


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _key_set_digest(environment: Mapping[str, str]) -> str:
    return hashlib.sha256(
        "\0".join(sorted(name.casefold() for name in environment)).encode(
            "utf-8"
        )
    ).hexdigest()


def _key_names_digest(names: Sequence[str]) -> str:
    folded = [name.casefold() for name in names]
    if len(folded) != len(set(folded)):
        raise ClaudeChildEnvironmentError(
            "planned Claude child environment keys collide"
        )
    return hashlib.sha256(
        "\0".join(sorted(folded)).encode("utf-8")
    ).hexdigest()


def _environment_integrity_material(
    environment: Mapping[str, str],
) -> bytes:
    material = "\0".join(
        f"{name.casefold()}={environment[name]}"
        for name in sorted(environment, key=str.casefold)
    )
    return material.encode("utf-8")


def _environment_integrity_tag(
    environment: Mapping[str, str],
    key: bytearray,
) -> bytes:
    return hmac.digest(
        bytes(key),
        _environment_integrity_material(environment),
        "sha256",
    )


def _zeroize(value: bytearray) -> None:
    for index in range(len(value)):
        value[index] = 0


def _normalize_environment(
    environment: Mapping[str, str],
    *,
    label: str,
) -> tuple[dict[str, str], dict[str, str]]:
    if not isinstance(environment, Mapping):
        raise ClaudeChildEnvironmentError(f"{label} must be a mapping")
    normalized: dict[str, str] = {}
    names: dict[str, str] = {}
    for raw_name, raw_value in environment.items():
        if (
            not isinstance(raw_name, str)
            or not raw_name
            or "=" in raw_name
            or "\x00" in raw_name
            or not isinstance(raw_value, str)
            or "\x00" in raw_value
        ):
            raise ClaudeChildEnvironmentError(
                f"{label} contains malformed text"
            )
        folded = raw_name.casefold()
        if folded in names:
            raise ClaudeChildEnvironmentError(
                f"{label} has case-ambiguous variable names"
            )
        names[folded] = raw_name
        normalized[raw_name] = raw_value
    return normalized, names


def _lookup(
    environment: Mapping[str, str],
    names: Mapping[str, str],
    canonical_name: str,
) -> str | None:
    actual = names.get(canonical_name.casefold())
    return None if actual is None else environment[actual]


def _canonical_selected_policies(
    policies: Sequence[str],
) -> list[str]:
    if isinstance(policies, (str, bytes)) or not isinstance(
        policies,
        Sequence,
    ):
        raise ClaudeChildEnvironmentError(
            "phase/toolchain policy denominator must be a sequence"
        )
    selected = list(policies)
    if (
        any(
            not isinstance(policy, str)
            or policy not in _POLICY_ENVIRONMENT_NAMES
            for policy in selected
        )
        or len(set(selected)) != len(selected)
        or "base" not in selected
    ):
        raise ClaudeChildEnvironmentError(
            "phase/toolchain environment policy is unknown or lacks base"
        )
    return sorted(selected)


def _canonical_functional_controls(
    controls: Mapping[str, str],
    *,
    claude_code_version: str,
) -> dict[str, str]:
    source, names = _normalize_environment(
        controls,
        label="functional controls",
    )
    allowed = _FUNCTIONAL_CONTROLS_BY_VERSION.get(claude_code_version)
    required = _REQUIRED_FUNCTIONAL_CONTROLS_BY_VERSION.get(
        claude_code_version
    )
    if allowed is None or required is None:
        raise ClaudeChildEnvironmentError(
            "Claude functional-control version is unsupported"
        )
    canonical: dict[str, str] = {}
    for actual_name, value in source.items():
        name = next(
            (
                candidate
                for candidate in allowed
                if candidate.casefold() == actual_name.casefold()
            ),
            None,
        )
        if name is None:
            raise ClaudeChildEnvironmentError(
                "unreviewed Claude functional control"
            )
        if name in _BOOLEAN_FUNCTIONAL_CONTROLS:
            if value != "1":
                raise ClaudeChildEnvironmentError(
                    "Claude boolean functional control must equal 1"
                )
        elif name in _FALSE_FUNCTIONAL_CONTROLS:
            if value != "false":
                raise ClaudeChildEnvironmentError(
                    "Claude disable-by-false functional control must equal false"
                )
        elif _POSITIVE_INTEGER_RE.fullmatch(value) is None:
            raise ClaudeChildEnvironmentError(
                "Claude numeric functional control is malformed"
            )
        canonical[name] = value
    if any(canonical.get(name) != value for name, value in required.items()):
        raise ClaudeChildEnvironmentError(
            "required Claude functional control is missing or substituted"
        )
    return dict(sorted(canonical.items()))


def normalize_claude_phase_environment_policies(
    policies: Sequence[str],
) -> list[str]:
    """Public exact compiler shared by WorkPlan and runtime authorities."""

    return _canonical_selected_policies(policies)


def normalize_claude_functional_controls(
    controls: Mapping[str, str],
    *,
    claude_code_version: str,
) -> dict[str, str]:
    """Public version-pinned compiler for reviewed functional controls."""

    return _canonical_functional_controls(
        controls,
        claude_code_version=claude_code_version,
    )


def _is_sensitive_name(name: str) -> bool:
    upper = name.upper()
    return (
        upper in _SENSITIVE_EXACT_NAMES
        or upper.startswith(_SENSITIVE_PREFIXES)
        or upper.endswith(_SENSITIVE_SUFFIXES)
    )


def planned_claude_child_environment_names(
    *,
    ambient: Mapping[str, str],
    selected_route: str,
    endpoint_environment_names: Sequence[str],
    phase_environment_policies: Sequence[str],
    functional_control_names: Sequence[str],
    home_variable_policy: str,
) -> tuple[str, ...]:
    """Derive the exact attempt-independent final environment names.

    No credential value or profile path is required.  WER later compiles the
    concrete environment and exact-compares its redacted names/digest to this
    WorkPlan authority.  Values are never returned.
    """

    _source, names = _normalize_environment(
        ambient,
        label="ambient environment",
    )
    policies = _canonical_selected_policies(phase_environment_policies)
    if selected_route not in _SELECTED_ROUTE_ENV:
        raise ClaudeChildEnvironmentError(
            "selected Claude auth route is unsupported"
        )
    if home_variable_policy not in {
        "PRIVATE_HOME",
        "PRESERVE_TOOLCHAIN_HOME",
    }:
        raise ClaudeChildEnvironmentError(
            "home variable policy is unsupported"
        )
    endpoint_names = _canonical_selected_names(
        endpoint_environment_names,
        allowed={
            "ANTHROPIC_BASE_URL",
            "ANTHROPIC_BEDROCK_BASE_URL",
            "ANTHROPIC_VERTEX_BASE_URL",
            "ANTHROPIC_FOUNDRY_BASE_URL",
            "ANTHROPIC_FOUNDRY_RESOURCE",
        },
        label="Claude endpoint environment names",
    )
    controls = _canonical_selected_names(
        functional_control_names,
        allowed=_REVIEWED_FUNCTIONAL_CONTROLS,
        label="Claude functional control names",
    )
    planned: set[str] = set()
    allowed_policy_names = set().union(
        *(_POLICY_ENVIRONMENT_NAMES[policy] for policy in policies)
    )
    for canonical_name in allowed_policy_names:
        if (
            home_variable_policy == "PRIVATE_HOME"
            and canonical_name in _TOOLCHAIN_HOME_KEYS
        ):
            continue
        if canonical_name.casefold() in names:
            planned.add(canonical_name)
    planned.update(_ATTEMPT_PROFILE_KEYS)
    if home_variable_policy == "PRIVATE_HOME":
        planned.update(_PRIVATE_HOME_REQUIRED_KEYS)
    planned.update(_SELECTED_ROUTE_ENV[selected_route])
    planned.update(endpoint_names)
    planned.update(controls)
    for credential_name in _CLOUD_CREDENTIAL_ENV.get(selected_route, ()):
        if credential_name.casefold() in names:
            planned.add(credential_name)
    return tuple(sorted(planned, key=str.casefold))


def planned_claude_child_environment_key_set_sha256(
    *,
    ambient: Mapping[str, str],
    selected_route: str,
    endpoint_environment_names: Sequence[str],
    phase_environment_policies: Sequence[str],
    functional_control_names: Sequence[str],
    home_variable_policy: str,
) -> str:
    """Digest the exact names emitted by the shared planning compiler."""

    return _key_names_digest(
        planned_claude_child_environment_names(
            ambient=ambient,
            selected_route=selected_route,
            endpoint_environment_names=endpoint_environment_names,
            phase_environment_policies=phase_environment_policies,
            functional_control_names=functional_control_names,
            home_variable_policy=home_variable_policy,
        )
    )


def _canonical_selected_names(
    value: Sequence[str],
    *,
    allowed: set[str] | frozenset[str],
    label: str,
) -> list[str]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ClaudeChildEnvironmentError(f"{label} must be a sequence")
    result = list(value)
    if (
        any(not isinstance(name, str) or name not in allowed for name in result)
        or len(result) != len(set(result))
    ):
        raise ClaudeChildEnvironmentError(
            f"{label} is duplicated or unsupported"
        )
    return sorted(result)


class ClaudePrivateHomeOverlayAuthority:
    """One-shot attempt-profile authority for a closed private HOME overlay."""

    __slots__ = (
        "__active",
        "__authority_sha256",
        "__environment",
        "__integrity_key",
        "__integrity_tag",
        "__lock",
    )

    def __init__(
        self,
        *,
        environment: Mapping[str, str],
        authority_sha256: str,
        _token: object,
    ) -> None:
        if _token is not _PRIVATE_HOME_OVERLAY_TOKEN:
            raise TypeError(
                "private-home overlay authority is attempt-profile-owned"
            )
        source, _names = _normalize_environment(
            environment,
            label="private-home overlay",
        )
        self.__environment = source
        self.__authority_sha256 = authority_sha256
        self.__integrity_key = bytearray(secrets.token_bytes(32))
        self.__integrity_tag = bytearray(
            _environment_integrity_tag(source, self.__integrity_key)
        )
        self.__active = True
        self.__lock = threading.Lock()

    def __repr__(self) -> str:
        return "<ClaudePrivateHomeOverlayAuthority opaque>"

    def __copy__(self) -> None:
        raise TypeError("private-home overlay authority cannot be copied")

    def __deepcopy__(self, _memo: object) -> None:
        raise TypeError("private-home overlay authority cannot be copied")

    def __reduce__(self) -> None:
        raise TypeError(
            "private-home overlay authority cannot be serialized"
        )

    def _consume(
        self,
        *,
        attempt_profile_environment: Mapping[str, str],
    ) -> tuple[dict[str, str], str]:
        with self.__lock:
            if not self.__active:
                raise ClaudeChildEnvironmentError(
                    "private-home overlay authority is stale or consumed"
                )
            source, _names = _normalize_environment(
                self.__environment,
                label="private-home overlay",
            )
            actual = _environment_integrity_tag(
                source,
                self.__integrity_key,
            )
            if not hmac.compare_digest(actual, self.__integrity_tag):
                raise ClaudeChildEnvironmentError(
                    "private-home overlay authority was rebound"
                )
            supplied, supplied_names = _normalize_environment(
                attempt_profile_environment,
                label="attempt profile environment",
            )
            source_names = {
                name.casefold(): name
                for name in source
            }
            for name in (
                _ATTEMPT_PROFILE_KEYS
                | {
                    "HOME",
                    "USERPROFILE",
                    "APPDATA",
                    "LOCALAPPDATA",
                }
            ):
                expected = _lookup(source, source_names, name)
                if expected is None:
                    continue
                if _lookup(supplied, supplied_names, name) != expected:
                    raise ClaudeChildEnvironmentError(
                        "private-home overlay differs from attempt profile"
                    )
            self.__active = False
            _zeroize(self.__integrity_key)
            _zeroize(self.__integrity_tag)
            self.__environment.clear()
            return source, self.__authority_sha256


def _mint_claude_private_home_overlay_authority(
    *,
    attempt_profile_environment: Mapping[str, str],
    attempt_profile_binding: Mapping[str, Any],
) -> ClaudePrivateHomeOverlayAuthority:
    """Attempt-profile-only bridge into the child environment compiler."""

    if not isinstance(attempt_profile_binding, Mapping):
        raise ClaudeChildEnvironmentError(
            "attempt-profile binding is required for private HOME"
        )
    binding = dict(attempt_profile_binding)
    profile_sha256 = binding.get("profile_sha256")
    core = dict(binding)
    core.pop("profile_sha256", None)
    if (
        binding.get("schema") != "plamen.claude_attempt_profile.v3"
        or binding.get("home_variable_policy") != "PRIVATE_HOME"
        or not isinstance(profile_sha256, str)
        or _SHA256_RE.fullmatch(profile_sha256) is None
        or _digest(core) != profile_sha256
        or binding.get("execution_generation_sha256")
        not in {None, binding.get("work_plan_sha256")}
        or not isinstance(binding.get("work_plan_sha256"), str)
        or _SHA256_RE.fullmatch(binding["work_plan_sha256"]) is None
    ):
        raise ClaudeChildEnvironmentError(
            "attempt-profile binding cannot authorize private HOME"
        )
    source, names = _normalize_environment(
        attempt_profile_environment,
        label="attempt profile environment",
    )
    required_original = {
        "CLAUDE_CONFIG_DIR",
        "CLAUDE_CODE_TMPDIR",
        "HOME",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
    }
    if any(_lookup(source, names, name) in {None, ""} for name in required_original):
        raise ClaudeChildEnvironmentError(
            "attempt profile lacks private-home roots"
        )
    from pathlib import Path  # local to keep path logic at the authority edge

    home = Path(str(_lookup(source, names, "HOME")))
    if (
        str(home) != _lookup(source, names, "USERPROFILE")
        or not home.is_absolute()
    ):
        raise ClaudeChildEnvironmentError(
            "attempt profile private HOME roots disagree"
        )
    overlay = dict(source)
    overlay.update(
        {
            "XDG_CONFIG_HOME": str(home / ".config"),
            "XDG_CACHE_HOME": str(home / ".cache"),
            "XDG_DATA_HOME": str(home / ".local" / "share"),
        }
    )
    authority_core = {
        "schema": PRIVATE_HOME_OVERLAY_AUTHORITY_SCHEMA,
        "run_id": binding.get("run_id"),
        "execution_generation_sha256": binding["work_plan_sha256"],
        "attempt_id": binding.get("attempt_id"),
        "attempt_profile_binding_sha256": profile_sha256,
        "home_overlay_names": sorted(
            _PRIVATE_HOME_REQUIRED_KEYS,
            key=str.casefold,
        ),
        "home_overlay_value_denominator_sha256": hashlib.sha256(
            _environment_integrity_material(
                {
                    name: overlay[name]
                    for name in _PRIVATE_HOME_REQUIRED_KEYS
                }
            )
        ).hexdigest(),
    }
    if (
        not isinstance(authority_core["run_id"], str)
        or not authority_core["run_id"]
        or not isinstance(authority_core["attempt_id"], str)
        or not authority_core["attempt_id"]
    ):
        raise ClaudeChildEnvironmentError(
            "attempt-profile execution identity is malformed"
        )
    return ClaudePrivateHomeOverlayAuthority(
        environment=overlay,
        authority_sha256=_digest(authority_core),
        _token=_PRIVATE_HOME_OVERLAY_TOKEN,
    )


class CompiledClaudeChildEnvironment:
    """Opaque in-memory environment plus redacted durable authority."""

    __slots__ = (
        "__active",
        "__environment",
        "__integrity_key",
        "__integrity_tag",
        "__lock",
        "__private_home_overlay_authority_sha256",
        "__receipt",
        "_auth_environment_receipt",
        "_source_observation",
    )

    def __init__(
        self,
        *,
        environment: Mapping[str, str],
        receipt: Mapping[str, Any],
        auth_environment_receipt: Mapping[str, Any],
        source_observation: Mapping[str, Any],
        private_home_overlay_authority_sha256: str | None,
    ) -> None:
        source = dict(environment)
        key = bytearray(secrets.token_bytes(32))
        self.__environment = source
        self.__integrity_key = key
        self.__integrity_tag = bytearray(
            _environment_integrity_tag(source, key)
        )
        self.__receipt = dict(receipt)
        self._auth_environment_receipt = dict(
            auth_environment_receipt
        )
        self._source_observation = dict(source_observation)
        self.__private_home_overlay_authority_sha256 = (
            private_home_overlay_authority_sha256
        )
        self.__active = True
        self.__lock = threading.RLock()

    @property
    def environment(self) -> Mapping[str, str]:
        with self.__lock:
            if not self.__active:
                raise ClaudeChildEnvironmentError(
                    "compiled Claude child environment is invalidated"
                )
            return MappingProxyType(dict(self.__environment))

    @property
    def receipt(self) -> dict[str, Any]:
        return json.loads(_canonical_json(self.__receipt).decode("utf-8"))

    @property
    def active(self) -> bool:
        with self.__lock:
            return self.__active

    def __repr__(self) -> str:
        return (
            "CompiledClaudeChildEnvironment("
            f"receipt_sha256={self.receipt.get('receipt_sha256')!r})"
        )

    def __reduce__(self) -> None:
        raise TypeError(
            "CompiledClaudeChildEnvironment cannot be serialized"
        )

    def __copy__(self) -> None:
        raise TypeError(
            "CompiledClaudeChildEnvironment cannot be copied"
        )

    def __deepcopy__(self, _memo: object) -> None:
        raise TypeError(
            "CompiledClaudeChildEnvironment cannot be copied"
        )

    def _verified_environment(self) -> dict[str, str]:
        with self.__lock:
            if not self.__active:
                raise ClaudeChildEnvironmentError(
                    "compiled Claude child environment is invalidated"
                )
            actual = _environment_integrity_tag(
                self.__environment,
                self.__integrity_key,
            )
            if not hmac.compare_digest(
                actual,
                self.__integrity_tag,
            ):
                raise ClaudeChildEnvironmentError(
                    "compiled Claude child environment values drifted"
                )
            return dict(self.__environment)

    def _invalidate_private_values(self) -> None:
        """Drop secret values and zero private integrity material once."""

        with self.__lock:
            if not self.__active:
                return
            self.__environment.clear()
            _zeroize(self.__integrity_key)
            _zeroize(self.__integrity_tag)
            self.__integrity_key = bytearray()
            self.__integrity_tag = bytearray()
            self.__active = False

    def _live_private_home_authority_sha256(self) -> str | None:
        with self.__lock:
            if not self.__active:
                raise ClaudeChildEnvironmentError(
                    "compiled Claude child environment is invalidated"
                )
            return self.__private_home_overlay_authority_sha256


def compile_claude_child_environment(
    *,
    ambient: Mapping[str, str],
    auth_environment: Mapping[str, str],
    auth_environment_receipt: Mapping[str, Any],
    source_observation: Mapping[str, Any],
    attempt_profile_environment: Mapping[str, str],
    private_home_overlay_authority: (
        ClaudePrivateHomeOverlayAuthority | None
    ) = None,
    phase_environment_policies: Sequence[str],
    home_variable_policy: str,
    functional_controls: Mapping[str, str] | None = None,
) -> CompiledClaudeChildEnvironment:
    """Compile a minimal child environment from reviewed named authorities."""

    ambient_source, ambient_names = _normalize_environment(
        ambient,
        label="ambient environment",
    )
    profile_source, profile_names = _normalize_environment(
        attempt_profile_environment,
        label="attempt profile environment",
    )
    # Reject caller-controlled, non-secret policy/profile shape before
    # consuming the one-shot auth capability.  A malformed attempt must not
    # burn credentials merely because validation was sequenced too late.
    policies = _canonical_selected_policies(phase_environment_policies)
    if home_variable_policy not in {
        "PRIVATE_HOME",
        "PRESERVE_TOOLCHAIN_HOME",
    }:
        raise ClaudeChildEnvironmentError(
            "home variable policy must be explicit"
        )
    if home_variable_policy == "PRIVATE_HOME":
        if (
            type(private_home_overlay_authority)
            is not ClaudePrivateHomeOverlayAuthority
        ):
            raise ClaudeChildEnvironmentError(
                "typed attempt-profile private-home overlay authority "
                "is required"
            )
    elif private_home_overlay_authority is not None:
        raise ClaudeChildEnvironmentError(
            "preserved HOME cannot carry private-home overlay authority"
        )
    for actual_name in profile_source:
        if not any(
            candidate.casefold() == actual_name.casefold()
            for candidate in (_ATTEMPT_PROFILE_KEYS | _TOOLCHAIN_HOME_KEYS)
        ):
            raise ClaudeChildEnvironmentError(
                "attempt profile contains an unreviewed profile variable"
            )
    try:
        preflight_auth_receipt = replay_claude_auth_environment(
            auth_environment_receipt
        )
    except ClaudeAuthRouteError as exc:
        raise ClaudeChildEnvironmentError(
            f"Claude auth authority did not replay: {exc}"
        ) from exc
    private_home_overlay_authority_sha256: str | None = None
    if home_variable_policy == "PRIVATE_HOME":
        assert (
            type(private_home_overlay_authority)
            is ClaudePrivateHomeOverlayAuthority
        )
        (
            profile_source,
            private_home_overlay_authority_sha256,
        ) = private_home_overlay_authority._consume(
            attempt_profile_environment=attempt_profile_environment,
        )
        profile_source, profile_names = _normalize_environment(
            profile_source,
            label="authorized private-home overlay",
        )
    controls = _canonical_functional_controls(
        (
            _REQUIRED_FUNCTIONAL_CONTROLS_BY_VERSION[
                preflight_auth_receipt["claude_code_version"]
            ]
            if functional_controls is None
            else functional_controls
        ),
        claude_code_version=preflight_auth_receipt["claude_code_version"],
    )
    try:
        auth_receipt = reconcile_claude_auth_environment(
            auth_environment,
            auth_environment_receipt,
            source_observation=source_observation,
        )
        if type(auth_environment) is not ClaudeAuthEnvironmentCapability:
            raise ClaudeAuthRouteError(
                "live compiled auth-environment capability is required"
            )
        auth_source, auth_names = _normalize_environment(
            auth_environment._consume_verified_environment(
                receipt_sha256=auth_receipt["receipt_sha256"],
            ),
            label="auth environment",
        )
        observation = replay_claude_auth_source_observation(
            source_observation
        )
    except ClaudeAuthRouteError as exc:
        raise ClaudeChildEnvironmentError(
            f"Claude auth authority did not replay: {exc}"
        ) from exc

    if auth_receipt != preflight_auth_receipt:
        raise ClaudeChildEnvironmentError(
            "Claude auth receipt changed during child compilation"
        )

    allowed_policy_names = set().union(
        *(_POLICY_ENVIRONMENT_NAMES[policy] for policy in policies)
    )
    child: dict[str, str] = {}
    for canonical_name in sorted(allowed_policy_names):
        if (
            home_variable_policy == "PRIVATE_HOME"
            and canonical_name in _TOOLCHAIN_HOME_KEYS
        ):
            continue
        value = _lookup(ambient_source, ambient_names, canonical_name)
        if value is not None:
            child[canonical_name] = value

    # Attempt-private Claude state and temp paths are the only profile
    # environment overlay.  Toolchain home/config roots remain ambient.
    for actual_name, value in profile_source.items():
        canonical_name = next(
            (
                candidate
                for candidate in (_ATTEMPT_PROFILE_KEYS | _TOOLCHAIN_HOME_KEYS)
                if candidate.casefold() == actual_name.casefold()
            ),
            None,
        )
        if canonical_name is None:  # preflight above makes this unreachable.
            raise ClaudeChildEnvironmentError(
                "attempt profile contains an unreviewed profile variable"
            )
        if canonical_name in _TOOLCHAIN_HOME_KEYS:
            if home_variable_policy == "PRESERVE_TOOLCHAIN_HOME":
                ambient_value = _lookup(
                    ambient_source,
                    ambient_names,
                    canonical_name,
                )
                if ambient_value is None or value != ambient_value:
                    raise ClaudeChildEnvironmentError(
                        "attempt profile cannot replace toolchain home under "
                        "the preserve policy"
                    )
                continue
            child[canonical_name] = value
            continue
        if not value:
            raise ClaudeChildEnvironmentError(
                "attempt profile path is empty"
            )
        child[canonical_name] = value
    if "CLAUDE_CONFIG_DIR" not in child:
        raise ClaudeChildEnvironmentError(
            "attempt profile lacks CLAUDE_CONFIG_DIR"
        )
    if (
        home_variable_policy == "PRIVATE_HOME"
        and not _PRIVATE_HOME_REQUIRED_KEYS.issubset(child)
    ):
        raise ClaudeChildEnvironmentError(
            "private-home policy lacks its closed home/config denominator"
        )

    for name, value in controls.items():
        child[name] = value

    selected_route = auth_receipt["selected_route"]
    route_names = set(_SELECTED_ROUTE_ENV[selected_route])
    route_names.update(
        auth_receipt["endpoint_policy"]["endpoint_environment"]
    )
    route_names.update(_CLOUD_CREDENTIAL_ENV.get(selected_route, ()))
    for canonical_name in sorted(route_names):
        value = _lookup(auth_source, auth_names, canonical_name)
        if value is not None:
            child[canonical_name] = value
    for required_name in _SELECTED_ROUTE_ENV[selected_route]:
        if required_name not in child:
            raise ClaudeChildEnvironmentError(
                "selected Claude auth route disappeared during filtering"
            )

    # A final normalization catches collisions introduced by future policy
    # additions before any value digest is computed.
    child, _ = _normalize_environment(
        child,
        label="compiled child environment",
    )
    selected_names = {name.casefold() for name in child}
    dropped_claude = sorted(
        {
            name
            for name in ambient_source
            if name.upper().startswith("CLAUDE_CODE_")
            and name.casefold() not in selected_names
        },
        key=str.casefold,
    )
    dropped_sensitive = sorted(
        {
            name
            for name in ambient_source
            if _is_sensitive_name(name)
            and name.casefold() not in selected_names
        },
        key=str.casefold,
    )
    core = {
        "schema": CHILD_ENVIRONMENT_SCHEMA,
        "auth_environment_receipt_sha256": auth_receipt["receipt_sha256"],
        "source_observation_sha256": observation["receipt_sha256"],
        "selected_route": selected_route,
        "phase_environment_policies": policies,
        "home_variable_policy": home_variable_policy,
        "configuration_isolation_status": (
            "ATTEMPT_PRIVATE_HOME_BOUND"
            if home_variable_policy == "PRIVATE_HOME"
            else "UNVERIFIED_CLAUDE_CONFIG_REDIRECTION"
        ),
        "proof_grade_configuration_isolation": (
            home_variable_policy == "PRIVATE_HOME"
        ),
        "configuration_isolation_authority_class": (
            "LIVE_TYPED_PRIVATE_HOME"
            if home_variable_policy == "PRIVATE_HOME"
            else "REPLAYABLE_NON_PROOF"
        ),
        "private_home_overlay_authority_sha256": (
            private_home_overlay_authority_sha256
        ),
        "attempt_profile_keys": sorted(
            name
            for name in child
            if name in _ATTEMPT_PROFILE_KEYS
        ),
        "functional_control_names": sorted(controls),
        "dropped_claude_code_names": dropped_claude,
        "dropped_sensitive_names": dropped_sensitive,
        # Names are non-secret launch authority.  Keep the explicit
        # denominator alongside its digest so reviewers and downstream
        # compilers do not have to infer which optional toolchain keys were
        # present in the ambient fixture.
        "final_environment_names": sorted(child, key=str.casefold),
        "final_environment_key_set_sha256": _key_set_digest(child),
        "credential_values_recorded": False,
        "credential_content_hashes_recorded": False,
    }
    receipt = {**core, "receipt_sha256": _digest(core)}
    compiled = CompiledClaudeChildEnvironment(
        environment=child,
        receipt=receipt,
        auth_environment_receipt=auth_receipt,
        source_observation=observation,
        private_home_overlay_authority_sha256=(
            private_home_overlay_authority_sha256
        ),
    )
    return compiled


def _replay_claude_child_environment_receipt(
    value: Mapping[str, Any],
    *,
    live_private_home_overlay_authority_sha256: str | None,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ClaudeChildEnvironmentError(
            "Claude child environment receipt must be an object"
        )
    clone = dict(value)
    expected_fields = {
        "schema",
        "auth_environment_receipt_sha256",
        "source_observation_sha256",
        "selected_route",
        "phase_environment_policies",
        "home_variable_policy",
        "configuration_isolation_status",
        "proof_grade_configuration_isolation",
        "configuration_isolation_authority_class",
        "private_home_overlay_authority_sha256",
        "attempt_profile_keys",
        "functional_control_names",
        "dropped_claude_code_names",
        "dropped_sensitive_names",
        "final_environment_names",
        "final_environment_key_set_sha256",
        "credential_values_recorded",
        "credential_content_hashes_recorded",
        "receipt_sha256",
    }
    if set(clone) != expected_fields:
        raise ClaudeChildEnvironmentError(
            "Claude child environment receipt fields drifted"
        )
    digest = clone.pop("receipt_sha256")
    policies = clone.get("phase_environment_policies")
    profile_keys = clone.get("attempt_profile_keys")
    controls = clone.get("functional_control_names")
    dropped_claude = clone.get("dropped_claude_code_names")
    dropped_sensitive = clone.get("dropped_sensitive_names")
    final_names = clone.get("final_environment_names")
    if (
        clone.get("schema") != CHILD_ENVIRONMENT_SCHEMA
        or not isinstance(
            clone.get("auth_environment_receipt_sha256"),
            str,
        )
        or _SHA256_RE.fullmatch(
            clone["auth_environment_receipt_sha256"]
        )
        is None
        or not isinstance(clone.get("source_observation_sha256"), str)
        or _SHA256_RE.fullmatch(clone["source_observation_sha256"]) is None
        or clone.get("selected_route") not in _SELECTED_ROUTE_ENV
        or not isinstance(policies, list)
        or policies != sorted(set(policies))
        or "base" not in policies
        or any(policy not in _POLICY_ENVIRONMENT_NAMES for policy in policies)
        or clone.get("home_variable_policy")
        not in {"PRIVATE_HOME", "PRESERVE_TOOLCHAIN_HOME"}
        or (
            clone.get("home_variable_policy") == "PRIVATE_HOME"
            and (
                clone.get("configuration_isolation_status")
                != "ATTEMPT_PRIVATE_HOME_BOUND"
                or clone.get("proof_grade_configuration_isolation")
                is not True
                or clone.get(
                    "configuration_isolation_authority_class"
                )
                != "LIVE_TYPED_PRIVATE_HOME"
                or not isinstance(
                    clone.get(
                        "private_home_overlay_authority_sha256"
                    ),
                    str,
                )
                or _SHA256_RE.fullmatch(
                    clone["private_home_overlay_authority_sha256"]
                )
                is None
                or live_private_home_overlay_authority_sha256
                != clone["private_home_overlay_authority_sha256"]
            )
        )
        or (
            clone.get("home_variable_policy")
            == "PRESERVE_TOOLCHAIN_HOME"
            and (
                clone.get("configuration_isolation_status")
                != "UNVERIFIED_CLAUDE_CONFIG_REDIRECTION"
                or clone.get("proof_grade_configuration_isolation")
                is not False
                or clone.get(
                    "configuration_isolation_authority_class"
                )
                != "REPLAYABLE_NON_PROOF"
                or clone.get(
                    "private_home_overlay_authority_sha256"
                )
                is not None
                or live_private_home_overlay_authority_sha256 is not None
            )
        )
        or not isinstance(profile_keys, list)
        or profile_keys != sorted(set(profile_keys))
        or any(key not in _ATTEMPT_PROFILE_KEYS for key in profile_keys)
        or "CLAUDE_CONFIG_DIR" not in profile_keys
        or not isinstance(controls, list)
        or controls != sorted(set(controls))
        or any(
            name
            not in _REVIEWED_FUNCTIONAL_CONTROLS
            for name in controls
        )
        or not isinstance(dropped_claude, list)
        or dropped_claude
        != sorted(set(dropped_claude), key=str.casefold)
        or any(
            not isinstance(name, str)
            or not name.upper().startswith("CLAUDE_CODE_")
            for name in dropped_claude
        )
        or not isinstance(dropped_sensitive, list)
        or dropped_sensitive
        != sorted(set(dropped_sensitive), key=str.casefold)
        or any(
            not isinstance(name, str) or not _is_sensitive_name(name)
            for name in dropped_sensitive
        )
        or not isinstance(final_names, list)
        or final_names != sorted(set(final_names), key=str.casefold)
        or any(
            not isinstance(name, str)
            or not name
            or "=" in name
            or "\x00" in name
            for name in final_names
        )
        or _key_names_digest(final_names)
        != clone.get("final_environment_key_set_sha256")
        or not isinstance(
            clone.get("final_environment_key_set_sha256"),
            str,
        )
        or _SHA256_RE.fullmatch(
            clone["final_environment_key_set_sha256"]
        )
        is None
        or clone.get("credential_values_recorded") is not False
        or clone.get("credential_content_hashes_recorded") is not False
        or not isinstance(digest, str)
        or _SHA256_RE.fullmatch(digest) is None
        or digest != _digest(clone)
    ):
        raise ClaudeChildEnvironmentError(
            "Claude child environment receipt does not replay"
        )
    return {**clone, "receipt_sha256": digest}


def replay_claude_child_environment_receipt(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Replay durable evidence only; private-HOME proof needs its live cap."""

    return _replay_claude_child_environment_receipt(
        value,
        live_private_home_overlay_authority_sha256=None,
    )


def _assert_final_route(
    environment: Mapping[str, str],
    names: Mapping[str, str],
    *,
    selected_route: str,
) -> None:
    present: list[str] = []
    for route, route_names in _SELECTED_ROUTE_ENV.items():
        if not route_names:
            continue
        if all(
            _lookup(environment, names, name) not in {None, ""}
            for name in route_names
        ):
            present.append(route)
    if selected_route in {
        "API_KEY_HELPER",
        "STORED_SUBSCRIPTION_OAUTH",
    }:
        # These routes intentionally have no credential selector in the child
        # environment. Their source observation remains bound separately.
        if present:
            raise ClaudeChildEnvironmentError(
                "a competing Claude auth source survived filtering"
            )
    elif present != [selected_route]:
        raise ClaudeChildEnvironmentError(
            "selected Claude auth route was not preserved"
        )


def reconcile_claude_child_environment(
    value: CompiledClaudeChildEnvironment,
) -> dict[str, Any]:
    """Reconcile the final child mapping before launch/after observation."""

    if not isinstance(value, CompiledClaudeChildEnvironment):
        raise ClaudeChildEnvironmentError(
            "compiled Claude child environment object is required"
        )
    receipt = _replay_claude_child_environment_receipt(
        value.receipt,
        live_private_home_overlay_authority_sha256=(
            value._live_private_home_authority_sha256()
        ),
    )
    try:
        auth_receipt = replay_claude_auth_environment(
            value._auth_environment_receipt
        )
        observation = replay_claude_auth_source_observation(
            value._source_observation
        )
    except ClaudeAuthRouteError as exc:
        raise ClaudeChildEnvironmentError(
            f"embedded Claude auth authority drifted: {exc}"
        ) from exc
    if (
        auth_receipt["receipt_sha256"]
        != receipt["auth_environment_receipt_sha256"]
        or observation["receipt_sha256"]
        != receipt["source_observation_sha256"]
        or auth_receipt["selected_route"] != receipt["selected_route"]
    ):
        raise ClaudeChildEnvironmentError(
            "Claude child environment authority binding drifted"
        )
    environment, names = _normalize_environment(
        value._verified_environment(),
        label="compiled child environment",
    )
    if (
        _key_set_digest(environment)
        != receipt["final_environment_key_set_sha256"]
        or sorted(environment, key=str.casefold)
        != receipt["final_environment_names"]
    ):
        raise ClaudeChildEnvironmentError(
            "Claude child environment values or denominator drifted"
        )
    _assert_final_route(
        environment,
        names,
        selected_route=receipt["selected_route"],
    )
    endpoint = auth_receipt["endpoint_policy"]["endpoint_environment"]
    for name, expected_value in endpoint.items():
        if _lookup(environment, names, name) != expected_value:
            raise ClaudeChildEnvironmentError(
                "Claude child endpoint drifted"
            )
    return receipt


__all__ = [
    "CHILD_ENVIRONMENT_SCHEMA",
    "ClaudeChildEnvironmentError",
    "ClaudePrivateHomeOverlayAuthority",
    "CompiledClaudeChildEnvironment",
    "PRIVATE_HOME_OVERLAY_AUTHORITY_SCHEMA",
    "compile_claude_child_environment",
    "normalize_claude_functional_controls",
    "normalize_claude_phase_environment_policies",
    "planned_claude_child_environment_names",
    "planned_claude_child_environment_key_set_sha256",
    "reconcile_claude_child_environment",
    "replay_claude_child_environment_receipt",
]
