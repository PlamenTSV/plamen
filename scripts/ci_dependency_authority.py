"""Deterministic authority for Plamen's CI Python dependency graph.

The module is intentionally stdlib-only at import time.  The pre-resolver
``static`` gate can therefore reject drift before any network-backed bootstrap.
The full gate imports the exact locked ``packaging``/``jsonschema`` versions
only after the isolated resolver environment has been installed.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import sysconfig
import tempfile
from typing import Any, Mapping
from urllib.parse import unquote, urlparse
import venv


POLICY_PATH = Path("verification_policy/ci_dependency_authority.v1.json")
RECEIPT_PATH = Path("verification_policy/ci_dependency_provenance.v2.json")
SCHEMA_PATH = Path(
    "verification_policy/ci_dependency_provenance.v2.schema.json"
)
RELEASE_EVIDENCE_PATH = Path(
    "verification_policy/ci_release_metadata_evidence.v1.json"
)
ADVISORY_EVIDENCE_PATH = Path(
    "verification_policy/ci_advisory_evidence.v1.json"
)
RELEASE_RESPONSE_DIR = Path(
    "verification_policy/ci_release_responses"
)
ADVISORY_REQUEST_PATH = Path(
    "verification_policy/ci_advisory_responses/request.json"
)
ADVISORY_RESPONSE_PATH = Path(
    "verification_policy/ci_advisory_responses/response.json"
)
POLICY_SCHEMA = "plamen.ci-dependency-authority.v1"
RECEIPT_SCHEMA = "plamen.ci-dependency-provenance.v2"
RELEASE_SCHEMA = "plamen.ci-release-metadata-evidence.v1"
ADVISORY_SCHEMA = "plamen.ci-advisory-evidence.v1"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_EXACT = re.compile(
    r"^==([A-Za-z0-9][A-Za-z0-9.*+!_-]*)$"
)
_REQUIREMENT = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)"
    r"(?:\[[A-Za-z0-9,._-]+\])?"
    r"(?P<specifier>"
    r"(?:(?:===|==|~=|!=|<=|>=|<|>)[A-Za-z0-9.*+!_-]+)"
    r"(?:\s*,\s*(?:===|==|~=|!=|<=|>=|<|>)"
    r"[A-Za-z0-9.*+!_-]+)*)"
    r"(?:\s*;\s*(?P<marker>.+))?$"
)
_LOCK_ROW = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)=="
    r"([A-Za-z0-9][A-Za-z0-9.+_-]*)\b"
)
_ACTION_SHA = re.compile(r"^[0-9a-f]{40}$")
_WORKFLOW_PATHS = (
    Path(".github/workflows/tests.yml"),
    Path(".github/workflows/install-smoke.yml"),
)
_EXPECTED_ACTIONS = {
    "actions/checkout",
    "actions/setup-python",
    "actions/dependency-review-action",
}
_MAX_RAW_RESPONSE_BYTES = 8 * 1024 * 1024
PLAMEN_RUNTIME_ASSETS = (
    {
        "kind": "control",
        "mode": "named-files",
        "root": "verification_policy",
        "names": (
            "ci_dependency_authority.v1.json",
            "ci_dependency_provenance.v2.json",
            "ci_dependency_provenance.v2.schema.json",
            "ci_release_metadata_evidence.v1.json",
            "ci_advisory_evidence.v1.json",
        ),
    },
    {
        "kind": "control",
        "mode": "tree",
        "root": "verification_policy/ci_release_responses",
        "pattern": "*.json",
        "max_files": 128,
    },
    {
        "kind": "control",
        "mode": "tree",
        "root": "verification_policy/ci_advisory_responses",
        "pattern": "*.json",
        "max_files": 8,
    },
    {
        "kind": "runtime-data",
        "mode": "named-files",
        "root": ".",
        "names": (
            "requirements.txt",
            "requirements-dev.txt",
            "requirements-ci.constraints",
            "requirements-ci.lock",
            "requirements-ci-resolver.in",
            "requirements-ci-resolver.lock",
        ),
    },
)


class CIDependencyAuthorityError(ValueError):
    """The checked CI dependency authority is incomplete or inconsistent."""


@dataclass(frozen=True)
class LockedRequirement:
    version: str
    hashes: tuple[str, ...]
    marker: str | None = None


def _canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).casefold()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    ).encode("utf-8")


def _canonical_generated_lock_bytes(raw: bytes) -> bytes:
    """Return the resolver lock in the repository's cross-platform LF form."""

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CIDependencyAuthorityError(
            "generated dependency lock is not UTF-8"
        ) from exc
    normalized = text.replace("\r\n", "\n")
    if "\r" in normalized:
        raise CIDependencyAuthorityError(
            "generated dependency lock contains a bare carriage return"
        )
    if not normalized.endswith("\n"):
        raise CIDependencyAuthorityError(
            "generated dependency lock lacks a final newline"
        )
    return normalized.encode("utf-8")


def _compact_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        separators=(",", ":"),
        sort_keys=True,
        ensure_ascii=True,
    ).encode("utf-8")


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CIDependencyAuthorityError(
                f"JSON object contains duplicate key: {key!r}"
            )
        result[key] = value
    return result


def _parse_json_bytes(raw: bytes, label: str) -> Any:
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_json_object,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CIDependencyAuthorityError(
            f"{label} is invalid JSON"
        ) from exc


def _json(path: Path, label: str) -> dict[str, Any]:
    try:
        payload = _parse_json_bytes(path.read_bytes(), label)
    except Exception as exc:
        if isinstance(exc, CIDependencyAuthorityError):
            raise
        raise CIDependencyAuthorityError(
            f"{label} is unreadable or invalid JSON: {type(exc).__name__}"
        ) from exc
    if not isinstance(payload, dict):
        raise CIDependencyAuthorityError(f"{label} root must be an object")
    return payload


def _is_reparse(path: Path) -> bool:
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError:
        return True
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def _exact_keys(
    value: Mapping[str, Any],
    expected: set[str],
    label: str,
) -> None:
    actual = set(value)
    if actual != expected:
        raise CIDependencyAuthorityError(
            f"{label} keys are invalid: missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)}"
        )


def _bounded_raw_file(
    root: Path,
    relative: str,
    *,
    expected_parent: Path,
    label: str,
) -> bytes:
    if not isinstance(relative, str):
        raise CIDependencyAuthorityError(f"{label} path is not a string")
    candidate_relative = Path(relative)
    if (
        candidate_relative.is_absolute()
        or candidate_relative.as_posix() != relative
        or ".." in candidate_relative.parts
    ):
        raise CIDependencyAuthorityError(f"{label} path is not canonical")
    try:
        base = root.resolve(strict=True)
        expected_root = (base / expected_parent).resolve(strict=True)
    except OSError as exc:
        raise CIDependencyAuthorityError(
            f"{label} raw preimage directory is missing"
        ) from exc
    candidate = base / candidate_relative
    cursor = base
    for part in candidate_relative.parts:
        cursor /= part
        if cursor.is_symlink() or _is_reparse(cursor):
            raise CIDependencyAuthorityError(
                f"{label} raw preimage traverses a link/reparse point"
            )
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise CIDependencyAuthorityError(f"{label} raw preimage is missing") from exc
    if (
        not resolved.is_relative_to(expected_root)
        or not candidate.is_file()
        or candidate.is_symlink()
        or _is_reparse(candidate)
    ):
        raise CIDependencyAuthorityError(
            f"{label} raw preimage escapes its closed directory"
        )
    try:
        size = candidate.stat().st_size
        if size <= 0 or size > _MAX_RAW_RESPONSE_BYTES:
            raise CIDependencyAuthorityError(
                f"{label} raw preimage size is outside the reviewed bound"
            )
        return candidate.read_bytes()
    except OSError as exc:
        raise CIDependencyAuthorityError(
            f"{label} raw preimage is unreadable"
        ) from exc


def _closed_raw_directory(
    root: Path,
    relative: Path,
    *,
    label: str,
) -> set[str]:
    try:
        base = root.resolve(strict=True)
        directory = base / relative
        cursor = base
        for part in relative.parts:
            cursor /= part
            if cursor.is_symlink() or _is_reparse(cursor):
                raise CIDependencyAuthorityError(
                    f"{label} directory traverses a link/reparse point"
                )
        if not directory.is_dir():
            raise CIDependencyAuthorityError(
                f"{label} directory is not a regular directory"
            )
        result: set[str] = set()
        for path in directory.iterdir():
            if (
                not path.is_file()
                or path.is_symlink()
                or _is_reparse(path)
            ):
                raise CIDependencyAuthorityError(
                    f"{label} directory contains a non-regular entry"
                )
            result.add(path.relative_to(base).as_posix())
        return result
    except OSError as exc:
        raise CIDependencyAuthorityError(
            f"{label} directory is unreadable"
        ) from exc


def _parse_lock_text(
    text: str,
    *,
    label: str,
) -> dict[str, LockedRequirement]:
    """Parse pip-compile text without trusting comments or formatting."""

    rows: list[str] = []
    current = ""
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped == "--only-binary :all:":
            continue
        current = f"{current} {stripped}".strip()
        if current.endswith("\\"):
            current = current[:-1].rstrip()
            continue
        rows.append(current)
        current = ""
    if current:
        raise CIDependencyAuthorityError(
            f"unterminated lock continuation: {label}"
        )
    locked: dict[str, LockedRequirement] = {}
    for row in rows:
        match = _LOCK_ROW.match(row)
        if match is None:
            raise CIDependencyAuthorityError(f"invalid lock row: {row!r}")
        name = _canonical(match.group(1))
        version = match.group(2)
        hashes = tuple(
            sorted(set(re.findall(r"--hash=sha256:([0-9a-f]{64})", row)))
        )
        if not hashes:
            raise CIDependencyAuthorityError(
                f"locked project has no SHA-256 hashes: {name}"
            )
        if name in locked:
            raise CIDependencyAuthorityError(
                f"duplicate locked project: {name}"
            )
        marker = None
        if ";" in row.split("--hash=", 1)[0]:
            marker = row.split(";", 1)[1].split("--hash=", 1)[0].strip()
        locked[name] = LockedRequirement(version, hashes, marker)
    if not locked:
        raise CIDependencyAuthorityError("CI application lock is empty")
    return locked


def parse_lock(path: Path) -> dict[str, LockedRequirement]:
    """Parse a pip-compile hash lock without trusting its comments."""

    return _parse_lock_text(
        path.read_text(encoding="utf-8"),
        label=str(path),
    )


def _verify_host_resolution(
    checked: Mapping[str, LockedRequirement],
    regenerated: Mapping[str, LockedRequirement],
) -> None:
    """Verify resolver output against the reviewed current-host projection.

    pip evaluates PEP 508 markers while compiling. A Linux or macOS resolver
    therefore omits Windows-only rows, while the universal checked lock keeps
    those rows for Windows installation. Every emitted row must be identical
    to its checked row, and every checked row active on this host must appear.
    Inactive checked rows remain bound by the receipt and evidence denominator.
    """

    from packaging.markers import Marker, default_environment

    for name, row in regenerated.items():
        if checked.get(name) != row:
            raise CIDependencyAuthorityError(
                "isolated host resolution differs from checked lock row: "
                f"{name}"
            )
    environment = default_environment()
    active = {
        name
        for name, row in checked.items()
        if row.marker is None
        or Marker(row.marker).evaluate(environment=environment)
    }
    missing = sorted(active - set(regenerated))
    if missing:
        raise CIDependencyAuthorityError(
            "isolated host resolution omits active checked rows: "
            f"{missing}"
        )


def _read_requirement_inputs(
    root: Path,
    entry: str = "requirements-dev.txt",
) -> tuple[dict[str, str], tuple[str, ...], tuple[str, ...]]:
    """Return exact pins, traversed files, and all declared projects.

    The pre-resolver gate is intentionally stdlib-only, but it must not ignore
    a requirement syntax it does not understand.  Every non-comment row is
    therefore either a closed local include or a conventional version
    specifier.  URL, editable, index, and arbitrary pip-option rows fail loud.
    """

    exact: dict[str, str] = {}
    declared: set[str] = set()
    declarations_seen: set[tuple[str, str]] = set()
    visited: set[str] = set()
    stack = [entry]
    while stack:
        relative = stack.pop()
        normalized = Path(relative).as_posix()
        if normalized in visited:
            continue
        if (
            normalized.startswith("../")
            or Path(normalized).is_absolute()
            or ".." in Path(normalized).parts
            or "\\" in normalized
        ):
            raise CIDependencyAuthorityError(
                f"requirements input escapes repository: {normalized}"
            )
        visited.add(normalized)
        path = root / normalized
        try:
            rows = path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            raise CIDependencyAuthorityError(
                f"requirements input is missing: {normalized}"
            ) from exc
        for raw in rows:
            row = raw.split("#", 1)[0].strip()
            if not row:
                continue
            include = re.match(
                r"^(?:-r|--requirement|-c|--constraint)\s+(.+)$",
                row,
            )
            if include:
                child = (
                    Path(normalized).parent / include.group(1).strip()
                ).as_posix()
                stack.append(child)
                continue
            match = _REQUIREMENT.fullmatch(row)
            if match is None:
                raise CIDependencyAuthorityError(
                    f"unsupported requirement authority row in "
                    f"{normalized}: {row!r}"
                )
            name = _canonical(match.group("name"))
            declaration_key = (normalized, name)
            if declaration_key in declarations_seen:
                raise CIDependencyAuthorityError(
                    f"duplicate requirements input for {name} in {normalized}"
                )
            declarations_seen.add(declaration_key)
            declared.add(name)
            exact_match = _EXACT.fullmatch(
                re.sub(r"\s+", "", match.group("specifier"))
            )
            if exact_match is None:
                continue
            version = exact_match.group(1)
            previous = exact.get(name)
            if previous is not None and previous != version:
                raise CIDependencyAuthorityError(
                    f"conflicting requirements input for {name}: "
                    f"{previous} versus {version}"
                )
            exact[name] = version
    return exact, tuple(sorted(visited)), tuple(sorted(declared))


def _load_policy(root: Path) -> dict[str, Any]:
    policy = _json(root / POLICY_PATH, "CI dependency policy")
    _exact_keys(
        policy,
        {
            "schema",
            "resolver",
            "paths",
            "matrix",
            "checked_at",
            "github_actions",
            "universal_wheels",
            "wheel_coverage",
            "clean_claim",
        },
        "CI dependency policy",
    )
    if policy.get("schema") != POLICY_SCHEMA:
        raise CIDependencyAuthorityError("CI dependency policy schema invalid")
    return policy


def load_receipt(root: Path) -> dict[str, Any]:
    return _json(root / RECEIPT_PATH, "CI dependency receipt")


def verify_static_bindings(
    root: Path,
    *,
    verify_workflows: bool = True,
) -> dict[str, LockedRequirement]:
    """Fail before resolver installation if reviewed inputs and lock drift."""

    root = Path(root)
    policy = _load_policy(root)
    if verify_workflows:
        verify_workflow_action_bindings(root, policy=policy)
    paths = policy.get("paths")
    if not isinstance(paths, dict):
        raise CIDependencyAuthorityError("CI policy paths must be an object")
    expected_paths = {
        "requirements": "requirements-dev.txt",
        "constraints": "requirements-ci.constraints",
        "lock": "requirements-ci.lock",
        "resolver_input": "requirements-ci-resolver.in",
        "resolver_lock": "requirements-ci-resolver.lock",
        "receipt": RECEIPT_PATH.as_posix(),
        "receipt_schema": SCHEMA_PATH.as_posix(),
        "release_evidence": RELEASE_EVIDENCE_PATH.as_posix(),
        "advisory_evidence": ADVISORY_EVIDENCE_PATH.as_posix(),
    }
    _exact_keys(paths, set(expected_paths), "CI dependency policy paths")
    if paths != expected_paths:
        raise CIDependencyAuthorityError(
            "CI dependency policy paths are not the closed reviewed set"
        )
    locked = parse_lock(root / paths["lock"])
    exact, traversed, declared = _read_requirement_inputs(
        root, paths["requirements"]
    )
    if paths["constraints"] not in traversed:
        raise CIDependencyAuthorityError(
            "requirements input does not bind the exact constraints file"
        )
    if set(declared) != set(locked):
        raise CIDependencyAuthorityError(
            "requirements input project denominator differs from CI lock: "
            f"missing={sorted(set(declared) - set(locked))}, "
            f"extra={sorted(set(locked) - set(declared))}"
        )
    if set(exact) != set(locked):
        raise CIDependencyAuthorityError(
            "requirements input exact-pin denominator differs from CI lock: "
            f"missing={sorted(set(exact) - set(locked))}, "
            f"extra={sorted(set(locked) - set(exact))}"
        )
    for name, version in exact.items():
        if locked[name].version != version:
            raise CIDependencyAuthorityError(
                f"{name} requirements input requires {version}, "
                f"but CI lock contains {locked[name].version}"
            )
    resolver_exact, resolver_inputs, resolver_declared = _read_requirement_inputs(
        root, paths["resolver_input"]
    )
    if resolver_inputs != (paths["resolver_input"],):
        raise CIDependencyAuthorityError(
            "resolver bootstrap input must be one closed exact file"
        )
    resolver_lock = parse_lock(root / paths["resolver_lock"])
    resolver = policy.get("resolver")
    if not isinstance(resolver, dict):
        raise CIDependencyAuthorityError("CI resolver policy is invalid")
    expected_resolver_keys = {
        "name",
        "version",
        "python_implementation",
        "python_version",
        "index_url",
        "command",
    }
    _exact_keys(resolver, expected_resolver_keys, "CI resolver policy")
    if (
        resolver.get("name") != "pip-tools"
        or resolver_exact.get("pip-tools") != resolver.get("version")
        or resolver_lock.get("pip-tools") is None
        or resolver_lock["pip-tools"].version != resolver.get("version")
        or resolver.get("python_implementation") != "CPython"
        or resolver.get("python_version") != "3.12"
        or resolver.get("index_url") != "https://pypi.org/simple"
    ):
        raise CIDependencyAuthorityError(
            "resolver input/runtime/index authority is inconsistent"
        )
    if (
        set(resolver_declared) != set(resolver_lock)
        or set(resolver_exact) != set(resolver_lock)
    ):
        raise CIDependencyAuthorityError(
            "resolver bootstrap input denominator differs from resolver lock"
        )
    for name, version in resolver_exact.items():
        if resolver_lock[name].version != version:
            raise CIDependencyAuthorityError(
                f"resolver bootstrap input requires {name}=={version}, "
                f"but resolver lock contains {resolver_lock[name].version}"
            )
    command = resolver.get("command")
    expected_command = [
        "python",
        "-I",
        "-m",
        "piptools",
        "compile",
        "--generate-hashes",
        "--allow-unsafe",
        "--strip-extras",
        "--resolver=backtracking",
        "--no-config",
        "--pip-args=--only-binary=:all:",
        "--output-file",
        "requirements-ci.lock",
        "requirements-dev.txt",
    ]
    if command != expected_command:
        raise CIDependencyAuthorityError(
            "resolver command is not the closed reviewed invocation"
        )

    receipt = load_receipt(root)
    authority = receipt.get("lock_authority")
    if not isinstance(authority, dict):
        raise CIDependencyAuthorityError("receipt lock authority missing")
    inputs = authority.get("input_sha256")
    expected_input_paths = sorted(
        {
            *traversed,
            paths["resolver_input"],
            paths["resolver_lock"],
        }
    )
    if not isinstance(inputs, dict) or set(inputs) != set(
        expected_input_paths
    ):
        raise CIDependencyAuthorityError(
            "receipt input hash denominator is incomplete"
        )
    for relative in expected_input_paths:
        if inputs[relative] != _sha256(root / relative):
            raise CIDependencyAuthorityError(
                f"receipt input digest mismatch: {relative}"
            )
    if authority.get("output_sha256") != _sha256(root / paths["lock"]):
        raise CIDependencyAuthorityError("receipt lock output digest mismatch")
    return locked


def _parse_time(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise CIDependencyAuthorityError(f"{label} is not RFC3339 UTC")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise CIDependencyAuthorityError(
            f"{label} is not RFC3339 UTC"
        ) from exc
    if parsed.tzinfo != timezone.utc:
        raise CIDependencyAuthorityError(f"{label} is not UTC")
    return parsed


def _validated_policy_actions(
    policy: Mapping[str, Any],
    *,
    checked: datetime,
) -> dict[str, dict[str, str]]:
    actions = policy.get("github_actions")
    if not isinstance(actions, list):
        raise CIDependencyAuthorityError(
            "CI dependency policy GitHub Actions must be an array"
        )
    by_name: dict[str, dict[str, str]] = {}
    expected_keys = {
        "name",
        "version",
        "commit_sha",
        "source",
        "observed_at",
    }
    for ordinal, value in enumerate(actions):
        if not isinstance(value, dict):
            raise CIDependencyAuthorityError(
                f"CI dependency policy GitHub Action {ordinal} is invalid"
            )
        _exact_keys(
            value,
            expected_keys,
            f"CI dependency policy GitHub Action {ordinal}",
        )
        name = value.get("name")
        version = value.get("version")
        commit = value.get("commit_sha")
        source = value.get("source")
        if (
            not isinstance(name, str)
            or name not in _EXPECTED_ACTIONS
            or name in by_name
            or not isinstance(version, str)
            or re.fullmatch(r"\d+\.\d+\.\d+", version) is None
            or not isinstance(commit, str)
            or _ACTION_SHA.fullmatch(commit) is None
            or source
            != f"https://github.com/{name}/releases/tag/v{version}"
            or _parse_time(
                value.get("observed_at"),
                f"GitHub Action {name!r} observed_at",
            )
            > checked
        ):
            raise CIDependencyAuthorityError(
                f"CI dependency policy GitHub Action invalid: {name!r}"
            )
        by_name[name] = dict(value)
    if set(by_name) != _EXPECTED_ACTIONS:
        raise CIDependencyAuthorityError(
            "CI dependency policy GitHub Action denominator is incomplete"
        )
    return by_name


def verify_workflow_action_bindings(
    root: Path,
    *,
    policy: Mapping[str, Any] | None = None,
) -> None:
    """Bind every shipped workflow Action use to the reviewed source/commit."""

    try:
        import yaml
    except ImportError as exc:
        raise CIDependencyAuthorityError(
            "workflow Action authority requires the exact locked PyYAML"
        ) from exc

    root = Path(root)
    resolved_policy = _load_policy(root) if policy is None else policy
    checked = _parse_time(
        resolved_policy.get("checked_at"), "CI dependency policy checked_at"
    )
    expected = _validated_policy_actions(
        resolved_policy,
        checked=checked,
    )
    reviewed_workflows = {
        relative.as_posix() for relative in _WORKFLOW_PATHS
    }
    observed_workflows = _closed_raw_directory(
        root,
        Path(".github/workflows"),
        label="workflow Action authority",
    )
    if observed_workflows != reviewed_workflows:
        raise CIDependencyAuthorityError(
            "workflow file denominator differs from the closed reviewed set: "
            f"missing={sorted(reviewed_workflows - observed_workflows)}, "
            f"extra={sorted(observed_workflows - reviewed_workflows)}"
        )
    seen: set[str] = set()

    def mapping_items(node: Any, label: str) -> list[tuple[str, Any]]:
        if not isinstance(node, yaml.MappingNode):
            raise CIDependencyAuthorityError(
                f"workflow mapping is invalid: {label}"
            )
        result: list[tuple[str, Any]] = []
        keys: set[str] = set()
        for key_node, value_node in node.value:
            if (
                not isinstance(key_node, yaml.ScalarNode)
                or key_node.tag != "tag:yaml.org,2002:str"
            ):
                raise CIDependencyAuthorityError(
                    f"workflow mapping key is not a scalar string: {label}"
                )
            key = key_node.value
            if key == "<<" or key in keys:
                raise CIDependencyAuthorityError(
                    f"workflow mapping has merge/duplicate key: {label}:{key}"
                )
            keys.add(key)
            result.append((key, value_node))
        return result

    def scalar_uses(node: Any, label: str) -> str:
        if (
            not isinstance(node, yaml.ScalarNode)
            or node.tag != "tag:yaml.org,2002:str"
        ):
            raise CIDependencyAuthorityError(
                f"workflow Action use is not a literal scalar: {label}"
            )
        identity = node.value
        if "${{" in identity or "}}" in identity:
            raise CIDependencyAuthorityError(
                f"workflow Action use is expression-valued: {label}"
            )
        return identity

    def validate_document_graph(document: Any, label: str) -> None:
        """Reject YAML graph ambiguity before enumerating Action locations."""

        visited: set[int] = set()
        stack: list[Any] = [document]
        while stack:
            node = stack.pop()
            identity = id(node)
            if identity in visited:
                raise CIDependencyAuthorityError(
                    f"workflow YAML alias is not reviewed: {label}"
                )
            visited.add(identity)
            if isinstance(node, yaml.MappingNode):
                keys: set[str] = set()
                for key_node, value_node in node.value:
                    if (
                        not isinstance(key_node, yaml.ScalarNode)
                        or key_node.tag != "tag:yaml.org,2002:str"
                    ):
                        raise CIDependencyAuthorityError(
                            "workflow mapping key is not a scalar string: "
                            f"{label}"
                        )
                    key = key_node.value
                    if key == "<<" or key in keys:
                        raise CIDependencyAuthorityError(
                            "workflow mapping has merge/duplicate key: "
                            f"{label}:{key}"
                        )
                    keys.add(key)
                    stack.extend((key_node, value_node))
            elif isinstance(node, yaml.SequenceNode):
                stack.extend(node.value)
            elif not isinstance(node, yaml.ScalarNode):
                raise CIDependencyAuthorityError(
                    f"workflow YAML node type is unsupported: {label}"
                )

    def validate_use(identity: str, label: str) -> None:
        if identity.startswith("./") or identity.startswith("../"):
            raise CIDependencyAuthorityError(
                f"workflow local Action use is not reviewed: {label}"
            )
        if "@" not in identity:
            raise CIDependencyAuthorityError(
                f"workflow Action use has no immutable commit: {label}"
            )
        name, commit = identity.rsplit("@", 1)
        row = expected.get(name)
        if (
            row is None
            or _ACTION_SHA.fullmatch(commit) is None
            or commit != row["commit_sha"]
        ):
            raise CIDependencyAuthorityError(
                "workflow Action differs from reviewed source/commit: "
                f"{label}"
            )
        seen.add(name)

    for relative in _WORKFLOW_PATHS:
        try:
            text = (root / relative).read_text(encoding="utf-8")
            document = yaml.compose(text, Loader=yaml.BaseLoader)
        except (OSError, UnicodeError, yaml.YAMLError) as exc:
            raise CIDependencyAuthorityError(
                f"workflow Action authority is unreadable: {relative.as_posix()}"
            ) from exc
        if document is None:
            raise CIDependencyAuthorityError(
                f"workflow Action authority is empty: {relative.as_posix()}"
            )
        validate_document_graph(document, relative.as_posix())
        root_items = dict(
            mapping_items(document, relative.as_posix())
        )
        jobs = root_items.get("jobs")
        if jobs is None:
            raise CIDependencyAuthorityError(
                f"workflow jobs mapping is missing: {relative.as_posix()}"
            )
        for job_id, job_node in mapping_items(
            jobs, f"{relative.as_posix()}:jobs"
        ):
            job_label = f"{relative.as_posix()}:jobs.{job_id}"
            job_items = dict(mapping_items(job_node, job_label))
            if "uses" in job_items:
                validate_use(
                    scalar_uses(job_items["uses"], f"{job_label}.uses"),
                    f"{job_label}.uses",
                )
            steps = job_items.get("steps")
            if steps is None:
                continue
            if not isinstance(steps, yaml.SequenceNode):
                raise CIDependencyAuthorityError(
                    f"workflow steps is not a sequence: {job_label}.steps"
                )
            for ordinal, step_node in enumerate(steps.value):
                step_label = f"{job_label}.steps[{ordinal}]"
                step_items = dict(mapping_items(step_node, step_label))
                if "uses" in step_items:
                    validate_use(
                        scalar_uses(
                            step_items["uses"], f"{step_label}.uses"
                        ),
                        f"{step_label}.uses",
                    )
    if seen != set(expected):
        raise CIDependencyAuthorityError(
            "workflow Action denominator differs from reviewed policy"
        )


def _target_tags(python: str, platform: str) -> set[Any]:
    from packaging import tags

    py = tuple(int(item) for item in python.split("."))
    if platform == "linux-x86_64":
        platforms = [
            "manylinux_2_17_x86_64",
            "manylinux2014_x86_64",
            "linux_x86_64",
        ]
    elif platform == "windows-x86_64":
        platforms = ["win_amd64"]
    elif platform == "macos-arm64":
        platforms = list(tags.mac_platforms((11, 0), "arm64"))
    elif platform == "macos-x86_64":
        platforms = list(tags.mac_platforms((11, 0), "x86_64"))
    else:
        raise CIDependencyAuthorityError(
            f"unrecognized wheel target platform: {platform}"
        )
    return set(tags.cpython_tags(py, platforms=platforms)) | set(
        tags.compatible_tags(py, platforms=platforms)
    )


def _artifact_rows(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    universal = payload.get("universal_wheels")
    coverage = payload.get("wheel_coverage")
    if not isinstance(universal, list) or not isinstance(coverage, list):
        raise CIDependencyAuthorityError("receipt wheel coverage is invalid")
    for row in universal:
        if not isinstance(row, dict):
            raise CIDependencyAuthorityError("universal wheel row invalid")
        rows.append(dict(row))
    for target in coverage:
        if not isinstance(target, dict) or not isinstance(
            target.get("artifacts"), list
        ):
            raise CIDependencyAuthorityError("target wheel row invalid")
        for artifact in target["artifacts"]:
            if not isinstance(artifact, dict):
                raise CIDependencyAuthorityError("target artifact row invalid")
            rows.append(dict(artifact))
    return rows


def _validate_release_evidence(
    evidence: Mapping[str, Any],
    *,
    root: Path,
    locked: Mapping[str, LockedRequirement],
    receipt: Mapping[str, Any],
    checked: datetime,
) -> tuple[Mapping[str, Any], Mapping[str, Mapping[str, Any]]]:
    _exact_keys(
        evidence,
        {
            "schema",
            "source",
            "observed_at",
            "response_set_sha256",
            "responses",
            "releases",
        },
        "PyPI release evidence",
    )
    source = "https://pypi.org/pypi/{name}/{version}/json"
    observed = _parse_time(
        evidence.get("observed_at"), "PyPI release evidence observed_at"
    )
    if (
        evidence.get("schema") != RELEASE_SCHEMA
        or evidence.get("source") != source
        or receipt.get("source") != source
        or receipt.get("observed_at") != evidence.get("observed_at")
        or observed > checked
    ):
        raise CIDependencyAuthorityError(
            "PyPI release evidence source/timestamp binding invalid"
        )
    responses = evidence.get("responses")
    releases = evidence.get("releases")
    if (
        not isinstance(responses, dict)
        or not isinstance(releases, dict)
        or set(responses) != set(locked)
        or set(releases) != set(locked)
        or evidence.get("response_set_sha256")
        != hashlib.sha256(_canonical_json_bytes(responses)).hexdigest()
    ):
        raise CIDependencyAuthorityError(
            "PyPI release response digest denominator is invalid"
        )
    expected_release_rows: dict[str, dict[str, Any]] = {}
    artifact_index: dict[str, dict[str, Any]] = {}
    expected_raw_paths: set[str] = set()
    from packaging.specifiers import InvalidSpecifier, SpecifierSet
    from packaging.utils import parse_wheel_filename

    for name, locked_row in sorted(locked.items()):
        response = responses.get(name)
        if not isinstance(response, dict):
            raise CIDependencyAuthorityError(
                f"PyPI raw response evidence missing for {name}"
            )
        _exact_keys(
            response,
            {
                "project",
                "version",
                "request_url",
                "raw_path",
                "raw_sha256",
                "canonical_response_sha256",
            },
            f"PyPI response evidence {name}",
        )
        request_url = f"https://pypi.org/pypi/{name}/{locked_row.version}/json"
        raw_path = (
            RELEASE_RESPONSE_DIR
            / f"{name}-{locked_row.version}.json"
        ).as_posix()
        if (
            response.get("project") != name
            or response.get("version") != locked_row.version
            or response.get("request_url") != request_url
            or response.get("raw_path") != raw_path
            or not isinstance(response.get("raw_sha256"), str)
            or _HEX64.fullmatch(response["raw_sha256"]) is None
            or not isinstance(response.get("canonical_response_sha256"), str)
            or _HEX64.fullmatch(response["canonical_response_sha256"]) is None
        ):
            raise CIDependencyAuthorityError(
                f"PyPI raw response row invalid: {name}"
            )
        expected_raw_paths.add(raw_path)
        raw = _bounded_raw_file(
            root,
            raw_path,
            expected_parent=RELEASE_RESPONSE_DIR,
            label=f"PyPI {name}",
        )
        if hashlib.sha256(raw).hexdigest() != response["raw_sha256"]:
            raise CIDependencyAuthorityError(
                f"PyPI raw response digest mismatch: {name}"
            )
        payload = _parse_json_bytes(
            raw,
            f"PyPI raw response {name}",
        )
        if (
            not isinstance(payload, dict)
            or hashlib.sha256(_compact_json_bytes(payload)).hexdigest()
            != response["canonical_response_sha256"]
        ):
            raise CIDependencyAuthorityError(
                f"PyPI canonical response digest mismatch: {name}"
            )
        info = payload.get("info")
        urls = payload.get("urls")
        project_requires = (
            info.get("requires_python") if isinstance(info, dict) else None
        )
        if (
            not isinstance(info, dict)
            or _canonical(str(info.get("name", ""))) != name
            or str(info.get("version", "")) != locked_row.version
            or not isinstance(project_requires, (str, type(None)))
            or not isinstance(urls, list)
        ):
            raise CIDependencyAuthorityError(
                f"PyPI raw response identity/metadata invalid: {name}"
            )
        try:
            if project_requires:
                SpecifierSet(project_requires)
        except InvalidSpecifier as exc:
            raise CIDependencyAuthorityError(
                f"PyPI project Requires-Python is invalid: {name}"
            ) from exc
        normalized_artifacts: dict[str, str] = {}
        normalized_metadata: dict[str, dict[str, Any]] = {}
        for ordinal, file_row in enumerate(urls):
            if not isinstance(file_row, dict):
                raise CIDependencyAuthorityError(
                    f"PyPI artifact row invalid: {name}:{ordinal}"
                )
            if file_row.get("packagetype") != "bdist_wheel":
                continue
            filename = file_row.get("filename")
            digest_map = file_row.get("digests")
            digest = (
                digest_map.get("sha256")
                if isinstance(digest_map, dict)
                else None
            )
            artifact_url = file_row.get("url")
            file_requires = file_row.get("requires_python")
            yanked = file_row.get("yanked")
            if (
                not isinstance(filename, str)
                or "/" in filename
                or "\\" in filename
                or not filename.endswith(".whl")
                or filename in normalized_artifacts
                or not isinstance(digest, str)
                or _HEX64.fullmatch(digest) is None
                or not isinstance(artifact_url, str)
                or not isinstance(file_requires, (str, type(None)))
                or not isinstance(yanked, bool)
            ):
                raise CIDependencyAuthorityError(
                    f"PyPI wheel metadata invalid/ambiguous: {name}:{ordinal}"
                )
            try:
                if file_requires:
                    SpecifierSet(file_requires)
            except InvalidSpecifier as exc:
                raise CIDependencyAuthorityError(
                    "PyPI wheel Requires-Python is invalid: "
                    f"{name}:{filename}"
                ) from exc
            parsed_url = urlparse(artifact_url)
            try:
                explicit_port = parsed_url.port
            except ValueError as exc:
                raise CIDependencyAuthorityError(
                    f"PyPI wheel URL binding invalid: {name}:{filename}"
                ) from exc
            if (
                parsed_url.scheme != "https"
                or parsed_url.hostname != "files.pythonhosted.org"
                or explicit_port is not None
                or parsed_url.username is not None
                or parsed_url.password is not None
                or parsed_url.query
                or parsed_url.fragment
                or unquote(Path(parsed_url.path).name) != filename
            ):
                raise CIDependencyAuthorityError(
                    f"PyPI wheel URL binding invalid: {name}:{filename}"
                )
            try:
                parsed_name, parsed_version, _, _ = parse_wheel_filename(
                    filename
                )
            except Exception as exc:
                raise CIDependencyAuthorityError(
                    f"PyPI wheel filename invalid: {name}:{filename}"
                ) from exc
            if (
                _canonical(str(parsed_name)) != name
                or str(parsed_version) != locked_row.version
            ):
                raise CIDependencyAuthorityError(
                    f"PyPI wheel identity mismatch: {name}:{filename}"
                )
            normalized_artifacts[filename] = digest
            normalized_metadata[filename] = {
                "requires_python": file_requires,
                "url": artifact_url,
                "yanked": yanked,
            }
            artifact_index[f"{name}\0{filename}"] = {
                "project": name,
                "version": locked_row.version,
                "filename": filename,
                "sha256": digest,
                "url": artifact_url,
                "project_requires_python": project_requires,
                "file_requires_python": file_requires,
                "yanked": yanked,
            }
        if not normalized_artifacts:
            raise CIDependencyAuthorityError(
                f"PyPI response has no wheels: {name}"
            )
        expected_release_rows[name] = {
            "artifact_metadata": dict(sorted(normalized_metadata.items())),
            "artifacts": dict(sorted(normalized_artifacts.items())),
            "requires_python": project_requires or "",
            "response_sha256": response["raw_sha256"],
            "version": locked_row.version,
        }
    actual_raw_paths = _closed_raw_directory(
        root,
        RELEASE_RESPONSE_DIR,
        label="PyPI raw response",
    )
    if actual_raw_paths != expected_raw_paths:
        raise CIDependencyAuthorityError(
            "PyPI raw response file denominator is not closed"
        )
    if releases != expected_release_rows:
        raise CIDependencyAuthorityError(
            "PyPI normalized evidence differs from raw-response replay"
        )
    return expected_release_rows, artifact_index


def _validate_advisory_evidence(
    evidence: Mapping[str, Any],
    *,
    root: Path,
    locked: Mapping[str, LockedRequirement],
    receipt: Mapping[str, Any],
    checked: datetime,
) -> None:
    _exact_keys(
        evidence,
        {
            "schema",
            "source",
            "observed_at",
            "request",
            "request_sha256",
            "raw_request_path",
            "raw_request_sha256",
            "response",
            "response_sha256",
            "raw_response_path",
            "source_response_sha256",
            "query_count",
            "result",
            "advisory_ids",
            "limitation",
        },
        "OSV advisory evidence",
    )
    source = "https://api.osv.dev/v1/querybatch"
    observed = _parse_time(
        evidence.get("observed_at"), "OSV advisory evidence observed_at"
    )
    expected_request = {
        "queries": [
            {
                "package": {"ecosystem": "PyPI", "name": name},
                "version": row.version,
            }
            for name, row in sorted(locked.items())
        ]
    }
    request = evidence.get("request")
    response = evidence.get("response")
    raw_request_path = evidence.get("raw_request_path")
    raw_response_path = evidence.get("raw_response_path")
    raw_request = _bounded_raw_file(
        root,
        raw_request_path,
        expected_parent=ADVISORY_REQUEST_PATH.parent,
        label="OSV request",
    )
    raw_response = _bounded_raw_file(
        root,
        raw_response_path,
        expected_parent=ADVISORY_RESPONSE_PATH.parent,
        label="OSV response",
    )
    parsed_request = _parse_json_bytes(raw_request, "OSV raw request")
    parsed_response = _parse_json_bytes(raw_response, "OSV raw response")
    actual_raw_paths = _closed_raw_directory(
        root,
        ADVISORY_REQUEST_PATH.parent,
        label="OSV raw request/response",
    )
    if actual_raw_paths != {
        ADVISORY_REQUEST_PATH.as_posix(),
        ADVISORY_RESPONSE_PATH.as_posix(),
    }:
        raise CIDependencyAuthorityError(
            "OSV raw request/response file denominator is not closed"
        )
    if (
        evidence.get("schema") != ADVISORY_SCHEMA
        or evidence.get("source") != source
        or receipt.get("source") != source
        or receipt.get("observed_at") != evidence.get("observed_at")
        or observed > checked
        or raw_request_path != ADVISORY_REQUEST_PATH.as_posix()
        or raw_response_path != ADVISORY_RESPONSE_PATH.as_posix()
        or request != expected_request
        or parsed_request != expected_request
        or request != parsed_request
        or evidence.get("request_sha256")
        != hashlib.sha256(_compact_json_bytes(request)).hexdigest()
        or evidence.get("raw_request_sha256")
        != hashlib.sha256(raw_request).hexdigest()
        or not isinstance(response, dict)
        or response != parsed_response
        or evidence.get("response_sha256")
        != hashlib.sha256(_compact_json_bytes(response)).hexdigest()
        or evidence.get("source_response_sha256")
        != hashlib.sha256(raw_response).hexdigest()
        or evidence.get("query_count") != len(locked)
        or receipt.get("query_count") != len(locked)
    ):
        raise CIDependencyAuthorityError(
            "OSV advisory request/response binding invalid"
        )
    results = response.get("results")
    if not isinstance(results, list) or len(results) != len(locked):
        raise CIDependencyAuthorityError(
            "OSV advisory response denominator is incomplete"
        )
    observed_ids: set[str] = set()
    for ordinal, result in enumerate(results):
        if not isinstance(result, dict):
            raise CIDependencyAuthorityError(
                f"OSV advisory response row invalid: {ordinal}"
            )
        vulns = result.get("vulns", [])
        if not isinstance(vulns, list):
            raise CIDependencyAuthorityError(
                f"OSV advisory vulnerability row invalid: {ordinal}"
            )
        for vuln in vulns:
            if (
                not isinstance(vuln, dict)
                or not isinstance(vuln.get("id"), str)
                or not vuln["id"]
            ):
                raise CIDependencyAuthorityError(
                    f"OSV advisory identifier invalid: {ordinal}"
                )
            observed_ids.add(vuln["id"])
    ids = evidence.get("advisory_ids")
    expected_result = (
        "none-observed-at-check"
        if not observed_ids
        else "advisories-observed"
    )
    if (
        ids != sorted(observed_ids)
        or evidence.get("result") != expected_result
        or receipt.get("result") != expected_result
        or evidence.get("limitation")
        != (
            "Point-in-time primary-source observation; advisory data may "
            "change and must be refreshed before release."
        )
    ):
        raise CIDependencyAuthorityError(
            "OSV advisory result binding is invalid"
        )


def validate_receipt_payload(
    root: Path,
    payload: Mapping[str, Any],
    *,
    now: datetime | None = None,
) -> None:
    """Validate schema, evidence, action provenance, and wheel semantics."""

    root = Path(root)
    policy = _load_policy(root)
    schema = _json(root / SCHEMA_PATH, "CI receipt JSON schema")
    try:
        import jsonschema

        jsonschema.Draft202012Validator(schema).validate(dict(payload))
    except ImportError as exc:
        raise CIDependencyAuthorityError(
            "full receipt validation requires locked jsonschema"
        ) from exc
    except Exception as exc:
        raise CIDependencyAuthorityError(
            f"CI receipt schema validation failed: {type(exc).__name__}"
        ) from exc
    if payload.get("schema") != RECEIPT_SCHEMA:
        raise CIDependencyAuthorityError("CI receipt schema marker invalid")

    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise CIDependencyAuthorityError("validation clock must be aware")
    checked = _parse_time(payload.get("checked_at"), "checked_at")
    policy_checked = _parse_time(
        policy.get("checked_at"), "CI dependency policy checked_at"
    )
    release = payload.get("release_metadata")
    advisory = payload.get("advisory_review")
    if not isinstance(release, dict) or not isinstance(advisory, dict):
        raise CIDependencyAuthorityError("receipt evidence binding invalid")
    release_at = _parse_time(
        release.get("observed_at"), "release_metadata.observed_at"
    )
    advisory_at = _parse_time(
        advisory.get("observed_at"), "advisory_review.observed_at"
    )
    if (
        checked != policy_checked
        or checked > now
        or release_at > checked
        or advisory_at > checked
    ):
        raise CIDependencyAuthorityError(
            "receipt timestamps are future or causally incoherent"
        )
    actions = payload.get("github_actions")
    if not isinstance(actions, list):
        raise CIDependencyAuthorityError("GitHub Action evidence invalid")
    _validated_policy_actions(policy, checked=checked)
    expected_actions = policy["github_actions"]
    if actions != expected_actions:
        raise CIDependencyAuthorityError(
            "GitHub Action source/tag/commit evidence differs from policy"
        )
    for action in actions:
        if (
            not _ACTION_SHA.fullmatch(action["commit_sha"])
            or action["source"]
            != (
                f"https://github.com/{action['name']}/releases/tag/"
                f"v{action['version']}"
            )
            or _parse_time(
                action["observed_at"],
                f"GitHub Action {action['name']} observed_at",
            )
            > checked
        ):
            raise CIDependencyAuthorityError(
                f"GitHub Action evidence invalid: {action.get('name')}"
            )

    release_evidence = _json(
        root / RELEASE_EVIDENCE_PATH, "PyPI release evidence"
    )
    advisory_evidence = _json(
        root / ADVISORY_EVIDENCE_PATH, "OSV advisory evidence"
    )
    if (
        release.get("evidence_sha256")
        != _sha256(root / RELEASE_EVIDENCE_PATH)
        or advisory.get("evidence_sha256")
        != _sha256(root / ADVISORY_EVIDENCE_PATH)
        or release.get("response_set_sha256")
        != release_evidence.get("response_set_sha256")
        or advisory.get("response_sha256")
        != advisory_evidence.get("response_sha256")
    ):
        raise CIDependencyAuthorityError(
            "external evidence response digests are not preserved"
        )
    locked = parse_lock(root / "requirements-ci.lock")
    releases, raw_artifact_index = _validate_release_evidence(
        release_evidence,
        root=root,
        locked=locked,
        receipt=release,
        checked=checked,
    )
    _validate_advisory_evidence(
        advisory_evidence,
        root=root,
        locked=locked,
        receipt=advisory,
        checked=checked,
    )
    receipt_locked = payload.get("locked_projects")
    expected_locked = [
        {"name": name, "version": row.version}
        for name, row in sorted(locked.items())
    ]
    if receipt_locked != expected_locked:
        raise CIDependencyAuthorityError(
            "receipt locked project denominator/version differs from lock"
        )

    from packaging.markers import Marker, default_environment
    from packaging.specifiers import InvalidSpecifier, SpecifierSet
    from packaging.utils import parse_wheel_filename
    from packaging.version import Version

    def validate_artifact(
        artifact: Mapping[str, Any],
        *,
        supported: set[Any] | None = None,
        python: str | None = None,
    ) -> tuple[str, set[Any]]:
        filename = artifact["filename"]
        project = _canonical(artifact["project"])
        digest = artifact["sha256"]
        locked_row = locked.get(project)
        evidence = releases.get(project)
        raw_artifact = raw_artifact_index.get(f"{project}\0{filename}")
        try:
            parsed_name, parsed_version, _, wheel_tags = (
                parse_wheel_filename(filename)
            )
        except Exception as exc:
            raise CIDependencyAuthorityError(
                f"invalid wheel filename: {filename}"
            ) from exc
        if (
            locked_row is None
            or not isinstance(evidence, dict)
            or not isinstance(raw_artifact, dict)
            or _canonical(str(parsed_name)) != project
            or str(parsed_version) != locked_row.version
            or evidence.get("version") != locked_row.version
            or evidence.get("artifacts", {}).get(filename) != digest
            or raw_artifact.get("sha256") != digest
            or raw_artifact.get("project") != project
            or raw_artifact.get("version") != locked_row.version
            or raw_artifact.get("filename") != filename
            or digest not in locked_row.hashes
            or (supported is not None and not (wheel_tags & supported))
        ):
            raise CIDependencyAuthorityError(
                f"artifact filename/digest/project/version invalid: {filename}"
            )
        if python is not None:
            require_python(raw_artifact, python)
        return project, set(wheel_tags)

    def target_environment(python: str, platform: str) -> dict[str, str]:
        environment = default_environment()
        environment.update(
            {
                "implementation_name": "cpython",
                "implementation_version": f"{python}.0",
                "python_full_version": f"{python}.0",
                "python_version": python,
            }
        )
        if platform == "windows-x86_64":
            environment.update(
                {
                    "os_name": "nt",
                    "platform_machine": "AMD64",
                    "platform_system": "Windows",
                    "sys_platform": "win32",
                }
            )
        elif platform == "linux-x86_64":
            environment.update(
                {
                    "os_name": "posix",
                    "platform_machine": "x86_64",
                    "platform_system": "Linux",
                    "sys_platform": "linux",
                }
            )
        elif platform == "macos-arm64":
            environment.update(
                {
                    "os_name": "posix",
                    "platform_machine": "arm64",
                    "platform_system": "Darwin",
                    "sys_platform": "darwin",
                }
            )
        elif platform == "macos-x86_64":
            environment.update(
                {
                    "os_name": "posix",
                    "platform_machine": "x86_64",
                    "platform_system": "Darwin",
                    "sys_platform": "darwin",
                }
            )
        else:
            raise CIDependencyAuthorityError(
                f"unrecognized wheel target platform: {platform}"
            )
        return environment

    def active_projects(python: str, platform: str) -> set[str]:
        environment = target_environment(python, platform)
        active: set[str] = set()
        for name, row in locked.items():
            try:
                applies = (
                    True
                    if row.marker is None
                    else Marker(row.marker).evaluate(environment=environment)
                )
            except Exception as exc:
                raise CIDependencyAuthorityError(
                    f"locked marker is invalid: {name}"
                ) from exc
            if applies:
                active.add(name)
        return active

    def require_python(artifact: Mapping[str, Any], python: str) -> None:
        project = str(artifact["project"])
        file_expression = artifact.get("file_requires_python")
        project_expression = artifact.get("project_requires_python")
        expression = (
            file_expression
            if isinstance(file_expression, str) and file_expression
            else project_expression or ""
        )
        try:
            compatible = Version(f"{python}.0") in SpecifierSet(expression)
        except (InvalidSpecifier, ValueError) as exc:
            raise CIDependencyAuthorityError(
                f"Requires-Python is invalid: {project}"
            ) from exc
        if not compatible:
            raise CIDependencyAuthorityError(
                f"Requires-Python rejects {python}: {project}"
            )

    universal_projects: set[str] = set()
    universal_tags: dict[str, set[Any]] = {}
    for artifact in payload["universal_wheels"]:
        project, wheel_tags = validate_artifact(artifact)
        if project in universal_projects:
            raise CIDependencyAuthorityError(
                f"duplicate universal wheel project: {project}"
            )
        universal_projects.add(project)
        universal_tags[project] = wheel_tags

    coverage_targets: set[tuple[str, str]] = set()
    for target in payload["wheel_coverage"]:
        python = target["python"]
        platform = target["platform"]
        target_key = (python, platform)
        if target_key in coverage_targets:
            raise CIDependencyAuthorityError(
                f"duplicate wheel target: {target_key}"
            )
        coverage_targets.add(target_key)
        supported = _target_tags(python, platform)
        active = active_projects(python, platform)
        inactive_universal = universal_projects - active
        if inactive_universal:
            raise CIDependencyAuthorityError(
                "universal wheel project is inactive for declared target: "
                f"{sorted(inactive_universal)}"
            )
        for project, wheel_tags in universal_tags.items():
            if not (wheel_tags & supported):
                raise CIDependencyAuthorityError(
                    "universal wheel is incompatible with declared target: "
                    f"{project} / {target_key}"
                )
            universal_artifact = next(
                artifact
                for artifact in payload["universal_wheels"]
                if _canonical(artifact["project"]) == project
            )
            require_python(
                raw_artifact_index[
                    f"{project}\0{universal_artifact['filename']}"
                ],
                python,
            )
        target_projects: set[str] = set()
        for artifact in target["artifacts"]:
            project, _ = validate_artifact(
                artifact,
                supported=supported,
                python=python,
            )
            if project in target_projects or project in universal_projects:
                raise CIDependencyAuthorityError(
                    f"duplicate wheel project for target: {project}"
                )
            target_projects.add(project)
        expected_target_projects = active - universal_projects
        if target_projects != expected_target_projects:
            raise CIDependencyAuthorityError(
                "wheel project coverage denominator differs for target "
                f"{target_key}: missing="
                f"{sorted(expected_target_projects - target_projects)}, "
                f"extra={sorted(target_projects - expected_target_projects)}"
            )
    expected_targets = {
        (python, platform)
        for python in policy["matrix"]["python"]
        for platform in policy["matrix"]["platform"]
    }
    if coverage_targets != expected_targets:
        raise CIDependencyAuthorityError(
            "wheel coverage target denominator is incomplete"
        )

    covered_projects = universal_projects | {
        _canonical(artifact["project"])
        for target in payload["wheel_coverage"]
        for artifact in target["artifacts"]
    }
    if covered_projects != set(locked):
        raise CIDependencyAuthorityError(
            "wheel project coverage denominator differs from lock"
        )


def render_receipt(root: Path) -> bytes:
    """Render the sole accepted checked receipt from reviewed source data."""

    root = Path(root)
    policy = _load_policy(root)
    locked = parse_lock(root / "requirements-ci.lock")
    _, traversed, _ = _read_requirement_inputs(root)
    input_paths = sorted(
        {
            *traversed,
            "requirements-ci-resolver.in",
            "requirements-ci-resolver.lock",
        }
    )
    releases = _json(root / RELEASE_EVIDENCE_PATH, "release evidence")
    advisory = _json(root / ADVISORY_EVIDENCE_PATH, "advisory evidence")
    payload = {
        "schema": RECEIPT_SCHEMA,
        "authority": "generated-reviewed-point-in-time",
        "checked_at": policy["checked_at"],
        "resolver": policy["resolver"],
        "lock_authority": {
            "input_sha256": {
                relative: _sha256(root / relative)
                for relative in input_paths
            },
            "output_path": "requirements-ci.lock",
            "output_sha256": _sha256(root / "requirements-ci.lock"),
        },
        "github_actions": policy["github_actions"],
        "matrix": policy["matrix"],
        "release_metadata": {
            "source": releases["source"],
            "observed_at": releases["observed_at"],
            "evidence_path": RELEASE_EVIDENCE_PATH.as_posix(),
            "evidence_sha256": _sha256(root / RELEASE_EVIDENCE_PATH),
            "response_set_sha256": releases["response_set_sha256"],
        },
        "advisory_review": {
            "source": advisory["source"],
            "observed_at": advisory["observed_at"],
            "evidence_path": ADVISORY_EVIDENCE_PATH.as_posix(),
            "evidence_sha256": _sha256(root / ADVISORY_EVIDENCE_PATH),
            "response_sha256": advisory["response_sha256"],
            "query_count": advisory["query_count"],
            "result": advisory["result"],
        },
        "clean_claim": policy["clean_claim"],
        "locked_projects": [
            {"name": name, "version": row.version}
            for name, row in sorted(locked.items())
        ],
        "universal_wheels": policy["universal_wheels"],
        "wheel_coverage": policy["wheel_coverage"],
    }
    return (
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    ).encode("utf-8")


def regenerate_lock_bytes(root: Path) -> bytes:
    """Resolve in a fresh directory and return the deterministic lock bytes."""

    root = Path(root)
    policy = _load_policy(root)
    resolver = policy["resolver"]
    if (
        sys.implementation.name != "cpython"
        or f"{sys.version_info.major}.{sys.version_info.minor}"
        != resolver["python_version"]
    ):
        raise CIDependencyAuthorityError(
            "lock regeneration requires the reviewed CPython 3.12 resolver"
        )
    if sys.prefix == sys.base_prefix:
        raise CIDependencyAuthorityError(
            "lock regeneration requires a fresh isolated virtual environment"
        )
    prefix = Path(sys.prefix).resolve()
    config = prefix / "pyvenv.cfg"
    try:
        config_text = config.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise CIDependencyAuthorityError(
            "lock regeneration requires a readable virtual environment"
        ) from exc
    if re.search(
        r"(?im)^\s*include-system-site-packages\s*=\s*true\s*$",
        config_text,
    ):
        raise CIDependencyAuthorityError(
            "resolver virtual environment enables system site packages"
        )
    resolver_lock = parse_lock(root / "requirements-ci-resolver.lock")
    site_paths = tuple(
        sorted(
            {
                str(Path(value).resolve())
                for key, value in sysconfig.get_paths().items()
                if key in {"purelib", "platlib"}
            }
        )
    )
    if not site_paths or any(
        not Path(value).is_relative_to(prefix) for value in site_paths
    ):
        raise CIDependencyAuthorityError(
            "resolver package metadata paths escape the virtual environment"
        )
    installed: dict[str, str] = {}
    for distribution in importlib.metadata.distributions(path=site_paths):
        name = distribution.metadata.get("Name")
        if not isinstance(name, str) or not name:
            raise CIDependencyAuthorityError(
                "resolver environment contains an unnamed distribution"
            )
        canonical = _canonical(name)
        if canonical in installed:
            raise CIDependencyAuthorityError(
                f"resolver environment contains duplicate project: {canonical}"
            )
        origin = Path(distribution.locate_file("")).resolve()
        if not origin.is_relative_to(prefix):
            raise CIDependencyAuthorityError(
                f"resolver distribution origin escapes venv: {canonical}"
            )
        for relative in distribution.files or ():
            member = Path(distribution.locate_file(relative)).resolve()
            if not member.is_relative_to(prefix):
                raise CIDependencyAuthorityError(
                    "resolver distribution file escapes venv: "
                    f"{canonical}:{relative}"
                )
        installed[canonical] = distribution.version
    expected_installed = {
        name: row.version for name, row in resolver_lock.items()
    }
    if installed != expected_installed:
        raise CIDependencyAuthorityError(
            "lock regeneration requires the exact isolated resolver lock: "
            f"missing={sorted(set(expected_installed) - set(installed))}, "
            f"extra={sorted(set(installed) - set(expected_installed))}, "
            "version_mismatch="
            f"{sorted(name for name in set(installed) & set(expected_installed) if installed[name] != expected_installed[name])}"
        )
    with tempfile.TemporaryDirectory(prefix="plamen-ci-lock-") as raw:
        work = Path(raw)
        _, inputs, _ = _read_requirement_inputs(root)
        for relative in inputs:
            target = work / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(root / relative, target)
        allowed = {
            "PATH",
            "PATHEXT",
            "SYSTEMROOT",
            "WINDIR",
            "COMSPEC",
            "TEMP",
            "TMP",
            "TMPDIR",
            "LANG",
            "LC_ALL",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
            "REQUESTS_CA_BUNDLE",
            "CURL_CA_BUNDLE",
        }
        env = {
            key: value
            for key, value in os.environ.items()
            if key.upper() in allowed
        }
        env["PIP_CONFIG_FILE"] = os.devnull
        env["PIP_INDEX_URL"] = resolver["index_url"]
        env["PIP_ONLY_BINARY"] = ":all:"
        env["PIP_CACHE_DIR"] = str(work / "pip-cache")
        env["PYTHONNOUSERSITE"] = "1"
        command = [sys.executable, *resolver["command"][1:]]
        completed = _run_utf8_diagnostic(
            command,
            cwd=work,
            env=env,
        )
        if completed.returncode != 0:
            raise CIDependencyAuthorityError(
                "deterministic lock regeneration failed: "
                + completed.stderr[-2000:]
            )
        return _canonical_generated_lock_bytes(
            (work / "requirements-ci.lock").read_bytes()
        )


def _venv_python(prefix: Path) -> Path:
    if os.name == "nt":
        return prefix / "Scripts" / "python.exe"
    return prefix / "bin" / "python"


def _bootstrap_environment(work: Path, index_url: str) -> dict[str, str]:
    allowed = {
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "TEMP",
        "TMP",
        "TMPDIR",
        "LANG",
        "LC_ALL",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
    }
    env = {
        key: value
        for key, value in os.environ.items()
        if key.upper() in allowed
    }
    env.update(
        {
            "PIP_CONFIG_FILE": os.devnull,
            "PIP_INDEX_URL": index_url,
            "PIP_ONLY_BINARY": ":all:",
            "PIP_CACHE_DIR": str(work / "pip-cache"),
            "PYTHONNOUSERSITE": "1",
        }
    )
    return env


def _run_utf8_diagnostic(
    command: list[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
) -> subprocess.CompletedProcess[str]:
    """Run a governed child with deterministic, diagnostic-safe decoding."""

    return subprocess.run(
        command,
        cwd=cwd,
        env=dict(env),
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def bootstrap_gate(root: Path) -> None:
    """Run the full gate only inside a code-owned isolated resolver venv."""

    root = Path(root).resolve()
    verify_static_bindings(root, verify_workflows=False)
    policy = _load_policy(root)
    resolver = policy["resolver"]
    if (
        sys.implementation.name != "cpython"
        or f"{sys.version_info.major}.{sys.version_info.minor}"
        != resolver["python_version"]
    ):
        raise CIDependencyAuthorityError(
            "bootstrap gate requires the reviewed CPython resolver"
        )
    with tempfile.TemporaryDirectory(prefix="plamen-ci-bootstrap-") as raw:
        work = Path(raw)
        prefix = work / "resolver-venv"
        venv.EnvBuilder(
            clear=True,
            with_pip=True,
            system_site_packages=False,
        ).create(prefix)
        python = _venv_python(prefix)
        env = _bootstrap_environment(work, resolver["index_url"])
        install = _run_utf8_diagnostic(
            [
                str(python),
                "-I",
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--only-binary=:all:",
                "--require-hashes",
                "-r",
                str((root / "requirements-ci-resolver.lock").resolve()),
            ],
            cwd=root,
            env=env,
        )
        if install.returncode != 0:
            raise CIDependencyAuthorityError(
                "isolated resolver bootstrap failed: "
                + install.stderr[-2000:]
            )
        completed = _run_utf8_diagnostic(
            [
                str(python),
                "-I",
                str((root / "scripts/ci_dependency_authority.py").resolve()),
                "gate",
                "--root",
                str(root),
            ],
            cwd=root,
            env=env,
        )
        if completed.returncode != 0:
            raise CIDependencyAuthorityError(
                "isolated full dependency gate failed: "
                + completed.stderr[-2000:]
            )


def verify_repository(
    root: Path,
    *,
    now: datetime | None = None,
    regenerate_lock: bool = True,
) -> None:
    verify_static_bindings(root)
    checked = (Path(root) / RECEIPT_PATH).read_bytes()
    rendered = render_receipt(root)
    if checked != rendered:
        raise CIDependencyAuthorityError(
            "checked receipt is not exact generator output"
        )
    validate_receipt_payload(Path(root), json.loads(checked), now=now)
    if regenerate_lock:
        regenerated = regenerate_lock_bytes(Path(root))
        regenerated_lock = _parse_lock_text(
            regenerated.decode("utf-8"),
            label="isolated deterministic resolution",
        )
        checked_lock = parse_lock(Path(root) / "requirements-ci.lock")
        _verify_host_resolution(checked_lock, regenerated_lock)


def build_dependency_snapshot(
    root: Path,
    *,
    sha: str,
    ref: str,
    run_id: str,
    scanned: str,
) -> dict[str, Any]:
    """Build GitHub's dependency-submission v0 payload from the exact lock."""

    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise CIDependencyAuthorityError("snapshot SHA must be a Git commit")
    _parse_time(scanned, "snapshot scanned")
    locked = parse_lock(Path(root) / "requirements-ci.lock")
    return {
        "version": 0,
        "sha": sha,
        "ref": ref,
        "job": {"correlator": f"plamen-ci-lock-{run_id}", "id": run_id},
        "detector": {"name": "plamen-ci-dependency-authority", "version": "1"},
        "scanned": scanned,
        "manifests": {
            "requirements-ci.lock": {
                "name": "requirements-ci.lock",
                "file": {"source_location": "requirements-ci.lock"},
                "resolved": {
                    f"pkg:pypi/{name}@{row.version}": {
                        "package_url": f"pkg:pypi/{name}@{row.version}",
                        "relationship": "direct",
                        "scope": "runtime",
                        "dependencies": [],
                    }
                    for name, row in sorted(locked.items())
                },
            }
        },
    }


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command",
        choices={
            "bootstrap-gate",
            "static",
            "gate",
            "render-lock",
            "render-receipt",
            "dependency-snapshot",
        },
    )
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path)
    parser.add_argument("--sha")
    parser.add_argument("--ref")
    parser.add_argument("--run-id")
    parser.add_argument("--scanned")
    args = parser.parse_args(argv)
    try:
        if args.command == "bootstrap-gate":
            bootstrap_gate(args.root)
        elif args.command == "static":
            verify_static_bindings(args.root)
        elif args.command == "gate":
            verify_repository(args.root)
        elif args.command == "render-lock":
            if args.output is None:
                raise CIDependencyAuthorityError("--output is required")
            _write(args.output, regenerate_lock_bytes(args.root))
        elif args.command == "render-receipt":
            if args.output is None:
                raise CIDependencyAuthorityError("--output is required")
            _write(args.output, render_receipt(args.root))
        else:
            if not all((args.output, args.sha, args.ref, args.run_id, args.scanned)):
                raise CIDependencyAuthorityError(
                    "dependency-snapshot requires output, sha, ref, run-id, scanned"
                )
            _write(
                args.output,
                (
                    json.dumps(
                        build_dependency_snapshot(
                            args.root,
                            sha=args.sha,
                            ref=args.ref,
                            run_id=args.run_id,
                            scanned=args.scanned,
                        ),
                        indent=2,
                        sort_keys=True,
                    )
                    + "\n"
                ).encode("utf-8"),
            )
    except CIDependencyAuthorityError as exc:
        print(f"CI dependency authority failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
