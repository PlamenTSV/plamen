"""Pure deterministic runtime-policy artifacts; no authority is created here."""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping

INSTALLED_CENSUS_SCHEMA = "plamen.installed_runtime_census.v1"
BAKED_CLOSURE_SCHEMA = "plamen.baked-image-member-closure.v1"
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_MODE = re.compile(r"0[0-7]{3}\Z")
_ROW_KEYS = frozenset({"kind", "linkname", "mode", "path", "sha256", "size"})
BLOCKED_NETWORK_ADMIN_SYSCALLS = (
    "bpf", "fsconfig", "fsmount", "fsopen", "mount", "move_mount",
    "open_tree", "pivot_root", "setns", "umount2", "unshare",
)


class RuntimePolicyArtifactError(RuntimeError):
    pass


def _canonical(value: Any) -> bytes:
    try:
        return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise RuntimePolicyArtifactError("artifact is not canonicalizable") from exc


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RuntimePolicyArtifactError("duplicate JSON key")
        result[key] = value
    return result


def _json(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not raw or len(raw) > 64 * 1024 * 1024:
        raise RuntimePolicyArtifactError("installed census bytes are invalid")
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_pairs,
                           parse_constant=lambda _v: (_ for _ in ()).throw(
                               RuntimePolicyArtifactError("nonfinite JSON number")))
    except RuntimePolicyArtifactError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimePolicyArtifactError("installed census JSON is malformed") from exc
    if type(value) is not dict or _canonical(value) != raw:
        raise RuntimePolicyArtifactError("installed census is not canonical")
    return value


def render_baked_image_member_closure(
    installed_census_raw: bytes, *, required_paths: Mapping[str, str]
) -> bytes:
    """Project exact required regular files from an authenticated census's bytes."""
    census = _json(installed_census_raw)
    if (frozenset(census) != {"entries", "schema_version"}
            or census.get("schema_version") != INSTALLED_CENSUS_SCHEMA
            or type(census.get("entries")) is not list):
        raise RuntimePolicyArtifactError("installed census schema is not exact")
    if (type(required_paths) is not dict or not required_paths
            or any(type(k) is not str or type(v) is not str or not v.startswith("/")
                   for k, v in required_paths.items())):
        raise RuntimePolicyArtifactError("required image-member roster is invalid")
    entries: dict[str, dict[str, Any]] = {}
    previous: bytes | None = None
    for row in census["entries"]:
        if type(row) is not dict or frozenset(row) != _ROW_KEYS:
            raise RuntimePolicyArtifactError("installed census row schema is not exact")
        path = row.get("path")
        encoded = path.encode("utf-8") if isinstance(path, str) else b""
        if not encoded or path.startswith("/") or previous is not None and encoded <= previous:
            raise RuntimePolicyArtifactError("installed census path order is invalid")
        previous = encoded
        if path in entries:
            raise RuntimePolicyArtifactError("installed census path is duplicated")
        entries[path] = row
    members: list[dict[str, Any]] = []
    for name, absolute in sorted(required_paths.items()):
        relative = absolute.removeprefix("/")
        row = entries.get(relative)
        if (row is None or row.get("kind") != "file" or row.get("linkname") != ""
                or not isinstance(row.get("mode"), str) or _MODE.fullmatch(row["mode"]) is None
                or not isinstance(row.get("sha256"), str)
                or _HEX64.fullmatch(row["sha256"]) is None
                or row["sha256"] == "0" * 64 or type(row.get("size")) is not int
                or row["size"] < 1):
            raise RuntimePolicyArtifactError(f"required image member is invalid: {name}")
        members.append({"mode": row["mode"], "name": name, "path": absolute,
                        "sha256": row["sha256"], "size": row["size"]})
    unsigned = {"installed_census_sha256": hashlib.sha256(installed_census_raw).hexdigest(),
                "members": members, "schema_version": BAKED_CLOSURE_SCHEMA}
    return _canonical({**unsigned, "closure_sha256": hashlib.sha256(_canonical(unsigned)).hexdigest()})


def validate_baked_image_member_closure(
    raw: bytes, installed_census_raw: bytes, *, required_paths: Mapping[str, str]
) -> dict[str, Any]:
    expected = render_baked_image_member_closure(
        installed_census_raw, required_paths=required_paths)
    if raw != expected:
        raise RuntimePolicyArtifactError("baked image-member closure differs from census")
    return _json(raw)


def render_linux_guest_seccomp_profile() -> bytes:
    """Render the fixed arm64 containment profile for independent review."""
    profile = {
        "architectures": ["SCMP_ARCH_AARCH64"],
        "defaultAction": "SCMP_ACT_ALLOW",
        "flags": [],
        "syscalls": [
            {"action": "SCMP_ACT_ERRNO", "errnoRet": 1,
             "names": list(BLOCKED_NETWORK_ADMIN_SYSCALLS)},
            {"action": "SCMP_ACT_ERRNO", "args": [
                {"index": 0, "op": "SCMP_CMP_MASKED_EQ",
                 "value": 0xffffffff, "valueTwo": 16}],
             "errnoRet": 1, "names": ["socket"]},
            {"action": "SCMP_ACT_ERRNO", "args": [
                {"index": 0, "op": "SCMP_CMP_MASKED_EQ",
                 "value": 0xffffffff, "valueTwo": 17}],
             "errnoRet": 1, "names": ["socket"]},
            {"action": "SCMP_ACT_ERRNO", "args": [
                {"index": 1, "op": "SCMP_CMP_MASKED_EQ", "value": 15,
                 "valueTwo": 3}],
             "errnoRet": 1, "names": ["socket"]},
        ],
    }
    return _canonical(profile)


def validate_linux_guest_seccomp_profile(raw: bytes) -> dict[str, Any]:
    expected = render_linux_guest_seccomp_profile()
    if raw != expected:
        raise RuntimePolicyArtifactError("seccomp profile differs from reviewed candidate")
    return _json(raw)
