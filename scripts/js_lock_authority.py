#!/usr/bin/env python3
"""Pure, strict selection of one JavaScript lockfile authority.

This module deliberately has no filesystem, subprocess, environment, or network
surface.  Callers must acquire stable bytes themselves and must separately bind
the selected package-manager executable before materializing dependencies.
"""

from __future__ import annotations

from dataclasses import dataclass
import base64
import binascii
import hashlib
import json
import re
from typing import Any, Mapping
from urllib.parse import urlsplit


SCHEMA = "plamen.js-lock-selection.v2"
YARN_INTEGRITY_AUTHORITY_SCHEMA = "plamen.yarn-integrity-authority.v2"
DECLARED_PACKAGE_MANAGER_LOCK = "DECLARED_PACKAGE_MANAGER_LOCK"
UNIQUE_MANIFEST_CONSISTENT_LOCK = "UNIQUE_MANIFEST_CONSISTENT_LOCK"
SUPPORTED_LOCKFILES = frozenset(
    {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock"}
)
KNOWN_UNSUPPORTED_LOCKFILES = frozenset(
    {"pnpm-lock.yaml", "bun.lock", "bun.lockb"}
)
_DEPENDENCY_SECTIONS = (
    "dependencies",
    "devDependencies",
    "optionalDependencies",
)
_PACKAGE_NAME_RE = re.compile(
    r"(?:[a-z0-9][a-z0-9._~-]*|@[a-z0-9][a-z0-9._~-]*/[a-z0-9][a-z0-9._~-]*)",
    re.ASCII,
)
_PACKAGE_MANAGER_RE = re.compile(
    r"(npm|yarn|pnpm)@([0-9A-Za-z][0-9A-Za-z.+_-]*)", re.ASCII
)
_UNQUOTED_YARN_TOKEN_RE = re.compile(r"[^\s,:\"\\]+", re.ASCII)
_SRI_LENGTHS = {"sha256": 32, "sha384": 48, "sha512": 64}
_UNSUPPORTED_SPEC_PREFIXES = (
    "file:",
    "link:",
    "git:",
    "git+",
    "ssh:",
    "github:",
    "gitlab:",
    "bitbucket:",
    "workspace:",
    "portal:",
    "patch:",
    "http:",
    "https:",
)


class JSLockAuthorityError(ValueError):
    """A typed, non-fallback selection failure."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        assessments: tuple["LockCandidateAssessment", ...] = (),
    ) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.assessments = assessments


class _DuplicateJSONKey(ValueError):
    pass


class _CandidateInvalid(ValueError):
    def __init__(self, *codes: str) -> None:
        if not codes:
            codes = ("LOCKFILE_INVALID",)
        self.codes = tuple(dict.fromkeys(codes))
        super().__init__(",".join(self.codes))


@dataclass(frozen=True)
class LockCandidateAssessment:
    filename: str
    family: str
    lockfile_sha256: str
    consistent: bool
    error_codes: tuple[str, ...]
    reachable_stanza_count: int = 0
    reachable_selectors_sha256: str = ""
    unused_stanza_count: int = 0
    unused_selectors_sha256: str = ""

    def binding_dict(self) -> dict[str, Any]:
        return {
            "consistent": self.consistent,
            "error_codes": list(self.error_codes),
            "family": self.family,
            "filename": self.filename,
            "lockfile_sha256": self.lockfile_sha256,
            "reachable_selectors_sha256": self.reachable_selectors_sha256,
            "reachable_stanza_count": self.reachable_stanza_count,
            "unused_selectors_sha256": self.unused_selectors_sha256,
            "unused_stanza_count": self.unused_stanza_count,
        }


@dataclass(frozen=True)
class JSLockSelection:
    schema: str
    family: str
    filename: str
    declared_package_manager: str
    selection_basis: str
    package_json_sha256: str
    lockfile_sha256: str
    direct_requirements_sha256: str
    reachable_selectors_sha256: str
    reachable_stanza_count: int
    unused_selectors_sha256: str
    unused_stanza_count: int
    candidates: tuple[LockCandidateAssessment, ...]
    selection_sha256: str

    def binding_dict(self) -> dict[str, Any]:
        return {
            "candidates": [item.binding_dict() for item in self.candidates],
            "declared_package_manager": self.declared_package_manager,
            "direct_requirements_sha256": self.direct_requirements_sha256,
            "family": self.family,
            "filename": self.filename,
            "lockfile_sha256": self.lockfile_sha256,
            "package_json_sha256": self.package_json_sha256,
            "reachable_selectors_sha256": self.reachable_selectors_sha256,
            "reachable_stanza_count": self.reachable_stanza_count,
            "schema": self.schema,
            "selection_basis": self.selection_basis,
            "unused_selectors_sha256": self.unused_selectors_sha256,
            "unused_stanza_count": self.unused_stanza_count,
        }


@dataclass(frozen=True)
class YarnIntegrityAuthority:
    """Exact Yarn-v1 projection expected in ``.yarn-integrity``.

    Yarn Classic records one ``selector -> resolved`` row for every reachable
    selector.  Binding only the selector names is insufficient: an attacker
    can preserve the denominator while substituting every resolved archive.
    This immutable projection is independently derived from the authenticated
    manifest and lock bytes and is replayed against the installed tree.
    """

    schema: str
    lockfile_entries: tuple[tuple[str, str], ...]
    direct_packages: tuple[tuple[str, str, str], ...]
    resolved_origins: tuple[tuple[str, str, int], ...]
    lockfile_entries_sha256: str
    direct_packages_sha256: str
    resolved_origins_sha256: str
    authority_sha256: str

    def binding_dict(self) -> dict[str, Any]:
        return {
            "direct_packages": [list(row) for row in self.direct_packages],
            "direct_packages_sha256": self.direct_packages_sha256,
            "lockfile_entries": [list(row) for row in self.lockfile_entries],
            "lockfile_entries_sha256": self.lockfile_entries_sha256,
            "resolved_origins": [list(row) for row in self.resolved_origins],
            "resolved_origins_sha256": self.resolved_origins_sha256,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class _Manifest:
    sections: tuple[tuple[str, tuple[tuple[str, str], ...]], ...]
    direct: tuple[tuple[str, str], ...]
    package_manager_family: str
    package_manager_raw: str


@dataclass(frozen=True)
class _YarnEntry:
    selectors: tuple[str, ...]
    version: str | None
    resolved: str | None
    integrity: str | None
    dependencies: tuple[tuple[str, str], ...]


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _digest_rows(rows: tuple[str, ...] | list[str]) -> str:
    return _sha256(_canonical_bytes(list(rows)))


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJSONKey(key)
        result[key] = value
    return result


def _strict_json(data: bytes, prefix: str) -> Any:
    if type(data) is not bytes:
        raise _CandidateInvalid(f"{prefix}_BYTES_REQUIRED")
    if data.startswith(b"\xef\xbb\xbf"):
        raise _CandidateInvalid(f"{prefix}_UTF8_BOM_REJECTED")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise _CandidateInvalid(f"{prefix}_INVALID_UTF8") from exc
    if "\x00" in text:
        raise _CandidateInvalid(f"{prefix}_NUL_REJECTED")
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicate_pairs)
    except _DuplicateJSONKey as exc:
        raise _CandidateInvalid(f"{prefix}_DUPLICATE_KEY") from exc
    except json.JSONDecodeError as exc:
        raise _CandidateInvalid(f"{prefix}_INVALID_JSON") from exc


def _validate_package_name(name: Any) -> str:
    if type(name) is not str or not _PACKAGE_NAME_RE.fullmatch(name):
        raise JSLockAuthorityError(
            "PACKAGE_JSON_DEPENDENCY_NAME_INVALID",
            "a dependency name is outside the supported canonical npm name grammar",
        )
    return name


def _manifest(package_json: bytes) -> _Manifest:
    try:
        raw = _strict_json(package_json, "PACKAGE_JSON")
    except _CandidateInvalid as exc:
        raise JSLockAuthorityError(exc.codes[0], "package.json is invalid") from exc
    if type(raw) is not dict:
        raise JSLockAuthorityError(
            "PACKAGE_JSON_ROOT_NOT_OBJECT", "package.json root must be an object"
        )

    sections: list[tuple[str, tuple[tuple[str, str], ...]]] = []
    combined: dict[str, str] = {}
    for section in _DEPENDENCY_SECTIONS:
        value = raw.get(section, {})
        if type(value) is not dict:
            raise JSLockAuthorityError(
                "PACKAGE_JSON_DEPENDENCY_SECTION_INVALID",
                f"package.json {section} must be an object",
            )
        rows: list[tuple[str, str]] = []
        for name, spec in value.items():
            canonical_name = _validate_package_name(name)
            if type(spec) is not str or not spec or spec != spec.strip():
                raise JSLockAuthorityError(
                    "PACKAGE_JSON_DEPENDENCY_SPEC_INVALID",
                    f"package.json {section} contains an invalid dependency specifier",
                )
            prior = combined.get(canonical_name)
            if prior is not None and prior != spec:
                raise JSLockAuthorityError(
                    "PACKAGE_JSON_DEPENDENCY_CONFLICT",
                    "one dependency name has conflicting root specifiers",
                )
            combined[canonical_name] = spec
            rows.append((canonical_name, spec))
        sections.append((section, tuple(sorted(rows))))

    manager_family = ""
    manager_raw = ""
    if "packageManager" in raw:
        manager = raw["packageManager"]
        if type(manager) is not str or not manager:
            raise JSLockAuthorityError(
                "PACKAGE_MANAGER_INVALID",
                "packageManager must be an exact name@version string",
            )
        match = _PACKAGE_MANAGER_RE.fullmatch(manager)
        if match is None:
            raise JSLockAuthorityError(
                "PACKAGE_MANAGER_INVALID",
                "packageManager must be an exact supported name@version string",
            )
        manager_family = match.group(1)
        manager_raw = manager

    return _Manifest(
        sections=tuple(sections),
        direct=tuple(sorted(combined.items())),
        package_manager_family=manager_family,
        package_manager_raw=manager_raw,
    )


def _lock_family(filename: str) -> str:
    if filename in {"package-lock.json", "npm-shrinkwrap.json"}:
        return "npm"
    if filename == "yarn.lock":
        return "yarn"
    return "unsupported"


def _npm_assessment(
    filename: str, data: bytes, manifest: _Manifest
) -> LockCandidateAssessment:
    digest = _sha256(data)
    try:
        raw = _strict_json(data, "NPM_LOCK")
        if type(raw) is not dict:
            raise _CandidateInvalid("NPM_LOCK_ROOT_NOT_OBJECT")
        version = raw.get("lockfileVersion")
        if type(version) is not int or version not in {2, 3}:
            raise _CandidateInvalid("NPM_LOCK_VERSION_UNSUPPORTED")
        packages = raw.get("packages")
        if type(packages) is not dict or type(packages.get("")) is not dict:
            raise _CandidateInvalid("NPM_LOCK_ROOT_PACKAGE_MISSING")
        root = packages[""]
        errors: list[str] = []
        manifest_sections = dict(manifest.sections)
        for section in _DEPENDENCY_SECTIONS:
            lock_map = root.get(section, {})
            if type(lock_map) is not dict or any(
                type(key) is not str or type(value) is not str
                for key, value in lock_map.items()
            ):
                errors.append(f"NPM_ROOT_{section.upper()}_INVALID")
                continue
            expected = dict(manifest_sections[section])
            if lock_map != expected:
                errors.append(f"NPM_ROOT_{section.upper()}_MISMATCH")
        if errors:
            raise _CandidateInvalid(*errors)
    except _CandidateInvalid as exc:
        return LockCandidateAssessment(
            filename=filename,
            family="npm",
            lockfile_sha256=digest,
            consistent=False,
            error_codes=exc.codes,
        )
    return LockCandidateAssessment(
        filename=filename,
        family="npm",
        lockfile_sha256=digest,
        consistent=True,
        error_codes=(),
    )


def _decode_yarn_string(token: str, code: str) -> str:
    if token.startswith('"'):
        try:
            value = json.loads(token)
        except json.JSONDecodeError as exc:
            raise _CandidateInvalid(code) from exc
        if type(value) is not str:
            raise _CandidateInvalid(code)
        return value
    if not _UNQUOTED_YARN_TOKEN_RE.fullmatch(token):
        raise _CandidateInvalid(code)
    return token


def _split_yarn_header(raw: str) -> tuple[str, ...]:
    pieces: list[str] = []
    start = 0
    quoted = False
    escaped = False
    for index, char in enumerate(raw):
        if escaped:
            escaped = False
            continue
        if quoted and char == "\\":
            escaped = True
            continue
        if char == '"':
            quoted = not quoted
            continue
        if char == "," and not quoted:
            pieces.append(raw[start:index].strip())
            start = index + 1
    if quoted or escaped:
        raise _CandidateInvalid("YARN_LOCK_HEADER_SYNTAX_INVALID")
    pieces.append(raw[start:].strip())
    if any(not item for item in pieces):
        raise _CandidateInvalid("YARN_LOCK_HEADER_SYNTAX_INVALID")
    decoded = tuple(
        _decode_yarn_string(item, "YARN_LOCK_SELECTOR_INVALID")
        for item in pieces
    )
    if len(set(decoded)) != len(decoded):
        raise _CandidateInvalid("YARN_LOCK_DUPLICATE_SELECTOR")
    return decoded


def _parse_yarn_scalar(raw: str, code: str) -> str:
    value = raw.strip()
    if not value:
        raise _CandidateInvalid(code)
    return _decode_yarn_string(value, code)


def _consume_yarn_token(raw: str, start: int, code: str) -> tuple[str, int]:
    while start < len(raw) and raw[start].isspace():
        start += 1
    if start >= len(raw):
        raise _CandidateInvalid(code)
    if raw[start] == '"':
        try:
            value, end = json.JSONDecoder().raw_decode(raw[start:])
        except json.JSONDecodeError as exc:
            raise _CandidateInvalid(code) from exc
        if type(value) is not str:
            raise _CandidateInvalid(code)
        return value, start + end
    end = start
    while end < len(raw) and not raw[end].isspace():
        end += 1
    token = raw[start:end]
    return _decode_yarn_string(token, code), end


def _parse_yarn_dependency(raw: str) -> tuple[str, str]:
    name, offset = _consume_yarn_token(raw, 0, "YARN_LOCK_DEPENDENCY_INVALID")
    spec, offset = _consume_yarn_token(
        raw, offset, "YARN_LOCK_DEPENDENCY_INVALID"
    )
    if raw[offset:].strip():
        raise _CandidateInvalid("YARN_LOCK_DEPENDENCY_INVALID")
    if not _PACKAGE_NAME_RE.fullmatch(name) or not spec:
        raise _CandidateInvalid("YARN_LOCK_DEPENDENCY_INVALID")
    return name, spec


def _parse_yarn_v1(data: bytes) -> tuple[_YarnEntry, ...]:
    if type(data) is not bytes:
        raise _CandidateInvalid("YARN_LOCK_BYTES_REQUIRED")
    if data.startswith(b"\xef\xbb\xbf"):
        raise _CandidateInvalid("YARN_LOCK_UTF8_BOM_REJECTED")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise _CandidateInvalid("YARN_LOCK_INVALID_UTF8") from exc
    if "\x00" in text or "\r" in text:
        raise _CandidateInvalid("YARN_LOCK_TEXT_INVALID")
    lines = text.split("\n")
    if "# yarn lockfile v1" not in lines[:4]:
        raise _CandidateInvalid("YARN_LOCK_V1_HEADER_REQUIRED")

    entries: list[_YarnEntry] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        if not line or line.startswith("#"):
            index += 1
            continue
        if line != line.rstrip() or line.startswith((" ", "\t")) or not line.endswith(":"):
            raise _CandidateInvalid("YARN_LOCK_STANZA_HEADER_INVALID")
        selectors = _split_yarn_header(line[:-1])
        index += 1
        scalar_fields: dict[str, str] = {}
        dependencies: dict[str, str] = {}
        while index < len(lines):
            current = lines[index]
            if not current or current.startswith("#"):
                index += 1
                continue
            if not current.startswith((" ", "\t")):
                break
            if "\t" in current or current != current.rstrip():
                raise _CandidateInvalid("YARN_LOCK_INDENTATION_INVALID")
            if not current.startswith("  ") or current.startswith("   "):
                raise _CandidateInvalid("YARN_LOCK_INDENTATION_INVALID")
            field_line = current[2:]
            if field_line in {"dependencies:", "optionalDependencies:"}:
                field_name = field_line[:-1]
                if field_name in scalar_fields:
                    raise _CandidateInvalid("YARN_LOCK_DUPLICATE_FIELD")
                scalar_fields[field_name] = ""
                index += 1
                while index < len(lines):
                    child = lines[index]
                    if not child or child.startswith("#"):
                        index += 1
                        continue
                    if not child.startswith("    "):
                        break
                    if "\t" in child or child != child.rstrip():
                        raise _CandidateInvalid("YARN_LOCK_INDENTATION_INVALID")
                    name, spec = _parse_yarn_dependency(child[4:])
                    if name in dependencies and dependencies[name] != spec:
                        raise _CandidateInvalid(
                            "YARN_LOCK_DUPLICATE_DEPENDENCY"
                        )
                    dependencies[name] = spec
                    index += 1
                continue
            if " " not in field_line:
                raise _CandidateInvalid("YARN_LOCK_FIELD_INVALID")
            field_name, raw_value = field_line.split(" ", 1)
            if field_name not in {"version", "resolved", "integrity"}:
                raise _CandidateInvalid("YARN_LOCK_FIELD_UNSUPPORTED")
            if field_name in scalar_fields:
                raise _CandidateInvalid("YARN_LOCK_DUPLICATE_FIELD")
            scalar_fields[field_name] = _parse_yarn_scalar(
                raw_value, "YARN_LOCK_FIELD_INVALID"
            )
            index += 1
        entries.append(
            _YarnEntry(
                selectors=selectors,
                version=scalar_fields.get("version"),
                resolved=scalar_fields.get("resolved"),
                integrity=scalar_fields.get("integrity"),
                dependencies=tuple(sorted(dependencies.items())),
            )
        )
    if not entries:
        raise _CandidateInvalid("YARN_LOCK_EMPTY")
    return tuple(entries)


def _unsupported_spec(spec: str) -> bool:
    lowered = spec.lower()
    return lowered.startswith(_UNSUPPORTED_SPEC_PREFIXES) or spec.startswith(
        ("/", "./", "../", "~/", "\\")
    )


def _validate_resolved_https(value: str | None) -> tuple[str, str, int]:
    if not value:
        raise _CandidateInvalid("YARN_LOCK_RESOLVED_REQUIRED")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise _CandidateInvalid("YARN_LOCK_RESOLVED_INVALID") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
        or parsed.query
        or not parsed.path.startswith("/")
        or "\\" in parsed.path
    ):
        raise _CandidateInvalid("YARN_LOCK_RESOLVED_NOT_SAFE_HTTPS")
    try:
        parsed.hostname.encode("ascii")
    except UnicodeEncodeError as exc:
        raise _CandidateInvalid("YARN_LOCK_RESOLVED_HOST_INVALID") from exc
    if parsed.fragment and not re.fullmatch(
        r"[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64}", parsed.fragment
    ):
        raise _CandidateInvalid("YARN_LOCK_RESOLVED_FRAGMENT_INVALID")
    return ("https", str(parsed.hostname).lower(), 443)


def _validate_integrity(value: str | None) -> None:
    if not value:
        raise _CandidateInvalid("YARN_LOCK_INTEGRITY_REQUIRED")
    tokens = value.split()
    if not tokens:
        raise _CandidateInvalid("YARN_LOCK_INTEGRITY_INVALID")
    for token in tokens:
        if "-" not in token:
            raise _CandidateInvalid("YARN_LOCK_INTEGRITY_INVALID")
        algorithm, encoded = token.split("-", 1)
        expected = _SRI_LENGTHS.get(algorithm)
        if expected is None:
            raise _CandidateInvalid("YARN_LOCK_INTEGRITY_ALGORITHM_UNSUPPORTED")
        try:
            digest = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise _CandidateInvalid("YARN_LOCK_INTEGRITY_INVALID") from exc
        if len(digest) != expected:
            raise _CandidateInvalid("YARN_LOCK_INTEGRITY_INVALID")


def _yarn_assessment(
    filename: str, data: bytes, manifest: _Manifest
) -> LockCandidateAssessment:
    digest = _sha256(data)
    try:
        entries = _parse_yarn_v1(data)
        selector_map: dict[str, int] = {}
        for entry_index, entry in enumerate(entries):
            for selector in entry.selectors:
                if selector in selector_map:
                    raise _CandidateInvalid("YARN_LOCK_DUPLICATE_SELECTOR")
                selector_map[selector] = entry_index

        queue: list[int] = []
        for name, spec in manifest.direct:
            if _unsupported_spec(spec):
                raise _CandidateInvalid("YARN_LOCK_UNSUPPORTED_PROTOCOL")
            selector = f"{name}@{spec}"
            if selector not in selector_map:
                raise _CandidateInvalid("YARN_LOCK_DIRECT_SELECTOR_MISSING")
            queue.append(selector_map[selector])

        reachable: set[int] = set()
        while queue:
            entry_index = queue.pop(0)
            if entry_index in reachable:
                continue
            reachable.add(entry_index)
            entry = entries[entry_index]
            if not entry.version:
                raise _CandidateInvalid("YARN_LOCK_VERSION_REQUIRED")
            _validate_resolved_https(entry.resolved)
            _validate_integrity(entry.integrity)
            for name, spec in entry.dependencies:
                if _unsupported_spec(spec):
                    raise _CandidateInvalid("YARN_LOCK_UNSUPPORTED_PROTOCOL")
                selector = f"{name}@{spec}"
                child = selector_map.get(selector)
                if child is None:
                    raise _CandidateInvalid(
                        "YARN_LOCK_REACHABLE_SELECTOR_MISSING"
                    )
                queue.append(child)

        reachable_selectors = sorted(
            selector
            for entry_index in reachable
            for selector in entries[entry_index].selectors
        )
        unused_indices = set(range(len(entries))) - reachable
        unused_selectors = sorted(
            selector
            for entry_index in unused_indices
            for selector in entries[entry_index].selectors
        )
    except _CandidateInvalid as exc:
        return LockCandidateAssessment(
            filename=filename,
            family="yarn",
            lockfile_sha256=digest,
            consistent=False,
            error_codes=exc.codes,
        )

    return LockCandidateAssessment(
        filename=filename,
        family="yarn",
        lockfile_sha256=digest,
        consistent=True,
        error_codes=(),
        reachable_stanza_count=len(reachable),
        reachable_selectors_sha256=_digest_rows(reachable_selectors),
        unused_stanza_count=len(unused_indices),
        unused_selectors_sha256=_digest_rows(unused_selectors),
    )


def select_js_lock_authority(
    package_json: bytes,
    lockfiles: Mapping[str, bytes],
) -> JSLockSelection:
    """Select exactly one manifest-consistent npm or Yarn-v1 lock.

    The returned object is immutable semantic evidence.  It is not permission
    to execute a package manager and intentionally carries no path or handle.
    """

    if type(package_json) is not bytes:
        raise JSLockAuthorityError(
            "PACKAGE_JSON_BYTES_REQUIRED", "package_json must be exact bytes"
        )
    if type(lockfiles) is not dict:
        raise JSLockAuthorityError(
            "LOCKFILES_EXACT_DICT_REQUIRED", "lockfiles must be an exact dict"
        )
    for filename, data in lockfiles.items():
        if type(filename) is not str or not filename or type(data) is not bytes:
            raise JSLockAuthorityError(
                "LOCKFILE_ENTRY_INVALID",
                "each lockfile entry must be an exact filename and exact bytes",
            )
        if filename not in SUPPORTED_LOCKFILES | KNOWN_UNSUPPORTED_LOCKFILES:
            raise JSLockAuthorityError(
                "LOCKFILE_NAME_UNSUPPORTED", "an unsupported lockfile name is present"
            )

    manifest = _manifest(package_json)
    if not lockfiles:
        raise JSLockAuthorityError(
            "NO_JS_LOCKFILES", "package.json has no JavaScript lockfile"
        )

    assessments: list[LockCandidateAssessment] = []
    unsupported_present = False
    for filename in sorted(lockfiles):
        data = lockfiles[filename]
        family = _lock_family(filename)
        if family == "npm":
            assessments.append(_npm_assessment(filename, data, manifest))
        elif family == "yarn":
            assessments.append(_yarn_assessment(filename, data, manifest))
        else:
            unsupported_present = True
            assessments.append(
                LockCandidateAssessment(
                    filename=filename,
                    family="unsupported",
                    lockfile_sha256=_sha256(data),
                    consistent=False,
                    error_codes=("LOCK_FAMILY_UNSUPPORTED",),
                )
            )
    frozen_assessments = tuple(assessments)

    declared = manifest.package_manager_family
    if declared == "pnpm":
        raise JSLockAuthorityError(
            "DECLARED_PACKAGE_MANAGER_UNSUPPORTED",
            "the declared package manager has no strict validator",
            assessments=frozen_assessments,
        )
    if declared:
        family_candidates = [
            item for item in assessments if item.family == declared
        ]
        if not family_candidates:
            raise JSLockAuthorityError(
                "DECLARED_LOCK_MISSING",
                "the declared package manager has no matching lockfile",
                assessments=frozen_assessments,
            )
        valid = [item for item in family_candidates if item.consistent]
        if not valid:
            raise JSLockAuthorityError(
                "DECLARED_LOCK_INCONSISTENT",
                "the declared package manager lock is manifest-inconsistent",
                assessments=frozen_assessments,
            )
        if len(valid) != 1 or len(family_candidates) != 1:
            raise JSLockAuthorityError(
                "DECLARED_LOCK_AMBIGUOUS",
                "the declared package manager has multiple lockfiles",
                assessments=frozen_assessments,
            )
        selected = valid[0]
        selection_basis = DECLARED_PACKAGE_MANAGER_LOCK
    else:
        if unsupported_present:
            raise JSLockAuthorityError(
                "UNSUPPORTED_LOCK_FAMILY_PRESENT",
                "unique consistency cannot be proven while an unsupported lock family is present",
                assessments=frozen_assessments,
            )
        valid = [item for item in assessments if item.consistent]
        if not valid:
            raise JSLockAuthorityError(
                "NO_MANIFEST_CONSISTENT_LOCK",
                "no supported lockfile exactly matches package.json",
                assessments=frozen_assessments,
            )
        if len(valid) != 1:
            raise JSLockAuthorityError(
                "AMBIGUOUS_MANIFEST_CONSISTENT_LOCKS",
                "more than one lockfile exactly matches package.json",
                assessments=frozen_assessments,
            )
        selected = valid[0]
        selection_basis = UNIQUE_MANIFEST_CONSISTENT_LOCK

    direct_rows = tuple(
        f"{section}\0{name}\0{spec}"
        for section, rows in manifest.sections
        for name, spec in rows
    )
    binding = {
        "candidates": [item.binding_dict() for item in frozen_assessments],
        "declared_package_manager": manifest.package_manager_raw,
        "direct_requirements_sha256": _digest_rows(list(direct_rows)),
        "family": selected.family,
        "filename": selected.filename,
        "lockfile_sha256": selected.lockfile_sha256,
        "package_json_sha256": _sha256(package_json),
        "reachable_selectors_sha256": selected.reachable_selectors_sha256,
        "reachable_stanza_count": selected.reachable_stanza_count,
        "schema": SCHEMA,
        "selection_basis": selection_basis,
        "unused_selectors_sha256": selected.unused_selectors_sha256,
        "unused_stanza_count": selected.unused_stanza_count,
    }
    return JSLockSelection(
        schema=SCHEMA,
        family=selected.family,
        filename=selected.filename,
        declared_package_manager=manifest.package_manager_raw,
        selection_basis=selection_basis,
        package_json_sha256=binding["package_json_sha256"],
        lockfile_sha256=selected.lockfile_sha256,
        direct_requirements_sha256=binding["direct_requirements_sha256"],
        reachable_selectors_sha256=selected.reachable_selectors_sha256,
        reachable_stanza_count=selected.reachable_stanza_count,
        unused_selectors_sha256=selected.unused_selectors_sha256,
        unused_stanza_count=selected.unused_stanza_count,
        candidates=frozen_assessments,
        selection_sha256=_sha256(_canonical_bytes(binding)),
    )


def derive_yarn_integrity_authority(
    package_json: bytes,
    yarn_lock: bytes,
    selection: JSLockSelection,
) -> YarnIntegrityAuthority:
    """Derive the exact reachable Yarn integrity map from retained bytes.

    The caller must provide the already-selected authority.  This function
    replays all selected fields and then independently walks the dependency
    graph; it never trusts a caller-supplied selector set or resolved URL.
    """

    if type(selection) is not JSLockSelection:
        raise JSLockAuthorityError(
            "YARN_INTEGRITY_SELECTION_TYPE_INVALID",
            "Yarn integrity replay requires an exact JSLockSelection",
        )
    if (
        selection.schema != SCHEMA
        or selection.family != "yarn"
        or selection.filename != "yarn.lock"
        or selection.package_json_sha256 != _sha256(package_json)
        or selection.lockfile_sha256 != _sha256(yarn_lock)
        or selection.selection_sha256
        != _sha256(_canonical_bytes(selection.binding_dict()))
    ):
        raise JSLockAuthorityError(
            "YARN_INTEGRITY_SELECTION_MISMATCH",
            "Yarn integrity replay differs from the selected lock authority",
        )
    manifest = _manifest(package_json)
    expected_basis = (
        DECLARED_PACKAGE_MANAGER_LOCK
        if manifest.package_manager_family
        else UNIQUE_MANIFEST_CONSISTENT_LOCK
    )
    if (
        selection.declared_package_manager != manifest.package_manager_raw
        or selection.selection_basis != expected_basis
    ):
        raise JSLockAuthorityError(
            "YARN_INTEGRITY_SELECTION_BASIS_MISMATCH",
            "Yarn integrity replay differs from the lock-selection basis",
        )
    direct_rows = tuple(
        f"{section}\0{name}\0{spec}"
        for section, rows in manifest.sections
        for name, spec in rows
    )
    if selection.direct_requirements_sha256 != _digest_rows(list(direct_rows)):
        raise JSLockAuthorityError(
            "YARN_INTEGRITY_DIRECT_REQUIREMENTS_MISMATCH",
            "Yarn integrity replay differs from manifest requirements",
        )
    try:
        entries = _parse_yarn_v1(yarn_lock)
        selector_map: dict[str, int] = {}
        for entry_index, entry in enumerate(entries):
            for selector in entry.selectors:
                if selector in selector_map:
                    raise _CandidateInvalid("YARN_LOCK_DUPLICATE_SELECTOR")
                selector_map[selector] = entry_index

        queue: list[int] = []
        direct_packages: list[tuple[str, str, str]] = []
        for name, spec in manifest.direct:
            if _unsupported_spec(spec):
                raise _CandidateInvalid("YARN_LOCK_UNSUPPORTED_PROTOCOL")
            selector = f"{name}@{spec}"
            entry_index = selector_map.get(selector)
            if entry_index is None:
                raise _CandidateInvalid("YARN_LOCK_DIRECT_SELECTOR_MISSING")
            version = entries[entry_index].version
            if not version:
                raise _CandidateInvalid("YARN_LOCK_VERSION_REQUIRED")
            direct_packages.append((name, selector, version))
            queue.append(entry_index)

        reachable: set[int] = set()
        while queue:
            entry_index = queue.pop(0)
            if entry_index in reachable:
                continue
            reachable.add(entry_index)
            entry = entries[entry_index]
            if not entry.version:
                raise _CandidateInvalid("YARN_LOCK_VERSION_REQUIRED")
            _validate_resolved_https(entry.resolved)
            _validate_integrity(entry.integrity)
            for name, spec in entry.dependencies:
                if _unsupported_spec(spec):
                    raise _CandidateInvalid("YARN_LOCK_UNSUPPORTED_PROTOCOL")
                child = selector_map.get(f"{name}@{spec}")
                if child is None:
                    raise _CandidateInvalid("YARN_LOCK_REACHABLE_SELECTOR_MISSING")
                queue.append(child)
    except _CandidateInvalid as exc:
        raise JSLockAuthorityError(
            "YARN_INTEGRITY_REPLAY_FAILED",
            ",".join(exc.codes),
        ) from exc

    reachable_selectors = sorted(
        selector
        for entry_index in reachable
        for selector in entries[entry_index].selectors
    )
    unused_indices = set(range(len(entries))) - reachable
    unused_selectors = sorted(
        selector
        for entry_index in unused_indices
        for selector in entries[entry_index].selectors
    )
    selected_assessment = next(
        (
            item
            for item in selection.candidates
            if item.filename == "yarn.lock" and item.consistent
        ),
        None,
    )
    if (
        selected_assessment is None
        or selected_assessment.lockfile_sha256 != selection.lockfile_sha256
        or len(reachable) != selection.reachable_stanza_count
        or _digest_rows(reachable_selectors)
        != selection.reachable_selectors_sha256
        or len(unused_indices) != selection.unused_stanza_count
        or _digest_rows(unused_selectors) != selection.unused_selectors_sha256
    ):
        raise JSLockAuthorityError(
            "YARN_INTEGRITY_SELECTION_MISMATCH",
            "Yarn graph replay differs from the selected lock authority",
        )

    lockfile_entries = tuple(
        sorted(
            (
                selector,
                str(entries[entry_index].resolved or ""),
            )
            for entry_index in reachable
            for selector in entries[entry_index].selectors
        )
    )
    frozen_direct = tuple(sorted(direct_packages))
    resolved_origins = tuple(
        sorted(
            {
                _validate_resolved_https(entries[entry_index].resolved)
                for entry_index in reachable
            }
        )
    )
    lockfile_entries_sha256 = _sha256(
        _canonical_bytes([list(row) for row in lockfile_entries])
    )
    direct_packages_sha256 = _sha256(
        _canonical_bytes([list(row) for row in frozen_direct])
    )
    resolved_origins_sha256 = _sha256(
        _canonical_bytes([list(row) for row in resolved_origins])
    )
    body = {
        "direct_packages": [list(row) for row in frozen_direct],
        "direct_packages_sha256": direct_packages_sha256,
        "lockfile_entries": [list(row) for row in lockfile_entries],
        "lockfile_entries_sha256": lockfile_entries_sha256,
        "resolved_origins": [list(row) for row in resolved_origins],
        "resolved_origins_sha256": resolved_origins_sha256,
        "schema": YARN_INTEGRITY_AUTHORITY_SCHEMA,
    }
    return YarnIntegrityAuthority(
        schema=YARN_INTEGRITY_AUTHORITY_SCHEMA,
        lockfile_entries=lockfile_entries,
        direct_packages=frozen_direct,
        resolved_origins=resolved_origins,
        lockfile_entries_sha256=lockfile_entries_sha256,
        direct_packages_sha256=direct_packages_sha256,
        resolved_origins_sha256=resolved_origins_sha256,
        authority_sha256=_sha256(_canonical_bytes(body)),
    )


__all__ = [
    "DECLARED_PACKAGE_MANAGER_LOCK",
    "derive_yarn_integrity_authority",
    "JSLockAuthorityError",
    "JSLockSelection",
    "LockCandidateAssessment",
    "SCHEMA",
    "select_js_lock_authority",
    "YARN_INTEGRITY_AUTHORITY_SCHEMA",
    "YarnIntegrityAuthority",
    "UNIQUE_MANIFEST_CONSISTENT_LOCK",
]
