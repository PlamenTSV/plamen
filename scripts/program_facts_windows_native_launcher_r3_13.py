"""Inactive R3.13 Windows-native launcher and crash reconciler candidate.

This module is fixture-first evidence only.  No production driver, provider,
ledger-selection, installation, admission, or cutover path imports it.  Its
only native authority is an exact, separately pinned ordinary-user fixture
permit.  All global and production authority remains false.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile
import threading
from typing import Any, Mapping, Sequence
import weakref


SCHEMA = "plamen.program_facts.g3.launcher.r3_13.windows_process_crash.v1"
VALIDATION_SCHEMA = SCHEMA + ".validation"
PUBLICATION_SCHEMA = SCHEMA + ".publication"
RECONCILIATION_SCHEMA = SCHEMA + ".reconciliation"
RUNTIME_CLOSURE_SCHEMA = SCHEMA + ".runtime_closure"
MAX_GOVERNED_BYTES = 1_000_000
MAX_CHILD_RECEIPT_BYTES = 1_000_000
MAX_RUNTIME_FILE_BYTES = 64 * 1024 * 1024
PROFILE = "WINDOWS_ORDINARY_USER_PROTECTED_ROOT_PROCESS_CRASH_R3_13"
INFORMATION_CLASS_NAME = "FileRenameInfoEx"
INFORMATION_CLASS_U32 = 22
REQUEST_STRUCTURE = "FILE_RENAME_INFO"
RENAME_FLAGS_U32 = 0
CANDIDATE_ACTIVE = False
FIXTURE_NATIVE_EXECUTION_PERMIT_SHA256 = (
    "1cbec6e810df578b31325d2f115c9e0da5a4e0713c9e8b1a3a1bd746283346a0"
)

# These literals are executable closure requirements, not documentation-only
# names.  The path-configuration row records exact presence/absence for
# python312._pth; the image rows must include python.exe, python312.dll, and
# vcruntime140.dll on the governed CPython 3.12 x64 host.
_REQUIRED_RUNTIME_BASENAMES = {
    "python.exe",
    "python312.dll",
    "vcruntime140.dll",
}
_PATH_CONFIGURATION_BASENAME = "python312._pth"
_FILE_ATTRIBUTE_NORMAL = 0x00000080
_SYNCHRONIZE = 0x00100000

GLOBAL_AUTHORITY = {
    "admission_authority": False,
    "cutover_allowed": False,
    "installation_allowed": False,
    "native_execution_authority": False,
    "production_execution_allowed": False,
    "provider_authority": False,
    "publication_allowed": False,
    "spawn_allowed": False,
}

FIXTURE_NATIVE_AUTHORITY = {
    "fixture_native_execution": True,
    "production_native_execution": False,
    "global": False,
    "provider": False,
    "admission": False,
    "cutover": False,
}

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    # ``-I -S`` omits the script directory.  The exact launcher and every
    # helper origin loaded from it are manifest-pinned and retained below.
    sys.path.insert(0, str(_SCRIPT_DIR))
_REPO = _SCRIPT_DIR.parent
_HEX64 = re.compile(r"[0-9a-f]{64}")


# R3.13 preserves all 15 R3.12 governed inputs and adds the exact repaired
# review/implementation boundary plus both shared regression sources.  Every
# row is authenticated before any principal is parsed or child is created.
REQUIRED_INPUTS: tuple[dict[str, object], ...] = (
    {"path": "Temp/program_facts_g3_launcher_r3_11_20260809/r3_11_validator.py", "size": 24000, "sha256": "be60449c2c936e86422bc69eb9e6cce3b9b92c8e0b0a948d3e35ebb408cf5b38"},
    {"path": "Temp/program_facts_g3_launcher_r3_11_20260809/r3_11_contract.v1.json", "size": 13942, "sha256": "bccff97f0beb7b08c8dadba2ea3aacc212485dbfedccbb5621a1d4092e0e0b9e"},
    {"path": "Temp/program_facts_g3_launcher_r3_11_20260809/r3_11_lineage_recipes.v1.json", "size": 40388, "sha256": "29dc8afa8c6c5b7550527af2ef41b3fbecbf008126f8a463081a282aeb17d903"},
    {"path": "Temp/program_facts_g3_launcher_r3_10_20260809/r3_8_predecessor_results.v1.json", "size": 343290, "sha256": "a7ed6304dc1863719f62021152acf3e76e5961bebbc29f3385f05c46dc06f0cf"},
    {"path": "Temp/program_facts_g3_launcher_r3_10_20260809/r3_8_legacy_lineage.v1.json", "size": 69482, "sha256": "b1aed55351a64a050275c259346623fac9a759a81aeac561b789b0b8877ea35d"},
    {"path": "review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PROGRAM_FACTS_G3_00_PARITY_LAUNCHER_R3_10_STATE_OPERATIONAL_REVIEW_4c0c125b9b51a56a.md", "size": 38971, "sha256": "e775a3f015a50d1b8f6e3b54f1c0ea9858aa2b4e77d755eea91f37cae977571f"},
    {"path": "review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PROGRAM_FACTS_G3_00_PARITY_LAUNCHER_R3_10_NATIVE_CONTRACT_REVIEW_4c0c125b9b51a56a.md", "size": 28729, "sha256": "642a4788afe6c4f3343db383e54d791f0316d44df3841eb336a3ba53472a2236"},
    {"path": "architecture/program-facts-g3-00-parity-launcher-r3-10-dependency-closed-semantic-amendment.md", "size": 15831, "sha256": "4c0c125b9b51a56a3bcc191654468c9f94b7e2f470483e713641074901a729c9"},
    {"path": "Temp/program_facts_g3_launcher_r3_10_20260809/r3_10_identity_manifest.v1.json", "size": 3384, "sha256": "6cffa880db08a37b0087105d796c5907281c7114a4a46b8e3fefa7ce7b31ebcd"},
    {"path": "review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PROGRAM_FACTS_G3_00_PARITY_LAUNCHER_R3_10_IMPLEMENTATION_HANDOFF_4c0c125b9b51a56a.v1.json", "size": 4511, "sha256": "53290f0e3a788b730f18fa949a525cf467d56ffa6eec1061b7ee178ce5347ad7"},
    {"path": "architecture/program-facts-g3-00-parity-launcher-r3-11-closed-semantic-native-profile-amendment.md", "size": 12905, "sha256": "a83e4828f317dfc08e17885c75716a5776e4298b6a5146ca92a8274908551596"},
    {"path": "review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PROGRAM_FACTS_G3_00_PARITY_LAUNCHER_R3_11_STATE_OPERATIONAL_REVIEW_a83e4828f317dfc0.md", "size": 24347, "sha256": "69e1a1509f175a02a7e4a65dd7f233607d3d4f893afac1cf803d6f9a7a76514b"},
    {"path": "review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PROGRAM_FACTS_G3_00_PARITY_LAUNCHER_R3_11_NATIVE_CONTRACT_REVIEW_a83e4828f317dfc0.md", "size": 26516, "sha256": "148328b0d9721765fa9a54ffb12dd7bf69b6271c06050defa5a1536ac6d4ce1d"},
    {"path": "review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PROGRAM_FACTS_G3_00_PARITY_LAUNCHER_R3_11_AUTHOR_SELF_REVIEW_a83e4828f317dfc0.md", "size": 10307, "sha256": "6bcf86e1177ded4b1102b5691317583eb24d6cedc0ffa50ecd00b625070106ac"},
    {"path": "architecture/program-facts-g3-00-protected-control-root-recovery-contract-v4.md", "size": 16828, "sha256": "d1fa8428389eac4d46b296c850c9edf2388cc14da6f3be2f2c124f5bd0e929d2"},
    {"path": "scripts/program_facts_windows_native_launcher_r3_12.py", "size": 44534, "sha256": "a1ebb40eea8dbab01375d32ed1cfc23fdd7907bdbd267d826dfb6eb1258299b1"},
    {"path": "architecture/program-facts-g3-00-parity-launcher-r3-12-windows-native-audit-handoff-amendment.md", "size": 15083, "sha256": "74170252cb6913458a68d92653692ca1e7f92669ffc2027a6d20a935f2b63bca"},
    {"path": "review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PROGRAM_FACTS_G3_00_PARITY_LAUNCHER_R3_12_WINDOWS_NATIVE_HANDOFF_74170252cb691345.v1.json", "size": 6172, "sha256": "389da4424a98825b82060fafcec8594f64611a9cff722ba62200a492dcd021d7"},
    {"path": "review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PROGRAM_FACTS_G3_00_PARITY_LAUNCHER_R3_12_STATE_OPERATIONAL_REVIEW_74170252cb691345.md", "size": 26801, "sha256": "36303e8fe2a3fc8f6836a0cae1a1f9e1e90ad05e6ebe7c64002ed0a86808183e"},
    {"path": "review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PROGRAM_FACTS_G3_00_PARITY_LAUNCHER_R3_12_NATIVE_CONTRACT_REVIEW_74170252cb691345.md", "size": 22084, "sha256": "32e80e8c012821bd79d723bc5b471dae418ad6d435bc5a7cba29828152ec05dd"},
    {"path": "review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/r3_13_windows_native_candidate/r3_13_fixture_native_execution_permit.v1.json", "size": 507, "sha256": FIXTURE_NATIVE_EXECUTION_PERMIT_SHA256},
    {"path": "review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/r3_13_windows_native_candidate/test_r3_13_predecessor_red.py", "size": 4181, "sha256": "20dcbb1ab58baa332377653da2f143593f44366b322f5ad498b0fc3baf20d46b"},
    {"path": "scripts/test_isolated_execution_host.py", "size": 17557, "sha256": "3db922c8cfbfcb7e08b16c1acd5e54caaab1d732174d51db795c01b009be1841"},
    {"path": "scripts/test_semantic_runtime_dependency_r6_author_adversarial.py", "size": 5738, "sha256": "11218b4f560ff0ee27480c00ca58978625f64fe8680d7883a530227e43c19d22"},
    {"path": "review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/r3_12_windows_native_candidate/test_r3_12_bounded_stage_red.py", "size": 2655, "sha256": "da03435ef70b30be39f25dde8b1fa10d4b64f463ca36e7cd9065eda5f964437d"},
)


class CandidateValidationError(RuntimeError):
    """The fresh-validator boundary rejected a malformed caller contract."""


class WindowsPublicationError(RuntimeError):
    """One native fixture transaction failed closed with a stable code."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(code if not detail else f"{code}: {detail}")


class _DependencyClosureError(RuntimeError):
    pass


class ValidatedCandidateCapability:
    """Opaque registry identity for one subject/context/permit publication."""

    __slots__ = ("__weakref__",)

    def __new__(cls) -> "ValidatedCandidateCapability":
        raise TypeError("ValidatedCandidateCapability cannot be constructed directly")

    def __repr__(self) -> str:
        return "<ValidatedCandidateCapability registry-issued>"

    def __reduce__(self) -> object:
        raise TypeError("ValidatedCandidateCapability cannot be serialized")

    @property
    def receipt(self) -> dict[str, Any]:
        return _issuance_registry.receipt_for(self)


class _IssuanceRegistry:
    """Process-local one-shot state; callers are trusted not to mutate internals."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._rows: dict[int, tuple[weakref.ReferenceType[ValidatedCandidateCapability], dict[str, Any]]] = {}

    def issue(self, row: Mapping[str, Any]) -> ValidatedCandidateCapability:
        capability = object.__new__(ValidatedCandidateCapability)
        with self._lock:
            self._rows[id(capability)] = (weakref.ref(capability), dict(row))
        return capability

    def receipt_for(self, capability: ValidatedCandidateCapability) -> dict[str, Any]:
        with self._lock:
            stored = self._rows.get(id(capability))
            if stored is None or stored[0]() is not capability:
                raise WindowsPublicationError("CAPABILITY_NOT_LIVE")
            return json.loads(json.dumps(stored[1]["receipt"]))

    def consume(
        self,
        capability: ValidatedCandidateCapability,
        *,
        context_sha256: str,
        permit_sha256: str,
    ) -> dict[str, Any]:
        with self._lock:
            stored = self._rows.pop(id(capability), None)
        if stored is None or stored[0]() is not capability:
            raise WindowsPublicationError("CAPABILITY_ALREADY_SPENT_OR_UNKNOWN")
        row = stored[1]
        if row["context_sha256"] != context_sha256:
            raise WindowsPublicationError("CAPABILITY_CONTEXT_MISMATCH")
        if row["permit_sha256"] != permit_sha256:
            raise WindowsPublicationError("CAPABILITY_PERMIT_MISMATCH")
        return row


_issuance_registry = _IssuanceRegistry()


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sealed_receipt(core: Mapping[str, Any]) -> dict[str, Any]:
    value = dict(core)
    value["receipt_sha256"] = hashlib.sha256(_canonical(value)).hexdigest()
    return value


def _valid_hash(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _HEX64.fullmatch(value) is None:
        raise CandidateValidationError(f"{label}_SHA256_INVALID")
    return value


def _bounded_file(path: Path, maximum: int = MAX_GOVERNED_BYTES) -> bytes:
    from bounded_artifact_io import read_bounded_regular_bytes

    return read_bounded_regular_bytes(path, maximum, require_single_link=True)


def _checked_input(repo: Path, row: Mapping[str, object]) -> tuple[Path, bytes]:
    relative = str(row["path"])
    path = repo.joinpath(*PurePosixPath(relative).parts)
    try:
        raw = _bounded_file(path)
    except (OSError, ValueError) as exc:
        raise _DependencyClosureError("DEPENDENCY_READ_FAILURE") from exc
    if len(raw) != row["size"] or hashlib.sha256(raw).hexdigest() != row["sha256"]:
        raise _DependencyClosureError("DEPENDENCY_BYTES_MISMATCH")
    return path, raw


def _principal_from_authenticated(
    raw_by_path: Mapping[str, bytes], path: str, pattern: str
) -> str:
    try:
        text = raw_by_path[path].decode("utf-8", errors="strict")
    except (KeyError, UnicodeDecodeError) as exc:
        raise _DependencyClosureError("DEPENDENCY_PRINCIPAL_INVALID") from exc
    matches = re.findall(pattern, text, flags=re.MULTILINE)
    if len(matches) != 1 or not matches[0].strip():
        raise _DependencyClosureError("DEPENDENCY_PRINCIPAL_INVALID")
    return matches[0].strip()


def derive_pinned_predecessor_principals(
    repo_root: str | Path = _REPO,
    *,
    authenticated_inputs: Mapping[str, bytes] | None = None,
) -> dict[str, str]:
    """Parse principals only from the already authenticated complete closure."""

    if authenticated_inputs is None:
        repo = Path(repo_root)
        gathered: dict[str, bytes] = {}
        for row in REQUIRED_INPUTS:
            _path, raw = _checked_input(repo, row)
            gathered[str(row["path"])] = raw
        authenticated_inputs = gathered
    base = "review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/"
    state = base + "PROGRAM_FACTS_G3_00_PARITY_LAUNCHER_R3_11_STATE_OPERATIONAL_REVIEW_a83e4828f317dfc0.md"
    native = base + "PROGRAM_FACTS_G3_00_PARITY_LAUNCHER_R3_11_NATIVE_CONTRACT_REVIEW_a83e4828f317dfc0.md"
    author = base + "PROGRAM_FACTS_G3_00_PARITY_LAUNCHER_R3_11_AUTHOR_SELF_REVIEW_a83e4828f317dfc0.md"
    return {
        "r3_11_state_reviewer": _principal_from_authenticated(authenticated_inputs, state, r"^- Reviewer:\s*`([^`]+)`\s*$"),
        "r3_11_native_reviewer": _principal_from_authenticated(authenticated_inputs, native, r"^- Reviewer:\s*`([^`]+)`\s*$"),
        "r3_11_subject_author": _principal_from_authenticated(authenticated_inputs, author, r"^- Author/reviewer principal:\s*`([^`]+)`[.]?\s*$"),
    }


def _validation_rejection(
    *,
    subject_sha256: str,
    primary: str,
    subcode: str,
    launcher_sha256: str,
    interpreter_sha256: str,
    fresh_process_started: bool,
) -> dict[str, Any]:
    return _sealed_receipt({
        "schema": VALIDATION_SCHEMA,
        "status": "REJECTED",
        "primary": primary,
        "subcode": subcode,
        "subject_sha256": subject_sha256,
        "launcher_sha256": launcher_sha256,
        "interpreter_sha256": interpreter_sha256,
        "fresh_process_started": fresh_process_started,
        "global_authority": dict(GLOBAL_AUTHORITY),
    })


def _canonical_component(value: str, *, label: str) -> str:
    import report_assembly_capture as capture

    try:
        normalized = capture._canonical_path(value)
    except Exception as exc:
        raise WindowsPublicationError("PATH_COMPONENT_INVALID", label) from exc
    if "/" in normalized or "\\" in normalized or normalized != value:
        raise WindowsPublicationError("PATH_COMPONENT_INVALID", label)
    return normalized


def _publication_context(
    *,
    trust_anchor: str | Path,
    protected_root: str | Path,
    stage_name: str,
    destination_name: str,
) -> dict[str, str]:
    stage = _canonical_component(stage_name, label="stage")
    destination = _canonical_component(destination_name, label="destination")
    if stage.casefold() == destination.casefold():
        raise WindowsPublicationError("SOURCE_DESTINATION_ALIAS")
    return {
        "trust_anchor": os.path.abspath(os.fspath(trust_anchor)),
        "protected_root": os.path.abspath(os.fspath(protected_root)),
        "stage_name": stage,
        "destination_name": destination,
    }


def _permit_bytes(
    fixture_native_execution_permit: str | Path,
    permit_sha256: str,
) -> tuple[bytes, dict[str, Any]]:
    expected = _valid_hash(permit_sha256, label="PERMIT")
    if expected != FIXTURE_NATIVE_EXECUTION_PERMIT_SHA256:
        raise WindowsPublicationError("FIXTURE_NATIVE_PERMIT_PIN_MISMATCH")
    try:
        raw = _bounded_file(Path(fixture_native_execution_permit))
        parsed = json.loads(raw.decode("utf-8", errors="strict"))
    except (OSError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WindowsPublicationError("FIXTURE_NATIVE_PERMIT_INVALID") from exc
    if hashlib.sha256(raw).hexdigest() != expected:
        raise WindowsPublicationError("FIXTURE_NATIVE_PERMIT_IDENTITY_MISMATCH")
    required_authority = {
        "admission": False,
        "cutover": False,
        "global": False,
        "native_fixture_execution": True,
        "production_native_execution": False,
        "provider": False,
    }
    if (
        not isinstance(parsed, dict)
        or parsed.get("schema") != "plamen.program_facts.g3.launcher.r3_13.fixture_native_execution_permit.v1"
        or parsed.get("subject") != "R3_13_INACTIVE_CANDIDATE_TESTS"
        or parsed.get("authority") != required_authority
        or parsed.get("host") != "WINDOWS_NATIVE_X64"
    ):
        raise WindowsPublicationError("FIXTURE_NATIVE_PERMIT_INVALID")
    return raw, parsed


def _enforce_fixture_scope(context: Mapping[str, str], permit: Mapping[str, Any]) -> None:
    scope = permit.get("scope")
    if not isinstance(scope, dict):
        raise WindowsPublicationError("FIXTURE_NATIVE_PERMIT_INVALID")
    anchor = Path(context["trust_anchor"])
    temporary = os.path.normcase(os.path.abspath(tempfile.gettempdir()))
    try:
        inside = os.path.commonpath((temporary, str(anchor))) == temporary
    except ValueError:
        inside = False
    if (
        not inside
        or not anchor.name.startswith(str(scope.get("anchor_basename_prefix", "")))
        or scope.get("system_temporary_root_only") is not True
        or scope.get("directory_durability") is not False
        or scope.get("power_loss") is not False
    ):
        raise WindowsPublicationError("FIXTURE_NATIVE_PERMIT_SCOPE_MISMATCH")


def _path_file_row(path: str | Path) -> dict[str, Any]:
    import rooted_path_io as rooted

    candidate = Path(os.path.abspath(os.fspath(path)))
    digest = hashlib.sha256()
    size = 0
    with open(rooted.native_path(candidate), "rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_RUNTIME_FILE_BYTES:
                raise CandidateValidationError("RUNTIME_FILE_BYTES_EXCEEDED")
            digest.update(chunk)
    return {
        "kind": "file",
        "path": str(candidate),
        "size": size,
        "sha256": digest.hexdigest(),
    }


def _loaded_module_origins() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for name in sorted(sys.modules):
        if name == "__main__":
            continue
        module = sys.modules.get(name)
        if module is None:
            continue
        spec = getattr(module, "__spec__", None)
        origin = getattr(spec, "origin", None)
        file_value = getattr(module, "__file__", None)
        cached = getattr(module, "__cached__", None)
        row: dict[str, Any] = {
            "module": name,
            "origin": str(origin) if origin is not None else None,
        }
        if isinstance(file_value, str) and os.path.isfile(file_value):
            row["loaded_file"] = _path_file_row(file_value)
        else:
            row["loaded_file"] = None
        if isinstance(cached, str) and os.path.isfile(cached):
            row["cached_file"] = _path_file_row(cached)
        else:
            row["cached_file"] = None
        rows.append(row)
    return rows


def _windows_loaded_image_paths() -> list[str]:
    if os.name != "nt":
        return []
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    psapi.EnumProcessModulesEx.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.HMODULE),
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.DWORD,
    ]
    psapi.EnumProcessModulesEx.restype = wintypes.BOOL
    psapi.GetModuleFileNameExW.argtypes = [
        wintypes.HANDLE,
        wintypes.HMODULE,
        wintypes.LPWSTR,
        wintypes.DWORD,
    ]
    psapi.GetModuleFileNameExW.restype = wintypes.DWORD
    process = kernel32.GetCurrentProcess()
    capacity = 256
    while True:
        modules = (wintypes.HMODULE * capacity)()
        needed = wintypes.DWORD()
        if not psapi.EnumProcessModulesEx(
            process,
            modules,
            ctypes.sizeof(modules),
            ctypes.byref(needed),
            0x03,
        ):
            raise CandidateValidationError("RUNTIME_IMAGE_ENUMERATION_FAILED")
        count = int(needed.value) // ctypes.sizeof(wintypes.HMODULE)
        if count <= capacity:
            break
        capacity = count + 32
    paths: dict[str, str] = {}
    for index in range(count):
        buffer = ctypes.create_unicode_buffer(32768)
        length = int(
            psapi.GetModuleFileNameExW(process, modules[index], buffer, len(buffer))
        )
        if length <= 0 or length >= len(buffer):
            raise CandidateValidationError("RUNTIME_IMAGE_ORIGIN_FAILED")
        path = os.path.abspath(buffer.value)
        paths.setdefault(os.path.normcase(path), path)
    return [paths[key] for key in sorted(paths)]


def runtime_closure_snapshot() -> dict[str, Any]:
    """Capture the exact loaded child module and image origins for freezing."""

    if os.name != "nt":
        raise CandidateValidationError("WINDOWS_NATIVE_REQUIRED")
    executable = Path(sys.executable).resolve()
    version_tag = f"python{sys.version_info.major}{sys.version_info.minor}"
    pth_path = executable.parent / f"{version_tag}._pth"
    path_configuration = {
        "basename": _PATH_CONFIGURATION_BASENAME,
        "path": str(pth_path),
        "state": "PRESENT" if pth_path.is_file() else "ABSENT",
        "file": _path_file_row(pth_path) if pth_path.is_file() else None,
    }
    loaded_child_image_origins = [
        _path_file_row(path) for path in _windows_loaded_image_paths()
    ]
    basenames = {Path(row["path"]).name.casefold() for row in loaded_child_image_origins}
    if {value.casefold() for value in _REQUIRED_RUNTIME_BASENAMES} - basenames:
        raise CandidateValidationError("REQUIRED_RUNTIME_IMAGE_MISSING")
    return {
        "schema": RUNTIME_CLOSURE_SCHEMA,
        "host": "WINDOWS_NATIVE_X64",
        "pointer_size": __import__("struct").calcsize("P"),
        "python_version": sys.version,
        "executable": _path_file_row(executable),
        "path_configuration": path_configuration,
        "loaded_child_module_origins": _loaded_module_origins(),
        "loaded_child_image_origins": loaded_child_image_origins,
    }


def _runtime_rows(manifest: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    executable = manifest.get("executable")
    if isinstance(executable, dict):
        rows.append(executable)
    path_configuration = manifest.get("path_configuration")
    if isinstance(path_configuration, dict) and isinstance(path_configuration.get("file"), dict):
        rows.append(path_configuration["file"])
    modules = manifest.get("loaded_child_module_origins")
    if isinstance(modules, list):
        for module in modules:
            if not isinstance(module, dict):
                continue
            for key in ("loaded_file", "cached_file"):
                if isinstance(module.get(key), dict):
                    rows.append(module[key])
    images = manifest.get("loaded_child_image_origins")
    if isinstance(images, list):
        rows.extend(row for row in images if isinstance(row, dict))
    return rows


def _validate_runtime_manifest(manifest: object) -> dict[str, Any]:
    if not isinstance(manifest, dict):
        raise _DependencyClosureError("RUNTIME_MANIFEST_INVALID")
    if (
        manifest.get("schema") != RUNTIME_CLOSURE_SCHEMA
        or manifest.get("host") != "WINDOWS_NATIVE_X64"
        or manifest.get("pointer_size") != 8
        or not isinstance(manifest.get("loaded_child_module_origins"), list)
        or not isinstance(manifest.get("loaded_child_image_origins"), list)
    ):
        raise _DependencyClosureError("RUNTIME_MANIFEST_INVALID")
    for row in _runtime_rows(manifest):
        if (
            row.get("kind") != "file"
            or not isinstance(row.get("path"), str)
            or type(row.get("size")) is not int
            or row["size"] < 0
            or row["size"] > MAX_RUNTIME_FILE_BYTES
            or not isinstance(row.get("sha256"), str)
            or _HEX64.fullmatch(row["sha256"]) is None
        ):
            raise _DependencyClosureError("RUNTIME_MANIFEST_INVALID")
    executable = manifest.get("executable")
    if not isinstance(executable, dict):
        raise _DependencyClosureError("RUNTIME_MANIFEST_INVALID")
    if os.path.normcase(os.path.abspath(executable["path"])) != os.path.normcase(
        os.path.abspath(sys.executable)
    ):
        raise _DependencyClosureError("RUNTIME_EXECUTABLE_ORIGIN_MISMATCH")
    path_configuration = manifest.get("path_configuration")
    if (
        not isinstance(path_configuration, dict)
        or path_configuration.get("basename") != _PATH_CONFIGURATION_BASENAME
        or path_configuration.get("state") not in {"PRESENT", "ABSENT"}
    ):
        raise _DependencyClosureError("RUNTIME_PATH_CONFIGURATION_INVALID")
    names = {
        Path(row["path"]).name.casefold()
        for row in manifest["loaded_child_image_origins"]
        if isinstance(row, dict) and isinstance(row.get("path"), str)
    }
    if {value.casefold() for value in _REQUIRED_RUNTIME_BASENAMES} - names:
        raise _DependencyClosureError("REQUIRED_RUNTIME_IMAGE_MISSING")
    return manifest


def _verify_path_configuration(manifest: Mapping[str, Any]) -> None:
    row = manifest["path_configuration"]
    path = Path(row["path"])
    present = os.path.isfile(path)
    if (row["state"] == "PRESENT") != present:
        raise _DependencyClosureError("RUNTIME_PATH_CONFIGURATION_DRIFT")
    if present:
        observed = _path_file_row(path)
        if observed != row["file"]:
            raise _DependencyClosureError("RUNTIME_PATH_CONFIGURATION_DRIFT")


class _RetainedWindowsClosure:
    def __init__(self) -> None:
        self._rows: dict[str, dict[str, Any]] = {}
        self._handles: list[int] = []

    def add(self, row: Mapping[str, Any], *, label: str) -> None:
        import ctypes
        import owned_directory_guard as guard
        import rooted_path_io as rooted

        path = Path(str(row["path"]))
        key = os.path.normcase(os.path.abspath(str(path)))
        expected = {
            "path": str(path),
            "size": int(row["size"]),
            "sha256": str(row["sha256"]),
        }
        previous = self._rows.get(key)
        if previous is not None:
            if previous["size"] != expected["size"] or previous["sha256"] != expected["sha256"]:
                raise _DependencyClosureError("CLOSURE_ALIAS_IDENTITY_MISMATCH")
            return
        opened = rooted._CreateFileW(
            rooted.native_path(path),
            rooted._GENERIC_READ | _SYNCHRONIZE,
            rooted._FILE_SHARE_READ,
            None,
            rooted._OPEN_EXISTING,
            rooted._FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
        value = ctypes.cast(opened, ctypes.c_void_p).value
        if value in {None, rooted._INVALID_HANDLE_VALUE}:
            raise _DependencyClosureError("CLOSURE_RETAIN_OPEN_FAILED")
        handle = int(value)
        self._handles.append(handle)
        if not guard._SetHandleInformation(opened, guard._HANDLE_FLAG_INHERIT, 0):
            raise _DependencyClosureError("CLOSURE_HANDLE_INHERITANCE")
        self._validate_named_handle(handle, path, label=label)
        raw = rooted._windows_handle_bytes(handle)
        if len(raw) != expected["size"] or hashlib.sha256(raw).hexdigest() != expected["sha256"]:
            raise _DependencyClosureError("CLOSURE_RETAIN_IDENTITY_MISMATCH")
        expected["identity"] = guard._windows_handle_identity(handle)
        expected["handle"] = handle
        self._rows[key] = expected

    @staticmethod
    def _validate_named_handle(handle: int, path: Path, *, label: str) -> None:
        """Bind a runtime image name without rejecting trusted WinSxS hardlinks."""

        import ctypes
        import owned_directory_guard as guard
        import rooted_path_io as rooted

        opened_identity = guard._windows_handle_identity(handle)
        if (
            opened_identity["file_attributes"] & rooted._FILE_ATTRIBUTE_REPARSE_POINT
            or opened_identity["file_attributes"] & rooted._FILE_ATTRIBUTE_DIRECTORY
        ):
            raise _DependencyClosureError("RUNTIME_CLOSURE_NOT_REGULAR")
        named = rooted._CreateFileW(
            rooted.native_path(path),
            rooted._GENERIC_READ,
            rooted._FILE_SHARE_READ | rooted._FILE_SHARE_WRITE | rooted._FILE_SHARE_DELETE,
            None,
            rooted._OPEN_EXISTING,
            rooted._FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
        value = ctypes.cast(named, ctypes.c_void_p).value
        if value in {None, rooted._INVALID_HANDLE_VALUE}:
            raise _DependencyClosureError("RUNTIME_CLOSURE_NAME_OPEN_FAILED")
        try:
            if guard._windows_handle_identity(int(value)) != opened_identity:
                raise _DependencyClosureError("RUNTIME_CLOSURE_NAME_IDENTITY_MISMATCH")
        finally:
            guard._windows_close(int(value))

    def verify_all(self) -> None:
        import owned_directory_guard as guard
        import rooted_path_io as rooted

        for row in self._rows.values():
            handle = row["handle"]
            path = Path(row["path"])
            self._validate_named_handle(handle, path, label="R3.13 retained closure")
            if guard._windows_handle_identity(handle) != row["identity"]:
                raise _DependencyClosureError("CLOSURE_HANDLE_IDENTITY_DRIFT")
            raw = rooted._windows_handle_bytes(handle)
            if len(raw) != row["size"] or hashlib.sha256(raw).hexdigest() != row["sha256"]:
                raise _DependencyClosureError("CLOSURE_HANDLE_BYTES_DRIFT")

    def close(self) -> None:
        import owned_directory_guard as guard

        for handle in reversed(self._handles):
            guard._windows_close(handle)
        self._handles.clear()
        self._rows.clear()


class _CompletedChild:
    __slots__ = ("pid", "returncode", "stdout", "stderr")

    def __init__(self, pid: int, returncode: int, stdout: bytes, stderr: bytes) -> None:
        self.pid = pid
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _bounded_popen(
    argv: Sequence[str],
    *,
    input_bytes: bytes,
    cwd: str,
    env: Mapping[str, str],
    timeout_seconds: float,
) -> _CompletedChild:
    process = subprocess.Popen(
        list(argv),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=cwd,
        env=dict(env),
        shell=False,
        creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
    )
    assert process.stdin is not None and process.stdout is not None and process.stderr is not None
    process.stdin.write(input_bytes)
    process.stdin.close()
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    overflow = threading.Event()

    def drain(name: str, stream: Any) -> None:
        while True:
            chunk = stream.read(64 * 1024)
            if not chunk:
                break
            buffer = buffers[name]
            if len(buffer) < MAX_CHILD_RECEIPT_BYTES + 1:
                remaining = MAX_CHILD_RECEIPT_BYTES + 1 - len(buffer)
                buffer.extend(chunk[:remaining])
            if len(buffer) > MAX_CHILD_RECEIPT_BYTES:
                overflow.set()

    threads = [
        threading.Thread(target=drain, args=("stdout", process.stdout), daemon=True),
        threading.Thread(target=drain, args=("stderr", process.stderr), daemon=True),
    ]
    for thread in threads:
        thread.start()
    try:
        deadline = __import__("time").monotonic() + timeout_seconds
        while process.poll() is None:
            if overflow.is_set() or __import__("time").monotonic() >= deadline:
                process.kill()
                break
            __import__("time").sleep(0.01)
        returncode = process.wait(timeout=5)
    finally:
        for thread in threads:
            thread.join(timeout=5)
        process.stdout.close()
        process.stderr.close()
    if overflow.is_set():
        raise CandidateValidationError("CHILD_OUTPUT_LIMIT_EXCEEDED")
    return _CompletedChild(process.pid, returncode, bytes(buffers["stdout"]), bytes(buffers["stderr"]))


def validate_candidate_fresh(
    subject_path: str | Path,
    *,
    runtime_root: str | Path,
    expected_launcher_sha256: str,
    expected_interpreter_sha256: str,
    expected_runtime_closure_path: str | Path,
    expected_runtime_closure_sha256: str,
    fixture_native_execution_permit: str | Path,
    permit_sha256: str,
    trust_anchor: str | Path,
    protected_root: str | Path,
    stage_name: str,
    destination_name: str,
    repo_root: str | Path = _REPO,
    timeout_seconds: float = 60.0,
) -> tuple[dict[str, Any], ValidatedCandidateCapability | None]:
    """Pin the complete runtime/input closure, then validate in one real child."""

    launcher_expected = _valid_hash(expected_launcher_sha256, label="LAUNCHER")
    interpreter_expected = _valid_hash(expected_interpreter_sha256, label="INTERPRETER")
    runtime_expected = _valid_hash(expected_runtime_closure_sha256, label="RUNTIME_CLOSURE")
    if os.name != "nt":
        return _validation_rejection(
            subject_sha256="0" * 64,
            primary="PLATFORM",
            subcode="WINDOWS_NATIVE_REQUIRED",
            launcher_sha256=launcher_expected,
            interpreter_sha256=interpreter_expected,
            fresh_process_started=False,
        ), None
    if (
        not isinstance(timeout_seconds, (int, float))
        or isinstance(timeout_seconds, bool)
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
        or timeout_seconds > 300
    ):
        return _validation_rejection(
            subject_sha256="0" * 64,
            primary="CALLER_INPUT",
            subcode="TIMEOUT_INVALID",
            launcher_sha256=launcher_expected,
            interpreter_sha256=interpreter_expected,
            fresh_process_started=False,
        ), None

    import isolated_execution_host as isolated
    import rooted_path_io as rooted

    try:
        rooted.checked_directory(runtime_root, label="R3.13 validation runtime root")
        repo = rooted.checked_directory(repo_root, label="R3.13 pinned repository root")
        subject_raw = _bounded_file(Path(subject_path))
        launcher_path = Path(__file__).resolve()
        launcher_raw = _bounded_file(launcher_path)
        interpreter_path = Path(sys.executable).resolve()
        interpreter_raw = _bounded_file(interpreter_path, MAX_RUNTIME_FILE_BYTES)
        runtime_manifest_raw = _bounded_file(Path(expected_runtime_closure_path))
        if hashlib.sha256(runtime_manifest_raw).hexdigest() != runtime_expected:
            raise _DependencyClosureError("RUNTIME_MANIFEST_IDENTITY_MISMATCH")
        runtime_manifest = _validate_runtime_manifest(
            json.loads(runtime_manifest_raw.decode("utf-8", errors="strict"))
        )
        _permit_raw, permit = _permit_bytes(
            fixture_native_execution_permit,
            permit_sha256,
        )
        context = _publication_context(
            trust_anchor=trust_anchor,
            protected_root=protected_root,
            stage_name=stage_name,
            destination_name=destination_name,
        )
        _enforce_fixture_scope(context, permit)
    except (OSError, ValueError, UnicodeDecodeError, json.JSONDecodeError, _DependencyClosureError, WindowsPublicationError) as exc:
        return _validation_rejection(
            subject_sha256="0" * 64,
            primary="DEPENDENCY_CLOSURE",
            subcode=getattr(exc, "code", str(exc).split(":", 1)[0] or "DEPENDENCY_READ_FAILURE"),
            launcher_sha256=launcher_expected,
            interpreter_sha256=interpreter_expected,
            fresh_process_started=False,
        ), None

    subject_sha = hashlib.sha256(subject_raw).hexdigest()
    launcher_sha = hashlib.sha256(launcher_raw).hexdigest()
    interpreter_sha = hashlib.sha256(interpreter_raw).hexdigest()
    if launcher_sha != launcher_expected:
        raise CandidateValidationError("LAUNCHER_IDENTITY_MISMATCH")
    if interpreter_sha != interpreter_expected:
        raise CandidateValidationError("INTERPRETER_IDENTITY_MISMATCH")
    if runtime_manifest["executable"]["sha256"] != interpreter_sha:
        return _validation_rejection(
            subject_sha256=subject_sha,
            primary="RUNTIME_CLOSURE",
            subcode="INTERPRETER_MANIFEST_MISMATCH",
            launcher_sha256=launcher_sha,
            interpreter_sha256=interpreter_sha,
            fresh_process_started=False,
        ), None

    retained = _RetainedWindowsClosure()
    authenticated: dict[str, bytes] = {}
    try:
        try:
            for row in REQUIRED_INPUTS:
                source, raw = _checked_input(repo, row)
                authenticated[str(row["path"])] = raw
                retained.add(
                    {"path": str(source), "size": row["size"], "sha256": row["sha256"]},
                    label="R3.13 governed dependency",
                )
            # Principal derivation is deliberately after the complete guarded
            # loop, so dependency ordinals 11-13 cannot escape totalization.
            principals = derive_pinned_predecessor_principals(
                repo,
                authenticated_inputs=authenticated,
            )
            retained.add(
                {"path": str(launcher_path), "size": len(launcher_raw), "sha256": launcher_sha},
                label="R3.13 launcher",
            )
            retained.add(
                {"path": str(expected_runtime_closure_path), "size": len(runtime_manifest_raw), "sha256": runtime_expected},
                label="R3.13 runtime manifest",
            )
            for row in _runtime_rows(runtime_manifest):
                retained.add(row, label="R3.13 loaded runtime closure")
            _verify_path_configuration(runtime_manifest)
            retained.verify_all()
        except (OSError, ValueError, _DependencyClosureError):
            return _validation_rejection(
                subject_sha256=subject_sha,
                primary="DEPENDENCY_CLOSURE",
                subcode="DEPENDENCY_READ_FAILURE",
                launcher_sha256=launcher_sha,
                interpreter_sha256=interpreter_sha,
                fresh_process_started=False,
            ), None

        validator = repo / "Temp/program_facts_g3_launcher_r3_11_20260809/r3_11_validator.py"
        argv = [
            str(interpreter_path),
            "-I",
            "-S",
            "-B",
            str(launcher_path),
            "--validation-child",
            str(validator),
        ]
        try:
            completed = _bounded_popen(
                argv,
                input_bytes=subject_raw,
                cwd=str(repo),
                env=isolated._executor_environment(),
                timeout_seconds=float(timeout_seconds),
            )
            retained.verify_all()
            _verify_path_configuration(runtime_manifest)
        except (OSError, ValueError, CandidateValidationError, _DependencyClosureError):
            return _validation_rejection(
                subject_sha256=subject_sha,
                primary="EXECUTOR",
                subcode="FRESH_VALIDATOR_PROCESS_FAILED",
                launcher_sha256=launcher_sha,
                interpreter_sha256=interpreter_sha,
                fresh_process_started=True,
            ), None
        if completed.returncode != 0 or completed.stderr or not completed.stdout:
            return _validation_rejection(
                subject_sha256=subject_sha,
                primary="EXECUTOR",
                subcode="FRESH_VALIDATOR_PROCESS_FAILED",
                launcher_sha256=launcher_sha,
                interpreter_sha256=interpreter_sha,
                fresh_process_started=True,
            ), None
        try:
            child = json.loads(completed.stdout.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            child = None
        if (
            not isinstance(child, dict)
            or set(child) != {
                "isolated", "no_site", "pid", "primary", "subcode",
                "subject_sha256", "validator_sha256",
                "loaded_child_module_origins", "loaded_child_image_origins",
            }
            or child["subject_sha256"] != subject_sha
            or child["validator_sha256"] != REQUIRED_INPUTS[0]["sha256"]
            or child["isolated"] is not True
            or child["no_site"] is not True
            or type(child["pid"]) is not int
            or not (child["pid"] != os.getpid())
            or not (child["pid"] == completed.pid)
            or child["loaded_child_module_origins"] != runtime_manifest["loaded_child_module_origins"]
            or child["loaded_child_image_origins"] != runtime_manifest["loaded_child_image_origins"]
        ):
            return _validation_rejection(
                subject_sha256=subject_sha,
                primary="EXECUTOR",
                subcode="FRESH_VALIDATOR_RECEIPT_INVALID",
                launcher_sha256=launcher_sha,
                interpreter_sha256=interpreter_sha,
                fresh_process_started=True,
            ), None
        status = (
            "ACCEPTED"
            if (child["primary"], child["subcode"])
            == ("ACCEPTED", "R3_11_CLOSED_SEMANTIC_DESIGN_MODEL_VALID_NO_AUTHORITY")
            else "REJECTED"
        )
        context_sha = hashlib.sha256(_canonical(context)).hexdigest()
        receipt = _sealed_receipt({
            "schema": VALIDATION_SCHEMA,
            "status": status,
            "primary": child["primary"],
            "subcode": child["subcode"],
            "subject_sha256": subject_sha,
            "validator_sha256": child["validator_sha256"],
            "launcher_sha256": launcher_sha,
            "interpreter_sha256": interpreter_sha,
            "runtime_closure_sha256": runtime_expected,
            "loaded_child_module_origin_count": len(child["loaded_child_module_origins"]),
            "loaded_child_image_origin_count": len(child["loaded_child_image_origins"]),
            "fresh_process_started": True,
            "fresh_process_pid": completed.pid,
            "fresh_process_pid_distinct_from_parent": completed.pid != os.getpid(),
            "isolated_flag": True,
            "no_site_flag": True,
            "dependency_count": len(REQUIRED_INPUTS),
            "predecessor_principals": principals,
            "publication_context_sha256": context_sha,
            "fixture_native_permit_sha256": permit_sha256,
            "one_shot_registry_capability": status == "ACCEPTED",
            "trusted_same_process_caller_boundary": True,
            "global_authority": dict(GLOBAL_AUTHORITY),
        })
        capability = None
        if status == "ACCEPTED":
            capability = _issuance_registry.issue({
                "validated_subject_bytes": subject_raw,
                "subject_sha256": subject_sha,
                "context_sha256": context_sha,
                "permit_sha256": permit_sha256,
                "receipt": receipt,
            })
        return receipt, capability
    finally:
        retained.close()


def _ancestor_paths(anchor: Path, root: Path) -> tuple[Path, ...]:
    anchor_text = os.path.normcase(os.path.abspath(str(anchor)))
    root_text = os.path.normcase(os.path.abspath(str(root)))
    try:
        if os.path.normcase(os.path.commonpath((anchor_text, root_text))) != anchor_text:
            raise WindowsPublicationError("PROTECTED_ROOT_ESCAPES_TRUST_ANCHOR")
    except ValueError as exc:
        raise WindowsPublicationError("PROTECTED_ROOT_ESCAPES_TRUST_ANCHOR") from exc
    relative = os.path.relpath(str(root), str(anchor))
    if relative == ".":
        return (anchor,)
    parts = Path(relative).parts
    if any(part in {"", ".", ".."} for part in parts):
        raise WindowsPublicationError("PROTECTED_ROOT_ESCAPES_TRUST_ANCHOR")
    current = anchor
    rows = [anchor]
    for part in parts:
        current = current / part
        rows.append(current)
    return tuple(rows)


def _windows_private_acl_snapshot_handle(
    handle: int,
    *,
    label: str,
) -> tuple[str, tuple[tuple[int, int, int, str], ...]]:
    """Apply the private ordered-ACE policy to the already retained handle."""

    if os.name != "nt":
        raise WindowsPublicationError("WINDOWS_NATIVE_REQUIRED")
    import ctypes
    from ctypes import wintypes
    import claude_stored_subscription_source as security

    class _Acl(ctypes.Structure):
        _fields_ = [
            ("AclRevision", ctypes.c_ubyte),
            ("Sbz1", ctypes.c_ubyte),
            ("AclSize", wintypes.WORD),
            ("AceCount", wintypes.WORD),
            ("Sbz2", wintypes.WORD),
        ]

    class _AceHeader(ctypes.Structure):
        _fields_ = [
            ("AceType", ctypes.c_ubyte),
            ("AceFlags", ctypes.c_ubyte),
            ("AceSize", wintypes.WORD),
        ]

    class _AccessAce(ctypes.Structure):
        _fields_ = [
            ("Header", _AceHeader),
            ("Mask", wintypes.DWORD),
            ("SidStart", wintypes.DWORD),
        ]

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.GetSecurityInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetSecurityInfo.restype = wintypes.DWORD
    advapi32.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    advapi32.GetAce.restype = wintypes.BOOL
    advapi32.IsValidAcl.argtypes = [ctypes.c_void_p]
    advapi32.IsValidAcl.restype = wintypes.BOOL
    advapi32.IsValidSecurityDescriptor.argtypes = [ctypes.c_void_p]
    advapi32.IsValidSecurityDescriptor.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    owner = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    result = int(
        advapi32.GetSecurityInfo(
            wintypes.HANDLE(handle),
            security._WINDOWS_SE_FILE_OBJECT,
            security._WINDOWS_OWNER_SECURITY_INFORMATION
            | security._WINDOWS_DACL_SECURITY_INFORMATION,
            ctypes.byref(owner),
            None,
            ctypes.byref(dacl),
            None,
            ctypes.byref(descriptor),
        )
    )
    if result != 0 or not descriptor.value or not owner.value or not dacl.value:
        if descriptor.value:
            kernel32.LocalFree(descriptor)
        raise WindowsPublicationError("HANDLE_DACL_UNAVAILABLE", f"{label}:{result}")
    try:
        if not advapi32.IsValidSecurityDescriptor(descriptor) or not advapi32.IsValidAcl(dacl):
            raise WindowsPublicationError("HANDLE_DACL_MALFORMED", label)
        owner_sid = security._sid_to_string(owner, advapi32=advapi32, kernel32=kernel32)
        current_sid = security._current_windows_user_sid_string()
        if owner_sid != current_sid:
            raise WindowsPublicationError("HANDLE_OWNER_UNTRUSTED", label)
        acl = ctypes.cast(dacl, ctypes.POINTER(_Acl)).contents
        rows: list[tuple[int, int, int, str]] = []
        current_user_has_sensitive_access = False
        trusted = {current_sid, *security._WINDOWS_TRUSTED_PRIVILEGED_SIDS}
        for index in range(int(acl.AceCount)):
            ace_pointer = ctypes.c_void_p()
            if not advapi32.GetAce(dacl, index, ctypes.byref(ace_pointer)):
                raise WindowsPublicationError("HANDLE_DACL_ACE_UNREADABLE", label)
            ace = ctypes.cast(ace_pointer, ctypes.POINTER(_AccessAce)).contents
            ace_type = int(ace.Header.AceType)
            if ace_type not in {
                security._WINDOWS_ACCESS_ALLOWED_ACE_TYPE,
                security._WINDOWS_ACCESS_DENIED_ACE_TYPE,
            }:
                raise WindowsPublicationError("HANDLE_DACL_ACE_UNSUPPORTED", label)
            sid_pointer = ctypes.c_void_p(
                int(ace_pointer.value) + int(_AccessAce.SidStart.offset)
            )
            principal = security._sid_to_string(
                sid_pointer,
                advapi32=advapi32,
                kernel32=kernel32,
            )
            mask = int(ace.Mask)
            rows.append((ace_type, int(ace.Header.AceFlags), mask, principal))
            if (
                ace_type == security._WINDOWS_ACCESS_ALLOWED_ACE_TYPE
                and mask & security._WINDOWS_SENSITIVE_FILE_ACCESS
            ):
                if principal not in trusted:
                    raise WindowsPublicationError("HANDLE_DACL_UNTRUSTED_ALLOW", label)
                if principal == current_sid:
                    current_user_has_sensitive_access = True
        if not current_user_has_sensitive_access:
            raise WindowsPublicationError("HANDLE_DACL_CURRENT_USER_ACCESS_MISSING", label)
        return owner_sid, tuple(rows)
    finally:
        kernel32.LocalFree(descriptor)


def _acl_digest(snapshot: tuple[str, tuple[tuple[int, int, int, str], ...]]) -> str:
    owner, rows = snapshot
    return hashlib.sha256(
        _canonical({"owner": owner, "aces": [list(row) for row in rows]})
    ).hexdigest()


def _acl_derivation(
    snapshot: tuple[str, tuple[tuple[int, int, int, str], ...]],
) -> dict[str, Any]:
    _owner, rows = snapshot
    return {
        "owner_equals_current_launcher_token_user": True,
        "ordered_ace_count": len(rows),
        "ordered_ace_sha256": hashlib.sha256(
            _canonical([list(row) for row in rows])
        ).hexdigest(),
        "trusted_sensitive_principal_policy": "CURRENT_TOKEN_USER_OR_BUILTIN_ADMINISTRATORS_OR_LOCAL_SYSTEM",
        "unsupported_ace_types_rejected": True,
        "untrusted_sensitive_allow_ace_rejected": True,
        "current_launcher_user_sensitive_allow_required": True,
        "security_observation": "GetSecurityInfo(RETAINED_HANDLE)",
    }


def _retain_protected_ancestors(
    anchor: Path,
    root: Path,
) -> tuple[list[dict[str, Any]], list[int]]:
    import owned_directory_guard as guard
    import report_assembly_capture as capture

    handles: list[int] = []
    roster: list[dict[str, Any]] = []
    try:
        for ordinal, path in enumerate(_ancestor_paths(anchor, root)):
            import ctypes
            import rooted_path_io as rooted

            access = (
                guard._DELETE
                | guard._FILE_LIST_DIRECTORY
                | guard._FILE_ADD_SUBDIRECTORY
                | guard._FILE_TRAVERSE
                | guard._FILE_READ_ATTRIBUTES
                | guard._FILE_WRITE_ATTRIBUTES
                | guard._SYNCHRONIZE
                | 0x00020000  # READ_CONTROL for handle-bound GetSecurityInfo
            )
            opened = rooted._CreateFileW(
                rooted.native_path(path),
                access,
                guard._FILE_SHARE_READ | guard._FILE_SHARE_WRITE,
                None,
                guard._OPEN_EXISTING,
                guard._FILE_FLAG_BACKUP_SEMANTICS | guard._FILE_FLAG_OPEN_REPARSE_POINT,
                None,
            )
            value = ctypes.cast(opened, ctypes.c_void_p).value
            if value in {None, guard._INVALID_HANDLE_VALUE}:
                raise WindowsPublicationError("ANCESTOR_HANDLE_OPEN_FAILED")
            if not guard._SetHandleInformation(opened, guard._HANDLE_FLAG_INHERIT, 0):
                guard._windows_close(int(value))
                raise WindowsPublicationError("ANCESTOR_HANDLE_INHERITANCE")
            handle = int(value)
            handles.append(handle)
            identity = guard._windows_handle_identity(handle)
            expected = os.path.normcase(os.path.normpath(os.path.abspath(str(path))))
            observed = os.path.normcase(capture._windows_final_path(handle, relative=str(path)))
            if observed != expected:
                raise WindowsPublicationError("ANCESTOR_FINAL_PATH_MISMATCH")
            first = _windows_private_acl_snapshot_handle(handle, label="R3.13 protected ancestor")
            second = _windows_private_acl_snapshot_handle(handle, label="R3.13 protected ancestor")
            if first != second:
                raise WindowsPublicationError("ANCESTOR_DACL_CHANGED")
            roster.append({
                "ordinal": ordinal,
                "canonical_path": str(path),
                "volume_serial_number": identity["volume_serial_number"],
                "file_id_128": identity["file_id_128"],
                "file_attributes": identity["file_attributes"],
                "reparse_tag": identity["reparse_tag"],
                "dacl_sha256": _acl_digest(first),
                "dacl_derivation": _acl_derivation(first),
                "retained_no_delete_share": True,
                "no_follow": True,
            })
        return roster, handles
    except Exception as exc:
        for handle in reversed(handles):
            guard._windows_close(handle)
        if isinstance(exc, WindowsPublicationError):
            raise
        raise WindowsPublicationError("ANCESTOR_TRUST_VALIDATION_FAILED", type(exc).__name__) from exc


def _revalidate_protected_ancestors(
    roster: Sequence[Mapping[str, Any]],
    handles: Sequence[int],
) -> None:
    import owned_directory_guard as guard
    import report_assembly_capture as capture

    if len(roster) != len(handles) or not roster:
        raise WindowsPublicationError("ANCESTOR_ROSTER_INVALID")
    for row, handle in zip(roster, handles, strict=True):
        path = Path(str(row["canonical_path"]))
        identity = guard._windows_handle_identity(handle)
        if (
            identity["volume_serial_number"] != row["volume_serial_number"]
            or identity["file_id_128"] != row["file_id_128"]
            or identity["file_attributes"] != row["file_attributes"]
            or identity["reparse_tag"] != row["reparse_tag"]
            or os.path.normcase(capture._windows_final_path(handle, relative=str(path)))
            != os.path.normcase(os.path.normpath(os.path.abspath(str(path))))
        ):
            raise WindowsPublicationError("ANCESTOR_IDENTITY_DRIFT")
        acl = _windows_private_acl_snapshot_handle(handle, label="R3.13 protected ancestor")
        if _acl_digest(acl) != row["dacl_sha256"]:
            raise WindowsPublicationError("ANCESTOR_DACL_DRIFT")


def _flush_result(handle: int, *, ordinal: int, phase: str) -> dict[str, Any]:
    import ctypes
    import rooted_path_io as rooted

    ctypes.set_last_error(0)
    success = bool(rooted._FlushFileBuffers(handle))
    error = int(ctypes.get_last_error())
    result = {
        "ordinal": ordinal,
        "phase": phase,
        "api": "FlushFileBuffers",
        "success": success,
        "last_error_u32": error,
    }
    if not success:
        raise WindowsPublicationError("FLUSH_FILE_BUFFERS_FAILED", f"{phase}:{error}")
    if error != 0:
        raise WindowsPublicationError("FLUSH_SUCCESS_LAST_ERROR_NONZERO", f"{phase}:{error}")
    return result


def _rename_request_buffer(
    destination_path: Path,
    destination_name: str,
    anchor_handle: int,
) -> tuple[Any, dict[str, Any]]:
    import ctypes
    import owned_directory_guard as guard
    import rooted_path_io as rooted

    absolute_native_path = rooted.native_path(destination_path)
    name_raw = absolute_native_path.encode("utf-16-le", errors="strict")
    abi = guard.windows_abi_layout()
    structure_size = abi["FILE_RENAME_INFO.size"]
    filename_offset = abi["FILE_RENAME_INFO.FileName.offset"]
    buffer_length = structure_size + len(name_raw)
    buffer = ctypes.create_string_buffer(buffer_length)
    request = guard._FILE_RENAME_INFO.from_buffer(buffer)
    request.Flags = RENAME_FLAGS_U32
    request.RootDirectory = None
    request.FileNameLength = len(name_raw)
    ctypes.memmove(ctypes.addressof(buffer) + filename_offset, name_raw, len(name_raw))
    tail_start = filename_offset + len(name_raw)
    tail = bytes(buffer[tail_start:buffer_length])
    reserved = bytes(buffer[4:8])
    if any(reserved):
        raise WindowsPublicationError("RENAME_REQUEST_RESERVED_NONZERO")
    if any(tail):
        raise WindowsPublicationError("RENAME_REQUEST_TAIL_NONZERO")
    return buffer, {
        "api": "SetFileInformationByHandle",
        "information_class": INFORMATION_CLASS_NAME,
        "information_class_u32": INFORMATION_CLASS_U32,
        "request_structure": REQUEST_STRUCTURE,
        "flags_u32": RENAME_FLAGS_U32,
        "root_directory_handle_value": None,
        "destination_anchor_handle_value": anchor_handle,
        "destination_anchor_role": "RETAINED_PRE_POST_VERIFICATION_ANCHOR_NOT_REQUEST_OPERAND",
        "destination_path_kind": "ABSOLUTE_EXTENDED_LENGTH",
        "destination_path": absolute_native_path,
        "destination_name": destination_name,
        "filename_encoding": "UTF-16LE",
        "filename_bytes_hex": name_raw.hex(),
        "file_name_length_bytes": len(name_raw),
        "filename_excludes_nul": True,
        "structure_size_bytes": structure_size,
        "filename_offset_bytes": filename_offset,
        "buffer_length_bytes": buffer_length,
        "buffer_sha256": hashlib.sha256(bytes(buffer)).hexdigest(),
        "zero_reserved_hex": reserved.hex(),
        "zero_tail_hex": tail.hex(),
    }


def _test_crash(stage: str, selected: str | None) -> None:
    if selected == stage:
        if os.environ.get("PLAMEN_R313_TEST_CRASH") != "1":
            raise WindowsPublicationError("TEST_CRASH_NOT_AUTHORIZED")
        os._exit(97)


def _open_existing_file(
    path: Path,
    *,
    writable: bool,
    share_all: bool = False,
    label: str,
) -> int:
    import ctypes
    import owned_directory_guard as guard
    import rooted_path_io as rooted

    access = rooted._GENERIC_READ | _SYNCHRONIZE
    if writable:
        access |= rooted._GENERIC_WRITE | rooted._DELETE_ACCESS
    share = rooted._FILE_SHARE_READ
    if share_all:
        share |= rooted._FILE_SHARE_WRITE | rooted._FILE_SHARE_DELETE
    opened = rooted._CreateFileW(
        rooted.native_path(path),
        access,
        share,
        None,
        rooted._OPEN_EXISTING,
        rooted._FILE_FLAG_OPEN_REPARSE_POINT | (rooted._FILE_FLAG_WRITE_THROUGH if writable else 0),
        None,
    )
    value = ctypes.cast(opened, ctypes.c_void_p).value
    if value in {None, rooted._INVALID_HANDLE_VALUE}:
        raise WindowsPublicationError("EXISTING_FILE_OPEN_FAILED", label)
    if not guard._SetHandleInformation(opened, guard._HANDLE_FLAG_INHERIT, 0):
        guard._windows_close(int(value))
        raise WindowsPublicationError("FILE_HANDLE_INHERITANCE", label)
    handle = int(value)
    rooted._windows_validate_named_handle(handle, path, label=label)
    return handle


def _create_stage(path: Path) -> int:
    import ctypes
    import owned_directory_guard as guard
    import rooted_path_io as rooted

    access = rooted._GENERIC_READ | rooted._GENERIC_WRITE | rooted._DELETE_ACCESS | _SYNCHRONIZE
    flags = _FILE_ATTRIBUTE_NORMAL | rooted._FILE_FLAG_OPEN_REPARSE_POINT | rooted._FILE_FLAG_WRITE_THROUGH
    opened = rooted._CreateFileW(
        rooted.native_path(path),
        access,
        rooted._FILE_SHARE_READ,
        None,
        rooted._CREATE_NEW,
        flags,
        None,
    )
    value = ctypes.cast(opened, ctypes.c_void_p).value
    if value in {None, rooted._INVALID_HANDLE_VALUE}:
        raise WindowsPublicationError("SOURCE_CREATE_NEW_FAILED", str(ctypes.get_last_error()))
    if not guard._SetHandleInformation(opened, guard._HANDLE_FLAG_INHERIT, 0):
        guard._windows_close(int(value))
        raise WindowsPublicationError("SOURCE_HANDLE_INHERITANCE")
    handle = int(value)
    rooted._windows_validate_named_handle(handle, path, label="R3.13 staged source")
    return handle


def _write_subject(handle: int, validated_subject_bytes: bytes) -> list[dict[str, Any]]:
    import ctypes
    from ctypes import wintypes
    import rooted_path_io as rooted

    offset = 0
    writes: list[dict[str, Any]] = []
    while offset < len(validated_subject_bytes):
        chunk = validated_subject_bytes[offset: offset + 64 * 1024]
        buffer = ctypes.create_string_buffer(chunk)
        written = wintypes.DWORD()
        ctypes.set_last_error(0)
        success = bool(
            rooted._WriteFile(handle, buffer, len(chunk), ctypes.byref(written), None)
        )
        error = int(ctypes.get_last_error())
        writes.append({
            "ordinal": len(writes),
            "requested": len(chunk),
            "written": int(written.value),
            "success": success,
            "last_error_u32": error,
        })
        if not success or written.value != len(chunk) or error != 0:
            raise WindowsPublicationError("SOURCE_WRITE_FAILED", str(error))
        offset += int(written.value)
    return writes


def _post_destination_receipt(
    *,
    source_handle: int,
    source_identity: Mapping[str, Any],
    source_acl: tuple[str, tuple[tuple[int, int, int, str], ...]],
    stage_path: Path,
    destination_path: Path,
    stage_component: str,
    destination_component: str,
    anchor_handle: int,
    validated_subject_bytes: bytes,
) -> tuple[dict[str, Any], dict[str, Any]]:
    import owned_directory_guard as guard
    import rooted_path_io as rooted

    post_source_identity = guard._windows_handle_identity(source_handle)
    if post_source_identity != source_identity:
        raise WindowsPublicationError("SOURCE_HANDLE_IDENTITY_DRIFT")
    if guard._windows_relative_identity(anchor_handle, stage_component, is_directory=False) is not None:
        raise WindowsPublicationError("SOURCE_NAME_REMAINS_AFTER_RENAME")
    destination_identity = guard._windows_relative_identity(
        anchor_handle, destination_component, is_directory=False
    )
    if destination_identity != source_identity:
        raise WindowsPublicationError("POST_DESTINATION_IDENTITY_MISMATCH")
    destination_handle = _open_existing_file(
        destination_path,
        writable=False,
        share_all=True,
        label="R3.13 destination",
    )
    try:
        destination_handle_identity = guard._windows_handle_identity(destination_handle)
        if destination_handle_identity != source_identity:
            raise WindowsPublicationError("POST_DESTINATION_HANDLE_IDENTITY_MISMATCH")
        observed = rooted._windows_handle_bytes(destination_handle)
        if observed != validated_subject_bytes:
            raise WindowsPublicationError("POST_DESTINATION_BYTES_MISMATCH")
        destination_acl = _windows_private_acl_snapshot_handle(
            destination_handle,
            label="R3.13 destination",
        )
        if _acl_digest(destination_acl) != _acl_digest(source_acl):
            raise WindowsPublicationError("POST_DESTINATION_DACL_MISMATCH")
        return {
            "destination_path": str(destination_path),
            "destination_handle_value": destination_handle,
            "destination_file_id_128": destination_handle_identity["file_id_128"],
            "destination_volume_serial_number": destination_handle_identity["volume_serial_number"],
            "desired_access": "GENERIC_READ|SYNCHRONIZE",
            "share_mode": "FILE_SHARE_READ",
            "create_disposition": "OPEN_EXISTING",
            "flags": ["FILE_FLAG_OPEN_REPARSE_POINT"],
            "handle_noninheritable": True,
            "security_observation": "GetSecurityInfo(RETAINED_HANDLE)",
        }, {
            "source_name_absent": True,
            "destination_name_present": True,
            "source_handle_equals_destination_identity": True,
            "source_handle_equals_destination_bytes": True,
            "destination_dacl_equals_staged_source_dacl": True,
            "destination_file_id_128": destination_identity["file_id_128"],
            "destination_volume_serial_number": destination_identity["volume_serial_number"],
        }
    finally:
        guard._windows_close(destination_handle)


def _finish_source_transaction(
    *,
    source_handle: int,
    source_was_created: bool,
    stage_path: Path,
    destination_path: Path,
    stage_component: str,
    destination_component: str,
    anchor_handle: int,
    roster: Sequence[Mapping[str, Any]],
    handles: Sequence[int],
    validated_subject_bytes: bytes,
    crash_after: str | None,
    recovery_state: str,
) -> dict[str, Any]:
    import ctypes
    from ctypes import wintypes
    import owned_directory_guard as guard
    import rooted_path_io as rooted

    source_identity = guard._windows_handle_identity(source_handle)
    if (
        source_identity["volume_serial_number"] != roster[-1]["volume_serial_number"]
        or source_identity["reparse_tag"] != 0
    ):
        raise WindowsPublicationError("SOURCE_VOLUME_OR_REPARSE_MISMATCH")
    source_acl = _windows_private_acl_snapshot_handle(
        source_handle,
        label="R3.13 staged source",
    )
    if source_was_created:
        if rooted._windows_handle_bytes(source_handle) != b"":
            raise WindowsPublicationError("NEW_SOURCE_NOT_EMPTY")
        writes = _write_subject(source_handle, validated_subject_bytes)
    else:
        writes = []
        if rooted._windows_handle_bytes(source_handle) != validated_subject_bytes:
            raise WindowsPublicationError("SOURCE_ONLY_BYTES_MISMATCH")
    if rooted._windows_handle_bytes(source_handle) != validated_subject_bytes:
        raise WindowsPublicationError("SOURCE_HANDLE_BYTES_MISMATCH")
    source_open = {
        "source_path": str(stage_path),
        "source_handle_value": source_handle,
        "source_file_id_128": source_identity["file_id_128"],
        "source_volume_serial_number": source_identity["volume_serial_number"],
        "source_was_created": source_was_created,
        "handle_noninheritable": True,
        "dacl_sha256": _acl_digest(source_acl),
        "dacl_derivation": _acl_derivation(source_acl),
        "security_observation": "GetSecurityInfo(RETAINED_HANDLE)",
    }
    _test_crash("AFTER_STAGE_CREATE", crash_after)
    flushes = [_flush_result(source_handle, ordinal=0, phase="PRE_RENAME_PAYLOAD")]
    _test_crash("AFTER_PRE_FLUSH", crash_after)
    _revalidate_protected_ancestors(roster, handles)
    rooted._windows_validate_named_handle(
        source_handle,
        stage_path,
        label="R3.13 staged source",
    )
    request_buffer, request = _rename_request_buffer(
        destination_path,
        destination_component,
        anchor_handle,
    )
    request["hfile_handle_value"] = source_handle
    ctypes.set_last_error(0)
    renamed = bool(
        guard._SetFileInformationByHandle(
            wintypes.HANDLE(source_handle),
            INFORMATION_CLASS_U32,
            request_buffer,
            len(request_buffer),
        )
    )
    rename_error = int(ctypes.get_last_error())
    rename_result = {
        "success": renamed,
        "last_error_u32": rename_error,
        "source_handle_value": source_handle,
        "information_class_u32": INFORMATION_CLASS_U32,
    }
    if not renamed:
        raise WindowsPublicationError("FILE_RENAME_INFO_EX_FAILED", str(rename_error))
    if rename_error != 0:
        raise WindowsPublicationError("RENAME_SUCCESS_LAST_ERROR_NONZERO", str(rename_error))
    _test_crash("AFTER_RENAME", crash_after)
    flushes.append(_flush_result(source_handle, ordinal=1, phase="POST_RENAME_DESTINATION"))
    _test_crash("AFTER_POST_FLUSH", crash_after)
    destination_open, equality = _post_destination_receipt(
        source_handle=source_handle,
        source_identity=source_identity,
        source_acl=source_acl,
        stage_path=stage_path,
        destination_path=destination_path,
        stage_component=stage_component,
        destination_component=destination_component,
        anchor_handle=anchor_handle,
        validated_subject_bytes=validated_subject_bytes,
    )
    return {
        "source_open": source_open,
        "destination_open": destination_open,
        "write_results": writes,
        "flush_results": flushes,
        "rename_request": request,
        "rename_result": rename_result,
        "post_destination_equality": equality,
        "recovery_state": recovery_state,
    }


def _consume_publication_entry(
    capability: ValidatedCandidateCapability,
    *,
    fixture_native_execution_permit: str | Path,
    permit_sha256: str,
    trust_anchor: str | Path,
    protected_root: str | Path,
    stage_name: str,
    destination_name: str,
) -> tuple[dict[str, Any], dict[str, str], dict[str, Any]]:
    if not isinstance(capability, ValidatedCandidateCapability):
        raise WindowsPublicationError("VALIDATED_CANDIDATE_CAPABILITY_REQUIRED")
    _permit_raw, permit = _permit_bytes(fixture_native_execution_permit, permit_sha256)
    context = _publication_context(
        trust_anchor=trust_anchor,
        protected_root=protected_root,
        stage_name=stage_name,
        destination_name=destination_name,
    )
    _enforce_fixture_scope(context, permit)
    context_sha = hashlib.sha256(_canonical(context)).hexdigest()
    entry = _issuance_registry.consume(
        capability,
        context_sha256=context_sha,
        permit_sha256=permit_sha256,
    )
    return entry, context, permit


def _publication_roots(
    context: Mapping[str, str],
) -> tuple[Path, Path, Path, Path, list[dict[str, Any]], list[int]]:
    import rooted_path_io as rooted

    anchor = rooted.checked_directory(context["trust_anchor"], label="R3.13 trust anchor")
    root = rooted.checked_directory(context["protected_root"], label="R3.13 protected root")
    stage_path = rooted.safe_descendant(
        root,
        context["stage_name"],
        allow_missing=True,
        label="R3.13 stage",
    )
    destination_path = rooted.safe_descendant(
        root,
        context["destination_name"],
        allow_missing=True,
        label="R3.13 destination",
    )
    roster, handles = _retain_protected_ancestors(anchor, root)
    return anchor, root, stage_path, destination_path, roster, handles


def _success_receipt(
    *,
    schema: str,
    status: str,
    entry: Mapping[str, Any],
    permit_sha256: str,
    context: Mapping[str, str],
    transaction: Mapping[str, Any],
    roster: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    validated_subject_bytes = entry["validated_subject_bytes"]
    return _sealed_receipt({
        "schema": schema,
        "status": status,
        "profile": PROFILE,
        "candidate_active": CANDIDATE_ACTIVE,
        "validated_subject_sha256": entry["subject_sha256"],
        "payload_sha256": hashlib.sha256(validated_subject_bytes).hexdigest(),
        "payload_size": len(validated_subject_bytes),
        "publication_context_sha256": hashlib.sha256(_canonical(context)).hexdigest(),
        "fixture_native_permit_sha256": permit_sha256,
        "capability_consumed_once": True,
        "transaction": dict(transaction),
        "ancestor_policy": "EVERY_COMPONENT_FROM_TRUST_ANCHOR_RETAINED_NOFOLLOW_HANDLE_SECURITY",
        "ancestor_roster": list(roster),
        "process_crash_recovery_only": True,
        "power_loss_authority": False,
        "directory_flush_claimed": False,
        "fixture_native_authority": dict(FIXTURE_NATIVE_AUTHORITY),
        "global_authority": dict(GLOBAL_AUTHORITY),
    })


def publish_windows_process_crash_only(
    capability: ValidatedCandidateCapability,
    *,
    fixture_native_execution_permit: str | Path,
    permit_sha256: str,
    trust_anchor: str | Path,
    protected_root: str | Path,
    stage_name: str,
    destination_name: str,
    _test_crash_after: str | None = None,
) -> dict[str, Any]:
    """Publish only the validated subject bytes under one consumed capability."""

    if os.name != "nt":
        raise WindowsPublicationError("WINDOWS_NATIVE_REQUIRED")
    entry, context, _permit = _consume_publication_entry(
        capability,
        fixture_native_execution_permit=fixture_native_execution_permit,
        permit_sha256=permit_sha256,
        trust_anchor=trust_anchor,
        protected_root=protected_root,
        stage_name=stage_name,
        destination_name=destination_name,
    )
    validated_subject_bytes = entry["validated_subject_bytes"]
    if type(validated_subject_bytes) is not bytes or not validated_subject_bytes:
        raise WindowsPublicationError("VALIDATED_SUBJECT_BYTES_INVALID")
    _anchor, _root, stage_path, destination_path, roster, handles = _publication_roots(context)
    source_handle: int | None = None
    try:
        import owned_directory_guard as guard

        anchor_handle = handles[-1]
        _revalidate_protected_ancestors(roster, handles)
        source_state = guard._windows_relative_identity(
            anchor_handle, context["stage_name"], is_directory=False
        )
        destination_state = guard._windows_relative_identity(
            anchor_handle, context["destination_name"], is_directory=False
        )
        if source_state is not None or destination_state is not None:
            raise WindowsPublicationError("PREEXISTING_STATE_REQUIRES_RECONCILER")
        source_handle = _create_stage(stage_path)
        transaction = _finish_source_transaction(
            source_handle=source_handle,
            source_was_created=True,
            stage_path=stage_path,
            destination_path=destination_path,
            stage_component=context["stage_name"],
            destination_component=context["destination_name"],
            anchor_handle=anchor_handle,
            roster=roster,
            handles=handles,
            validated_subject_bytes=validated_subject_bytes,
            crash_after=_test_crash_after,
            recovery_state="NEITHER_FRESH_PUBLICATION",
        )
        _revalidate_protected_ancestors(roster, handles)
        return _success_receipt(
            schema=PUBLICATION_SCHEMA,
            status="SUCCESS_PROCESS_CRASH_RECOVERABLE",
            entry=entry,
            permit_sha256=permit_sha256,
            context=context,
            transaction=transaction,
            roster=roster,
        )
    finally:
        import owned_directory_guard as guard

        if source_handle is not None:
            guard._windows_close(source_handle)
        for handle in reversed(handles):
            guard._windows_close(handle)


def reconcile_windows_process_crash_publication_once(
    capability: ValidatedCandidateCapability,
    *,
    fixture_native_execution_permit: str | Path,
    permit_sha256: str,
    trust_anchor: str | Path,
    protected_root: str | Path,
    stage_name: str,
    destination_name: str,
) -> dict[str, Any]:
    """Accept exact SOURCE_ONLY/DESTINATION_ONLY; reject every AMBIGUOUS state."""

    if os.name != "nt":
        raise WindowsPublicationError("WINDOWS_NATIVE_REQUIRED")
    entry, context, _permit = _consume_publication_entry(
        capability,
        fixture_native_execution_permit=fixture_native_execution_permit,
        permit_sha256=permit_sha256,
        trust_anchor=trust_anchor,
        protected_root=protected_root,
        stage_name=stage_name,
        destination_name=destination_name,
    )
    validated_subject_bytes = entry["validated_subject_bytes"]
    _anchor, _root, stage_path, destination_path, roster, handles = _publication_roots(context)
    file_handle: int | None = None
    try:
        import owned_directory_guard as guard
        import rooted_path_io as rooted

        anchor_handle = handles[-1]
        _revalidate_protected_ancestors(roster, handles)
        source_identity = guard._windows_relative_identity(
            anchor_handle, context["stage_name"], is_directory=False
        )
        destination_identity = guard._windows_relative_identity(
            anchor_handle, context["destination_name"], is_directory=False
        )
        if source_identity is not None and destination_identity is None:
            recovery_state = "SOURCE_ONLY"
            file_handle = _open_existing_file(
                stage_path,
                writable=True,
                label="R3.13 SOURCE_ONLY stage",
            )
            transaction = _finish_source_transaction(
                source_handle=file_handle,
                source_was_created=False,
                stage_path=stage_path,
                destination_path=destination_path,
                stage_component=context["stage_name"],
                destination_component=context["destination_name"],
                anchor_handle=anchor_handle,
                roster=roster,
                handles=handles,
                validated_subject_bytes=validated_subject_bytes,
                crash_after=None,
                recovery_state=recovery_state,
            )
        elif source_identity is None and destination_identity is not None:
            recovery_state = "DESTINATION_ONLY"
            file_handle = _open_existing_file(
                destination_path,
                writable=True,
                label="R3.13 DESTINATION_ONLY destination",
            )
            observed_identity = guard._windows_handle_identity(file_handle)
            if (
                observed_identity != destination_identity
                or observed_identity["volume_serial_number"] != roster[-1]["volume_serial_number"]
                or observed_identity["reparse_tag"] != 0
                or rooted._windows_handle_bytes(file_handle) != validated_subject_bytes
            ):
                raise WindowsPublicationError("DESTINATION_ONLY_IDENTITY_OR_BYTES_MISMATCH")
            destination_acl = _windows_private_acl_snapshot_handle(
                file_handle,
                label="R3.13 DESTINATION_ONLY destination",
            )
            flush = _flush_result(
                file_handle,
                ordinal=0,
                phase="RECONCILE_DESTINATION_ONLY",
            )
            transaction = {
                "recovery_state": recovery_state,
                "destination_file_id_128": observed_identity["file_id_128"],
                "destination_volume_serial_number": observed_identity["volume_serial_number"],
                "destination_bytes_equal_validated_subject": True,
                "destination_dacl_sha256": _acl_digest(destination_acl),
                "destination_dacl_derivation": _acl_derivation(destination_acl),
                "flush_results": [flush],
            }
        else:
            recovery_state = "AMBIGUOUS"
            detail = (
                "BOTH_PRESENT" if source_identity is not None else "NEITHER_PRESENT"
            )
            raise WindowsPublicationError("AMBIGUOUS", detail)
        _revalidate_protected_ancestors(roster, handles)
        return _success_receipt(
            schema=RECONCILIATION_SCHEMA,
            status="SUCCESS_RECONCILED_PROCESS_CRASH_STATE",
            entry=entry,
            permit_sha256=permit_sha256,
            context=context,
            transaction=transaction,
            roster=roster,
        )
    finally:
        import owned_directory_guard as guard

        if file_handle is not None:
            guard._windows_close(file_handle)
        for handle in reversed(handles):
            guard._windows_close(handle)


def _read_stdin_bounded(maximum: int = MAX_GOVERNED_BYTES) -> bytes:
    raw = sys.stdin.buffer.read(maximum + 1)
    if len(raw) > maximum:
        raise CandidateValidationError("STDIN_BYTES_EXCEEDED")
    return raw


def _validation_child(validator_path: str) -> int:
    try:
        raw = _read_stdin_bounded()
        path = Path(validator_path)
        with open(path, "rb") as stream:
            source = stream.read(MAX_GOVERNED_BYTES + 1)
        if len(source) > MAX_GOVERNED_BYTES:
            raise CandidateValidationError("VALIDATOR_BYTES_EXCEEDED")
        namespace: dict[str, Any] = {
            "__file__": str(path),
            "__name__": "r3_11_fresh_validator",
        }
        exec(compile(source, str(path), "exec"), namespace)
        primary, subcode = namespace["validate_subject"](raw)
        closure = runtime_closure_snapshot()
        receipt = {
            "isolated": bool(sys.flags.isolated),
            "no_site": bool(sys.flags.no_site),
            "pid": os.getpid(),
            "primary": primary,
            "subcode": subcode,
            "subject_sha256": hashlib.sha256(raw).hexdigest(),
            "validator_sha256": hashlib.sha256(source).hexdigest(),
            "loaded_child_module_origins": closure["loaded_child_module_origins"],
            "loaded_child_image_origins": closure["loaded_child_image_origins"],
        }
        sys.stdout.buffer.write(_canonical(receipt))
        sys.stdout.buffer.flush()
        return 0
    except BaseException:
        return 70


def _runtime_closure_child() -> int:
    try:
        sys.stdout.buffer.write(_canonical(runtime_closure_snapshot()))
        sys.stdout.buffer.flush()
        return 0
    except BaseException:
        return 74


def _native_fixture_child() -> int:
    try:
        request = json.loads(
            _read_stdin_bounded(MAX_CHILD_RECEIPT_BYTES).decode("utf-8", errors="strict")
        )
        if not isinstance(request, dict):
            return 71
        common = {
            "fixture_native_execution_permit": request["fixture_native_execution_permit"],
            "permit_sha256": request["permit_sha256"],
            "trust_anchor": request["trust_anchor"],
            "protected_root": request["protected_root"],
            "stage_name": request["stage_name"],
            "destination_name": request["destination_name"],
        }
        validation, capability = validate_candidate_fresh(
            request["subject_path"],
            runtime_root=request["runtime_root"],
            expected_launcher_sha256=request["launcher_sha256"],
            expected_interpreter_sha256=request["interpreter_sha256"],
            expected_runtime_closure_path=request["expected_runtime_closure_path"],
            expected_runtime_closure_sha256=request["expected_runtime_closure_sha256"],
            repo_root=request["repo_root"],
            **common,
        )
        if capability is None:
            sys.stdout.buffer.write(_canonical(validation))
            sys.stdout.buffer.flush()
            return 72
        if request.get("operation", "PUBLISH") == "PUBLISH":
            receipt = publish_windows_process_crash_only(
                capability,
                _test_crash_after=request.get("crash_after"),
                **common,
            )
        elif request.get("operation") == "RECONCILE":
            receipt = reconcile_windows_process_crash_publication_once(
                capability,
                **common,
            )
        else:
            raise WindowsPublicationError("FIXTURE_OPERATION_INVALID")
        sys.stdout.buffer.write(_canonical(receipt))
        sys.stdout.buffer.flush()
        return 0
    except BaseException as exc:
        failure = {
            "status": "FIXTURE_CHILD_REJECTED",
            "exception_type": type(exc).__name__,
            "code": getattr(exc, "code", "UNCLASSIFIED_FIXTURE_FAILURE"),
        }
        try:
            sys.stdout.buffer.write(_canonical(failure))
            sys.stdout.buffer.flush()
        except BaseException:
            pass
        return 73


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) == 2 and args[0] == "--validation-child":
        return _validation_child(args[1])
    if args == ["--runtime-closure-child"]:
        return _runtime_closure_child()
    if args == ["--native-fixture-child"]:
        return _native_fixture_child()
    return 64


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "CANDIDATE_ACTIVE",
    "CandidateValidationError",
    "FIXTURE_NATIVE_EXECUTION_PERMIT_SHA256",
    "GLOBAL_AUTHORITY",
    "INFORMATION_CLASS_U32",
    "MAX_GOVERNED_BYTES",
    "PROFILE",
    "REQUIRED_INPUTS",
    "ValidatedCandidateCapability",
    "WindowsPublicationError",
    "derive_pinned_predecessor_principals",
    "publish_windows_process_crash_only",
    "reconcile_windows_process_crash_publication_once",
    "runtime_closure_snapshot",
    "validate_candidate_fresh",
]
