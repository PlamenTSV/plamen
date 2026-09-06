"""Inactive R3.12 Windows process-crash audit-handoff candidate.

Nothing imports this module from the production driver.  Its two explicit
entrypoints (fresh validation and protected-root publication) keep every
global/cutover authority false and exist only for fixture-first independent
review.  Linux power-loss publication, Linux statx/OFD/RENAME_EXCHANGE,
macOS, provider admission, and driver cutover are deliberately absent.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile
from typing import Any, Mapping, Sequence


SCHEMA = "plamen.program_facts.g3.launcher.r3_12.windows_process_crash.v1"
VALIDATION_SCHEMA = SCHEMA + ".validation"
PUBLICATION_SCHEMA = SCHEMA + ".publication"
MAX_GOVERNED_BYTES = 1_000_000
MAX_CHILD_RECEIPT_BYTES = 64 * 1024
PROFILE = "WINDOWS_ORDINARY_USER_PROTECTED_ROOT_PROCESS_CRASH_R3_12"
INFORMATION_CLASS_NAME = "FileRenameInfoEx"
INFORMATION_CLASS_U32 = 22
REQUEST_STRUCTURE = "FILE_RENAME_INFO"
RENAME_FLAGS_U32 = 0
CANDIDATE_ACTIVE = False
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

_REPO = Path(__file__).resolve().parent.parent
_HEX64 = re.compile(r"[0-9a-f]{64}")
_CAPABILITY_TOKEN = object()


# Every row is raw-byte governed by the one-million-byte limit.  The first ten
# rows are the exact R3.11 validator closure.  The remaining rows are R3.12's
# pinned REPAIR/design inputs and are staged even though the R3.11 validator
# itself does not address them.
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
)


class CandidateValidationError(RuntimeError):
    """The fresh validator boundary could not produce an accepted capability."""


class WindowsPublicationError(RuntimeError):
    """A protected-root publication failed closed with a stable reason code."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(code if not detail else f"{code}: {detail}")


class ValidatedCandidateCapability:
    """Opaque in-process proof that one exact subject passed one fresh child."""

    __slots__ = ("_token", "_subject_sha256", "_receipt")

    def __init__(self, token: object, subject_sha256: str, receipt: Mapping[str, Any]) -> None:
        if token is not _CAPABILITY_TOKEN:
            raise TypeError("ValidatedCandidateCapability is opaque")
        self._token = token
        self._subject_sha256 = subject_sha256
        self._receipt = dict(receipt)

    def __repr__(self) -> str:
        return "<ValidatedCandidateCapability opaque>"

    def __reduce__(self) -> object:
        raise TypeError("ValidatedCandidateCapability cannot be serialized")

    @property
    def receipt(self) -> dict[str, Any]:
        return json.loads(json.dumps(self._receipt))


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sealed_receipt(core: Mapping[str, Any]) -> dict[str, Any]:
    # Reuse the live ledger's canonical receipt preimage primitive without
    # invoking any ledger write, selection, admission, or cutover API.
    import artifact_ledger as ledger

    value = dict(core)
    value["receipt_sha256"] = ledger._canonical_json_digest(value)
    return value


def _valid_hash(value: object) -> str:
    if not isinstance(value, str) or _HEX64.fullmatch(value) is None:
        raise CandidateValidationError("expected SHA-256 is malformed")
    return value


def _bounded_file(path: Path) -> bytes:
    from bounded_artifact_io import read_bounded_regular_bytes

    return read_bounded_regular_bytes(
        Path(path),
        MAX_GOVERNED_BYTES,
        require_single_link=True,
    )


def _checked_input(repo: Path, row: Mapping[str, object]) -> tuple[Path, bytes]:
    relative = str(row["path"])
    path = repo.joinpath(*PurePosixPath(relative).parts)
    raw = _bounded_file(path)
    if (
        len(raw) != row["size"]
        or hashlib.sha256(raw).hexdigest() != row["sha256"]
    ):
        raise CandidateValidationError(f"DEPENDENCY_IDENTITY_MISMATCH:{relative}")
    return path, raw


def derive_pinned_predecessor_principals(repo_root: str | Path = _REPO) -> dict[str, str]:
    """Derive principals from authenticated predecessor bytes, never aliases."""

    repo = Path(repo_root)
    by_suffix = {str(row["path"]): row for row in REQUIRED_INPUTS}

    def field(path: str, pattern: str, label: str) -> str:
        _path, raw = _checked_input(repo, by_suffix[path])
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise CandidateValidationError(f"{label}_UTF8_INVALID") from exc
        matches = re.findall(pattern, text, flags=re.MULTILINE)
        if len(matches) != 1 or not matches[0].strip():
            raise CandidateValidationError(f"{label}_PRINCIPAL_UNBOUND")
        return matches[0].strip()

    base = "review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/"
    state = base + "PROGRAM_FACTS_G3_00_PARITY_LAUNCHER_R3_11_STATE_OPERATIONAL_REVIEW_a83e4828f317dfc0.md"
    native = base + "PROGRAM_FACTS_G3_00_PARITY_LAUNCHER_R3_11_NATIVE_CONTRACT_REVIEW_a83e4828f317dfc0.md"
    author = base + "PROGRAM_FACTS_G3_00_PARITY_LAUNCHER_R3_11_AUTHOR_SELF_REVIEW_a83e4828f317dfc0.md"
    return {
        "r3_11_state_reviewer": field(state, r"^- Reviewer:\s*`([^`]+)`\s*$", "STATE_REVIEW"),
        "r3_11_native_reviewer": field(native, r"^- Reviewer:\s*`([^`]+)`\s*$", "NATIVE_REVIEW"),
        "r3_11_subject_author": field(author, r"^- Author/reviewer principal:\s*`([^`]+)`[.]?\s*$", "SUBJECT_AUTHOR"),
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
        "isolated_flag": False,
        "no_site_flag": False,
        "global_authority": dict(GLOBAL_AUTHORITY),
    })


def validate_candidate_fresh(
    subject_path: str | Path,
    *,
    runtime_root: str | Path,
    expected_launcher_sha256: str,
    expected_interpreter_sha256: str,
    repo_root: str | Path = _REPO,
    timeout_seconds: float = 60.0,
) -> tuple[dict[str, Any], ValidatedCandidateCapability | None]:
    """Validate exactly one candidate in one staged ``python -I -S`` child."""

    launcher_expected = _valid_hash(expected_launcher_sha256)
    interpreter_expected = _valid_hash(expected_interpreter_sha256)
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
        or timeout_seconds <= 0
        or timeout_seconds > 300
    ):
        raise CandidateValidationError("validation timeout is outside 0..300 seconds")

    from bounded_artifact_io import read_bounded_regular_bytes
    import isolated_execution_host as isolated
    import rooted_path_io as rooted

    runtime = rooted.checked_directory(runtime_root, label="R3.12 validation runtime root")
    repo = rooted.checked_directory(repo_root, label="R3.12 pinned repository root")
    launcher_path = Path(__file__).resolve()
    interpreter_path = Path(sys.executable).resolve()
    try:
        subject_raw = read_bounded_regular_bytes(
            Path(subject_path), MAX_GOVERNED_BYTES, require_single_link=True
        )
        launcher_raw = read_bounded_regular_bytes(
            launcher_path, MAX_GOVERNED_BYTES, require_single_link=True
        )
        interpreter_raw = read_bounded_regular_bytes(
            interpreter_path, MAX_GOVERNED_BYTES, require_single_link=True
        )
    except (OSError, ValueError) as exc:
        raise CandidateValidationError("governed input bounded read failed") from exc
    subject_sha = hashlib.sha256(subject_raw).hexdigest()
    launcher_sha = hashlib.sha256(launcher_raw).hexdigest()
    interpreter_sha = hashlib.sha256(interpreter_raw).hexdigest()
    if launcher_sha != launcher_expected:
        raise CandidateValidationError("LAUNCHER_IDENTITY_MISMATCH")
    if interpreter_sha != interpreter_expected:
        raise CandidateValidationError("INTERPRETER_IDENTITY_MISMATCH")

    principals = derive_pinned_predecessor_principals(repo)
    with tempfile.TemporaryDirectory(prefix=".r312-validation-", dir=str(runtime)) as temporary:
        stage_root = Path(temporary).resolve(strict=True)
        stage = isolated._WindowsImmutableDependencyStage(stage_root)
        started = False
        try:
            staged_launcher = stage.copy_verified(
                {"path": str(launcher_path), "sha256": launcher_sha, "size": len(launcher_raw)},
                relative=Path("scripts/program_facts_windows_native_launcher_r3_12.py"),
                maximum_bytes=MAX_GOVERNED_BYTES,
            )
            # Retain the selected interpreter source against write/delete and
            # stage its exact bytes as a replayable identity witness.
            stage.copy_verified(
                {"path": str(interpreter_path), "sha256": interpreter_sha, "size": len(interpreter_raw)},
                relative=Path(".runtime/python.exe"),
                maximum_bytes=MAX_GOVERNED_BYTES,
            )
            try:
                for row in REQUIRED_INPUTS:
                    source, _raw = _checked_input(repo, row)
                    stage.copy_verified(
                        {"path": str(source), "sha256": row["sha256"], "size": row["size"]},
                        relative=Path(*PurePosixPath(str(row["path"])).parts),
                        maximum_bytes=MAX_GOVERNED_BYTES,
                    )
            except (OSError, ValueError, CandidateValidationError, isolated.IsolatedExecutionProtocolError):
                return _validation_rejection(
                    subject_sha256=subject_sha,
                    primary="DEPENDENCY_CLOSURE",
                    subcode="DEPENDENCY_READ_FAILURE",
                    launcher_sha256=launcher_sha,
                    interpreter_sha256=interpreter_sha,
                    fresh_process_started=False,
                ), None
            stage.verify_all()
            validator = stage_root / "Temp/program_facts_g3_launcher_r3_11_20260809/r3_11_validator.py"
            argv = [
                str(interpreter_path),
                "-I",
                "-S",
                "-B",
                str(staged_launcher),
                "--validation-child",
                str(validator),
            ]
            started = True
            completed = subprocess.run(
                argv,
                input=subject_raw,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(stage_root),
                env=isolated._executor_environment(),
                timeout=float(timeout_seconds),
                check=False,
                shell=False,
                creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
            )
            stage.verify_all()
            if (
                completed.returncode != 0
                or completed.stderr
                or not completed.stdout
                or len(completed.stdout) > MAX_CHILD_RECEIPT_BYTES
            ):
                return _validation_rejection(
                    subject_sha256=subject_sha,
                    primary="EXECUTOR",
                    subcode="FRESH_VALIDATOR_PROCESS_FAILED",
                    launcher_sha256=launcher_sha,
                    interpreter_sha256=interpreter_sha,
                    fresh_process_started=started,
                ), None
            child = json.loads(completed.stdout.decode("utf-8", errors="strict"))
            if (
                not isinstance(child, dict)
                or set(child) != {
                    "isolated", "no_site", "pid", "primary", "subcode",
                    "subject_sha256", "validator_sha256",
                }
                or child["subject_sha256"] != subject_sha
                or child["validator_sha256"] != REQUIRED_INPUTS[0]["sha256"]
                or child["isolated"] is not True
                or child["no_site"] is not True
                or type(child["pid"]) is not int
                or child["pid"] <= 0
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
            receipt = _sealed_receipt({
                "schema": VALIDATION_SCHEMA,
                "status": status,
                "primary": child["primary"],
                "subcode": child["subcode"],
                "subject_sha256": subject_sha,
                "validator_sha256": child["validator_sha256"],
                "launcher_sha256": launcher_sha,
                "interpreter_sha256": interpreter_sha,
                "fresh_process_started": True,
                "fresh_process_pid": child["pid"],
                "isolated_flag": True,
                "no_site_flag": True,
                "dependency_count": len(REQUIRED_INPUTS),
                "max_governed_raw_bytes": MAX_GOVERNED_BYTES,
                "predecessor_principals": principals,
                "global_authority": dict(GLOBAL_AUTHORITY),
            })
            capability = (
                ValidatedCandidateCapability(_CAPABILITY_TOKEN, subject_sha, receipt)
                if status == "ACCEPTED"
                else None
            )
            return receipt, capability
        finally:
            stage.close()


def _canonical_component(value: str, *, label: str) -> str:
    import report_assembly_capture as capture

    try:
        normalized = capture._canonical_path(value)
    except Exception as exc:
        raise WindowsPublicationError("PATH_COMPONENT_INVALID", label) from exc
    if "/" in normalized or "\\" in normalized or normalized != value:
        raise WindowsPublicationError("PATH_COMPONENT_INVALID", label)
    return normalized


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


def _acl_digest(snapshot: tuple[str, tuple[tuple[int, int, int, str], ...]]) -> str:
    owner, rows = snapshot
    return hashlib.sha256(_canonical({"owner": owner, "aces": [list(row) for row in rows]})).hexdigest()


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
        "trusted_sensitive_principal_policy": (
            "CURRENT_TOKEN_USER_OR_BUILTIN_ADMINISTRATORS_OR_LOCAL_SYSTEM"
        ),
        "unsupported_ace_types_rejected": True,
        "untrusted_sensitive_allow_ace_rejected": True,
        "current_launcher_user_sensitive_allow_required": True,
    }


def _retain_protected_ancestors(anchor: Path, root: Path) -> tuple[list[dict[str, Any]], list[int]]:
    import claude_stored_subscription_source as security
    import owned_directory_guard as guard
    import report_assembly_capture as capture

    handles: list[int] = []
    roster: list[dict[str, Any]] = []
    try:
        for ordinal, path in enumerate(_ancestor_paths(anchor, root)):
            handle = guard._windows_open_absolute_directory(path)
            handles.append(handle)
            identity = guard._windows_handle_identity(handle)
            expected = os.path.normcase(os.path.normpath(os.path.abspath(str(path))))
            observed = os.path.normcase(capture._windows_final_path(handle, relative=str(path)))
            if observed != expected:
                raise WindowsPublicationError("ANCESTOR_FINAL_PATH_MISMATCH")
            first = security._windows_private_acl_snapshot(path, label="R3.12 protected ancestor")
            second = security._windows_private_acl_snapshot(path, label="R3.12 protected ancestor")
            if first != second:
                raise WindowsPublicationError("ANCESTOR_DACL_CHANGED")
            roster.append({
                "ordinal": ordinal,
                "canonical_path": str(path),
                "volume_serial_number": identity["volume_serial_number"],
                "file_id_128": identity["file_id_128"],
                "file_attributes": identity["file_attributes"],
                "reparse_tag": identity["reparse_tag"],
                "owner_is_launcher_principal": True,
                "ordered_ace_trust_derived": True,
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
        raise WindowsPublicationError(
            "ANCESTOR_TRUST_VALIDATION_FAILED", type(exc).__name__
        ) from exc


def _revalidate_protected_ancestors(
    roster: Sequence[Mapping[str, Any]], handles: Sequence[int]
) -> None:
    import claude_stored_subscription_source as security
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
        try:
            acl = security._windows_private_acl_snapshot(path, label="R3.12 protected ancestor")
        except Exception as exc:
            raise WindowsPublicationError(
                "ANCESTOR_TRUST_REVALIDATION_FAILED", type(exc).__name__
            ) from exc
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
    # SetFileInformationByHandle accepts class 22 with the documented absolute
    # path/null RootDirectory form on the governed host.  The retained
    # directory handle remains the exact pre/post verification anchor; it is
    # intentionally not misreported as a request operand.
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
        "flags_offset_bytes": 0,
        "reserved_offset_bytes": 4,
        "reserved_length_bytes": len(reserved),
        "zero_reserved_hex": reserved.hex(),
        "root_directory_offset_bytes": abi["FILE_RENAME_INFO.RootDirectory.offset"],
        "file_name_length_offset_bytes": abi["FILE_RENAME_INFO.FileNameLength.offset"],
        "filename_offset_bytes": filename_offset,
        "buffer_length_bytes": buffer_length,
        "buffer_hex": bytes(buffer).hex(),
        "buffer_sha256": hashlib.sha256(bytes(buffer)).hexdigest(),
        "tail_length_bytes": len(tail),
        "zero_tail_hex": tail.hex(),
    }


def _test_crash(stage: str, selected: str | None) -> None:
    if selected == stage:
        if os.environ.get("PLAMEN_R312_TEST_CRASH") != "1":
            raise WindowsPublicationError("TEST_CRASH_NOT_AUTHORIZED")
        os._exit(97)


def publish_windows_process_crash_only(
    capability: ValidatedCandidateCapability,
    *,
    trust_anchor: str | Path,
    protected_root: str | Path,
    stage_name: str,
    destination_name: str,
    payload: bytes,
    _test_crash_after: str | None = None,
) -> dict[str, Any]:
    """Execute one no-replace Windows publication under a retained root handle."""

    if os.name != "nt":
        raise WindowsPublicationError("WINDOWS_NATIVE_REQUIRED")
    if (
        not isinstance(capability, ValidatedCandidateCapability)
        or capability._token is not _CAPABILITY_TOKEN
        or capability._receipt.get("status") != "ACCEPTED"
    ):
        raise WindowsPublicationError("VALIDATED_CANDIDATE_CAPABILITY_REQUIRED")
    if type(payload) is not bytes or len(payload) > MAX_GOVERNED_BYTES:
        raise WindowsPublicationError("PAYLOAD_RAW_BYTES_LIMIT")
    if not payload:
        raise WindowsPublicationError("PAYLOAD_EMPTY")
    stage_component = _canonical_component(stage_name, label="stage")
    destination_component = _canonical_component(destination_name, label="destination")
    if stage_component.casefold() == destination_component.casefold():
        raise WindowsPublicationError("SOURCE_DESTINATION_ALIAS")

    import ctypes
    from ctypes import wintypes
    import claude_stored_subscription_source as security
    import owned_directory_guard as guard
    import rooted_path_io as rooted

    anchor = rooted.checked_directory(trust_anchor, label="R3.12 trust anchor")
    root = rooted.checked_directory(protected_root, label="R3.12 protected root")
    stage_path = rooted.safe_descendant(root, stage_component, allow_missing=True, label="R3.12 stage")
    destination_path = rooted.safe_descendant(root, destination_component, allow_missing=True, label="R3.12 destination")
    roster, handles = _retain_protected_ancestors(anchor, root)
    anchor_handle = handles[-1]
    source_handle: int | None = None
    destination_handle: int | None = None
    try:
        _revalidate_protected_ancestors(roster, handles)
        if guard._windows_relative_identity(anchor_handle, destination_component, is_directory=False) is not None:
            raise WindowsPublicationError("DESTINATION_EXISTS")
        access = rooted._GENERIC_READ | rooted._GENERIC_WRITE | rooted._DELETE_ACCESS | _SYNCHRONIZE
        share = rooted._FILE_SHARE_READ
        flags = (
            _FILE_ATTRIBUTE_NORMAL
            | rooted._FILE_FLAG_OPEN_REPARSE_POINT
            | rooted._FILE_FLAG_WRITE_THROUGH
        )
        opened = rooted._CreateFileW(
            rooted.native_path(stage_path),
            access,
            share,
            None,
            rooted._CREATE_NEW,
            flags,
            None,
        )
        value = ctypes.cast(opened, ctypes.c_void_p).value
        if value in {None, rooted._INVALID_HANDLE_VALUE}:
            raise WindowsPublicationError("SOURCE_CREATE_NEW_FAILED", str(ctypes.get_last_error()))
        source_handle = int(value)
        if not guard._SetHandleInformation(opened, guard._HANDLE_FLAG_INHERIT, 0):
            raise WindowsPublicationError("SOURCE_HANDLE_INHERITANCE")
        source_identity = guard._windows_handle_identity(source_handle)
        if (
            source_identity["volume_serial_number"] != roster[-1]["volume_serial_number"]
            or source_identity["reparse_tag"] != 0
        ):
            raise WindowsPublicationError("SOURCE_VOLUME_OR_REPARSE_MISMATCH")
        rooted._windows_validate_named_handle(source_handle, stage_path, label="R3.12 staged source")
        source_acl = security._windows_private_acl_snapshot(stage_path, label="R3.12 staged source")
        source_open = {
            "source_path": str(stage_path),
            "source_handle_value": source_handle,
            "source_file_id_128": source_identity["file_id_128"],
            "source_volume_serial_number": source_identity["volume_serial_number"],
            "desired_access_u32": access,
            "share_mode_u32": share,
            "create_disposition": "CREATE_NEW",
            "create_disposition_u32": rooted._CREATE_NEW,
            "flags_and_attributes_u32": flags,
            "flags": ["FILE_ATTRIBUTE_NORMAL", "FILE_FLAG_OPEN_REPARSE_POINT", "FILE_FLAG_WRITE_THROUGH"],
            "handle_noninheritable": True,
            "dacl_trust_derived": True,
            "dacl_sha256": _acl_digest(source_acl),
            "dacl_derivation": _acl_derivation(source_acl),
        }
        _test_crash("AFTER_STAGE_CREATE", _test_crash_after)

        offset = 0
        writes: list[dict[str, int | bool]] = []
        while offset < len(payload):
            chunk = payload[offset: offset + 64 * 1024]
            buffer = ctypes.create_string_buffer(chunk)
            written = wintypes.DWORD()
            ctypes.set_last_error(0)
            success = bool(rooted._WriteFile(source_handle, buffer, len(chunk), ctypes.byref(written), None))
            error = int(ctypes.get_last_error())
            writes.append({"ordinal": len(writes), "requested": len(chunk), "written": int(written.value), "success": success, "last_error_u32": error})
            if not success or written.value != len(chunk) or error != 0:
                raise WindowsPublicationError("SOURCE_WRITE_FAILED", str(error))
            offset += int(written.value)
        if rooted._windows_handle_bytes(source_handle) != payload:
            raise WindowsPublicationError("SOURCE_HANDLE_BYTES_MISMATCH")
        flushes = [_flush_result(source_handle, ordinal=0, phase="PRE_RENAME_PAYLOAD")]
        _test_crash("AFTER_PRE_FLUSH", _test_crash_after)
        _revalidate_protected_ancestors(roster, handles)
        rooted._windows_validate_named_handle(source_handle, stage_path, label="R3.12 staged source")
        request_buffer, request = _rename_request_buffer(
            destination_path,
            destination_component,
            anchor_handle,
        )
        request["hfile_handle_value"] = source_handle
        ctypes.set_last_error(0)
        renamed = bool(guard._SetFileInformationByHandle(
            wintypes.HANDLE(source_handle),
            INFORMATION_CLASS_U32,
            request_buffer,
            len(request_buffer),
        ))
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
        _test_crash("AFTER_RENAME", _test_crash_after)
        flushes.append(_flush_result(source_handle, ordinal=1, phase="POST_RENAME_DESTINATION"))
        _test_crash("AFTER_POST_FLUSH", _test_crash_after)

        post_source_identity = guard._windows_handle_identity(source_handle)
        if post_source_identity != source_identity:
            raise WindowsPublicationError("SOURCE_HANDLE_IDENTITY_DRIFT")
        if guard._windows_relative_identity(anchor_handle, stage_component, is_directory=False) is not None:
            raise WindowsPublicationError("SOURCE_NAME_REMAINS_AFTER_RENAME")
        destination_identity = guard._windows_relative_identity(anchor_handle, destination_component, is_directory=False)
        if destination_identity != source_identity:
            raise WindowsPublicationError("POST_DESTINATION_IDENTITY_MISMATCH")
        destination_access = rooted._GENERIC_READ | _SYNCHRONIZE
        destination_share = (
            rooted._FILE_SHARE_READ
            | rooted._FILE_SHARE_WRITE
            | rooted._FILE_SHARE_DELETE
        )
        destination_flags = rooted._FILE_FLAG_OPEN_REPARSE_POINT
        destination_opened = rooted._CreateFileW(
            rooted.native_path(destination_path),
            destination_access,
            # This observer must share the already-held source handle's
            # read/write/delete access.  The source handle's own share-read-
            # only policy still excludes any new writer or deleter.
            destination_share,
            None,
            rooted._OPEN_EXISTING,
            destination_flags,
            None,
        )
        destination_value = ctypes.cast(destination_opened, ctypes.c_void_p).value
        if destination_value in {None, rooted._INVALID_HANDLE_VALUE}:
            raise WindowsPublicationError("POST_DESTINATION_OPEN_FAILED", str(ctypes.get_last_error()))
        destination_handle = int(destination_value)
        rooted._windows_validate_named_handle(destination_handle, destination_path, label="R3.12 destination")
        destination_handle_identity = guard._windows_handle_identity(destination_handle)
        if destination_handle_identity != source_identity:
            raise WindowsPublicationError("POST_DESTINATION_HANDLE_IDENTITY_MISMATCH")
        destination_open = {
            "destination_path": str(destination_path),
            "destination_handle_value": destination_handle,
            "destination_file_id_128": destination_handle_identity["file_id_128"],
            "destination_volume_serial_number": destination_handle_identity["volume_serial_number"],
            "desired_access_u32": destination_access,
            "share_mode_u32": destination_share,
            "create_disposition": "OPEN_EXISTING",
            "create_disposition_u32": rooted._OPEN_EXISTING,
            "flags_and_attributes_u32": destination_flags,
            "flags": ["FILE_FLAG_OPEN_REPARSE_POINT"],
            "handle_noninheritable": True,
        }
        observed = rooted._windows_handle_bytes(destination_handle)
        if observed != payload:
            raise WindowsPublicationError("POST_DESTINATION_BYTES_MISMATCH")
        destination_acl = security._windows_private_acl_snapshot(destination_path, label="R3.12 destination")
        if _acl_digest(destination_acl) != source_open["dacl_sha256"]:
            raise WindowsPublicationError("POST_DESTINATION_DACL_MISMATCH")
        _revalidate_protected_ancestors(roster, handles)
        rooted.checked_directory(root, label="R3.12 protected root poststate")

        receipt = _sealed_receipt({
            "schema": PUBLICATION_SCHEMA,
            "status": "SUCCESS_PROCESS_CRASH_ONLY",
            "profile": PROFILE,
            "candidate_active": CANDIDATE_ACTIVE,
            "validated_subject_sha256": capability._subject_sha256,
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "payload_size": len(payload),
            "source_open": source_open,
            "destination_open": destination_open,
            "write_results": writes,
            "flush_results": flushes,
            "rename_request": request,
            "rename_result": rename_result,
            "destination_anchor": {
                "canonical_path": roster[-1]["canonical_path"],
                "handle_value": anchor_handle,
                "volume_serial_number": roster[-1]["volume_serial_number"],
                "file_id_128": roster[-1]["file_id_128"],
                "retained_through_post_destination_equality": True,
            },
            "ancestor_policy": "EVERY_COMPONENT_FROM_TRUST_ANCHOR_RETAINED_NOFOLLOW",
            "dacl_trust_derivation": "ORDERED_ACE_REDUCTION",
            "ancestor_roster": roster,
            "post_destination_equality": {
                "source_name_absent": True,
                "destination_name_present": True,
                "source_handle_equals_destination_identity": True,
                "source_handle_equals_destination_bytes": True,
                "destination_dacl_equals_staged_source_dacl": True,
                "destination_file_id_128": destination_identity["file_id_128"],
                "destination_volume_serial_number": destination_identity["volume_serial_number"],
            },
            "process_crash_recovery_only": True,
            "power_loss_authority": False,
            "directory_flush_claimed": False,
            "global_authority": dict(GLOBAL_AUTHORITY),
        })
        return receipt
    finally:
        if destination_handle is not None:
            guard._windows_close(destination_handle)
        if source_handle is not None:
            guard._windows_close(source_handle)
        for handle in reversed(handles):
            guard._windows_close(handle)


def _read_stdin_bounded() -> bytes:
    raw = sys.stdin.buffer.read(MAX_GOVERNED_BYTES + 1)
    if len(raw) > MAX_GOVERNED_BYTES:
        raise CandidateValidationError("SUBJECT_BYTES_EXCEEDED")
    return raw


def _validation_child(validator_path: str) -> int:
    try:
        raw = _read_stdin_bounded()
        path = Path(validator_path)
        source = path.open("rb").read(MAX_GOVERNED_BYTES + 1)
        if len(source) > MAX_GOVERNED_BYTES:
            raise CandidateValidationError("VALIDATOR_BYTES_EXCEEDED")
        namespace: dict[str, Any] = {
            "__file__": str(path),
            "__name__": "r3_11_fresh_validator",
        }
        exec(compile(source, str(path), "exec"), namespace)
        primary, subcode = namespace["validate_subject"](raw)
        receipt = {
            "isolated": bool(sys.flags.isolated),
            "no_site": bool(sys.flags.no_site),
            "pid": os.getpid(),
            "primary": primary,
            "subcode": subcode,
            "subject_sha256": hashlib.sha256(raw).hexdigest(),
            "validator_sha256": hashlib.sha256(source).hexdigest(),
        }
        sys.stdout.buffer.write(_canonical(receipt))
        sys.stdout.buffer.flush()
        return 0
    except BaseException:
        return 70


def _native_fixture_child() -> int:
    try:
        request = json.loads(_read_stdin_bounded().decode("utf-8", errors="strict"))
        if not isinstance(request, dict):
            return 71
        validation, capability = validate_candidate_fresh(
            request["subject_path"],
            runtime_root=request["runtime_root"],
            expected_launcher_sha256=request["launcher_sha256"],
            expected_interpreter_sha256=request["interpreter_sha256"],
            repo_root=request["repo_root"],
        )
        if capability is None:
            sys.stdout.buffer.write(_canonical(validation))
            return 72
        receipt = publish_windows_process_crash_only(
            capability,
            trust_anchor=request["trust_anchor"],
            protected_root=request["protected_root"],
            stage_name=request["stage_name"],
            destination_name=request["destination_name"],
            payload=base64.b64decode(request["payload_base64"], validate=True),
            _test_crash_after=request.get("crash_after"),
        )
        sys.stdout.buffer.write(_canonical(receipt))
        sys.stdout.buffer.flush()
        return 0
    except BaseException as exc:
        # This private fixture entrypoint exposes only stable classifications;
        # it never returns path text, ACL rows, payloads, or exception detail.
        failure = {
            "status": "FIXTURE_CHILD_REJECTED",
            "exception_type": type(exc).__name__,
            "code": getattr(exc, "code", "UNCLASSIFIED_FIXTURE_FAILURE"),
            "missing_module": getattr(exc, "name", None),
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
    if args == ["--native-fixture-child"]:
        return _native_fixture_child()
    return 64


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "CANDIDATE_ACTIVE",
    "CandidateValidationError",
    "GLOBAL_AUTHORITY",
    "INFORMATION_CLASS_U32",
    "MAX_GOVERNED_BYTES",
    "PROFILE",
    "REQUIRED_INPUTS",
    "ValidatedCandidateCapability",
    "WindowsPublicationError",
    "derive_pinned_predecessor_principals",
    "publish_windows_process_crash_only",
    "validate_candidate_fresh",
]
