"""Deterministic GT-blind RunBundle v2 exporter.

The CLI has four deliberately narrow operations: ``preflight``, ``export``,
``recover``, and ``verify``.  It accepts no ground-truth, private-lock,
expected-count, grader, or arbitrary-input option.  USER_RUN/B0_LOCAL exports
carry explicit unauthenticated evidence and can never self-promote to B1.
"""
from __future__ import annotations

import argparse
import copy
import ctypes
from dataclasses import dataclass
from datetime import datetime, timezone
import errno
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import stat
import sys
from typing import Any, Callable, Mapping, Sequence

try:
    import runbundle_contracts as C
    import runbundle_harvest as H
    import runbundle_phase_map as M
    import runbundle_privacy as P
    import runbundle_sources as S
except ImportError:  # pragma: no cover
    from . import runbundle_contracts as C
    from . import runbundle_harvest as H
    from . import runbundle_phase_map as M
    from . import runbundle_privacy as P
    from . import runbundle_sources as S


EXPORT_JOURNAL_SCHEMA = "plamen.real-audit-export-journal.v3"
MUTATION_RECEIPT_SCHEMA = "plamen.runbundle-export-mutation.v1"
PUBLICATION_READY_SCHEMA = "plamen.runbundle-publication-ready.v1"
PUBLICATION_CLEANUP_DEBT_SCHEMA = (
    "plamen.runbundle-promotion-cleanup-debt.v1"
)
PUBLICATION_RETIREMENT_SCHEMA = (
    "plamen.runbundle-publication-retirement.v2"
)
PUBLICATION_FAILURE_SCHEMA = "plamen.runbundle-publication-failure.v1"
PUBLIC_SCHEDULE_ROW_SCHEMA = "plamen.public-export-schedule-row.v1"
EXPORTER_PACKAGE = "plamen-runbundle-exporter"
EXPORTER_VERSION = "2.3.0"
INLINE_LIMIT = 1 << 20

INTEGRITY_ONLY = "INTEGRITY_ONLY"
AUTHENTICATED_EXPORT_ATTESTATION = "AUTHENTICATED_EXPORT_ATTESTATION"
UNSIGNED_LOCAL_INTEGRITY = "UNSIGNED_LOCAL_INTEGRITY"

_FORBIDDEN_ENV_FRAGMENTS = (
    "GROUND_TRUTH",
    "PRIVATE_CASE_LOCK",
    "EXPECTED_ISSUE",
    "EXPECTED_COUNT",
    "ANSWER_KEY",
    "GRADER_LABEL",
    "FORBIDDEN_PATH",
    "FORBIDDEN_HASH",
)
_STAGING_NAME_RE = re.compile(
    r"^\.(?P<target>.+)\.(?P<nonce>[0-9a-f]{16})\.staging$"
)
_PROMOTION_JOURNAL_NAME_RE = re.compile(
    r"^\.(?P<target>.+)\.(?P<nonce>[0-9a-f]{16})\.promotion\.json$"
)
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_MOVEFILE_WRITE_THROUGH = 0x8
_RENAME_NOREPLACE = 1
_RENAME_EXCL = 0x4


class RunBundleExportError(ValueError):
    """A RunBundle could not be exported or recovered safely."""


class RunBundleExportInterrupted(RunBundleExportError):
    """A test-only failpoint left a recoverable staging generation."""


class RunBundleMutationError(RunBundleExportError):
    """Live sources drifted; the durable receipt names the failed boundary."""

    def __init__(self, message: str, receipt_path: Path):
        super().__init__(message)
        self.receipt_path = Path(receipt_path)


class RunBundleRecoveryRequiredError(RunBundleExportError):
    """An unresolved local publication transaction requires recovery."""


class RunBundleCleanupDebtError(RunBundleExportError):
    """READY is integrity-valid, but promotion cleanup is incomplete."""

    def __init__(
        self,
        message: str,
        *,
        target: Path,
        journal: Path,
        debt_receipt: Path | None,
    ):
        super().__init__(message)
        self.target = Path(target)
        self.journal = Path(journal)
        self.debt_receipt = (
            None if debt_receipt is None else Path(debt_receipt)
        )


class RunBundleAuthorityError(RunBundleExportError):
    """The requested assurance exceeds the available local integrity claim."""


@dataclass(frozen=True, slots=True)
class ExportReceipt:
    bundle_root: Path
    run_id: str
    trust_profile: str
    bundle_seal_sha256: str
    public_case_lock_sha256: str
    publication_ceiling: str
    verification_sha256: str
    publication_ready_path: Path
    publication_ready_sha256: str
    source_stability_asserted_at_utc: str
    source_stability_snapshot_sha256: str | None
    source_stability_sha256: str
    bundle_integrity: str
    ready_schema: str
    ready_assurance: str
    source_observation_claim: str
    cleanup_state: str


def exporter_policy_preimage() -> dict[str, Any]:
    return {
        "schema_version": "plamen.runbundle-exporter-policy.v2",
        "package": EXPORTER_PACKAGE,
        "version": EXPORTER_VERSION,
        "commands": ["export", "preflight", "recover", "verify"],
        "accepted_trust_profiles": ["B0_LOCAL", "USER_RUN"],
        "forbidden_environment_fragments": list(_FORBIDDEN_ENV_FRAGMENTS),
        "overwrite": False,
        "ground_truth_input": False,
        "private_case_lock_input": False,
        "grader_input": False,
        "b1_self_promotion": False,
        "live_source_closure": {
            "authority": (
                "EXACT_ROSTER_BYTES_AND_PHYSICAL_IDENTITY"
            ),
            "checks": [
                "PRE_SEAL",
                "PRE_PUBLICATION",
                "POST_PROMOTION",
                "POST_VERIFY_PRE_READY",
            ],
            "mutation_outcome": "MUTATED_DURING_EXPORT",
            "accepted_bundle_on_mutation": False,
            "recovery_replays_authority": True,
            "claim_scope": (
                "BOUNDED_POINT_OBSERVATIONS_NOT_CONTINUOUS_OR_PERPETUAL"
            ),
        },
        "publication_ready": {
            "schema": PUBLICATION_READY_SCHEMA,
            "assurance": UNSIGNED_LOCAL_INTEGRITY,
            "authority": False,
            "claim": "SELF_ASSERTED_NOT_AUTHENTICATED",
            "same_user_tamper_resistance": False,
        },
        "authenticated_export_attestation_available": False,
        "promotion_cleanup_debt": "TYPED_FAIL_LOUD",
        "promoted_failure_retirement": True,
        "retirement_retry": "LOAD_OR_CREATE_EXACT_RECEIPT",
        "local_materialization_policy_sha256": (
            H.local_materialization_policy_sha256()
        ),
    }


def exporter_policy_sha256() -> str:
    return C.document_sha256(exporter_policy_preimage())


def exporter_code_sha256() -> str:
    files = (
        Path(__file__).resolve(),
        Path(C.__file__).resolve(),
        Path(H.__file__).resolve(),
        Path(M.__file__).resolve(),
        Path(P.__file__).resolve(),
        Path(S.__file__).resolve(),
    )
    rows = []
    for path in files:
        raw = P.read_stable_regular_bytes(
            path, maximum_bytes=64 << 20, label="exporter source module"
        )
        rows.append({"name": path.name, "sha256": C.sha256_bytes(raw)})
    return C.document_sha256({"files": sorted(rows, key=lambda row: row["name"])})


def schema_set_sha256() -> str:
    return C.document_sha256(
        {
            "schemas": sorted(C.PUBLIC_SCHEMA_VERSIONS),
            "phase_maps": [
                M.phase_map_preimage(kind)
                for kind in sorted(M.PIPELINE_KINDS)
            ],
            "source_registry_sha256": S.source_registry_sha256(),
        }
    )


def assert_export_environment_gt_blind(
    environment: Mapping[str, str] | None = None,
) -> None:
    source = os.environ if environment is None else environment
    matches = sorted(
        key
        for key in source
        if any(fragment in key.upper() for fragment in _FORBIDDEN_ENV_FRAGMENTS)
    )
    if matches:
        raise RunBundleExportError(
            "forbidden private/post-run environment input is present: "
            + ", ".join(matches)
        )


def _write_new(path: Path, raw: bytes) -> None:
    if path.exists():
        raise RunBundleExportError(f"fresh output required; path exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    try:
        descriptor = os.open(path, flags, 0o600)
        try:
            view = memoryview(raw)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("short write")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise RunBundleExportError(f"cannot create {path.name}") from exc
    _fsync_directory(path.parent)


def _write_or_load_exact_control(
    path: Path,
    raw: bytes,
    *,
    label: str,
) -> Path:
    """Create once, or accept only the exact existing canonical bytes."""

    if path.exists():
        try:
            existing = P.read_stable_regular_bytes(
                path,
                maximum_bytes=1 << 20,
                label=label,
            )
        except P.RunBundlePrivacyError as exc:
            raise RunBundleExportError(
                f"existing {label} is unsafe"
            ) from exc
        if existing != raw:
            raise RunBundleExportError(f"{label} digest collision")
        return path
    temporary = path.parent / (
        f".{path.name}.{secrets.token_hex(8)}.tmp"
    )
    _write_new(temporary, raw)
    try:
        try:
            os.link(
                _native_fs_path(temporary),
                _native_fs_path(path),
                follow_symlinks=False,
            )
            _fsync_directory(path.parent)
        except FileExistsError:
            existing = P.read_stable_regular_bytes(
                path,
                maximum_bytes=1 << 20,
                label=label,
            )
            if existing != raw:
                raise RunBundleExportError(f"{label} digest collision")
        except OSError as exc:
            raise RunBundleExportError(
                f"cannot atomically publish {label}"
            ) from exc
    finally:
        try:
            temporary.unlink(missing_ok=True)
            _fsync_directory(path.parent)
        except (OSError, RunBundleExportError) as exc:
            raise RunBundleExportError(
                f"cannot finalize atomic {label}"
            ) from exc
    try:
        published = P.read_stable_regular_bytes(
            path,
            maximum_bytes=1 << 20,
            label=label,
        )
    except P.RunBundlePrivacyError as exc:
        raise RunBundleExportError(
            f"published {label} is unsafe"
        ) from exc
    if published != raw:
        raise RunBundleExportError(f"published {label} drifted")
    return path


def _fsync_directory(path: Path) -> None:
    """Persist one POSIX directory update; Windows file moves use WRITE_THROUGH."""

    if os.name == "nt":
        return
    flags = os.O_RDONLY | int(getattr(os, "O_DIRECTORY", 0))
    try:
        descriptor = os.open(path, flags)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise RunBundleExportError(
            f"cannot persist directory update for {Path(path).name}"
        ) from exc


def _native_fs_path(path: Path) -> str:
    value = str(Path(os.path.abspath(os.fspath(path))))
    if os.name != "nt":
        return value
    if value.startswith("\\\\"):
        return "\\\\?\\UNC\\" + value[2:]
    return "\\\\?\\" + value


def _durable_directory_rename_new(source: Path, target: Path) -> None:
    """Atomically publish one same-parent directory without replacement."""

    source = Path(os.path.abspath(os.fspath(source)))
    target = Path(os.path.abspath(os.fspath(target)))
    if source.parent != target.parent:
        raise RunBundleExportError(
            "directory publication requires one physical parent"
    )
    try:
        source_row = os.stat(_native_fs_path(source), follow_symlinks=False)
    except OSError as exc:
        raise RunBundleExportError(
            "directory publication source is unavailable"
        ) from exc
    if not stat.S_ISDIR(source_row.st_mode) or stat.S_ISLNK(source_row.st_mode):
        raise RunBundleExportError(
            "directory publication source is not a plain directory"
        )
    if (
        int(getattr(source_row, "st_file_attributes", 0) or 0)
        & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    ):
        raise RunBundleExportError(
            "directory publication source is a reparse point"
        )
    if os.path.lexists(_native_fs_path(target)):
        raise RunBundleExportError(
            "directory publication target already exists"
        )

    if os.name == "nt":
        from ctypes import wintypes

        move = ctypes.WinDLL("kernel32", use_last_error=True).MoveFileExW
        move.argtypes = (
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            wintypes.DWORD,
        )
        move.restype = wintypes.BOOL
        if not move(
            _native_fs_path(source),
            _native_fs_path(target),
            _MOVEFILE_WRITE_THROUGH,
        ):
            error = ctypes.get_last_error()
            if error in {80, 183}:
                raise RunBundleExportError(
                    "directory publication target already exists"
                )
            raise RunBundleExportError(
                f"durable directory publication failed ({error})"
            )
    elif sys.platform.startswith("linux"):
        library = ctypes.CDLL(None, use_errno=True)
        renameat2 = getattr(library, "renameat2", None)
        if renameat2 is None:
            raise RunBundleExportError(
                "atomic no-replace directory publication is unavailable"
            )
        renameat2.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        renameat2.restype = ctypes.c_int
        result = renameat2(
            -100,
            os.fsencode(source),
            -100,
            os.fsencode(target),
            _RENAME_NOREPLACE,
        )
        if result != 0:
            error = ctypes.get_errno()
            if error == errno.EEXIST:
                raise RunBundleExportError(
                    "directory publication target already exists"
                )
            raise RunBundleExportError(
                f"durable directory publication failed ({error})"
            )
        _fsync_directory(target.parent)
    elif sys.platform == "darwin":
        library = ctypes.CDLL(None, use_errno=True)
        renamex = getattr(library, "renamex_np", None)
        if renamex is None:
            raise RunBundleExportError(
                "atomic no-replace directory publication is unavailable"
            )
        renamex.argtypes = (
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        renamex.restype = ctypes.c_int
        result = renamex(
            os.fsencode(source),
            os.fsencode(target),
            _RENAME_EXCL,
        )
        if result != 0:
            error = ctypes.get_errno()
            if error == errno.EEXIST:
                raise RunBundleExportError(
                    "directory publication target already exists"
                )
            raise RunBundleExportError(
                f"durable directory publication failed ({error})"
            )
        _fsync_directory(target.parent)
    else:
        raise RunBundleExportError(
            "atomic no-replace directory publication is unsupported"
        )

    if os.path.lexists(_native_fs_path(source)) or not os.path.isdir(
        _native_fs_path(target)
    ):
        raise RunBundleExportError(
            "durable directory publication postcondition failed"
        )


def _safe_remove_tree(path: Path, *, parent: Path) -> None:
    target = Path(path).resolve()
    boundary = Path(parent).resolve()
    if target.parent != boundary or not target.name.endswith(".staging"):
        raise RunBundleExportError("refused unsafe staging cleanup")
    if target.exists():
        shutil.rmtree(target)


def _journal_body(
    *,
    stage: str,
    staging: Path,
    out: Path,
    documents_sha256: str,
    objects_sha256: str,
    public_case_lock_sha256: str,
    live_source_authority_sha256: str | None,
    exporter_code_digest: str,
    exporter_policy_digest: str,
    run_id: str,
) -> dict[str, Any]:
    return {
        "schema_version": EXPORT_JOURNAL_SCHEMA,
        "stage": stage,
        "staging_path": str(staging.resolve()),
        "output_path": str(out.resolve()),
        "documents_sha256": documents_sha256,
        "objects_sha256": objects_sha256,
        "public_case_lock_sha256": public_case_lock_sha256,
        "live_source_authority_sha256": (
            live_source_authority_sha256
        ),
        "exporter_code_sha256": exporter_code_digest,
        "exporter_policy_sha256": exporter_policy_digest,
        "run_id": run_id,
    }


def _write_journal_path(path: Path, body: Mapping[str, Any]) -> Path:
    if path.exists():
        path.unlink()
    value = C.bind_embedded_sha256(dict(body), "journal_sha256")
    _write_new(path, C.canonical_document_bytes(value))
    return path


def _write_journal(staging: Path, body: Mapping[str, Any]) -> Path:
    return _write_journal_path(staging / "export.journal.json", body)


def _promotion_journal_path(staging: Path, target: Path) -> Path:
    match = _STAGING_NAME_RE.fullmatch(Path(staging).name)
    if (
        match is None
        or match.group("target") != Path(target).name
        or Path(staging).parent != Path(target).parent
    ):
        raise RunBundleExportError(
            "promotion journal staging topology is invalid"
        )
    return Path(target).parent / (
        f".{Path(target).name}.{match.group('nonce')}.promotion.json"
    )


def _write_promotion_journal(
    staging: Path,
    target: Path,
    body: Mapping[str, Any],
) -> Path:
    return _write_journal_path(
        _promotion_journal_path(staging, target),
        body,
    )


def _load_journal(path: Path) -> dict[str, Any]:
    try:
        value = C.strict_json_load(path, require_canonical=True)
    except (C.RunBundleContractError, P.RunBundlePrivacyError) as exc:
        raise RunBundleExportError("export journal is invalid") from exc
    expected = {
        "schema_version",
        "stage",
        "staging_path",
        "output_path",
        "documents_sha256",
        "objects_sha256",
        "public_case_lock_sha256",
        "live_source_authority_sha256",
        "exporter_code_sha256",
        "exporter_policy_sha256",
        "run_id",
        "journal_sha256",
    }
    if type(value) is not dict or set(value) != expected:
        raise RunBundleExportError("export journal is not closed")
    if value["schema_version"] != EXPORT_JOURNAL_SCHEMA:
        raise RunBundleExportError("unknown export journal schema")
    if value["stage"] not in {
        "PAYLOAD",
        "OBJECTS",
        "INDEX",
        "PROMOTION",
    }:
        raise RunBundleExportError("export journal stage is invalid")
    live_authority = value["live_source_authority_sha256"]
    if live_authority is not None and (
        not isinstance(live_authority, str)
        or _DIGEST_RE.fullmatch(live_authority) is None
    ):
        raise RunBundleExportError(
            "export journal live source authority is invalid"
        )
    try:
        C.verify_embedded_sha256(value, "journal_sha256")
    except C.RunBundleContractError as exc:
        raise RunBundleExportError("export journal digest is invalid") from exc
    return value


def _validate_live_source_authority_pair(
    *,
    expected_sha256: str | None,
    closure: Callable[[], str] | None,
) -> None:
    if (expected_sha256 is None) != (closure is None):
        raise RunBundleExportError(
            "live source authority digest and closure are required together"
        )
    if expected_sha256 is not None and (
        not isinstance(expected_sha256, str)
        or _DIGEST_RE.fullmatch(expected_sha256) is None
    ):
        raise RunBundleExportError("live source authority digest is invalid")


def _write_mutation_receipt(
    *,
    parent: Path,
    target_name: str,
    run_id: str,
    input_source_authority_sha256: str,
    exporter_code_digest: str,
    exporter_policy_digest: str,
    stage: str,
) -> Path:
    body = {
        "schema_version": MUTATION_RECEIPT_SCHEMA,
        "outcome": "MUTATED_DURING_EXPORT",
        "stage": stage,
        "run_id": run_id,
        "output_name": target_name,
        "input_source_authority_sha256": (
            input_source_authority_sha256
        ),
        "exporter_code_sha256": exporter_code_digest,
        "exporter_policy_sha256": exporter_policy_digest,
    }
    value = C.bind_embedded_sha256(body, "receipt_sha256")
    raw = C.canonical_document_bytes(value)
    receipt = parent / (
        f".{target_name}.mutation-{value['receipt_sha256'][:16]}.json"
    )
    if receipt.exists():
        try:
            existing = P.read_stable_regular_bytes(
                receipt,
                maximum_bytes=1 << 20,
                label="export mutation receipt",
            )
        except P.RunBundlePrivacyError as exc:
            raise RunBundleExportError(
                "existing mutation receipt is unsafe"
            ) from exc
        if existing != raw:
            raise RunBundleExportError(
                "mutation receipt digest collision"
            )
        return receipt
    return _write_or_load_exact_control(
        receipt,
        raw,
        label="export mutation receipt",
    )


def _check_live_source_closure(
    *,
    expected_sha256: str | None,
    closure: Callable[[], str] | None,
    parent: Path,
    target_name: str,
    run_id: str,
    exporter_code_digest: str,
    exporter_policy_digest: str,
    stage: str,
) -> str | None:
    _validate_live_source_authority_pair(
        expected_sha256=expected_sha256,
        closure=closure,
    )
    if expected_sha256 is None or closure is None:
        return None
    try:
        observed_sha256 = closure()
    except (
        S.RunBundleSourceError,
        P.RunBundlePrivacyError,
        OSError,
    ) as exc:
        receipt = _write_mutation_receipt(
            parent=parent,
            target_name=target_name,
            run_id=run_id,
            input_source_authority_sha256=expected_sha256,
            exporter_code_digest=exporter_code_digest,
            exporter_policy_digest=exporter_policy_digest,
            stage=stage,
        )
        raise RunBundleMutationError(
            "MUTATED_DURING_EXPORT: live source closure changed",
            receipt,
        ) from exc
    if observed_sha256 != expected_sha256:
        receipt = _write_mutation_receipt(
            parent=parent,
            target_name=target_name,
            run_id=run_id,
            input_source_authority_sha256=expected_sha256,
            exporter_code_digest=exporter_code_digest,
            exporter_policy_digest=exporter_policy_digest,
            stage=stage,
        )
        raise RunBundleMutationError(
            "MUTATED_DURING_EXPORT: live source authority mismatched",
            receipt,
        )
    return observed_sha256


_UTC_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$"
)


def _utc_now_text() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _observe_live_source_closure(
    *,
    expected_sha256: str | None,
    closure: Callable[[], str] | None,
    parent: Path,
    target_name: str,
    run_id: str,
    exporter_code_digest: str,
    exporter_policy_digest: str,
    stage: str,
    observation_stage: str | None = None,
) -> dict[str, Any]:
    started_at_utc = _utc_now_text()
    observed = _check_live_source_closure(
        expected_sha256=expected_sha256,
        closure=closure,
        parent=parent,
        target_name=target_name,
        run_id=run_id,
        exporter_code_digest=exporter_code_digest,
        exporter_policy_digest=exporter_policy_digest,
        stage=stage,
    )
    body = {
        "schema_version": (
            "plamen.runbundle-source-stability-observation.v1"
        ),
        "stage": observation_stage or stage,
        "state": (
            "LIVE_SOURCE_MATCHED_AT_OBSERVATION"
            if expected_sha256 is not None
            else "NO_LIVE_SOURCE_AUTHORITY"
        ),
        "source_authority_sha256": observed,
        "started_at_utc": started_at_utc,
        "completed_at_utc": _utc_now_text(),
        "claim_limitation": (
            "BOUNDED_POINT_OBSERVATION_NOT_CONTINUOUS_OR_PERPETUAL"
        ),
    }
    return C.bind_embedded_sha256(body, "observation_sha256")


def _validate_utc_text(value: Any) -> str:
    if not isinstance(value, str) or _UTC_RE.fullmatch(value) is None:
        raise RunBundleExportError("publication timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise RunBundleExportError("publication timestamp is invalid") from exc
    if parsed.tzinfo != timezone.utc:
        raise RunBundleExportError("publication timestamp is not UTC")
    return value


def publication_ready_path(bundle: Path) -> Path:
    target = Path(bundle).resolve()
    return target.parent / f".{target.name}.READY.json"


def publication_retirement_path(bundle: Path) -> Path:
    target = Path(bundle).resolve()
    return target.parent / f".{target.name}.RETIRED.json"


def publication_cleanup_debt_path(bundle: Path) -> Path:
    target = Path(bundle).resolve()
    return target.parent / f".{target.name}.CLEANUP_DEBT.json"


def validate_publication_ready(value: Any) -> dict[str, Any]:
    fields = {
        "schema_version",
        "status",
        "run_id",
        "output_name",
        "bundle_seal_sha256",
        "verification_sha256",
        "public_case_lock_sha256",
        "source_stability",
        "source_stability_sha256",
        "exporter_code_sha256",
        "exporter_policy_sha256",
        "ready_sha256",
    }
    if type(value) is not dict or set(value) != fields:
        raise RunBundleExportError("publication READY receipt is not closed")
    row = C.strict_json_loads(
        C.canonical_document_bytes(value), require_canonical=True
    )
    if (
        row["schema_version"] != PUBLICATION_READY_SCHEMA
        or row["status"] != "READY"
    ):
        raise RunBundleExportError("publication READY receipt is invalid")
    if (
        not isinstance(row["run_id"], str)
        or not row["run_id"]
        or any(char.isspace() for char in row["run_id"])
    ):
        raise RunBundleExportError("publication READY run ID is invalid")
    try:
        output_name = P.assert_safe_relative_path(
            row["output_name"], label="publication output name"
        )
    except P.RunBundlePrivacyError as exc:
        raise RunBundleExportError(str(exc)) from exc
    if "/" in output_name:
        raise RunBundleExportError("publication output name is not a basename")
    for field in (
        "bundle_seal_sha256",
        "verification_sha256",
        "public_case_lock_sha256",
        "source_stability_sha256",
        "exporter_code_sha256",
        "exporter_policy_sha256",
        "ready_sha256",
    ):
        if (
            not isinstance(row[field], str)
            or _DIGEST_RE.fullmatch(row[field]) is None
        ):
            raise RunBundleExportError(
                f"publication READY {field} is invalid"
            )
    stability = row["source_stability"]
    if type(stability) is not dict or set(stability) != {
        "state",
        "source_authority_sha256",
        "observations",
        "observation_set_sha256",
        "claim_limitation",
    }:
        raise RunBundleExportError(
            "publication source-stability assertion is not closed"
        )
    if stability["state"] not in {
        "LIVE_SOURCE_MATCHED_AT_BOUNDED_CHECKS",
        "NO_LIVE_SOURCE_AUTHORITY",
    }:
        raise RunBundleExportError(
            "publication source-stability state is invalid"
        )
    authority = stability["source_authority_sha256"]
    if stability["state"] == "LIVE_SOURCE_MATCHED_AT_BOUNDED_CHECKS":
        if (
            not isinstance(authority, str)
            or _DIGEST_RE.fullmatch(authority) is None
        ):
            raise RunBundleExportError(
                "publication source authority is invalid"
            )
    elif authority is not None:
        raise RunBundleExportError(
            "materialized publication cannot claim a source authority"
        )
    observations = stability["observations"]
    if type(observations) is not list or len(observations) != 2:
        raise RunBundleExportError(
            "publication source-stability observation roster is invalid"
        )
    expected_stages = [
        "POST_PROMOTION",
        "POST_VERIFY_PRE_READY",
    ]
    validated_observations: list[dict[str, Any]] = []
    for index, observation in enumerate(observations):
        expected_observation_fields = {
            "schema_version",
            "stage",
            "state",
            "source_authority_sha256",
            "started_at_utc",
            "completed_at_utc",
            "claim_limitation",
            "observation_sha256",
        }
        if (
            type(observation) is not dict
            or set(observation) != expected_observation_fields
            or observation["schema_version"]
            != "plamen.runbundle-source-stability-observation.v1"
            or observation["stage"] != expected_stages[index]
        ):
            raise RunBundleExportError(
                "publication source-stability observation is invalid"
            )
        expected_state = (
            "LIVE_SOURCE_MATCHED_AT_OBSERVATION"
            if authority is not None
            else "NO_LIVE_SOURCE_AUTHORITY"
        )
        if (
            observation["state"] != expected_state
            or observation["source_authority_sha256"] != authority
            or observation["claim_limitation"]
            != "BOUNDED_POINT_OBSERVATION_NOT_CONTINUOUS_OR_PERPETUAL"
        ):
            raise RunBundleExportError(
                "publication source-stability observation authority is invalid"
            )
        started = _validate_utc_text(observation["started_at_utc"])
        completed = _validate_utc_text(observation["completed_at_utc"])
        if started > completed:
            raise RunBundleExportError(
                "publication source-stability observation time is inverted"
            )
        try:
            C.verify_embedded_sha256(observation, "observation_sha256")
        except C.RunBundleContractError as exc:
            raise RunBundleExportError(
                "publication source-stability observation digest mismatched"
            ) from exc
        validated_observations.append(observation)
    if (
        validated_observations[0]["completed_at_utc"]
        > validated_observations[1]["started_at_utc"]
        or stability["observation_set_sha256"]
        != C.document_sha256({"observations": observations})
        or stability["claim_limitation"]
        != "BOUNDED_OBSERVATIONS_NOT_CONTINUOUS_OR_PERPETUAL_IMMUTABILITY"
    ):
        raise RunBundleExportError(
            "publication source-stability claim scope is invalid"
        )
    if C.document_sha256(stability) != row["source_stability_sha256"]:
        raise RunBundleExportError(
            "publication source-stability digest mismatched"
        )
    try:
        C.verify_embedded_sha256(row, "ready_sha256")
        P.validate_public_payload(row)
    except (C.RunBundleContractError, P.RunBundlePrivacyError) as exc:
        raise RunBundleExportError(
            "publication READY receipt failed validation"
        ) from exc
    return row


def _publish_publication_ready(
    *,
    target: Path,
    verified: C.RunBundleVerificationReceipt,
    source_authority_sha256: str | None,
    preverify_observation: Mapping[str, Any],
    live_source_closure: Callable[[], str] | None,
    exporter_code_digest: str,
    exporter_policy_digest: str,
    final_mutation_stage: str = "POST_VERIFY_PRE_READY",
) -> tuple[Path, dict[str, Any]]:
    final_observation = _observe_live_source_closure(
        expected_sha256=source_authority_sha256,
        closure=live_source_closure,
        parent=target.parent,
        target_name=target.name,
        run_id=verified.run_id,
        exporter_code_digest=exporter_code_digest,
        exporter_policy_digest=exporter_policy_digest,
        stage=final_mutation_stage,
        observation_stage="POST_VERIFY_PRE_READY",
    )
    observations = [
        dict(preverify_observation),
        final_observation,
    ]
    stability = {
        "state": (
            "LIVE_SOURCE_MATCHED_AT_BOUNDED_CHECKS"
            if source_authority_sha256 is not None
            else "NO_LIVE_SOURCE_AUTHORITY"
        ),
        "source_authority_sha256": source_authority_sha256,
        "observations": observations,
        "observation_set_sha256": C.document_sha256(
            {"observations": observations}
        ),
        "claim_limitation": (
            "BOUNDED_OBSERVATIONS_NOT_CONTINUOUS_OR_PERPETUAL_IMMUTABILITY"
        ),
    }
    body = {
        "schema_version": PUBLICATION_READY_SCHEMA,
        "status": "READY",
        "run_id": verified.run_id,
        "output_name": target.name,
        "bundle_seal_sha256": verified.bundle_seal_sha256,
        "verification_sha256": verified.verification_sha256,
        "public_case_lock_sha256": verified.public_case_lock_sha256,
        "source_stability": stability,
        "source_stability_sha256": C.document_sha256(stability),
        "exporter_code_sha256": exporter_code_digest,
        "exporter_policy_sha256": exporter_policy_digest,
    }
    value = validate_publication_ready(
        C.bind_embedded_sha256(body, "ready_sha256")
    )
    path = publication_ready_path(target)
    return (
        _write_or_load_exact_control(
            path,
            C.canonical_document_bytes(value),
            label="publication READY receipt",
        ),
        value,
    )


def _load_publication_ready(
    target: Path,
    verified: C.RunBundleVerificationReceipt,
) -> tuple[Path, dict[str, Any], bytes]:
    path = publication_ready_path(target)
    try:
        raw = P.read_stable_regular_bytes(
            path,
            maximum_bytes=1 << 20,
            label="publication READY receipt",
        )
        value = validate_publication_ready(
            C.strict_json_loads(raw, require_canonical=True)
        )
    except (P.RunBundlePrivacyError, C.RunBundleContractError) as exc:
        raise RunBundleExportError(
            "publication READY receipt is absent or invalid"
        ) from exc
    if (
        value["output_name"] != target.name
        or value["run_id"] != verified.run_id
        or value["bundle_seal_sha256"] != verified.bundle_seal_sha256
        or value["verification_sha256"] != verified.verification_sha256
        or value["public_case_lock_sha256"]
        != verified.public_case_lock_sha256
    ):
        raise RunBundleExportError(
            "publication READY receipt does not bind the bundle"
        )
    return path, value, raw


def _load_promotion_journal_for_target(
    *,
    path: Path,
    target: Path,
    verified: C.RunBundleVerificationReceipt,
    ready: Mapping[str, Any],
) -> tuple[dict[str, Any], bytes]:
    try:
        raw = P.read_stable_regular_bytes(
            path,
            maximum_bytes=1 << 20,
            label="promotion journal",
        )
    except P.RunBundlePrivacyError as exc:
        raise RunBundleExportError("promotion journal is unsafe") from exc
    row = _load_journal(path)
    if raw != C.canonical_document_bytes(row):
        raise RunBundleExportError(
            "promotion journal changed during validation"
        )
    if (
        row["stage"] != "PROMOTION"
        or not _same_path(Path(row["output_path"]), target)
        or row["run_id"] != verified.run_id
        or row["public_case_lock_sha256"]
        != verified.public_case_lock_sha256
        or row["exporter_code_sha256"]
        != ready["exporter_code_sha256"]
        or row["exporter_policy_sha256"]
        != ready["exporter_policy_sha256"]
    ):
        raise RunBundleExportError(
            "promotion journal does not bind the local READY generation"
        )
    return row, raw


def _matching_promotion_journals(target: Path) -> list[Path]:
    try:
        names = sorted(entry.name for entry in os.scandir(target.parent))
    except OSError as exc:
        raise RunBundleExportError(
            "output parent could not be enumerated"
        ) from exc
    return [
        target.parent / name
        for name in names
        if (
            (match := _PROMOTION_JOURNAL_NAME_RE.fullmatch(name)) is not None
            and match.group("target") == target.name
        )
    ]


def validate_publication_cleanup_debt(value: Any) -> dict[str, Any]:
    fields = {
        "schema_version",
        "status",
        "debt_type",
        "failure_class",
        "run_id",
        "output_name",
        "bundle_seal_sha256",
        "ready_name",
        "ready_sha256",
        "promotion_journal_name",
        "promotion_journal_sha256",
        "exporter_code_sha256",
        "exporter_policy_sha256",
        "debt_sha256",
    }
    if type(value) is not dict or set(value) != fields:
        raise RunBundleExportError(
            "publication cleanup-debt receipt is not closed"
        )
    row = C.strict_json_loads(
        C.canonical_document_bytes(value), require_canonical=True
    )
    if (
        row["schema_version"] != PUBLICATION_CLEANUP_DEBT_SCHEMA
        or row["status"] != "CLEANUP_DEBT"
        or row["debt_type"] != "PROMOTION_JOURNAL_CLEANUP"
        or row["failure_class"]
        not in {"OSError", "RunBundleExportError"}
    ):
        raise RunBundleExportError(
            "publication cleanup-debt receipt is invalid"
        )
    try:
        output_name = P.assert_safe_relative_path(
            row["output_name"], label="cleanup-debt output name"
        )
        ready_name = P.assert_safe_relative_path(
            row["ready_name"], label="cleanup-debt READY name"
        )
        journal_name = P.assert_safe_relative_path(
            row["promotion_journal_name"],
            label="cleanup-debt promotion-journal name",
        )
    except P.RunBundlePrivacyError as exc:
        raise RunBundleExportError(str(exc)) from exc
    if (
        "/" in output_name
        or "/" in ready_name
        or "/" in journal_name
        or _PROMOTION_JOURNAL_NAME_RE.fullmatch(journal_name) is None
    ):
        raise RunBundleExportError(
            "publication cleanup-debt basename is invalid"
        )
    if (
        not isinstance(row["run_id"], str)
        or not row["run_id"]
        or any(char.isspace() for char in row["run_id"])
    ):
        raise RunBundleExportError(
            "publication cleanup-debt run ID is invalid"
        )
    for field in (
        "bundle_seal_sha256",
        "ready_sha256",
        "promotion_journal_sha256",
        "exporter_code_sha256",
        "exporter_policy_sha256",
        "debt_sha256",
    ):
        if (
            not isinstance(row[field], str)
            or _DIGEST_RE.fullmatch(row[field]) is None
        ):
            raise RunBundleExportError(
                f"publication cleanup-debt {field} is invalid"
            )
    try:
        C.verify_embedded_sha256(row, "debt_sha256")
        P.validate_public_payload(row)
    except (C.RunBundleContractError, P.RunBundlePrivacyError) as exc:
        raise RunBundleExportError(
            "publication cleanup-debt receipt failed validation"
        ) from exc
    return row


def _load_publication_cleanup_debt(
    *,
    target: Path,
    verified: C.RunBundleVerificationReceipt,
    ready_path: Path,
    ready: Mapping[str, Any],
    ready_raw: bytes,
    journal_path: Path | None,
    journal_raw: bytes | None,
) -> tuple[Path, dict[str, Any], bytes] | None:
    path = publication_cleanup_debt_path(target)
    if not path.exists():
        return None
    try:
        raw = P.read_stable_regular_bytes(
            path,
            maximum_bytes=1 << 20,
            label="publication cleanup-debt receipt",
        )
        value = validate_publication_cleanup_debt(
            C.strict_json_loads(raw, require_canonical=True)
        )
    except (P.RunBundlePrivacyError, C.RunBundleContractError) as exc:
        raise RunBundleExportError(
            "publication cleanup-debt receipt is unsafe"
        ) from exc
    if (
        value["output_name"] != target.name
        or value["run_id"] != verified.run_id
        or value["bundle_seal_sha256"] != verified.bundle_seal_sha256
        or value["ready_name"] != ready_path.name
        or value["ready_sha256"] != C.sha256_bytes(ready_raw)
        or value["exporter_code_sha256"]
        != ready["exporter_code_sha256"]
        or value["exporter_policy_sha256"]
        != ready["exporter_policy_sha256"]
    ):
        raise RunBundleExportError(
            "publication cleanup-debt receipt does not bind READY"
        )
    match = _PROMOTION_JOURNAL_NAME_RE.fullmatch(
        value["promotion_journal_name"]
    )
    if match is None or match.group("target") != target.name:
        raise RunBundleExportError(
            "publication cleanup-debt journal binding is invalid"
        )
    if journal_path is not None and (
        value["promotion_journal_name"] != journal_path.name
        or journal_raw is None
        or value["promotion_journal_sha256"] != C.sha256_bytes(journal_raw)
    ):
        raise RunBundleExportError(
            "publication cleanup-debt receipt does not bind the journal"
        )
    return path, value, raw


def _write_publication_cleanup_debt(
    *,
    target: Path,
    verified: C.RunBundleVerificationReceipt,
    ready_path: Path,
    ready: Mapping[str, Any],
    ready_raw: bytes,
    journal_path: Path,
    journal_raw: bytes,
    failure: BaseException,
) -> Path:
    failure_class = (
        "RunBundleExportError"
        if isinstance(failure, RunBundleExportError)
        else "OSError"
    )
    body = {
        "schema_version": PUBLICATION_CLEANUP_DEBT_SCHEMA,
        "status": "CLEANUP_DEBT",
        "debt_type": "PROMOTION_JOURNAL_CLEANUP",
        "failure_class": failure_class,
        "run_id": verified.run_id,
        "output_name": target.name,
        "bundle_seal_sha256": verified.bundle_seal_sha256,
        "ready_name": ready_path.name,
        "ready_sha256": C.sha256_bytes(ready_raw),
        "promotion_journal_name": journal_path.name,
        "promotion_journal_sha256": C.sha256_bytes(journal_raw),
        "exporter_code_sha256": ready["exporter_code_sha256"],
        "exporter_policy_sha256": ready["exporter_policy_sha256"],
    }
    value = validate_publication_cleanup_debt(
        C.bind_embedded_sha256(body, "debt_sha256")
    )
    path = publication_cleanup_debt_path(target)
    return _write_or_load_exact_control(
        path,
        C.canonical_document_bytes(value),
        label="publication cleanup-debt receipt",
    )


def _complete_promotion_cleanup(
    *,
    target: Path,
    journal: Path,
    verified: C.RunBundleVerificationReceipt,
    ready_path: Path,
    ready: Mapping[str, Any],
    ready_raw: bytes,
) -> None:
    journal_path = Path(journal)
    if not journal_path.exists():
        existing_debt = _load_publication_cleanup_debt(
            target=target,
            verified=verified,
            ready_path=ready_path,
            ready=ready,
            ready_raw=ready_raw,
            journal_path=None,
            journal_raw=None,
        )
        if existing_debt is None:
            _fsync_directory(target.parent)
            return
        debt_path, _debt, _debt_raw = existing_debt
        try:
            debt_path.unlink()
            _fsync_directory(target.parent)
        except (OSError, RunBundleExportError) as exc:
            raise RunBundleCleanupDebtError(
                "promotion cleanup debt remains after READY",
                target=target,
                journal=journal_path,
                debt_receipt=debt_path,
            ) from exc
        return

    _journal, journal_raw = _load_promotion_journal_for_target(
        path=journal_path,
        target=target,
        verified=verified,
        ready=ready,
    )
    existing_debt = _load_publication_cleanup_debt(
        target=target,
        verified=verified,
        ready_path=ready_path,
        ready=ready,
        ready_raw=ready_raw,
        journal_path=journal_path,
        journal_raw=journal_raw,
    )
    try:
        journal_path.unlink()
        _fsync_directory(target.parent)
    except (OSError, RunBundleExportError) as exc:
        debt_path: Path | None = None
        try:
            debt_path = _write_publication_cleanup_debt(
                target=target,
                verified=verified,
                ready_path=ready_path,
                ready=ready,
                ready_raw=ready_raw,
                journal_path=journal_path,
                journal_raw=journal_raw,
                failure=exc,
            )
        except RunBundleExportError:
            debt_path = None
        raise RunBundleCleanupDebtError(
            "promotion cleanup debt remains after READY",
            target=target,
            journal=journal_path,
            debt_receipt=debt_path,
        ) from exc
    if existing_debt is not None:
        debt_path, _debt, _debt_raw = existing_debt
        try:
            debt_path.unlink()
            _fsync_directory(target.parent)
        except (OSError, RunBundleExportError) as exc:
            raise RunBundleCleanupDebtError(
                "promotion cleanup debt receipt could not be cleared",
                target=target,
                journal=journal_path,
                debt_receipt=debt_path,
            ) from exc


def _write_publication_failure_receipt(
    *,
    target: Path,
    run_id: str,
    stage: str,
    exporter_code_digest: str,
    exporter_policy_digest: str,
) -> Path:
    body = {
        "schema_version": PUBLICATION_FAILURE_SCHEMA,
        "status": "PUBLICATION_FAILED",
        "stage": stage,
        "run_id": run_id,
        "output_name": target.name,
        "exporter_code_sha256": exporter_code_digest,
        "exporter_policy_sha256": exporter_policy_digest,
    }
    value = C.bind_embedded_sha256(body, "receipt_sha256")
    path = target.parent / (
        f".{target.name}.failure-{value['receipt_sha256'][:16]}.json"
    )
    return _write_or_load_exact_control(
        path,
        C.canonical_document_bytes(value),
        label="publication failure receipt",
    )


def _bundle_seal_at(root: Path) -> str:
    try:
        raw = P.read_stable_regular_bytes(
            root / "SEALED.sha256",
            maximum_bytes=128,
            label="retired generation seal",
        )
    except P.RunBundlePrivacyError as exc:
        raise RunBundleExportError(
            "retired generation seal is unavailable"
        ) from exc
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise RunBundleExportError(
            "retired generation seal is invalid"
        ) from exc
    if re.fullmatch(r"[0-9a-f]{64}\n", text) is None:
        raise RunBundleExportError(
            "retired generation seal is invalid"
        )
    return text[:-1]


def validate_publication_retirement(value: Any) -> dict[str, Any]:
    fields = {
        "schema_version",
        "status",
        "run_id",
        "output_name",
        "control_receipt_name",
        "control_receipt_sha256",
        "bundle_seal_sha256",
        "retired_at_utc",
        "retirement_rule",
        "exporter_code_sha256",
        "exporter_policy_sha256",
        "retirement_sha256",
    }
    if type(value) is not dict or set(value) != fields:
        raise RunBundleExportError(
            "publication retirement receipt is not closed"
        )
    row = C.strict_json_loads(
        C.canonical_document_bytes(value), require_canonical=True
    )
    if (
        row["schema_version"] != PUBLICATION_RETIREMENT_SCHEMA
        or row["status"] != "RETIRED"
        or row["retirement_rule"] != "NO_READY_NO_HARVEST"
    ):
        raise RunBundleExportError(
            "publication retirement receipt is invalid"
        )
    try:
        output_name = P.assert_safe_relative_path(
            row["output_name"], label="retirement output name"
        )
        control_name = P.assert_safe_relative_path(
            row["control_receipt_name"],
            label="retirement control-receipt name",
        )
    except P.RunBundlePrivacyError as exc:
        raise RunBundleExportError(str(exc)) from exc
    if "/" in output_name or "/" in control_name:
        raise RunBundleExportError(
            "publication retirement basename is invalid"
        )
    if (
        not isinstance(row["run_id"], str)
        or not row["run_id"]
        or any(char.isspace() for char in row["run_id"])
    ):
        raise RunBundleExportError(
            "publication retirement run ID is invalid"
        )
    _validate_utc_text(row["retired_at_utc"])
    for field in (
        "control_receipt_sha256",
        "bundle_seal_sha256",
        "exporter_code_sha256",
        "exporter_policy_sha256",
        "retirement_sha256",
    ):
        if (
            not isinstance(row[field], str)
            or _DIGEST_RE.fullmatch(row[field]) is None
        ):
            raise RunBundleExportError(
                f"publication retirement {field} is invalid"
            )
    try:
        C.verify_embedded_sha256(row, "retirement_sha256")
        P.validate_public_payload(row)
    except (C.RunBundleContractError, P.RunBundlePrivacyError) as exc:
        raise RunBundleExportError(
            "publication retirement receipt failed validation"
        ) from exc
    return row


def _load_publication_retirement(
    *,
    target: Path,
    run_id: str,
    exporter_code_digest: str,
    exporter_policy_digest: str,
    control_receipt: Path | None,
) -> tuple[Path, dict[str, Any], bytes, Path]:
    path = publication_retirement_path(target)
    try:
        raw = P.read_stable_regular_bytes(
            path,
            maximum_bytes=1 << 20,
            label="publication retirement receipt",
        )
        value = validate_publication_retirement(
            C.strict_json_loads(raw, require_canonical=True)
        )
    except (P.RunBundlePrivacyError, C.RunBundleContractError) as exc:
        raise RunBundleExportError(
            "publication retirement receipt is unsafe"
        ) from exc
    referenced_control = target.parent / value["control_receipt_name"]
    try:
        control_raw = P.read_stable_regular_bytes(
            referenced_control,
            maximum_bytes=1 << 20,
            label="publication retirement control receipt",
        )
    except P.RunBundlePrivacyError as exc:
        raise RunBundleExportError(
            "publication retirement control receipt is unavailable"
        ) from exc
    if (
        value["output_name"] != target.name
        or value["run_id"] != run_id
        or value["control_receipt_sha256"] != C.sha256_bytes(control_raw)
        or value["exporter_code_sha256"] != exporter_code_digest
        or value["exporter_policy_sha256"] != exporter_policy_digest
        or (
            control_receipt is not None
            and not _same_path(control_receipt, referenced_control)
        )
    ):
        raise RunBundleExportError(
            "publication retirement receipt binding mismatched"
        )
    return path, value, raw, referenced_control


def _retirement_quarantine_path(
    target: Path,
    retirement: Mapping[str, Any],
) -> Path:
    return target.parent / (
        f".{target.name}.retired-{retirement['retirement_sha256'][:16]}"
    )


def _complete_retirement(
    *,
    target: Path,
    retirement: Mapping[str, Any],
) -> Path:
    quarantine = _retirement_quarantine_path(target, retirement)
    target_exists = os.path.lexists(target)
    quarantine_exists = os.path.lexists(quarantine)
    if target_exists and quarantine_exists:
        raise RunBundleExportError(
            "publication retirement topology is ambiguous"
        )
    if not target_exists and not quarantine_exists:
        raise RunBundleExportError(
            "publication retired generation is missing"
        )
    generation = target if target_exists else quarantine
    _existing_alias_free_path(
        generation,
        label="publication retired generation",
        directory=True,
    )
    if _bundle_seal_at(generation) != retirement["bundle_seal_sha256"]:
        raise RunBundleExportError(
            "publication retired generation binding mismatched"
        )
    if target_exists:
        try:
            _durable_directory_rename_new(target, quarantine)
        except (OSError, RunBundleExportError) as exc:
            raise RunBundleExportError(
                "publication retirement/quarantine failed; "
                "retired target remains in place"
            ) from exc
    if target.exists() or not quarantine.is_dir():
        raise RunBundleExportError(
            "publication retirement/quarantine postcondition failed"
        )
    if _bundle_seal_at(quarantine) != retirement["bundle_seal_sha256"]:
        raise RunBundleExportError(
            "publication quarantine generation drifted"
        )
    return quarantine


def _retire_promoted_target(
    *,
    target: Path,
    control_receipt: Path,
    run_id: str,
    exporter_code_digest: str,
    exporter_policy_digest: str,
    allow_unverified_ready: bool = False,
) -> None:
    if (
        publication_ready_path(target).exists()
        and not allow_unverified_ready
    ):
        raise RunBundleExportError(
            "refused to retire a target carrying publication READY"
        )
    retirement_path = publication_retirement_path(target)
    if retirement_path.exists():
        _path, value, _raw, _control = _load_publication_retirement(
            target=target,
            run_id=run_id,
            exporter_code_digest=exporter_code_digest,
            exporter_policy_digest=exporter_policy_digest,
            control_receipt=control_receipt,
        )
        _complete_retirement(target=target, retirement=value)
        return
    if not target.exists():
        raise RunBundleExportError(
            "publication target is absent before retirement"
        )
    try:
        control_raw = P.read_stable_regular_bytes(
            control_receipt,
            maximum_bytes=1 << 20,
            label="publication failure control receipt",
        )
    except P.RunBundlePrivacyError as exc:
        raise RunBundleExportError(
            "publication failure receipt is unavailable"
        ) from exc
    body = {
        "schema_version": PUBLICATION_RETIREMENT_SCHEMA,
        "status": "RETIRED",
        "run_id": run_id,
        "output_name": target.name,
        "control_receipt_name": control_receipt.name,
        "control_receipt_sha256": C.sha256_bytes(control_raw),
        "bundle_seal_sha256": _bundle_seal_at(target),
        "retired_at_utc": _utc_now_text(),
        "retirement_rule": "NO_READY_NO_HARVEST",
        "exporter_code_sha256": exporter_code_digest,
        "exporter_policy_sha256": exporter_policy_digest,
    }
    value = validate_publication_retirement(
        C.bind_embedded_sha256(body, "retirement_sha256")
    )
    _write_or_load_exact_control(
        retirement_path,
        C.canonical_document_bytes(value),
        label="publication retirement receipt",
    )
    _path, loaded, _raw, _control = _load_publication_retirement(
        target=target,
        run_id=run_id,
        exporter_code_digest=exporter_code_digest,
        exporter_policy_digest=exporter_policy_digest,
        control_receipt=control_receipt,
    )
    _complete_retirement(target=target, retirement=loaded)


def _same_path(left: Path, right: Path) -> bool:
    return os.path.normcase(str(left)) == os.path.normcase(str(right))


def _existing_alias_free_path(
    value: Path,
    *,
    label: str,
    directory: bool,
) -> Path:
    absolute = Path(os.path.abspath(os.fspath(value)))
    try:
        resolved = absolute.resolve(strict=True)
        row = absolute.lstat()
    except OSError as exc:
        raise RunBundleExportError(f"{label} is unavailable") from exc
    if not _same_path(absolute, resolved):
        raise RunBundleExportError(f"{label} contains a filesystem alias")
    if stat.S_ISLNK(row.st_mode) or (
        int(getattr(row, "st_file_attributes", 0) or 0)
        & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    ):
        raise RunBundleExportError(f"{label} is a link/reparse alias")
    expected = stat.S_ISDIR(row.st_mode) if directory else stat.S_ISREG(row.st_mode)
    if not expected:
        raise RunBundleExportError(f"{label} has the wrong filesystem type")
    if not directory and int(getattr(row, "st_nlink", 1) or 1) != 1:
        raise RunBundleExportError(f"{label} is a hardlink alias")
    return absolute


def _authorized_recovery_topology(
    *,
    journal: Path,
    out: Path,
) -> tuple[Path, Path, Path, bool]:
    """Bind recovery to a caller-authorized output and one exact staging nonce."""

    journal_path = _existing_alias_free_path(
        journal, label="recovery journal", directory=False
    )
    authorized_absolute = Path(os.path.abspath(os.fspath(out)))
    authorized_parent = _existing_alias_free_path(
        authorized_absolute.parent,
        label="authorized recovery output parent",
        directory=True,
    )
    authorized_target = authorized_parent / authorized_absolute.name
    if authorized_target.name in {"", ".", ".."}:
        raise RunBundleExportError(
            "authorized recovery output basename is invalid"
        )

    if journal_path.name == "export.journal.json":
        staging = _existing_alias_free_path(
            journal_path.parent, label="recovery staging", directory=True
        )
        parent = _existing_alias_free_path(
            staging.parent, label="recovery output parent", directory=True
        )
        match = _STAGING_NAME_RE.fullmatch(staging.name)
        if (
            match is None
            or not _same_path(parent, authorized_parent)
            or match.group("target") != authorized_target.name
            or not _same_path(
                journal_path, staging / "export.journal.json"
            )
            or os.path.lexists(authorized_target)
        ):
            raise RunBundleExportError(
                "journal is outside the authorized recovery topology"
            )
        return journal_path, staging, authorized_target, False

    match = _PROMOTION_JOURNAL_NAME_RE.fullmatch(journal_path.name)
    if (
        match is None
        or not _same_path(journal_path.parent, authorized_parent)
        or match.group("target") != authorized_target.name
    ):
        raise RunBundleExportError(
            "journal is outside the authorized recovery topology"
        )
    staging = authorized_parent / (
        f".{authorized_target.name}.{match.group('nonce')}.staging"
    )
    staging_exists = os.path.lexists(staging)
    target_exists = os.path.lexists(authorized_target)
    if staging_exists == target_exists:
        raise RunBundleExportError(
            "promotion recovery requires exactly one published generation"
        )
    if staging_exists:
        _existing_alias_free_path(
            staging, label="recovery staging", directory=True
        )
    else:
        _existing_alias_free_path(
            authorized_target,
            label="recovery promoted target",
            directory=True,
        )
    return journal_path, staging, authorized_target, target_exists


def _document_digest(documents: Mapping[str, Any]) -> str:
    return C.document_sha256(
        {
            name: (
                C.sha256_bytes(C.canonical_jsonl_bytes(value))
                if name == "phase_events.jsonl"
                else C.document_sha256(value)
            )
            for name, value in sorted(documents.items())
        }
    )


def _object_digest(object_bytes: Mapping[str, bytes]) -> str:
    return C.document_sha256(
        {
            "objects": [
                {
                    "relative_path": path,
                    "byte_length": len(raw),
                    "sha256": C.sha256_bytes(raw),
                }
                for path, raw in sorted(object_bytes.items())
            ]
        }
    )


def _capture_staged_payload(staging: Path) -> tuple[str, str]:
    documents: dict[str, Any] = {}
    for name in sorted(C.PUBLIC_PAYLOAD_FILE_NAMES):
        path = staging / name
        if name == "phase_events.jsonl":
            raw = P.read_stable_regular_bytes(
                path, maximum_bytes=C.MAX_JSON_BYTES, label=name
            )
            documents[name] = C.strict_jsonl_loads(raw, require_canonical=True)
        else:
            documents[name] = C.strict_json_load(
                path, require_canonical=True
            )
    object_bytes = {
        row["relative_path"]: P.read_stable_regular_bytes(
            staging
            / "objects"
            / "sha256"
            / PurePosixPath(row["relative_path"]),
            maximum_bytes=1 << 30,
            label="staged object",
        )
        for row in P.inspect_regular_tree(staging / "objects" / "sha256")
    }
    # inspect_regular_tree paths are relative to objects/sha256.
    object_bytes = {
        f"objects/sha256/{relative}": raw
        for relative, raw in object_bytes.items()
    }
    return _document_digest(documents), _object_digest(object_bytes)


def _write_payload(
    staging: Path,
    documents: Mapping[str, Any],
    object_bytes: Mapping[str, bytes],
) -> None:
    staging.mkdir(parents=False, exist_ok=False)
    for name in sorted(C.PUBLIC_PAYLOAD_FILE_NAMES):
        value = documents[name]
        raw = (
            C.canonical_jsonl_bytes(value)
            if name == "phase_events.jsonl"
            else C.canonical_document_bytes(value)
        )
        _write_new(staging / name, raw)
    object_root = staging / "objects" / "sha256"
    object_root.mkdir(parents=True, exist_ok=False)
    for relative, raw in sorted(object_bytes.items()):
        try:
            safe = P.assert_safe_relative_path(
                relative, label="export object path"
            )
        except P.RunBundlePrivacyError as exc:
            raise RunBundleExportError(str(exc)) from exc
        digest = C.sha256_bytes(raw)
        if safe != f"objects/sha256/{digest}":
            raise RunBundleExportError(
                "object path must equal its exact content digest"
            )
        _write_new(staging / PurePosixPath(safe), raw)


def _seal_staging(
    staging: Path,
    *,
    exact_public_lock_bytes: bytes,
    journal: Path | None,
) -> C.RunBundleVerificationReceipt:
    if journal is not None and journal.exists():
        journal.unlink()
    try:
        index = P.build_bundle_index(staging)
        _write_new(staging / "bundle_index.json", P.bundle_index_bytes(index))
        seal = P.bundle_seal_sha256(index)
        _write_new(staging / "SEALED.sha256", (seal + "\n").encode("ascii"))
        return C.verify_runbundle_v2(staging, exact_public_lock_bytes)
    except (P.RunBundlePrivacyError, C.RunBundleContractError) as exc:
        raise RunBundleExportError("sealed staging verification failed") from exc


def _receipt(
    root: Path,
    verified: C.RunBundleVerificationReceipt,
    documents: Mapping[str, Any],
    ready_path: Path,
    ready: Mapping[str, Any],
    *,
    cleanup_state: str = "COMPLETE",
) -> ExportReceipt:
    manifest = documents["run_manifest.json"]
    stability = ready["source_stability"]
    return ExportReceipt(
        bundle_root=root.resolve(),
        run_id=verified.run_id,
        trust_profile=manifest["trust_profile"],
        bundle_seal_sha256=verified.bundle_seal_sha256,
        public_case_lock_sha256=verified.public_case_lock_sha256,
        publication_ceiling=C.derive_publication_ceiling(manifest),
        verification_sha256=verified.verification_sha256,
        publication_ready_path=ready_path.resolve(),
        publication_ready_sha256=C.sha256_bytes(
            C.canonical_document_bytes(dict(ready))
        ),
        source_stability_asserted_at_utc=(
            stability["observations"][-1]["completed_at_utc"]
        ),
        source_stability_snapshot_sha256=(
            stability["source_authority_sha256"]
        ),
        source_stability_sha256=ready["source_stability_sha256"],
        bundle_integrity="VERIFIED",
        ready_schema=ready["schema_version"],
        ready_assurance="UNAUTHENTICATED_LOCAL",
        source_observation_claim="SELF_ASSERTED_NOT_AUTHENTICATED",
        cleanup_state=cleanup_state,
    )


def _assert_fresh_publication_controls(target: Path) -> None:
    prefixes = (
        f".{target.name}.mutation-",
        f".{target.name}.failure-",
        f".{target.name}.retired-",
    )
    exact = {
        publication_ready_path(target).name,
        publication_retirement_path(target).name,
        publication_cleanup_debt_path(target).name,
    }
    try:
        names = {entry.name for entry in os.scandir(target.parent)}
    except OSError as exc:
        raise RunBundleExportError(
            "output parent could not be enumerated"
        ) from exc
    promotion_controls = {
        name
        for name in names
        if (
            (match := _PROMOTION_JOURNAL_NAME_RE.fullmatch(name)) is not None
            and match.group("target") == target.name
        )
    }
    if names & exact or promotion_controls or any(
        name.startswith(prefix)
        for name in names
        for prefix in prefixes
    ):
        raise RunBundleExportError(
            "fresh output required; prior publication controls exist"
        )


def export_materialized_payload(
    *,
    documents: Mapping[str, Any],
    exact_public_lock_bytes: bytes,
    object_bytes: Mapping[str, bytes],
    out: Path,
    _fault_after: str | None = None,
    _live_source_authority_sha256: str | None = None,
    _live_source_closure: Callable[[], str] | None = None,
) -> ExportReceipt:
    """Seal one already harvested payload into a fresh deterministic bundle."""

    assert_export_environment_gt_blind()
    _validate_live_source_authority_pair(
        expected_sha256=_live_source_authority_sha256,
        closure=_live_source_closure,
    )
    code_digest = exporter_code_sha256()
    policy_digest = exporter_policy_sha256()
    target = Path(out).resolve()
    parent = target.parent
    if target.exists():
        raise RunBundleExportError("fresh output required; target exists")
    if not parent.is_dir():
        raise RunBundleExportError("output parent must already exist")
    _assert_fresh_publication_controls(target)
    try:
        lock = C.strict_json_loads(
            exact_public_lock_bytes, require_canonical=True
        )
        C.validate_bundle_payload_set(
            dict(documents), lock, object_bytes=dict(object_bytes)
        )
    except C.RunBundleContractError as exc:
        raise RunBundleExportError("materialized payload contract is invalid") from exc
    document_digest = _document_digest(documents)
    objects_digest = _object_digest(object_bytes)
    lock_digest = C.sha256_bytes(exact_public_lock_bytes)
    run_id = documents["run_manifest.json"]["run_id"]
    staging = parent / (
        f".{target.name}.{secrets.token_hex(8)}.staging"
    )
    journal: Path | None = None
    interrupted = False
    promoted_target = False
    ready_published = False
    ready_verified = False
    try:
        _write_payload(staging, documents, object_bytes)
        journal = _write_journal(
            staging,
            _journal_body(
                stage="PAYLOAD",
                staging=staging,
                out=target,
                documents_sha256=document_digest,
                objects_sha256=objects_digest,
                public_case_lock_sha256=lock_digest,
                live_source_authority_sha256=(
                    _live_source_authority_sha256
                ),
                exporter_code_digest=code_digest,
                exporter_policy_digest=policy_digest,
                run_id=run_id,
            ),
        )
        if _fault_after == "PAYLOAD":
            interrupted = True
            raise RunBundleExportInterrupted("interrupted after payload")
        _write_journal(
            staging,
            _journal_body(
                stage="OBJECTS",
                staging=staging,
                out=target,
                documents_sha256=document_digest,
                objects_sha256=objects_digest,
                public_case_lock_sha256=lock_digest,
                live_source_authority_sha256=(
                    _live_source_authority_sha256
                ),
                exporter_code_digest=code_digest,
                exporter_policy_digest=policy_digest,
                run_id=run_id,
            ),
        )
        if _fault_after == "OBJECTS":
            interrupted = True
            raise RunBundleExportInterrupted("interrupted after objects")
        # Index is built without the control journal, then the journal is
        # restored for the failpoint.  Recovery removes it before verification.
        journal.unlink()
        index = P.build_bundle_index(staging)
        _write_new(staging / "bundle_index.json", P.bundle_index_bytes(index))
        journal = _write_journal(
            staging,
            _journal_body(
                stage="INDEX",
                staging=staging,
                out=target,
                documents_sha256=document_digest,
                objects_sha256=objects_digest,
                public_case_lock_sha256=lock_digest,
                live_source_authority_sha256=(
                    _live_source_authority_sha256
                ),
                exporter_code_digest=code_digest,
                exporter_policy_digest=policy_digest,
                run_id=run_id,
            ),
        )
        if _fault_after == "INDEX":
            interrupted = True
            raise RunBundleExportInterrupted("interrupted after index")
        journal.unlink()
        _check_live_source_closure(
            expected_sha256=_live_source_authority_sha256,
            closure=_live_source_closure,
            parent=parent,
            target_name=target.name,
            run_id=run_id,
            exporter_code_digest=code_digest,
            exporter_policy_digest=policy_digest,
            stage="PRE_SEAL",
        )
        _write_new(
            staging / "SEALED.sha256",
            (P.bundle_seal_sha256(index) + "\n").encode("ascii"),
        )
        verified = C.verify_runbundle_v2(staging, exact_public_lock_bytes)
        _check_live_source_closure(
            expected_sha256=_live_source_authority_sha256,
            closure=_live_source_closure,
            parent=parent,
            target_name=target.name,
            run_id=run_id,
            exporter_code_digest=code_digest,
            exporter_policy_digest=policy_digest,
            stage="PRE_PUBLICATION",
        )
        journal = _write_promotion_journal(
            staging,
            target,
            _journal_body(
                stage="PROMOTION",
                staging=staging,
                out=target,
                documents_sha256=document_digest,
                objects_sha256=objects_digest,
                public_case_lock_sha256=lock_digest,
                live_source_authority_sha256=(
                    _live_source_authority_sha256
                ),
                exporter_code_digest=code_digest,
                exporter_policy_digest=policy_digest,
                run_id=run_id,
            ),
        )
        if target.exists():
            raise RunBundleExportError("target appeared during export")
        _durable_directory_rename_new(staging, target)
        promoted_target = True
        if _fault_after == "PROMOTED":
            interrupted = True
            raise RunBundleExportInterrupted("interrupted after promotion")
        preverify_observation = _observe_live_source_closure(
            expected_sha256=_live_source_authority_sha256,
            closure=_live_source_closure,
            parent=parent,
            target_name=target.name,
            run_id=run_id,
            exporter_code_digest=code_digest,
            exporter_policy_digest=policy_digest,
            stage="POST_PROMOTION",
        )
        promoted = C.verify_runbundle_v2(target, exact_public_lock_bytes)
        if promoted.verification_sha256 != verified.verification_sha256:
            raise RunBundleExportError("promoted bundle verification drifted")
        ready_path, ready = _publish_publication_ready(
            target=target,
            verified=promoted,
            source_authority_sha256=_live_source_authority_sha256,
            preverify_observation=preverify_observation,
            live_source_closure=_live_source_closure,
            exporter_code_digest=code_digest,
            exporter_policy_digest=policy_digest,
        )
        ready_published = True
        ready_path, ready, ready_raw = _load_publication_ready(
            target, promoted
        )
        ready_verified = True
        _complete_promotion_cleanup(
            target=target,
            journal=journal,
            verified=promoted,
            ready_path=ready_path,
            ready=ready,
            ready_raw=ready_raw,
        )
        return _receipt(
            target,
            promoted,
            documents,
            ready_path,
            ready,
        )
    except RunBundleMutationError as exc:
        if promoted_target:
            _retire_promoted_target(
                target=target,
                control_receipt=exc.receipt_path,
                run_id=run_id,
                exporter_code_digest=code_digest,
                exporter_policy_digest=policy_digest,
            )
        raise
    except RunBundleExportInterrupted:
        raise
    except RunBundleExportError:
        if promoted_target and not ready_verified and target.exists():
            failure = _write_publication_failure_receipt(
                target=target,
                run_id=run_id,
                stage="POST_PROMOTION",
                exporter_code_digest=code_digest,
                exporter_policy_digest=policy_digest,
            )
            _retire_promoted_target(
                target=target,
                control_receipt=failure,
                run_id=run_id,
                exporter_code_digest=code_digest,
                exporter_policy_digest=policy_digest,
                allow_unverified_ready=(
                    ready_published
                    or publication_ready_path(target).exists()
                ),
            )
        raise
    except (OSError, P.RunBundlePrivacyError, C.RunBundleContractError) as exc:
        if promoted_target and not ready_verified and target.exists():
            failure = _write_publication_failure_receipt(
                target=target,
                run_id=run_id,
                stage="POST_PROMOTION_IO",
                exporter_code_digest=code_digest,
                exporter_policy_digest=policy_digest,
            )
            _retire_promoted_target(
                target=target,
                control_receipt=failure,
                run_id=run_id,
                exporter_code_digest=code_digest,
                exporter_policy_digest=policy_digest,
                allow_unverified_ready=(
                    ready_published
                    or publication_ready_path(target).exists()
                ),
            )
        raise RunBundleExportError("RunBundle export failed") from exc
    finally:
        if not interrupted and staging.exists():
            _safe_remove_tree(staging, parent=parent)


def recover_export(
    *,
    journal: Path,
    exact_public_lock_bytes: bytes,
    out: Path,
    project_root: Path | None = None,
    scratchpad: Path | None = None,
    report: Path | None = None,
) -> ExportReceipt:
    assert_export_environment_gt_blind()
    authorized_absolute = Path(os.path.abspath(os.fspath(out)))
    authorized_parent = _existing_alias_free_path(
        authorized_absolute.parent,
        label="authorized recovery output parent",
        directory=True,
    )
    retirement_target = authorized_parent / authorized_absolute.name
    supplied_journal = Path(os.path.abspath(os.fspath(journal)))
    if (
        not os.path.lexists(supplied_journal)
        and retirement_target.is_dir()
        and publication_cleanup_debt_path(retirement_target).is_file()
    ):
        recovered = verify_export_integrity(
            retirement_target, exact_public_lock_bytes
        )
        if recovered.cleanup_state != "DEBT":
            raise RunBundleExportError(
                "cleanup-only recovery state is inconsistent"
            )
        promoted = C.verify_runbundle_v2(
            retirement_target, exact_public_lock_bytes
        )
        ready_path, ready, ready_raw = _load_publication_ready(
            retirement_target, promoted
        )
        debt = _load_publication_cleanup_debt(
            target=retirement_target,
            verified=promoted,
            ready_path=ready_path,
            ready=ready,
            ready_raw=ready_raw,
            journal_path=None,
            journal_raw=None,
        )
        if debt is None:
            raise RunBundleExportError(
                "cleanup-only recovery debt receipt disappeared"
            )
        _debt_path, debt_value, _debt_raw = debt
        expected_journal = (
            authorized_parent / debt_value["promotion_journal_name"]
        )
        if not _same_path(supplied_journal, expected_journal):
            raise RunBundleExportError(
                "cleanup-only recovery journal identity mismatched"
            )
        _complete_promotion_cleanup(
            target=retirement_target,
            journal=expected_journal,
            verified=promoted,
            ready_path=ready_path,
            ready=ready,
            ready_raw=ready_raw,
        )
        return verify_export_integrity(
            retirement_target, exact_public_lock_bytes
        )
    if publication_retirement_path(retirement_target).exists():
        journal_path = _existing_alias_free_path(
            journal,
            label="retired recovery journal",
            directory=False,
        )
        match = _PROMOTION_JOURNAL_NAME_RE.fullmatch(journal_path.name)
        if (
            match is None
            or match.group("target") != retirement_target.name
            or not _same_path(journal_path.parent, authorized_parent)
        ):
            raise RunBundleExportError(
                "retired recovery journal is outside the authorized topology"
            )
        row = _load_journal(journal_path)
        current_code_digest = exporter_code_sha256()
        current_policy_digest = exporter_policy_sha256()
        if (
            row["stage"] != "PROMOTION"
            or not _same_path(
                Path(row["output_path"]), retirement_target
            )
            or row["public_case_lock_sha256"]
            != C.sha256_bytes(exact_public_lock_bytes)
            or row["exporter_code_sha256"] != current_code_digest
            or row["exporter_policy_sha256"] != current_policy_digest
        ):
            raise RunBundleExportError(
                "retired recovery journal binding mismatched"
            )
        (
            _retirement_path,
            retirement,
            _retirement_raw,
            original_control,
        ) = _load_publication_retirement(
            target=retirement_target,
            run_id=row["run_id"],
            exporter_code_digest=current_code_digest,
            exporter_policy_digest=current_policy_digest,
            control_receipt=None,
        )
        _complete_retirement(
            target=retirement_target,
            retirement=retirement,
        )
        try:
            journal_path.unlink()
            _fsync_directory(authorized_parent)
        except (OSError, RunBundleExportError) as exc:
            raise RunBundleExportError(
                "retired publication cleanup debt remains"
            ) from exc
        if ".mutation-" in original_control.name:
            raise RunBundleMutationError(
                "MUTATED_DURING_EXPORT: retired generation quarantined",
                original_control,
            )
        raise RunBundleExportError(
            "publication is RETIRED after recovery completion"
        )
    (
        journal_path,
        staging,
        target,
        already_promoted,
    ) = _authorized_recovery_topology(
        journal=journal,
        out=out,
    )
    row = _load_journal(journal_path)
    if (
        row["staging_path"] != str(staging)
        or row["output_path"] != str(target)
    ):
        raise RunBundleExportError(
            "journal paths do not match the authorized recovery topology"
        )
    if already_promoted and row["stage"] != "PROMOTION":
        raise RunBundleExportError(
            "promoted recovery requires a promotion-stage journal"
        )
    if row["public_case_lock_sha256"] != C.sha256_bytes(
        exact_public_lock_bytes
    ):
        raise RunBundleExportError("recovery public case lock drifted")
    current_code_digest = exporter_code_sha256()
    current_policy_digest = exporter_policy_sha256()
    if (
        row["exporter_code_sha256"] != current_code_digest
        or row["exporter_policy_sha256"] != current_policy_digest
    ):
        raise RunBundleExportError("recovery exporter code/policy drifted")

    untrusted_ready_pending = False
    if already_promoted and publication_ready_path(target).exists():
        try:
            recovered = verify_export(
                target,
                exact_public_lock_bytes,
                required_assurance=INTEGRITY_ONLY,
            )
        except RunBundleRecoveryRequiredError:
            untrusted_ready_pending = True
        else:
            if recovered.cleanup_state != "DEBT":
                raise RunBundleExportError(
                    "promoted recovery journal survived a complete export"
                )
            promoted = C.verify_runbundle_v2(
                target, exact_public_lock_bytes
            )
            ready_path, ready, ready_raw = _load_publication_ready(
                target, promoted
            )
            _complete_promotion_cleanup(
                target=target,
                journal=journal_path,
                verified=promoted,
                ready_path=ready_path,
                ready=ready,
                ready_raw=ready_raw,
            )
            return verify_export_integrity(
                target, exact_public_lock_bytes
            )

    container = target if already_promoted else staging
    expected_live_authority = row["live_source_authority_sha256"]

    def reject_mutated_recovery(
        *,
        stage: str,
        detail: str,
        cause: BaseException | None = None,
    ) -> None:
        if expected_live_authority is None:
            raise RunBundleExportError(detail) from cause
        receipt = _write_mutation_receipt(
            parent=target.parent,
            target_name=target.name,
            run_id=row["run_id"],
            input_source_authority_sha256=expected_live_authority,
            exporter_code_digest=current_code_digest,
            exporter_policy_digest=current_policy_digest,
            stage=stage,
        )
        if already_promoted and target.exists():
            _retire_promoted_target(
                target=target,
                control_receipt=receipt,
                run_id=row["run_id"],
                exporter_code_digest=current_code_digest,
                exporter_policy_digest=current_policy_digest,
                allow_unverified_ready=(
                    publication_ready_path(target).exists()
                ),
            )
        elif staging.exists():
            _safe_remove_tree(staging, parent=target.parent)
        raise RunBundleMutationError(
            "MUTATED_DURING_EXPORT: " + detail,
            receipt,
        ) from cause

    supplied_live_paths = (project_root, scratchpad, report)
    if expected_live_authority is None:
        if any(path is not None for path in supplied_live_paths):
            raise RunBundleExportError(
                "recovery source authority was not present at export"
            )
        live_source_closure: Callable[[], str] | None = None
    else:
        if any(path is None for path in supplied_live_paths):
            raise RunBundleExportError(
                "recovery live source authority paths are required"
            )
        try:
            manifest = C.strict_json_load(
                container / "run_manifest.json",
                require_canonical=True,
            )
            pipeline_kind = manifest["phase_map"]["pipeline_kind"]
            recovery_inventory = S.inventory_run_sources(
                project_root=Path(project_root),
                scratchpad=Path(scratchpad),
                report=Path(report),
                pipeline_kind=pipeline_kind,
            )
        except (
            KeyError,
            TypeError,
            C.RunBundleContractError,
            P.RunBundlePrivacyError,
            S.RunBundleSourceError,
        ) as exc:
            reject_mutated_recovery(
                stage=(
                    "RECOVERY_POST_PROMOTION"
                    if already_promoted
                    else "RECOVERY_PRE_SEAL"
                ),
                detail="recovery source capture failed",
                cause=exc,
            )
        if (
            recovery_inventory.live_source_authority_sha256
            != expected_live_authority
        ):
            reject_mutated_recovery(
                stage=(
                    "RECOVERY_POST_PROMOTION"
                    if already_promoted
                    else "RECOVERY_PRE_SEAL"
                ),
                detail="recovery source authority mismatched",
            )

        def live_source_closure() -> str:
            return S.verify_live_source_closure(
                project_root=Path(project_root),
                scratchpad=Path(scratchpad),
                report=Path(report),
                inventory=recovery_inventory,
            )

    # A staging recovery rebuilds generated bytes. A promoted recovery keeps
    # the sealed generation immutable and replays only its payload commitment.
    if not already_promoted:
        for name in ("bundle_index.json", "SEALED.sha256"):
            path = staging / name
            if path.exists():
                path.unlink()
        if (
            journal_path.parent == staging
            and journal_path.name == "export.journal.json"
        ):
            journal_path.unlink()
    documents_sha256, objects_sha256 = _capture_staged_payload(container)
    if (
        documents_sha256 != row["documents_sha256"]
        or objects_sha256 != row["objects_sha256"]
    ):
        if not already_promoted:
            _write_journal(staging, row)
        raise RunBundleExportError(
            "recovery input changed; a fresh export is required"
        )

    verified_before_promotion: C.RunBundleVerificationReceipt | None = None
    promotion_journal = journal_path
    promoted_target = already_promoted
    ready_published = False
    ready_verified = False
    try:
        if not already_promoted:
            _check_live_source_closure(
                expected_sha256=expected_live_authority,
                closure=live_source_closure,
                parent=target.parent,
                target_name=target.name,
                run_id=row["run_id"],
                exporter_code_digest=current_code_digest,
                exporter_policy_digest=current_policy_digest,
                stage="RECOVERY_PRE_SEAL",
            )
            verified_before_promotion = _seal_staging(
                staging,
                exact_public_lock_bytes=exact_public_lock_bytes,
                journal=None,
            )
            _check_live_source_closure(
                expected_sha256=expected_live_authority,
                closure=live_source_closure,
                parent=target.parent,
                target_name=target.name,
                run_id=row["run_id"],
                exporter_code_digest=current_code_digest,
                exporter_policy_digest=current_policy_digest,
                stage="RECOVERY_PRE_PUBLICATION",
            )
            if verified_before_promotion.run_id != row["run_id"]:
                raise RunBundleExportError("recovery run identity drifted")
            if target.exists():
                raise RunBundleExportError("recovery target appeared")
            promotion_journal = _write_promotion_journal(
                staging,
                target,
                {
                    **{
                        key: value
                        for key, value in row.items()
                        if key != "journal_sha256"
                    },
                    "stage": "PROMOTION",
                },
            )
            _durable_directory_rename_new(staging, target)
            promoted_target = True
        elif untrusted_ready_pending:
            publication_ready_path(target).unlink()
            _fsync_directory(target.parent)
        preverify_observation = _observe_live_source_closure(
            expected_sha256=expected_live_authority,
            closure=live_source_closure,
            parent=target.parent,
            target_name=target.name,
            run_id=row["run_id"],
            exporter_code_digest=current_code_digest,
            exporter_policy_digest=current_policy_digest,
            stage="RECOVERY_POST_PROMOTION",
            observation_stage="POST_PROMOTION",
        )
        promoted = C.verify_runbundle_v2(target, exact_public_lock_bytes)
        if (
            verified_before_promotion is not None
            and promoted.verification_sha256
            != verified_before_promotion.verification_sha256
        ):
            raise RunBundleExportError(
                "recovered promoted bundle verification drifted"
            )
        ready_path, ready = _publish_publication_ready(
            target=target,
            verified=promoted,
            source_authority_sha256=expected_live_authority,
            preverify_observation=preverify_observation,
            live_source_closure=live_source_closure,
            exporter_code_digest=current_code_digest,
            exporter_policy_digest=current_policy_digest,
            final_mutation_stage="RECOVERY_POST_VERIFY_PRE_READY",
        )
        ready_published = True
        ready_path, ready, ready_raw = _load_publication_ready(
            target, promoted
        )
        ready_verified = True
        _complete_promotion_cleanup(
            target=target,
            journal=promotion_journal,
            verified=promoted,
            ready_path=ready_path,
            ready=ready,
            ready_raw=ready_raw,
        )
        documents: dict[str, Any] = {
            name: (
                C.strict_jsonl_loads(
                    P.read_stable_regular_bytes(
                        target / name,
                        maximum_bytes=C.MAX_JSON_BYTES,
                        label=name,
                    ),
                    require_canonical=True,
                )
                if name == "phase_events.jsonl"
                else C.strict_json_load(target / name, require_canonical=True)
            )
            for name in C.PUBLIC_PAYLOAD_FILE_NAMES
        }
        return _receipt(target, promoted, documents, ready_path, ready)
    except RunBundleMutationError as exc:
        if promoted_target:
            _retire_promoted_target(
                target=target,
                control_receipt=exc.receipt_path,
                run_id=row["run_id"],
                exporter_code_digest=current_code_digest,
                exporter_policy_digest=current_policy_digest,
            )
        elif staging.exists():
            _safe_remove_tree(staging, parent=target.parent)
        raise
    except (
        OSError,
        P.RunBundlePrivacyError,
        C.RunBundleContractError,
        RunBundleExportError,
    ) as exc:
        if promoted_target and not ready_verified and target.exists():
            failure = _write_publication_failure_receipt(
                target=target,
                run_id=row["run_id"],
                stage="RECOVERY_POST_PROMOTION",
                exporter_code_digest=current_code_digest,
                exporter_policy_digest=current_policy_digest,
            )
            _retire_promoted_target(
                target=target,
                control_receipt=failure,
                run_id=row["run_id"],
                exporter_code_digest=current_code_digest,
                exporter_policy_digest=current_policy_digest,
                allow_unverified_ready=(
                    ready_published
                    or publication_ready_path(target).exists()
                ),
            )
        elif not promoted_target and staging.exists():
            _safe_remove_tree(staging, parent=target.parent)
        if isinstance(exc, RunBundleExportError):
            raise
        raise RunBundleExportError("RunBundle recovery failed") from exc


def verify_export(
    bundle: Path,
    exact_public_lock_bytes: bytes,
    required_assurance: str = INTEGRITY_ONLY,
) -> ExportReceipt:
    if required_assurance not in {
        INTEGRITY_ONLY,
        AUTHENTICATED_EXPORT_ATTESTATION,
    }:
        raise RunBundleExportError("unknown export assurance requirement")
    root = Path(bundle).resolve()
    if publication_retirement_path(root).exists():
        raise RunBundleExportError(
            "RunBundle is RETIRED and is denied"
        )
    try:
        verified = C.verify_runbundle_v2(root, exact_public_lock_bytes)
        manifest = C.strict_json_load(
            root / "run_manifest.json", require_canonical=True
        )
        ready_path, ready, ready_raw = _load_publication_ready(
            root, verified
        )
    except (C.RunBundleContractError, P.RunBundlePrivacyError) as exc:
        raise RunBundleExportError("RunBundle verification failed") from exc
    journals = _matching_promotion_journals(root)
    if len(journals) > 1:
        raise RunBundleExportError(
            "multiple promotion transactions match the local bundle"
        )
    cleanup_state = "COMPLETE"
    if journals:
        journal_path = journals[0]
        _journal, journal_raw = _load_promotion_journal_for_target(
            path=journal_path,
            target=root,
            verified=verified,
            ready=ready,
        )
        debt = _load_publication_cleanup_debt(
            target=root,
            verified=verified,
            ready_path=ready_path,
            ready=ready,
            ready_raw=ready_raw,
            journal_path=journal_path,
            journal_raw=journal_raw,
        )
        if debt is None:
            raise RunBundleRecoveryRequiredError(
                "RECOVERY_REQUIRED: unresolved promotion transaction"
            )
        cleanup_state = "DEBT"
    else:
        debt = _load_publication_cleanup_debt(
            target=root,
            verified=verified,
            ready_path=ready_path,
            ready=ready,
            ready_raw=ready_raw,
            journal_path=None,
            journal_raw=None,
        )
        if debt is not None:
            cleanup_state = "DEBT"
    receipt = _receipt(
        root,
        verified,
        {"run_manifest.json": manifest},
        ready_path,
        ready,
        cleanup_state=cleanup_state,
    )
    if required_assurance == AUTHENTICATED_EXPORT_ATTESTATION:
        raise RunBundleAuthorityError(
            "READY v1 provides unsigned local integrity only; "
            "authenticated export attestation is unavailable"
        )
    return receipt


def verify_export_integrity(
    bundle: Path,
    exact_public_lock_bytes: bytes,
) -> ExportReceipt:
    """Explicit local-integrity verification with no provenance claim."""

    return verify_export(
        bundle,
        exact_public_lock_bytes,
        required_assurance=INTEGRITY_ONLY,
    )


def _object_bytes(draft: H.HarvestDraft) -> dict[str, bytes]:
    return {
        f"objects/sha256/{artifact.sha256}": artifact.raw
        for artifact in draft.inventory.artifacts
        if next(
            row
            for row in draft.raw_output_index["artifacts"]
            if row["artifact_id"] == artifact.artifact_id
        )["storage"]
        == "OBJECT"
    }


def _schedule_row(value: Any) -> dict[str, Any]:
    required = {
        "schema_version",
        "trust_profile",
        "run_id",
        "experiment_id",
        "cell_id",
        "repetition_index",
        "seed",
        "audit_system",
        "adapter",
        "experiment_plan_sha256",
        "campaign_schedule_sha256",
        "model_backend",
        "tool_policy",
        "budget",
        "resume",
        "public_launch_receipt",
        "pipeline_kind",
    }
    if type(value) is not dict or set(value) != required:
        raise RunBundleExportError("public schedule row is not closed")
    if value["schema_version"] != PUBLIC_SCHEDULE_ROW_SCHEMA:
        raise RunBundleExportError("unknown public schedule-row schema")
    if value["trust_profile"] not in C.LOCAL_TRUST_PROFILES:
        raise RunBundleExportError(
            "local exporter accepts only USER_RUN or B0_LOCAL"
        )
    try:
        P.validate_public_payload(value)
        M.pinned_phase_map(value["pipeline_kind"])
    except (P.RunBundlePrivacyError, M.RunBundlePhaseMapError) as exc:
        raise RunBundleExportError(str(exc)) from exc
    return value


def materialize_local_documents(
    *,
    draft: H.HarvestDraft,
    public_case_lock: Mapping[str, Any],
    schedule_row: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, bytes]]:
    """Compile a GT-blind draft into an unsigned USER_RUN/B0_LOCAL payload."""

    lock = C.validate_public_case_lock(dict(public_case_lock))
    schedule = _schedule_row(dict(schedule_row))
    phase_map = M.pinned_phase_map(schedule["pipeline_kind"])
    manifest = {
        "schema_version": C.RUN_MANIFEST_SCHEMA,
        "bundle_profile": C.REAL_AUDIT_V2,
        "trust_profile": schedule["trust_profile"],
        "run_id": schedule["run_id"],
        "case_id": lock["case_id"],
        "experiment_id": schedule["experiment_id"],
        "cell_id": schedule["cell_id"],
        "allocation_authority_ref": lock["allocation_authority"]["receipt_id"],
        "repetition_index": schedule["repetition_index"],
        "seed": schedule["seed"],
        "audit_system": schedule["audit_system"],
        "adapter": copy.deepcopy(schedule["adapter"]),
        "public_case_lock_sha256": C.public_case_lock_sha256(lock),
        "experiment_plan_sha256": schedule["experiment_plan_sha256"],
        "campaign_schedule_sha256": schedule["campaign_schedule_sha256"],
        "source_snapshot_sha256": lock["source_snapshot_sha256"],
        "phase_map": {
            "map_id": phase_map.map_id,
            "map_version": phase_map.map_version,
            "map_sha256": phase_map.map_sha256,
            "pipeline_kind": phase_map.pipeline_kind,
        },
        "model_backend": copy.deepcopy(schedule["model_backend"]),
        "tool_policy": copy.deepcopy(schedule["tool_policy"]),
        "budget": copy.deepcopy(schedule["budget"]),
        "blinding": {
            "ground_truth_available_to_runner": False,
            "prior_report_available_to_runner": False,
            "private_case_lock_available_to_runner": False,
            "grader_labels_available_to_runner": False,
            "rag_exposure": (
                "PUBLIC_ONLY"
                if schedule["tool_policy"]["rag_policy"] == "PUBLIC_ONLY"
                else "NONE"
            ),
        },
        "resume": copy.deepcopy(schedule["resume"]),
        "completion": {
            "state": "DEGRADED",
            "checkpoint_state": "DEGRADED",
            "final_report_gate_state": "DEGRADED",
        },
        "exporter": {
            "package": EXPORTER_PACKAGE,
            "version": EXPORTER_VERSION,
            "code_sha256": exporter_code_sha256(),
            "schema_set_sha256": schema_set_sha256(),
            "invocation_policy_sha256": exporter_policy_sha256(),
        },
        "public_launch_receipt": schedule["public_launch_receipt"],
        "run_context_authority": None,
    }
    if manifest["run_id"] != draft.run_id:
        raise RunBundleExportError("schedule run ID does not bind harvest draft")
    # No unsigned path may claim authenticated resource measurements.
    manifest["budget"]["measurement_receipt_refs"] = []
    manifest["budget"]["measurement_summary_receipt_ref"] = None

    native_rank = phase_map.native_order()
    artifacts = sorted(
        draft.raw_output_index["artifacts"],
        key=lambda row: (
            native_rank.get(row["native_phase"], 1 << 30),
            row["relative_source_path"].encode("utf-8"),
        ),
    )
    events: list[dict[str, Any]] = []
    for sequence, artifact in enumerate(artifacts, start=1):
        control = artifact["macro_phase"] == "CONTROL"
        final = artifact["producer_kind"] == "FINAL_REPORT"
        relation = "CONTROL" if control else "OUTPUT"
        events.append(
            {
                "schema_version": C.PHASE_EVENT_SCHEMA,
                "event_id": f"event-export-{sequence:08d}",
                "run_id": draft.run_id,
                "sequence": sequence,
                "attempt": manifest["resume"]["attempt"],
                "native_phase": artifact["native_phase"],
                "macro_phase": artifact["macro_phase"],
                "work_unit_id": artifact["work_unit_id"],
                "event_type": (
                    "REPORT_FINALIZED"
                    if final
                    else ("OUTPUTS_WRITTEN" if control else "OUTPUTS_COMMITTED")
                ),
                "commit_state": artifact["commit_state"],
                "source_artifact_ids": [],
                "input_artifact_ids": [],
                "output_artifact_ids": (
                    [] if control else [artifact["artifact_id"]]
                ),
                "artifact_relations": [
                    {
                        "artifact_id": artifact["artifact_id"],
                        "relation": relation,
                    }
                ],
                "source_receipt_id": C.UNAUTHENTICATED_AUTHORITY,
                "observed_at": "1970-01-01T00:00:00Z",
                "evidence_quality": "UNAUTHENTICATED",
            }
        )

    record_by_id = {
        record.record_id: (artifact, record)
        for artifact in draft.inventory.artifacts
        for record in artifact.records
    }
    lineage_debt_by_id = {
        debt["debt_id"]: debt for debt in draft.lineage["lineage_debts"]
    }
    nonfinding_rows = []
    for record_id in draft.nonfinding_record_ids:
        artifact, record = record_by_id[record_id]
        nonfinding_rows.append(
            {
                "record_id": record_id,
                "artifact_id": artifact.artifact_id,
                "byte_range": {
                    "start": record.byte_start,
                    "end": record.byte_end,
                },
                "record_sha256": record.record_sha256,
                "producer_kind": artifact.producer_kind,
                "source_contract_ref": artifact.source_contract_ref,
                "authority_receipt_id": C.UNAUTHENTICATED_AUTHORITY,
            }
        )
    debt_rows = []
    for record_id in draft.debt_record_ids:
        artifact, record = record_by_id[record_id]
        debt_id = draft.record_debt_ids[record_id]
        if debt_id not in lineage_debt_by_id:
            raise RunBundleExportError("record debt is absent from lineage")
        debt_rows.append(
            {
                "record_id": record_id,
                "artifact_id": artifact.artifact_id,
                "byte_range": {
                    "start": record.byte_start,
                    "end": record.byte_end,
                },
                "record_sha256": record.record_sha256,
                "producer_kind": artifact.producer_kind,
                "source_contract_ref": artifact.source_contract_ref,
                "debt_id": debt_id,
                "authority_receipt_id": C.UNAUTHENTICATED_AUTHORITY,
            }
        )
    occurrence_record_ids = sorted(
        {
            occurrence["record_id"]
            for occurrence in draft.lineage["occurrences"]
        },
        key=lambda item: item.encode("utf-8"),
    )
    report_entry_ids = sorted(
        [
            item["report_entry_id"]
            for item in draft.report_projection["report_entries"]
            + draft.report_projection["appendix_entries"]
        ]
        + [
            item["entry_id"]
            for item in draft.report_projection[
                "unmapped_finding_sections"
            ]
        ],
        key=lambda item: item.encode("utf-8"),
    )
    receipt = {
        "schema_version": C.HARVEST_RECEIPT_SCHEMA,
        "run_id": draft.run_id,
        "source_snapshot": {
            "source_snapshot_sha256": lock["source_snapshot_sha256"],
            "before_sha256": lock["source_snapshot_sha256"],
            "after_sha256": lock["source_snapshot_sha256"],
            "stable": True,
        },
        "artifact_roster": {
            "count": len(artifacts),
            "ids": sorted(
                (item["artifact_id"] for item in artifacts),
                key=lambda item: item.encode("utf-8"),
            ),
        },
        "record_reconciliation": {
            "discovered_count": (
                len(occurrence_record_ids)
                + len(nonfinding_rows)
                + len(debt_rows)
            ),
            "emitted_occurrence_count": len(occurrence_record_ids),
            "nonfinding_count": len(nonfinding_rows),
            "debt_count": len(debt_rows),
            "balanced": True,
            "occurrence_record_ids": occurrence_record_ids,
            "authenticated_nonfinding_records": sorted(
                nonfinding_rows, key=lambda item: item["record_id"].encode("utf-8")
            ),
            "explicit_debt_records": sorted(
                debt_rows, key=lambda item: item["record_id"].encode("utf-8")
            ),
            "partition_authority": None,
        },
        "candidate_roster": {
            "count": len(draft.candidate_set["candidates"]),
            "ids": [
                item["candidate_id"]
                for item in draft.candidate_set["candidates"]
            ],
        },
        "occurrence_roster": {
            "count": len(draft.lineage["occurrences"]),
            "ids": [
                item["occurrence_id"] for item in draft.lineage["occurrences"]
            ],
        },
        "edge_roster": {
            "count": len(draft.lineage["edges"]),
            "ids": [item["edge_id"] for item in draft.lineage["edges"]],
        },
        "report_entry_roster": {
            "count": len(report_entry_ids),
            "ids": report_entry_ids,
        },
        "redaction_summary": {"count": 0, "entries": []},
        "privacy_scan": {
            "status": "PASSED",
            "issue_count": 0,
            "policy_id": P.PUBLIC_STRUCTURAL_SCAN_POLICY_ID,
            "policy_version": P.PUBLIC_STRUCTURAL_SCAN_POLICY_VERSION,
            "claim_scope": "PUBLIC_STRUCTURAL_EXCLUSION_ONLY",
            "policy_sha256": P.public_structural_scan_policy_sha256(),
        },
        "export_status": {
            "state": "DEGRADED",
            "debts": [
                "LOCAL_UNAUTHENTICATED_EVIDENCE",
                *sorted(
                    {
                        debt["debt_code"]
                        for debt in draft.lineage["lineage_debts"]
                    }
                ),
            ],
        },
    }
    receipt = C.bind_embedded_sha256(receipt, "receipt_sha256")
    documents = {
        "run_manifest.json": manifest,
        "phase_events.jsonl": events,
        "candidate_findings.json": copy.deepcopy(draft.candidate_set),
        "candidate_lineage.json": copy.deepcopy(draft.lineage),
        "raw_outputs.json": copy.deepcopy(draft.raw_output_index),
        "report_projection.json": copy.deepcopy(draft.report_projection),
        "harvest_receipt.json": receipt,
    }
    objects = _object_bytes(draft)
    try:
        C.validate_bundle_payload_set(documents, lock, object_bytes=objects)
    except C.RunBundleContractError as exc:
        raise RunBundleExportError(
            "local materialization failed its closed contract"
        ) from exc
    return documents, objects


def _load_public_json(path: Path, *, label: str) -> dict[str, Any]:
    try:
        raw = P.read_stable_regular_bytes(
            path, maximum_bytes=16 << 20, label=label
        )
        value = C.strict_json_loads(raw, require_canonical=True)
        P.validate_public_payload(value)
    except (P.RunBundlePrivacyError, C.RunBundleContractError) as exc:
        raise RunBundleExportError(f"{label} is invalid") from exc
    if type(value) is not dict:
        raise RunBundleExportError(f"{label} must be an object")
    return value


def preflight(
    *,
    project_root: Path,
    scratchpad: Path,
    report: Path,
    public_case_lock: Path,
    schedule_row: Path,
) -> dict[str, Any]:
    assert_export_environment_gt_blind()
    lock = _load_public_json(public_case_lock, label="public case lock")
    C.validate_public_case_lock(lock)
    schedule = _schedule_row(
        _load_public_json(schedule_row, label="public schedule row")
    )
    inventory = S.inventory_run_sources(
        project_root=project_root,
        scratchpad=scratchpad,
        report=report,
        pipeline_kind=schedule["pipeline_kind"],
    )
    return {
        "schema_version": "plamen.runbundle-export-preflight.v1",
        "status": "READY",
        "trust_profile": schedule["trust_profile"],
        "publication_ceiling": schedule["trust_profile"],
        "public_case_lock_sha256": C.public_case_lock_sha256(lock),
        "input_snapshot_sha256": inventory.input_snapshot_sha256,
        "artifact_count": len(inventory.artifacts),
        "source_registry_sha256": inventory.registry_sha256,
        "exporter_policy_sha256": exporter_policy_sha256(),
    }


def export_from_run(
    *,
    project_root: Path,
    scratchpad: Path,
    report: Path,
    public_case_lock: Path,
    schedule_row: Path,
    out: Path,
) -> ExportReceipt:
    assert_export_environment_gt_blind()
    lock_raw = P.read_stable_regular_bytes(
        public_case_lock,
        maximum_bytes=16 << 20,
        label="public case lock",
    )
    lock = C.strict_json_loads(lock_raw, require_canonical=True)
    C.validate_public_case_lock(lock)
    schedule = _schedule_row(
        _load_public_json(schedule_row, label="public schedule row")
    )
    inventory = S.inventory_run_sources(
        project_root=project_root,
        scratchpad=scratchpad,
        report=report,
        pipeline_kind=schedule["pipeline_kind"],
    )
    draft = H.build_harvest_draft(
        run_id=schedule["run_id"],
        adapter_id=schedule["adapter"]["adapter_id"],
        inventory=inventory,
        inline_limit=INLINE_LIMIT,
    )
    documents, objects = materialize_local_documents(
        draft=draft,
        public_case_lock=lock,
        schedule_row=schedule,
    )

    def live_source_closure() -> str:
        return S.verify_live_source_closure(
            project_root=project_root,
            scratchpad=scratchpad,
            report=report,
            inventory=inventory,
        )

    return export_materialized_payload(
        documents=documents,
        exact_public_lock_bytes=lock_raw,
        object_bytes=objects,
        out=out,
        _live_source_authority_sha256=(
            inventory.live_source_authority_sha256
        ),
        _live_source_closure=live_source_closure,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="GT-blind real-audit RunBundle v2 exporter"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("preflight", "export"):
        command = sub.add_parser(name)
        command.add_argument("--project-root", type=Path, required=True)
        command.add_argument("--scratchpad", type=Path, required=True)
        command.add_argument("--report", type=Path, required=True)
        command.add_argument("--public-case-lock", type=Path, required=True)
        command.add_argument("--schedule-row", type=Path, required=True)
        if name == "export":
            command.add_argument("--out", type=Path, required=True)
    recover = sub.add_parser("recover")
    recover.add_argument("--journal", type=Path, required=True)
    recover.add_argument("--out", type=Path, required=True)
    recover.add_argument("--public-case-lock", type=Path, required=True)
    recover.add_argument("--project-root", type=Path)
    recover.add_argument("--scratchpad", type=Path)
    recover.add_argument("--report", type=Path)
    verify = sub.add_parser("verify")
    verify.add_argument("bundle", type=Path)
    verify.add_argument("--public-case-lock", type=Path, required=True)
    verify.add_argument(
        "--required-assurance",
        choices=(INTEGRITY_ONLY, AUTHENTICATED_EXPORT_ATTESTATION),
        default=INTEGRITY_ONLY,
    )
    return parser


def _print(value: Any) -> None:
    if isinstance(value, ExportReceipt):
        value = {
            "bundle_root": str(value.bundle_root),
            "run_id": value.run_id,
            "trust_profile": value.trust_profile,
            "bundle_seal_sha256": value.bundle_seal_sha256,
            "public_case_lock_sha256": value.public_case_lock_sha256,
            "publication_ceiling": value.publication_ceiling,
            "verification_sha256": value.verification_sha256,
            "bundle_integrity": value.bundle_integrity,
            "ready_schema": value.ready_schema,
            "ready_assurance": value.ready_assurance,
            "source_observation_claim": value.source_observation_claim,
            "cleanup_state": value.cleanup_state,
        }
    sys.stdout.buffer.write(C.canonical_document_bytes(value))


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "preflight":
            result = preflight(
                project_root=args.project_root,
                scratchpad=args.scratchpad,
                report=args.report,
                public_case_lock=args.public_case_lock,
                schedule_row=args.schedule_row,
            )
        elif args.command == "export":
            result = export_from_run(
                project_root=args.project_root,
                scratchpad=args.scratchpad,
                report=args.report,
                public_case_lock=args.public_case_lock,
                schedule_row=args.schedule_row,
                out=args.out,
            )
        elif args.command == "recover":
            lock_raw = P.read_stable_regular_bytes(
                args.public_case_lock,
                maximum_bytes=16 << 20,
                label="public case lock",
            )
            result = recover_export(
                journal=args.journal,
                exact_public_lock_bytes=lock_raw,
                out=args.out,
                project_root=args.project_root,
                scratchpad=args.scratchpad,
                report=args.report,
            )
        else:
            lock_raw = P.read_stable_regular_bytes(
                args.public_case_lock,
                maximum_bytes=16 << 20,
                label="public case lock",
            )
            result = verify_export(
                args.bundle,
                lock_raw,
                required_assurance=args.required_assurance,
            )
        _print(result)
        return 0
    except (
        RunBundleExportError,
        P.RunBundlePrivacyError,
        C.RunBundleContractError,
        S.RunBundleSourceError,
        H.RunBundleHarvestError,
    ) as exc:
        sys.stderr.write(f"runbundle-export: {exc}\n")
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = [
    "EXPORTER_PACKAGE",
    "EXPORTER_VERSION",
    "EXPORT_JOURNAL_SCHEMA",
    "AUTHENTICATED_EXPORT_ATTESTATION",
    "INTEGRITY_ONLY",
    "MUTATION_RECEIPT_SCHEMA",
    "ExportReceipt",
    "PUBLICATION_CLEANUP_DEBT_SCHEMA",
    "PUBLICATION_READY_SCHEMA",
    "PUBLICATION_RETIREMENT_SCHEMA",
    "PUBLIC_SCHEDULE_ROW_SCHEMA",
    "RunBundleAuthorityError",
    "RunBundleCleanupDebtError",
    "RunBundleExportError",
    "RunBundleExportInterrupted",
    "RunBundleMutationError",
    "RunBundleRecoveryRequiredError",
    "assert_export_environment_gt_blind",
    "export_from_run",
    "export_materialized_payload",
    "exporter_code_sha256",
    "exporter_policy_preimage",
    "exporter_policy_sha256",
    "main",
    "materialize_local_documents",
    "preflight",
    "publication_cleanup_debt_path",
    "publication_ready_path",
    "publication_retirement_path",
    "recover_export",
    "schema_set_sha256",
    "verify_export",
    "verify_export_integrity",
]
