"""Cold POSIX package/native installation transaction.

This is the transaction seam between the mutation-free source dispatcher and
the Darwin/Linux native builders.  The builder supplies transaction-grade
package and native effects; this module orders them, journals every durable
boundary, and publishes the ordinary public shim last.  A package receipt is
therefore an output of this transaction, never an admission prerequisite.
"""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any, Iterator

if os.name == "posix":
    import fcntl
else:  # pragma: no cover - module is dispatched only on POSIX
    fcntl = None

import posix_native_install_publication as public_shim


SOURCE_SCHEMA = "plamen.posix-native-install.source-freeze.v1"
PRIOR_SCHEMA = "plamen.posix-native-install.prior.v1"
STAGE_SCHEMA = "plamen.posix-native-install.stage.v1"
ARTIFACT_SCHEMA = "plamen.posix-native-install.artifact.v1"
JOURNAL_SCHEMA = "plamen.posix-native-install.journal.v1"
RECEIPT_SCHEMA = "plamen.posix-native-install.transaction-receipt.v1"
CONTROL_SUFFIX = (".local", "share", "plamen", "native-source-transactions")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_TXID = re.compile(r"[0-9a-f]{32}")
_MAX_JSON = 4 * 1024 * 1024
_STATES = {
    "ARMED", "PACKAGE_STAGED", "NATIVE_STAGED", "PUBLIC_STAGED",
    "PACKAGE_COMMITTED", "NATIVE_COMMITTED", "PUBLIC_COMMITTED",
    "COMMITTED", "ROLLING_BACK", "RECOVERY_REQUIRED", "ROLLED_BACK",
}


class PosixNativeInstallTransactionError(RuntimeError):
    """A bounded, fail-closed transaction error."""


class TEST_ONLY_ColdInstallCrash(BaseException):
    """Test-only process-loss simulation; intentionally bypasses rollback."""


def _fail(message: str) -> None:
    raise PosixNativeInstallTransactionError(message) from None


def _canonical(value: object) -> bytes:
    try:
        raw = (
            json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        _fail("install transaction authority is not canonical JSON")
    if len(raw) > _MAX_JSON:
        _fail("install transaction authority is oversized")
    return raw


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _safe_relative(value: object) -> str:
    if type(value) is not str or not value or "\x00" in value or "\\" in value:
        _fail("frozen source path is malformed")
    path = PurePosixPath(value)
    if path.is_absolute() or str(path) != value or any(part in {"", ".", ".."} for part in path.parts):
        _fail("frozen source path is unsafe")
    return value


def _regular_file(path: Path, *, maximum: int | None = None) -> tuple[os.stat_result, bytes]:
    fd = -1
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            _fail("frozen source member is not a direct regular file")
        if before.st_uid not in {0, os.getuid()} or stat.S_IMODE(before.st_mode) & (
            stat.S_IWGRP | stat.S_IWOTH
        ):
            _fail("frozen source member authority differs")
        if before.st_size <= 0 or (maximum is not None and before.st_size > maximum):
            _fail("frozen source member size differs")
        raw = b""
        while len(raw) < before.st_size:
            part = os.read(fd, before.st_size - len(raw))
            if not part:
                break
            raw += part
        after = os.fstat(fd)
    except OSError:
        _fail("frozen source member is unavailable")
    finally:
        if fd >= 0:
            os.close(fd)
    if (
        len(raw) != before.st_size
        or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    ):
        _fail("frozen source member changed during replay")
    return before, raw


def source_authority_from_validated_freeze(
    source_root: Path, freeze: object,
) -> dict[str, Any]:
    """Independently replay an already schema-decoded native source freeze.

    The builder remains responsible for its platform-specific roster definition
    check.  This seam repeats canonical-manifest and every-member byte checks so
    no mutation can occur between readiness/preflight and transaction arming.
    """

    root = source_root.absolute()
    if not root.is_dir() or root.is_symlink():
        _fail("frozen source root authority differs")
    if type(freeze) is not dict:
        _fail("native source freeze is malformed")
    supplied = dict(freeze)
    manifest_sha256 = supplied.pop("manifest_sha256", None)
    fields = {
        "platform", "roster_definition_sha256", "schema", "source_count",
        "source_roster_sha256", "sources", "version",
    }
    if (
        set(supplied) != fields
        or supplied.get("schema") != "plamen.native-production-source-freeze.v2"
        or supplied.get("version") != 2
        or type(supplied.get("version")) is not int
        or type(supplied.get("platform")) is not str
        or supplied["platform"] not in {"darwin-arm64", "linux-x86_64", "linux-arm64"}
        or _HEX64.fullmatch(supplied.get("roster_definition_sha256", "")) is None
        or _HEX64.fullmatch(supplied.get("source_roster_sha256", "")) is None
        or type(supplied.get("source_count")) is not int
        or supplied["source_count"] <= 0
        or type(supplied.get("sources")) is not list
        or len(supplied["sources"]) != supplied["source_count"]
    ):
        _fail("native source freeze envelope differs")
    manifest_raw = _canonical(supplied)
    observed_manifest_sha256 = hashlib.sha256(manifest_raw).hexdigest()
    if manifest_sha256 is not None and manifest_sha256 != observed_manifest_sha256:
        _fail("native source freeze manifest digest differs")
    roles: set[str] = set()
    paths: set[str] = set()
    for row in supplied["sources"]:
        if (
            type(row) is not dict
            or set(row) != {"path", "role", "sha256", "size"}
            or type(row.get("role")) is not str
            or not row["role"]
            or row["role"] in roles
            or _HEX64.fullmatch(row.get("sha256", "")) is None
            or type(row.get("size")) is not int
            or not 1 <= row["size"] <= 8 * 1024 * 1024
        ):
            _fail("native source freeze row differs")
        relative = _safe_relative(row["path"])
        if relative in paths:
            _fail("native source freeze path is duplicated")
        roles.add(row["role"]); paths.add(relative)
        _observed, raw = _regular_file(root / relative, maximum=8 * 1024 * 1024)
        if len(raw) != row["size"] or hashlib.sha256(raw).hexdigest() != row["sha256"]:
            _fail(f"frozen source member {row['role']} differs")
    return {
        "schema": SOURCE_SCHEMA,
        "platform": supplied["platform"],
        "source_root": str(root),
        "manifest_sha256": observed_manifest_sha256,
        "roster_definition_sha256": supplied["roster_definition_sha256"],
        "source_roster_sha256": supplied["source_roster_sha256"],
        "source_count": supplied["source_count"],
    }


def _validate_source(value: object) -> dict[str, Any]:
    fields = {
        "schema", "platform", "source_root", "manifest_sha256",
        "roster_definition_sha256", "source_roster_sha256", "source_count",
    }
    if (
        type(value) is not dict
        or set(value) != fields
        or value.get("schema") != SOURCE_SCHEMA
        or value.get("platform") not in {"darwin-arm64", "linux-x86_64", "linux-arm64"}
        or type(value.get("source_root")) is not str
        or not Path(value["source_root"]).is_absolute()
        or any(_HEX64.fullmatch(value.get(name, "")) is None for name in (
            "manifest_sha256", "roster_definition_sha256", "source_roster_sha256",
        ))
        or type(value.get("source_count")) is not int
        or value["source_count"] <= 0
    ):
        _fail("native source transaction authority is malformed")
    return dict(value)


def _validate_artifact(value: object, kind: str) -> dict[str, Any]:
    fields = {"schema", "kind", "path", "size", "sha256"}
    if kind == "package-receipt":
        fields.add("transaction_id")
    if (
        type(value) is not dict
        or set(value) != fields
        or value.get("schema") != ARTIFACT_SCHEMA
        or value.get("kind") != kind
        or type(value.get("path")) is not str
        or not Path(value["path"]).is_absolute()
        or type(value.get("size")) is not int
        or value["size"] <= 0
        or _HEX64.fullmatch(value.get("sha256", "")) is None
        or (
            kind == "package-receipt"
            and _TXID.fullmatch(value.get("transaction_id", "")) is None
        )
    ):
        _fail(f"{kind} authority is malformed")
    return dict(value)


def _validate_file_authority(value: object, path: Path) -> dict[str, Any]:
    if (
        type(value) is not dict
        or set(value) != {"schema", "path", "device", "inode", "mode", "size", "sha256"}
        or value.get("schema") != "plamen.posix-native-install.file-authority.v1"
        or value.get("path") != str(path)
        or any(type(value.get(name)) is not int for name in (
            "device", "inode", "mode", "size",
        ))
        or value.get("size", 0) <= 0
        or _HEX64.fullmatch(value.get("sha256", "")) is None
    ):
        _fail("installed file authority is malformed")
    return dict(value)


def _validate_prior(value: object, home: Path) -> dict[str, Any]:
    fields = {
        "schema", "state", "package_receipt", "native_install_receipt",
        "deployment_receipt", "public_launcher",
    }
    if type(value) is not dict or set(value) != fields or value.get("schema") != PRIOR_SCHEMA:
        _fail("prior installation observation is malformed")
    state = value.get("state")
    artifacts = (
        value["package_receipt"], value["native_install_receipt"],
        value["deployment_receipt"], value["public_launcher"],
    )
    if state == "ABSENT":
        if any(item is not None for item in artifacts):
            _fail("absent prior installation carries authority")
    elif state == "VERIFIED":
        if any(item is None for item in artifacts):
            _fail("verified prior installation is incomplete")
        _validate_artifact(value["package_receipt"], "package-receipt")
        _validate_artifact(value["native_install_receipt"], "native-install-receipt")
        _validate_artifact(value["deployment_receipt"], "deployment-receipt")
        _validate_file_authority(
            value["public_launcher"], home / ".local" / "bin" / "plamen",
        )
    else:
        _fail("prior installation is unauthenticated")
    return dict(value)


def _validate_stage(value: object, kind: str, transaction_id: str) -> dict[str, Any]:
    fields = {
        "schema", "kind", "transaction_id", "manifest_sha256", "artifact_count",
    }
    if kind == "package":
        fields |= {
            "interpreter_authority", "front_authority",
            "prestate_sha256",
        }
    if (
        type(value) is not dict
        or set(value) != fields
        or value.get("schema") != STAGE_SCHEMA
        or value.get("kind") != kind
        or value.get("transaction_id") != transaction_id
        or _HEX64.fullmatch(value.get("manifest_sha256", "")) is None
        or type(value.get("artifact_count")) is not int
        or value["artifact_count"] <= 0
        or (
            kind == "package"
            and _HEX64.fullmatch(value.get("prestate_sha256", "")) is None
        )
    ):
        _fail(f"{kind} stage authority is malformed")
    if kind == "package":
        _validate_file_authority(
            value["interpreter_authority"], Path(value["interpreter_authority"].get("path", "")),
        )
        _validate_file_authority(
            value["front_authority"], Path(value["front_authority"].get("path", "")),
        )
    return dict(value)


def _validate_native_receipts(value: object) -> dict[str, Any]:
    if type(value) is not dict or set(value) != {"install_receipt", "deployment_receipt"}:
        _fail("native receipt authority is malformed")
    return {
        "install_receipt": _validate_artifact(value["install_receipt"], "native-install-receipt"),
        "deployment_receipt": _validate_artifact(value["deployment_receipt"], "deployment-receipt"),
    }


def _mkdir_owned(parent_fd: int, name: str) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        return os.open(name, flags, dir_fd=parent_fd)
    except FileNotFoundError:
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
            os.fsync(parent_fd)
            return os.open(name, flags, dir_fd=parent_fd)
        except OSError:
            _fail("install control directory creation failed")
    except OSError:
        _fail("install control directory authority differs")


def _open_control(home: Path, transaction_id: str) -> tuple[int, int]:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        current = os.open(home, flags)
    except OSError:
        _fail("install account home authority differs")
    try:
        for component in CONTROL_SUFFIX:
            opened = _mkdir_owned(current, component)
            os.close(current); current = opened
            observed = os.fstat(current)
            if observed.st_uid != os.getuid() or stat.S_IMODE(observed.st_mode) & (
                stat.S_IWGRP | stat.S_IWOTH
            ):
                _fail("install control directory authority differs")
        root_fd = current
        transaction_fd = _mkdir_owned(root_fd, transaction_id)
        return root_fd, transaction_fd
    except BaseException:
        os.close(current)
        raise


def _strict_read(directory_fd: int, name: str) -> dict[str, Any] | None:
    try:
        fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory_fd)
    except FileNotFoundError:
        return None
    except OSError:
        _fail("install transaction record authority differs")
    try:
        observed = os.fstat(fd)
        if (
            not stat.S_ISREG(observed.st_mode)
            or observed.st_uid != os.getuid()
            or stat.S_IMODE(observed.st_mode) != 0o600
            or not 1 <= observed.st_size <= _MAX_JSON
        ):
            _fail("install transaction record authority differs")
        raw = b""
        while len(raw) < observed.st_size:
            part = os.read(fd, observed.st_size - len(raw))
            if not part:
                break
            raw += part
        after = os.fstat(fd)
        if len(raw) != observed.st_size or (
            observed.st_dev, observed.st_ino, observed.st_mode,
            observed.st_uid, observed.st_gid, observed.st_nlink,
            observed.st_size, observed.st_mtime_ns, observed.st_ctime_ns,
        ) != (
            after.st_dev, after.st_ino, after.st_mode,
            after.st_uid, after.st_gid, after.st_nlink,
            after.st_size, after.st_mtime_ns, after.st_ctime_ns,
        ):
            _fail("install transaction record changed during read")
    finally:
        os.close(fd)
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeError, ValueError):
        _fail("install transaction record is malformed")
    if type(value) is not dict or _canonical(value) != raw:
        _fail("install transaction record is not canonical")
    return value


def _atomic_write(directory_fd: int, name: str, value: object) -> None:
    raw = _canonical(value)
    temporary = f".{name}.{os.getpid()}.tmp"
    fd = -1
    try:
        fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory_fd,
        )
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                _fail("install transaction record write failed")
            view = view[count:]
        os.fsync(fd); os.close(fd); fd = -1
        os.replace(temporary, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        os.fsync(directory_fd)
    except OSError:
        _fail("install transaction record publication failed")
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError:
            pass


@contextmanager
def _writer_lock(root_fd: int) -> Iterator[None]:
    fd = -1
    try:
        fd = os.open(
            ".install.lock",
            os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=root_fd,
        )
        observed = os.fstat(fd)
        if (
            not stat.S_ISREG(observed.st_mode)
            or observed.st_uid != os.getuid()
            or stat.S_IMODE(observed.st_mode) != 0o600
        ):
            _fail("install transaction writer lock authority differs")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    except OSError:
        _fail("install transaction writer lock failed")
    finally:
        if fd >= 0:
            os.close(fd)


def _new_journal(
    transaction_id: str, plan_sha256: str, source: dict[str, Any], prior: dict[str, Any],
) -> dict[str, Any]:
    journal = {
        "schema": JOURNAL_SCHEMA,
        "transaction_id": transaction_id,
        "plan_sha256": plan_sha256,
        "state": "ARMED",
        "source_authority": source,
        "prior": prior,
        "package_stage": None,
        "native_stage": None,
        "public_plan": None,
        "package_receipt": None,
        "native_receipts": None,
        "error": None,
    }
    journal["journal_sha256"] = _digest(journal)
    return journal


def _seal_journal(journal: dict[str, Any]) -> dict[str, Any]:
    value = dict(journal)
    value.pop("journal_sha256", None)
    value["journal_sha256"] = _digest(value)
    return value


def _validate_journal(
    value: object, transaction_id: str, plan_sha256: str,
) -> dict[str, Any]:
    fields = {
        "schema", "transaction_id", "plan_sha256", "state", "source_authority",
        "prior", "package_stage", "native_stage", "public_plan",
        "package_receipt", "native_receipts", "error", "journal_sha256",
    }
    if (
        type(value) is not dict
        or set(value) != fields
        or value.get("schema") != JOURNAL_SCHEMA
        or value.get("transaction_id") != transaction_id
        or value.get("plan_sha256") != plan_sha256
        or value.get("state") not in _STATES
        or _HEX64.fullmatch(value.get("journal_sha256", "")) is None
    ):
        _fail("install transaction journal envelope differs")
    unsigned = dict(value); digest = unsigned.pop("journal_sha256")
    if _digest(unsigned) != digest:
        _fail("install transaction journal digest differs")
    _validate_source(value["source_authority"])
    return dict(value)


def _transition(
    transaction_fd: int, journal: dict[str, Any], state: str, fault: Any,
) -> dict[str, Any]:
    journal = dict(journal); journal["state"] = state; journal["error"] = None
    journal = _seal_journal(journal)
    _atomic_write(transaction_fd, "journal.json", journal)
    if fault is not None:
        fault(state)
    return journal


def _effect(effects: object, name: str):
    value = getattr(effects, name, None)
    if not callable(value):
        _fail(f"install transaction effect {name} is unavailable")
    return value


def _terminal_receipt(journal: dict[str, Any]) -> dict[str, Any]:
    value = {
        "schema": RECEIPT_SCHEMA,
        "transaction_id": journal["transaction_id"],
        "plan_sha256": journal["plan_sha256"],
        "source_authority": journal["source_authority"],
        "package_receipt": journal["package_receipt"],
        "native_install_receipt": journal["native_receipts"]["install_receipt"],
        "deployment_receipt": journal["native_receipts"]["deployment_receipt"],
        "public_launcher": public_shim.validate_published(journal["public_plan"]),
        "state": "COMMITTED",
    }
    value["receipt_sha256"] = _digest(value)
    return value


def _validate_terminal(
    value: object, journal: dict[str, Any], effects: object,
) -> dict[str, Any]:
    fields = {
        "schema", "transaction_id", "plan_sha256", "source_authority",
        "package_receipt", "native_install_receipt", "deployment_receipt",
        "public_launcher", "state", "receipt_sha256",
    }
    if (
        type(value) is not dict
        or set(value) != fields
        or value.get("schema") != RECEIPT_SCHEMA
        or value.get("transaction_id") != journal["transaction_id"]
        or value.get("plan_sha256") != journal["plan_sha256"]
        or value.get("source_authority") != journal["source_authority"]
        or value.get("state") != "COMMITTED"
        or _HEX64.fullmatch(value.get("receipt_sha256", "")) is None
    ):
        _fail("install transaction terminal receipt differs")
    unsigned = dict(value); digest = unsigned.pop("receipt_sha256")
    if _digest(unsigned) != digest:
        _fail("install transaction terminal receipt digest differs")
    package = _validate_artifact(value["package_receipt"], "package-receipt")
    native = _validate_native_receipts({
        "install_receipt": value["native_install_receipt"],
        "deployment_receipt": value["deployment_receipt"],
    })
    _effect(effects, "validate_package_receipt")(package)
    _effect(effects, "validate_native_receipts")(native, package)
    observed_public = public_shim.validate_published(journal["public_plan"])
    if any(
        observed_public[key] != value["public_launcher"][key]
        for key in ("path", "mode", "size", "sha256")
    ):
        _fail("install transaction public launcher receipt differs")
    return dict(value)


def _rollback(
    transaction_fd: int, journal: dict[str, Any], effects: object,
) -> dict[str, Any]:
    journal = dict(journal); journal["state"] = "ROLLING_BACK"; journal["error"] = None
    journal = _seal_journal(journal); _atomic_write(transaction_fd, "journal.json", journal)
    try:
        if journal["public_plan"] is not None:
            public_shim.rollback(journal["public_plan"])
        if journal["native_receipts"] is not None:
            _effect(effects, "rollback_native")(
                journal["native_receipts"], journal["prior"],
            )
        if journal["package_receipt"] is not None:
            _effect(effects, "rollback_package")(
                journal["package_receipt"], journal["prior"],
            )
        _effect(effects, "cleanup_stages")(
            journal["package_stage"], journal["native_stage"],
        )
    except Exception as exc:
        journal["state"] = "RECOVERY_REQUIRED"
        journal["error"] = f"{type(exc).__name__}:{str(exc)[:1000]}"
        journal = _seal_journal(journal); _atomic_write(transaction_fd, "journal.json", journal)
        raise
    journal["state"] = "ROLLED_BACK"; journal["error"] = None
    journal = _seal_journal(journal); _atomic_write(transaction_fd, "journal.json", journal)
    return journal


def execute_cold_install_transaction(
    *, home: Path, source_authority: object, effects: object,
    fault: Any = None,
) -> dict[str, Any]:
    """Stage, commit, recover, or exactly roll back one package/native install.

    Effect methods are deliberately narrow and must themselves be idempotent,
    receipt-validating subsystem transactions.  This coordinator never turns
    their Python return values into native authority; it replays each subsystem
    validator before publication and on every terminal replay.
    """

    account = home.absolute()
    source = _validate_source(source_authority)
    if not account.is_dir() or account.is_symlink():
        _fail("install account home authority differs")
    plan = {
        "schema": "plamen.posix-native-install.plan.v1",
        "home": str(account), "source_authority": source,
    }
    plan_sha256 = _digest(plan)
    transaction_id = hashlib.sha256(
        b"PLAMEN-POSIX-NATIVE-COLD-INSTALL-V1\0" + _canonical(plan)
    ).hexdigest()[:32]

    # A fresh install classifies its predecessor before creating controls.  A
    # recovery may already be between package and native commit, so its durable
    # journal (opened no-follow below) is the authority for the predecessor;
    # asking a cold-state observer to bless that expected partial state would
    # recreate the original circular gate.
    journal_hint = account.joinpath(
        *CONTROL_SUFFIX, transaction_id, "journal.json",
    )
    prior = None
    if not os.path.lexists(journal_hint):
        prior = _validate_prior(
            _effect(effects, "observe_prior")(account), account,
        )
    root_fd, transaction_fd = _open_control(account, transaction_id)
    transaction_root = account.joinpath(*CONTROL_SUFFIX, transaction_id)
    try:
        with _writer_lock(root_fd):
            existing = _strict_read(transaction_fd, "journal.json")
            if existing is None:
                if prior is None:
                    prior = _validate_prior(
                        _effect(effects, "observe_prior")(account), account,
                    )
                # Repeat beneath the single-writer lease to close the fresh
                # admission race.  Recovery intentionally does not classify
                # its expected partial live state as a new predecessor.
                locked_prior = _validate_prior(
                    _effect(effects, "observe_prior")(account), account,
                )
                if locked_prior != prior:
                    _fail("prior installation changed before transaction arm")
                journal = _new_journal(transaction_id, plan_sha256, source, prior)
                _atomic_write(transaction_fd, "journal.json", journal)
                if fault is not None:
                    fault("ARMED")
            else:
                journal = _validate_journal(existing, transaction_id, plan_sha256)
                prior = _validate_prior(journal["prior"], account)
                if journal["state"] == "COMMITTED":
                    terminal = _strict_read(transaction_fd, "receipt.json")
                    if terminal is None:
                        _fail("committed install transaction terminal is absent")
                    result = _validate_terminal(terminal, journal, effects)
                    # A process can die after the terminal transition but
                    # before private residue cleanup.  Cleanup is itself exact
                    # and idempotent, so terminal replay closes that window.
                    public_shim.cleanup(journal["public_plan"])
                    _effect(effects, "cleanup_stages")(
                        journal["package_stage"], journal["native_stage"],
                    )
                    return result
                if journal["state"] in {"ROLLING_BACK", "RECOVERY_REQUIRED"}:
                    journal = _rollback(transaction_fd, journal, effects)
                if journal["state"] == "ROLLED_BACK":
                    current = _validate_prior(
                        _effect(effects, "observe_prior")(account), account,
                    )
                    if current != prior:
                        _fail("rolled-back installation predecessor differs")
                    journal = _new_journal(transaction_id, plan_sha256, source, prior)
                    _atomic_write(transaction_fd, "journal.json", journal)

            try:
                if journal["package_stage"] is None:
                    package_stage = _validate_stage(
                        _effect(effects, "stage_package")(
                            account, transaction_root, source,
                        ),
                        "package", transaction_id,
                    )
                    journal["package_stage"] = package_stage
                    journal = _transition(transaction_fd, journal, "PACKAGE_STAGED", fault)
                _effect(effects, "validate_package_stage")(
                    journal["package_stage"], source,
                )

                if journal["native_stage"] is None:
                    native_stage = _validate_stage(
                        _effect(effects, "stage_native")(
                            account, transaction_root, source, journal["package_stage"],
                        ),
                        "native", transaction_id,
                    )
                    journal["native_stage"] = native_stage
                    journal = _transition(transaction_fd, journal, "NATIVE_STAGED", fault)
                _effect(effects, "validate_native_stage")(
                    journal["native_stage"], source, journal["package_stage"],
                )

                if journal["public_plan"] is None:
                    package_stage = journal["package_stage"]
                    public_plan = public_shim.prepare_publication(
                        home=str(account), transaction_id=transaction_id,
                        interpreter=package_stage["interpreter_authority"]["path"],
                        front_script=package_stage["front_authority"]["path"],
                        interpreter_authority=package_stage["interpreter_authority"],
                        front_authority=package_stage["front_authority"],
                        prior_authority=prior["public_launcher"],
                    )
                    journal["public_plan"] = public_plan
                    journal = _transition(transaction_fd, journal, "PUBLIC_STAGED", fault)

                if journal["package_receipt"] is None:
                    package_receipt = _validate_artifact(
                        _effect(effects, "commit_package")(
                            journal["package_stage"], source,
                        ),
                        "package-receipt",
                    )
                    _effect(effects, "validate_package_receipt")(package_receipt)
                    journal["package_receipt"] = package_receipt
                    journal = _transition(transaction_fd, journal, "PACKAGE_COMMITTED", fault)
                else:
                    _effect(effects, "validate_package_receipt")(
                        journal["package_receipt"],
                    )

                if journal["native_receipts"] is None:
                    native_receipts = _validate_native_receipts(
                        _effect(effects, "commit_native")(
                            journal["native_stage"], source,
                            journal["package_receipt"],
                        )
                    )
                    _effect(effects, "validate_native_receipts")(
                        native_receipts, journal["package_receipt"],
                    )
                    journal["native_receipts"] = native_receipts
                    journal = _transition(transaction_fd, journal, "NATIVE_COMMITTED", fault)
                else:
                    _effect(effects, "validate_native_receipts")(
                        journal["native_receipts"], journal["package_receipt"],
                    )

                published = public_shim.publish(journal["public_plan"])
                journal = _transition(transaction_fd, journal, "PUBLIC_COMMITTED", fault)
                terminal = _terminal_receipt(journal)
                if any(
                    terminal["public_launcher"][key] != published[key]
                    for key in ("path", "mode", "size", "sha256")
                ):
                    _fail("public launcher changed before terminal publication")
                _atomic_write(transaction_fd, "receipt.json", terminal)
                journal = _transition(transaction_fd, journal, "COMMITTED", fault)
                public_shim.cleanup(journal["public_plan"])
                _effect(effects, "cleanup_stages")(
                    journal["package_stage"], journal["native_stage"],
                )
                return _validate_terminal(terminal, journal, effects)
            except Exception as operation_error:
                try:
                    _rollback(transaction_fd, journal, effects)
                except Exception as rollback_error:
                    raise PosixNativeInstallTransactionError(
                        "install failed and authenticated rollback is incomplete: "
                        f"{type(operation_error).__name__}:{str(operation_error)[:500]} | "
                        f"{type(rollback_error).__name__}:{str(rollback_error)[:500]}"
                    ) from operation_error
                raise
    finally:
        os.close(transaction_fd); os.close(root_fd)


__all__ = [
    "ARTIFACT_SCHEMA", "JOURNAL_SCHEMA", "PRIOR_SCHEMA", "RECEIPT_SCHEMA",
    "SOURCE_SCHEMA", "STAGE_SCHEMA", "PosixNativeInstallTransactionError",
    "TEST_ONLY_ColdInstallCrash", "execute_cold_install_transaction",
    "source_authority_from_validated_freeze",
]
