"""Authenticated additive candidate authority for post-verification discovery.

The T8 verification queue is an immutable pre-verification publication.  A
verifier can nevertheless notice a new candidate.  This module records those
late candidates in a separately authenticated delta and exposes the only
supported report candidate universe: the exact union of the bound T8 queue and
that delta.

The delta is proposal-only.  It cannot mutate the queue or inventory, certify a
verdict, or become terminal authority.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import tempfile
from typing import Any, Iterable, Mapping

from post_verify_lifecycle import parse_post_verify_candidate_proposals
from queue_work_items import (
    QueueWorkItem,
    QueueWorkPlan,
    queue_record_set_digest,
    queue_records_from_json,
    validate_queue_work_items,
)
from verification_operator_consumers import (
    ConsumerAuthorityError,
    validate_verifier_operator_consumer_authority,
)


SCHEMA = "plamen.post_verify_candidate_delta.v1"
ARTIFACT = "post_verify_candidate_delta.json"
BASE_QUEUE = "verification_queue.work_items.json"
QUEUE_PLAN_AUTHORITY = (
    "_live_verify_queue_transaction/t0/resolved_plan.json"
)
QUEUE_FINAL_RECEIPT = "verify_queue_transaction.receipt.json"
QUEUE_WORK_PLAN = "verification_queue.work_plan.json"
QUEUE_MARKDOWN = "verification_queue.md"
CHECKPOINT_AUTHORITY = "_v2_checkpoint.json"
ARTIFACT_LEDGER = "_artifact_state.json"

# A dataclass is a useful immutable value carrier, but its public constructor is
# not an authority boundary.  The identity-only seal is deliberately excluded
# from equality and representation: only this module can mint a capability
# after validating and freezing the exact T9 postimage.
_PUBLICATION_CAPABILITY_SEAL = object()

# Canonical report derivation runs against an off-live, byte-exact projection
# of the authenticated report inputs.  That projection deliberately does not
# contain the complete private T0--T9 producer graph, so treating its copied
# live markers as a fresh live transaction would reject every safe stage on
# physical-file identity alone.  The context value is an in-process,
# root-bound capability minted only after the live publication and every
# report-universe input have replayed and matched the staged bytes.
_AUTHENTICATED_HISTORICAL_STAGE: ContextVar[tuple[str, str] | None] = (
    ContextVar("plamen_authenticated_historical_stage", default=None)
)

_HEX = frozenset("0123456789abcdef")
_TOP_FIELDS = frozenset({
    "schema_version", "run_id", "status", "base_queue_binding",
    "source_binding_count", "source_bindings", "source_set_digest",
    "source_candidate_count", "row_count", "rows", "debt_count", "debts",
    "delta_record_set_digest", "union_record_count",
    "union_record_set_digest", "terminal_authority", "delta_digest",
})
_BASE_FIELDS = frozenset({
    "artifact", "sha256", "size_bytes", "record_count",
    "record_set_digest",
})
_SOURCE_FIELDS = frozenset({
    "artifact", "sha256", "size_bytes", "source_kind",
})
_ROW_FIELDS = frozenset({
    "work_item", "work_item_digest", "source_kind", "source_artifact",
    "source_artifact_sha256", "source_record_ordinal",
    "source_record_digest", "claim",
})
_CLAIM_FIELDS = frozenset({"premise", "harm", "evidence"})
_DEBT_FIELDS = frozenset({
    "source_artifact", "source_record_identity", "reason_code", "detail",
})
_STATUSES = frozenset({"CLEAN", "COMPLETED_WITH_DEBT"})


class PostVerifyCandidateDeltaError(ValueError):
    """The post-verification candidate universe cannot be authenticated."""


@dataclass(frozen=True, slots=True)
class BoundReportCandidate:
    """One report candidate with its exact source authority binding."""

    item: QueueWorkItem
    source_kind: str
    source_artifact: str
    source_artifact_sha256: str
    source_record_ordinal: int
    source_record_digest: str
    claim: Mapping[str, str]
    authority_artifact: str
    authority_artifact_sha256: str
    authority_record_digest: str
    claim_digest: str


@dataclass(frozen=True, slots=True)
class CandidateUniverseAuthority:
    """Authenticated candidate denominator and every transitive input."""

    run_id: str
    base_queue_binding: Mapping[str, Any]
    delta_binding: Mapping[str, Any] | None
    union_record_count: int
    union_record_set_digest: str
    source_debts: tuple[Mapping[str, str], ...]
    input_artifacts: tuple[str, ...]
    candidates: tuple[BoundReportCandidate, ...]


@dataclass(frozen=True, slots=True)
class AuthenticatedQueuePublication:
    """In-process capability proving the exact ledger-committed T9 base."""

    scratchpad_root: str
    project_root: str
    run_id: str
    plan_digest: str
    final_receipt_sha256: str
    active_output_denominator: tuple[str, ...]
    base_queue_binding: Mapping[str, Any]
    work_plan_digest: str
    items: tuple[QueueWorkItem, ...]
    safe_to_consume: bool = True
    artifact_bindings: tuple[tuple[str, str, int], ...] = ()
    input_artifacts: tuple[str, ...] = ()
    _seal: object | None = field(
        default=None,
        init=False,
        repr=False,
        compare=False,
    )


@dataclass(frozen=True, slots=True)
class LateCandidateDeliveryStatus:
    """Authenticated late delivery status with no negative authority."""

    candidate_id: str
    delivery_state: str
    verifier_status: str
    verify_artifact: str | None
    verify_sha256: str | None
    delivery_artifact_sha256: str
    source_candidate_digest: str
    terminal_negative_authority: bool = False


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _exact(
    value: Any,
    fields: frozenset[str],
    context: str,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise PostVerifyCandidateDeltaError(f"{context} must be an object")
    actual = set(value)
    if actual != fields:
        missing = sorted(fields - actual)
        extra = sorted(actual - fields)
        raise PostVerifyCandidateDeltaError(
            f"{context} fields mismatch; missing={missing}; extra={extra}"
        )
    return dict(value)


def _text(value: Any, field: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise PostVerifyCandidateDeltaError(f"{field} must be text")
    if not allow_empty and not value.strip():
        raise PostVerifyCandidateDeltaError(f"{field} cannot be empty")
    return value


def _count(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise PostVerifyCandidateDeltaError(
            f"{field} must be a non-negative integer"
        )
    return value


def _hex(value: Any, field: str, *, allow_empty: bool = False) -> str:
    if allow_empty and value == "":
        return ""
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in _HEX for char in value)
    ):
        raise PostVerifyCandidateDeltaError(
            f"{field} must be a lowercase SHA-256 digest"
        )
    return value


def _strict_json(raw: bytes, context: str) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise PostVerifyCandidateDeltaError(
            f"{context} is not strict UTF-8"
        ) from exc

    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in values:
            if key in out:
                raise PostVerifyCandidateDeltaError(
                    f"{context} contains duplicate JSON key {key!r}"
                )
            out[key] = value
        return out

    def constant(value: str) -> None:
        raise PostVerifyCandidateDeltaError(
            f"{context} contains invalid JSON constant {value}"
        )

    try:
        value = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_constant=constant,
        )
    except PostVerifyCandidateDeltaError:
        raise
    except Exception as exc:
        raise PostVerifyCandidateDeltaError(
            f"{context} is not valid JSON: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise PostVerifyCandidateDeltaError(f"{context} must contain an object")
    return value


def _safe_source(root: Path, relative: str) -> tuple[Path, bytes]:
    name = _text(relative, "source artifact")
    pure = PurePosixPath(name.replace("\\", "/"))
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise PostVerifyCandidateDeltaError(
            f"source artifact is not a safe relative path: {relative!r}"
        )
    path = root.joinpath(*pure.parts)
    try:
        if path.is_symlink():
            raise PostVerifyCandidateDeltaError(
                f"source artifact cannot be a symlink: {relative}"
            )
        resolved_root = root.resolve(strict=True)
        resolved = path.resolve(strict=True)
        if os.path.commonpath((str(resolved_root), str(resolved))) != str(
            resolved_root
        ):
            raise PostVerifyCandidateDeltaError(
                f"source artifact escapes the scratchpad: {relative}"
            )
        if not resolved.is_file():
            raise PostVerifyCandidateDeltaError(
                f"source artifact is not a file: {relative}"
            )
        return resolved, resolved.read_bytes()
    except PostVerifyCandidateDeltaError:
        raise
    except Exception as exc:
        raise PostVerifyCandidateDeltaError(
            f"source artifact cannot be read exactly: {relative}: {exc}"
        ) from exc


def _path_present(path: Path) -> bool:
    """Return presence without allowing a dangling symlink to look absent."""

    return path.exists() or path.is_symlink()


def _live_ledger_reference(value: Any) -> bool:
    """Recognize a live verify-queue transaction in the parsed ledger."""

    if isinstance(value, str):
        normalized = value.replace("\\", "/").casefold()
        return any(token in normalized for token in (
            "_live_verify_queue_transaction",
            "t9.live_receipt_last_cas",
            "verify_queue_transaction.receipt.json",
        ))
    if isinstance(value, Mapping):
        return any(
            _live_ledger_reference(key) or _live_ledger_reference(item)
            for key, item in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(_live_ledger_reference(item) for item in value)
    return False


def _live_publication_residue(root: Path) -> tuple[str, ...]:
    """Enumerate signals that commit a reader to the live T9 authority path."""

    signals: list[str] = []
    for relative in (QUEUE_FINAL_RECEIPT, QUEUE_PLAN_AUTHORITY):
        if _path_present(root / relative):
            signals.append(relative)
    private_root = root / "_live_verify_queue_transaction"
    if _path_present(private_root):
        signals.append("_live_verify_queue_transaction")

    ledger_path = root / ARTIFACT_LEDGER
    if _path_present(ledger_path):
        try:
            _path, raw = _safe_source(root, ARTIFACT_LEDGER)
            ledger = _strict_json(raw, ARTIFACT_LEDGER)
        except PostVerifyCandidateDeltaError:
            # An unreadable ledger containing a recognizable live token is
            # still evidence of a live cutover.  It must fail closed through
            # the authenticated loader rather than being treated as legacy.
            try:
                raw = ledger_path.read_bytes()
            except OSError:
                raw = b""
            lowered = raw.lower().replace(b"\\", b"/")
            if any(token in lowered for token in (
                b"_live_verify_queue_transaction",
                b"t9.live_receipt_last_cas",
                b"verify_queue_transaction.receipt.json",
            )):
                signals.append(f"{ARTIFACT_LEDGER}:live-reference")
        else:
            if _live_ledger_reference(ledger):
                signals.append(f"{ARTIFACT_LEDGER}:live-reference")
    return tuple(sorted(set(signals)))


def _checkpoint_run_id(root: Path, *, required_live: bool) -> str:
    """Read the current checkpoint identity without permissive JSON fallback."""

    path = root / CHECKPOINT_AUTHORITY
    if not _path_present(path):
        return ""
    try:
        _source, raw = _safe_source(root, CHECKPOINT_AUTHORITY)
        payload = _strict_json(raw, CHECKPOINT_AUTHORITY)
    except PostVerifyCandidateDeltaError:
        if required_live:
            raise
        return ""
    value = payload.get("run_id")
    if value is None:
        return ""
    if not isinstance(value, str) or not value.strip():
        if required_live:
            raise PostVerifyCandidateDeltaError(
                "current checkpoint run authority is malformed"
            )
        return ""
    return value.strip()


def _capture_artifact(
    root: Path,
    relative: str,
    *,
    allow_absent: bool,
) -> bytes | None:
    path = root.joinpath(*PurePosixPath(relative).parts)
    if not _path_present(path):
        if allow_absent:
            return None
        raise PostVerifyCandidateDeltaError(
            f"T9 publication artifact is absent: {relative}"
        )
    _source, raw = _safe_source(root, relative)
    return raw


def _capture_t9_validation_state(
    root: Path,
    declared_public: tuple[str, ...],
) -> dict[str, bytes | None]:
    """Freeze every local byte consulted as live T9 publication authority."""

    names = {
        QUEUE_PLAN_AUTHORITY,
        QUEUE_FINAL_RECEIPT,
        ARTIFACT_LEDGER,
        CHECKPOINT_AUTHORITY,
        *declared_public,
    }
    private_root = root / "_live_verify_queue_transaction"
    if private_root.is_symlink():
        raise PostVerifyCandidateDeltaError(
            "T9 private authority root cannot be a symlink"
        )
    if private_root.is_dir():
        for path in private_root.rglob("*"):
            if path.is_symlink():
                raise PostVerifyCandidateDeltaError(
                    "T9 private authority contains a symlink"
                )
            if path.is_file():
                names.add(path.relative_to(root).as_posix())
    return {
        relative: _capture_artifact(
            root,
            relative,
            allow_absent=relative not in {
                QUEUE_PLAN_AUTHORITY,
                QUEUE_FINAL_RECEIPT,
            },
        )
        for relative in sorted(names)
    }


def _publication_binding_rows(
    snapshot: Mapping[str, bytes | None],
    names: Iterable[str],
) -> tuple[tuple[str, str, int], ...]:
    rows = []
    for relative in sorted(set(names)):
        raw = snapshot.get(relative)
        if raw is None:
            raise PostVerifyCandidateDeltaError(
                f"T9 active publication artifact is absent: {relative}"
            )
        rows.append((relative, _sha(raw), len(raw)))
    return tuple(rows)


def _require_publication_capability(
    root: Path,
    publication: AuthenticatedQueuePublication,
    *,
    run_id: str | None = None,
) -> None:
    """Reject constructed, stale, cross-root, or cross-run capability values."""

    if (
        not isinstance(publication, AuthenticatedQueuePublication)
        or publication._seal is not _PUBLICATION_CAPABILITY_SEAL
        or publication.safe_to_consume is not True
    ):
        raise PostVerifyCandidateDeltaError(
            "authenticated T9 publication capability was not minted by the "
            "publication authority"
        )
    try:
        resolved_root = str(Path(root).resolve(strict=False))
    except OSError as exc:
        raise PostVerifyCandidateDeltaError(
            f"candidate-universe scratchpad cannot be resolved: {exc}"
        ) from exc
    if publication.scratchpad_root != resolved_root:
        raise PostVerifyCandidateDeltaError(
            "authenticated T9 publication capability belongs to another "
            "scratchpad"
        )
    requested = str(run_id or "").strip()
    if requested and requested != publication.run_id:
        raise PostVerifyCandidateDeltaError(
            "candidate-universe run differs from authenticated T9 publication"
        )
    checkpoint_run = _checkpoint_run_id(root, required_live=True)
    if checkpoint_run and checkpoint_run != publication.run_id:
        raise PostVerifyCandidateDeltaError(
            "current checkpoint run differs from authenticated T9 publication"
        )
    # A capability carries an immutable semantic snapshot.  Re-checking all
    # bound files prevents it from being reused after publication replacement.
    for relative, expected_sha, expected_size in publication.artifact_bindings:
        raw = _capture_artifact(root, relative, allow_absent=False)
        assert raw is not None
        if len(raw) != expected_size or _sha(raw) != expected_sha:
            raise PostVerifyCandidateDeltaError(
                f"T9 publication authority changed after capability mint: "
                f"{relative}"
            )


def _select_current_queue_publication(
    root: Path,
    *,
    run_id: str | None,
    project_root: Path | None = None,
) -> AuthenticatedQueuePublication | None:
    """Select live T9 or an explicitly residue-free historical typed run."""

    stage_capability = _AUTHENTICATED_HISTORICAL_STAGE.get()
    if stage_capability is not None:
        try:
            resolved_root = str(Path(root).resolve(strict=True))
        except OSError as exc:
            raise PostVerifyCandidateDeltaError(
                f"candidate-universe stage cannot be resolved: {exc}"
            ) from exc
        stage_root, stage_run_id = stage_capability
        if resolved_root == stage_root:
            requested_run = str(run_id or "").strip()
            if requested_run and requested_run != stage_run_id:
                raise PostVerifyCandidateDeltaError(
                    "candidate-universe stage run differs from its "
                    "authenticated projection capability"
                )
            return None

    residue = _live_publication_residue(root)
    if not residue:
        # This is the only legacy compatibility boundary.  It is explicit:
        # absence of every private, receipt, and ledger live marker, not merely
        # absence of one convenient file.
        return None
    try:
        return load_authenticated_queue_publication(
            root,
            project_root=(
                Path(project_root)
                if project_root is not None
                else root.parent
            ),
            run_id=run_id,
        )
    except PostVerifyCandidateDeltaError as exc:
        raise PostVerifyCandidateDeltaError(
            "live T9 publication residue cannot downgrade to historical "
            f"typed authority ({', '.join(residue)}): {exc}"
        ) from exc


@contextmanager
def authenticated_historical_typed_stage_scope(
    live_scratchpad: Path,
    staged_scratchpad: Path,
    *,
    run_id: str,
):
    """Mint a bounded typed-history capability for one canonical stage.

    The live T9 graph is replayed first.  Every transitive input used by the
    authenticated report universe must then be present in the isolated stage
    with byte-for-byte equality.  Only that exact resolved stage root may use
    the historical typed reader while the scope is active; all live and other
    roots retain the ordinary fail-closed residue rule.
    """

    live = Path(live_scratchpad).resolve(strict=True)
    stage = Path(staged_scratchpad).resolve(strict=True)
    expected_parent = (live / ".pio" / "ri").resolve(strict=False)
    try:
        contained = os.path.commonpath((str(stage), str(expected_parent))) == str(
            expected_parent
        )
    except ValueError:
        contained = False
    if not contained or stage.name != "staged_target" or stage == live:
        raise PostVerifyCandidateDeltaError(
            "historical typed stage is outside the canonical recovery root"
        )

    publication = load_authenticated_queue_publication(
        live,
        project_root=live.parent,
        run_id=run_id,
    )
    authority = load_candidate_universe_authority(
        live,
        run_id=run_id,
        authenticated_publication=publication,
    )
    for relative in authority.input_artifacts:
        live_raw = _capture_artifact(live, relative, allow_absent=False)
        stage_raw = _capture_artifact(stage, relative, allow_absent=False)
        if stage_raw != live_raw:
            raise PostVerifyCandidateDeltaError(
                "historical typed stage differs from authenticated live "
                f"input: {relative}"
            )

    token = _AUTHENTICATED_HISTORICAL_STAGE.set(
        (str(stage), publication.run_id)
    )
    try:
        yield authority
    finally:
        _AUTHENTICATED_HISTORICAL_STAGE.reset(token)


def report_candidate_universe_requires_typed_authority(
    scratchpad: Path,
) -> bool:
    """Whether report readers are forbidden from using legacy Markdown.

    A complete historical typed queue and any trace of the live transaction
    both select the typed boundary.  In the latter case the authenticated
    loader will produce either a capability or explicit debt; deletion of the
    typed base cannot cause a Markdown downgrade.
    """

    root = Path(scratchpad)
    return (
        _path_present(root / BASE_QUEUE)
        or bool(_live_publication_residue(root))
    )


def _load_base(
    root: Path,
    *,
    authenticated_publication: AuthenticatedQueuePublication | None = None,
) -> tuple[tuple[QueueWorkItem, ...], dict[str, Any]]:
    if authenticated_publication is not None:
        _require_publication_capability(root, authenticated_publication)
        return (
            authenticated_publication.items,
            dict(authenticated_publication.base_queue_binding),
        )
    path, raw = _safe_source(root, BASE_QUEUE)
    try:
        items = queue_records_from_json(raw.decode("utf-8", errors="strict"))
    except Exception as exc:
        raise PostVerifyCandidateDeltaError(
            f"{BASE_QUEUE} is not a valid typed queue: {exc}"
        ) from exc
    binding = {
        "artifact": BASE_QUEUE,
        "sha256": _sha(raw),
        "size_bytes": len(raw),
        "record_count": len(items),
        "record_set_digest": queue_record_set_digest(items),
    }
    return items, binding


def load_authenticated_queue_publication(
    scratchpad: Path,
    *,
    project_root: Path,
    plan: Mapping[str, Any] | None = None,
    run_id: str | None = None,
) -> AuthenticatedQueuePublication:
    """Validate and freeze the exact ledger-committed T9 postimage.

    The validator and this consumer operate over the same immutable byte
    snapshot.  Any coherent rewrite during validation is therefore rejected,
    and downstream readers consume the typed values decoded from that snapshot
    instead of reopening mutable files.
    """

    root = Path(scratchpad)
    project = Path(project_root)
    supplied_run = str(run_id or "").strip()
    if not _path_present(root / QUEUE_PLAN_AUTHORITY):
        raise PostVerifyCandidateDeltaError(
            "T9 publication plan authority is absent"
        )
    _persisted_path, persisted_raw = _safe_source(
        root, QUEUE_PLAN_AUTHORITY
    )
    persisted_plan = _strict_json(persisted_raw, QUEUE_PLAN_AUTHORITY)
    if plan is None:
        resolved_plan: dict[str, Any] = persisted_plan
    elif not isinstance(plan, Mapping):
        raise PostVerifyCandidateDeltaError(
            "T9 publication plan authority is malformed"
        )
    elif dict(plan) != persisted_plan:
        raise PostVerifyCandidateDeltaError(
            "caller-supplied T9 plan differs from the committed plan preimage"
        )
    else:
        resolved_plan = dict(plan)

    declared_value = resolved_plan.get("public_output_denominator")
    if (
        not isinstance(declared_value, list)
        or any(
            not isinstance(value, str) or not value.strip()
            for value in declared_value
        )
        or len(declared_value) != len(set(declared_value))
    ):
        raise PostVerifyCandidateDeltaError(
            "T9 plan has no exact public output denominator"
        )
    declared_public = tuple(declared_value)
    for relative in declared_public:
        pure = PurePosixPath(relative.replace("\\", "/"))
        if (
            pure.is_absolute()
            or any(part in {"", ".", ".."} for part in pure.parts)
        ):
            raise PostVerifyCandidateDeltaError(
                "T9 public output denominator contains an unsafe path"
            )

    checkpoint_run = _checkpoint_run_id(root, required_live=True)
    plan_run = str(resolved_plan.get("run_id") or "").strip()
    identities = {
        value for value in (supplied_run, checkpoint_run, plan_run) if value
    }
    if len(identities) > 1:
        raise PostVerifyCandidateDeltaError(
            "requested, checkpoint, and T9 publication plan run authorities "
            "disagree"
        )
    run = supplied_run or checkpoint_run or plan_run
    if not run:
        raise PostVerifyCandidateDeltaError(
            "T9 publication run authority is absent"
        )

    before = _capture_t9_validation_state(root, declared_public)
    if before.get(QUEUE_PLAN_AUTHORITY) != persisted_raw:
        raise PostVerifyCandidateDeltaError(
            "T9 publication plan changed before validation"
        )
    try:
        from verify_queue_transaction import (
            validate_live_verify_queue_publication,
        )

        decision = validate_live_verify_queue_publication(
            scratchpad=root,
            project_root=project,
            plan=resolved_plan,
            run_id=run,
        )
    except Exception as exc:
        raise PostVerifyCandidateDeltaError(
            "T9 publication authority validation failed: "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    if (
        not isinstance(decision, Mapping)
        or decision.get("safe_to_consume") is not True
    ):
        issues = (
            list(decision.get("issues") or ())
            if isinstance(decision, Mapping)
            else ["publication validator returned no decision"]
        )
        raise PostVerifyCandidateDeltaError(
            "T9 publication authority rejected report consumption: "
            + "; ".join(map(str, issues))
        )
    after = _capture_t9_validation_state(root, declared_public)
    if before != after:
        changed = sorted(
            name
            for name in set(before) | set(after)
            if before.get(name) != after.get(name)
        )
        raise PostVerifyCandidateDeltaError(
            "T9 publication authority changed during validation (race): "
            + ", ".join(changed)
        )

    receipt_raw = before.get(QUEUE_FINAL_RECEIPT)
    if receipt_raw is None:
        raise PostVerifyCandidateDeltaError(
            "T9 final receipt publication authority is absent"
        )
    receipt = _strict_json(receipt_raw, QUEUE_FINAL_RECEIPT)
    plan_digest = str(resolved_plan.get("plan_digest") or "")
    active_value = receipt.get("active_output_denominator")
    if (
        receipt.get("schema_version")
        != "plamen.live_verify_queue_receipt.v1"
        or receipt.get("state") != "OUTPUT_COMMITTED"
        or receipt.get("run_id") != run
        or receipt.get("plan_digest") != plan_digest
    ):
        raise PostVerifyCandidateDeltaError(
            "T9 final receipt publication authority is malformed"
        )

    # The active conditional denominator is the exact materialized postimage,
    # never the declarative superset.  Older receipts may omit the redundant
    # list; a present list must agree exactly with the observed postimage.
    materialized = tuple(
        relative
        for relative in declared_public
        if before.get(relative) is not None
    )
    if active_value is not None:
        if (
            not isinstance(active_value, list)
            or any(not isinstance(value, str) for value in active_value)
            or len(active_value) != len(set(active_value))
            or set(active_value) != set(materialized)
        ):
            raise PostVerifyCandidateDeltaError(
                "T9 final receipt active-output denominator is not the exact "
                "materialized publication"
            )
    active = materialized
    required_public = {
        BASE_QUEUE,
        QUEUE_WORK_PLAN,
        QUEUE_MARKDOWN,
        QUEUE_FINAL_RECEIPT,
    }
    if not required_public <= set(active):
        raise PostVerifyCandidateDeltaError(
            "T9 active publication denominator omits the typed queue, work "
            "plan, Markdown projection, or final receipt"
        )

    base_raw = before.get(BASE_QUEUE)
    work_plan_raw = before.get(QUEUE_WORK_PLAN)
    markdown_raw = before.get(QUEUE_MARKDOWN)
    assert base_raw is not None
    assert work_plan_raw is not None
    assert markdown_raw is not None
    try:
        items = queue_records_from_json(
            base_raw.decode("utf-8", errors="strict")
        )
    except Exception as exc:
        raise PostVerifyCandidateDeltaError(
            f"T9 typed queue postimage is invalid: {type(exc).__name__}: {exc}"
        ) from exc
    base_binding = {
        "artifact": BASE_QUEUE,
        "sha256": _sha(base_raw),
        "size_bytes": len(base_raw),
        "record_count": len(items),
        "record_set_digest": queue_record_set_digest(items),
    }
    try:
        work_plan = QueueWorkPlan.from_json(
            work_plan_raw.decode("utf-8", errors="strict")
        )
        work_plan.validate_against(items)
    except Exception as exc:
        raise PostVerifyCandidateDeltaError(
            "T9 typed queue/work-plan authority is inconsistent: "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    try:
        markdown_text = markdown_raw.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise PostVerifyCandidateDeltaError(
            "T9 Markdown queue projection is not strict UTF-8"
        ) from exc
    try:
        # Production deliberately publishes a compact, human-oriented legacy
        # Markdown view beside the lossless typed JSON authority.  Re-render
        # that exact view from the authenticated typed records instead of
        # mis-parsing it as the unrelated typed-Markdown interchange format.
        from plamen_parsers import (
            render_verification_queue_work_item_markdown,
        )

        expected_markdown = render_verification_queue_work_item_markdown(items)
    except Exception as exc:
        raise PostVerifyCandidateDeltaError(
            "T9 Markdown queue projection cannot be derived exactly: "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    if markdown_text != expected_markdown:
        raise PostVerifyCandidateDeltaError(
            "T9 Markdown projection is not the exact production legacy view "
            "of the typed work-item authority"
        )

    bound_names = (*active, QUEUE_PLAN_AUTHORITY)
    artifact_bindings = _publication_binding_rows(before, bound_names)
    try:
        resolved_root = str(root.resolve(strict=False))
        resolved_project = str(project.resolve(strict=False))
    except OSError as exc:
        raise PostVerifyCandidateDeltaError(
            f"T9 publication roots cannot be resolved: {exc}"
        ) from exc
    publication = AuthenticatedQueuePublication(
        scratchpad_root=resolved_root,
        project_root=resolved_project,
        run_id=run,
        plan_digest=plan_digest,
        final_receipt_sha256=_sha(receipt_raw),
        active_output_denominator=active,
        base_queue_binding=base_binding,
        work_plan_digest=work_plan.digest,
        items=items,
        artifact_bindings=artifact_bindings,
        input_artifacts=tuple(
            relative for relative, _sha256, _size in artifact_bindings
        ),
    )
    object.__setattr__(
        publication,
        "_seal",
        _PUBLICATION_CAPABILITY_SEAL,
    )
    return publication


def _legacy_rows(
    root: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    parsed = parse_post_verify_candidate_proposals(root)
    rows: list[dict[str, Any]] = []
    for proposal in parsed["proposals"]:
        severity = proposal["severity"]
        if severity not in {
            "Critical", "High", "Medium", "Low", "Informational"
        }:
            severity = "Medium"
        item = QueueWorkItem.from_legacy_row({
            "finding id": proposal["work_item_id"],
            "candidate identity": proposal["work_item_id"],
            "severity": severity,
            "title": proposal["title"],
            "bug class": "post-verify-observation",
            "preferred tag": "CODE-TRACE",
            "location": proposal["location"],
            "primary artifact": proposal["primary_artifact"],
            "poc class": "structural",
            "evidence class": "late-independent-observation",
        })
        rows.append({
            "item": item,
            "source_kind": proposal["source_kind"],
            "source_artifact": proposal["source_artifact"],
            "source_artifact_sha256": proposal["source_artifact_sha256"],
            "source_record_ordinal": proposal["source_record_ordinal"],
            "source_record_digest": proposal["source_record_digest"],
            "claim": {
                "premise": proposal["mechanism"],
                "harm": proposal["harm"],
                "evidence": proposal["evidence"],
            },
        })
    debts = [{
        "source_artifact": parsed["source_artifact"],
        "source_record_identity": debt["source_record_identity"],
        "reason_code": debt["reason_code"],
        "detail": debt["detail"],
    } for debt in parsed["debts"]]
    return rows, debts, parsed


def _operator_row(value: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize one already-authenticated operator projection.

    The driver supplies the authority artifact and record binding.  Accepting a
    narrow semantic projection here keeps this module independent of the
    verifier-operator authority's internal schema while still binding every
    accepted byte and record.
    """

    row = dict(value)
    work_id = _text(
        row.get("work_item_id") or row.get("finding id"),
        "operator work_item_id",
    )
    source_artifact = _text(
        row.get("source_authority_artifact"),
        "operator source_authority_artifact",
    )
    source_sha = _hex(
        row.get("source_authority_sha256"),
        "operator source_authority_sha256",
    )
    ordinal = _count(
        row.get("source_record_ordinal"),
        "operator source_record_ordinal",
    )
    record_digest = _hex(
        row.get("source_record_digest"),
        "operator source_record_digest",
    )
    severity = str(row.get("severity") or "Unknown")
    if severity not in {
        "Critical", "High", "Medium", "Low", "Informational"
    }:
        # QueueWorkItem has a closed severity vocabulary.  Medium is a neutral
        # routing proposal here, not a terminal rating; verification/report
        # authority still owns the final severity.
        severity = "Medium"
    item = QueueWorkItem.from_legacy_row({
        "finding id": work_id,
        "candidate identity": work_id,
        "severity": severity,
        "title": str(row.get("title") or work_id),
        "bug class": str(row.get("bug_class") or "verifier-side-observation"),
        "preferred tag": "CODE-TRACE",
        "location": str(row.get("location") or ""),
        "primary artifact": str(
            row.get("primary_artifact") or source_artifact
        ),
        "poc class": str(row.get("poc_class") or "structural"),
        "evidence class": "late-independent-observation",
    })
    return {
        "item": item,
        "source_kind": str(
            row.get("source_kind") or "VERIFIER_OPERATOR_AUTHORITY"
        ),
        "source_artifact": source_artifact,
        "source_artifact_sha256": source_sha,
        "source_record_ordinal": ordinal,
        "source_record_digest": record_digest,
        "claim": {
            "premise": _text(
                row.get("mechanism")
                or "Verifier-side observation requires independent verification.",
                "operator premise",
            ),
            "harm": _text(
                row.get("harm")
                or "Potential security harm remains unproven.",
                "operator harm",
            ),
            "evidence": _text(
                row.get("evidence") or source_artifact,
                "operator evidence",
            ),
        },
    }


def _operator_source_rows(
    root: Path,
    *,
    source_artifact: str,
    source_artifact_sha256: str,
) -> list[dict[str, Any]]:
    """Rebuild operator projections from an exact authenticated authority.

    The delta's row is deliberately not an input.  The authority is decoded
    strictly, validated against its own source receipts, and projected again
    using the same narrow semantic boundary supplied by the live driver.
    """

    _path, raw = _safe_source(root, source_artifact)
    if _sha(raw) != source_artifact_sha256:
        raise PostVerifyCandidateDeltaError(
            f"operator source changed during replay: {source_artifact}"
        )
    try:
        authority = validate_verifier_operator_consumer_authority(
            _strict_json(raw, source_artifact),
            scratchpad=root,
        )
    except (ConsumerAuthorityError, PostVerifyCandidateDeltaError) as exc:
        raise PostVerifyCandidateDeltaError(
            f"operator source replay failed for {source_artifact}: {exc}"
        ) from exc
    work_by_id = {
        str(work["work_item_id"]): dict(work)
        for shard in authority["late_verification_shards"]
        for work in shard["rows"]
    }
    rows: list[dict[str, Any]] = []
    for ordinal, candidate in enumerate(authority["candidates"], start=1):
        candidate_id = str(candidate["candidate_id"])
        work = work_by_id.get(candidate_id)
        if work is None:
            raise PostVerifyCandidateDeltaError(
                "operator source replay lacks the candidate's verification work"
            )
        rows.append(_operator_row({
            **work,
            "finding id": candidate_id,
            "severity": str(work.get("severity") or "Unknown"),
            "title": candidate["title"],
            "location": candidate["location"],
            "mechanism": candidate["mechanism"],
            "evidence": candidate["evidence"],
            "source_kind": "VERIFIER_OPERATOR_AUTHORITY",
            "source_authority_artifact": source_artifact,
            "source_authority_sha256": source_artifact_sha256,
            "source_record_ordinal": ordinal,
            "source_record_digest": candidate["candidate_digest"],
        }))
    return rows


def _collision_safe_item(
    item: QueueWorkItem,
    *,
    occupied: set[str],
    source_record_digest: str,
) -> QueueWorkItem:
    if item.work_item_id not in occupied:
        return item
    seed = {
        "source_record_digest": source_record_digest,
        "colliding_work_item_id": item.work_item_id,
    }
    for counter in range(1, 1025):
        replacement = "VER-" + str(int(_digest({
            **seed, "counter": counter
        })[:16], 16))
        if replacement in occupied:
            continue
        legacy = item.to_dict()
        locations = legacy["location_records"]
        return QueueWorkItem.from_legacy_row({
            "finding id": replacement,
            "candidate identity": replacement,
            "aliases": [item.work_item_id],
            "severity": legacy["severity_proposal"]["level"],
            "title": legacy["title"],
            "bug class": legacy["bug_class"],
            "preferred tag": legacy["preferred_tag"],
            "location": (
                locations[0]["artifact"] if locations else ""
            ),
            "primary artifact": legacy["primary_artifacts"],
            "poc class": legacy["poc_class"],
            "evidence class": legacy["evidence_class"],
        })
    raise PostVerifyCandidateDeltaError(
        "could not derive a collision-free post-verification identity"
    )


def _replay_source_derived_rows(
    root: Path,
    *,
    base_items: tuple[QueueWorkItem, ...],
    bindings: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Independently enumerate and normalize the exact source denominator."""

    binding_by_key = {
        (str(binding["artifact"]), str(binding["source_kind"])): binding
        for binding in bindings
    }
    if len(binding_by_key) != len(bindings):
        raise PostVerifyCandidateDeltaError(
            "source replay received duplicate bindings"
        )
    for _artifact, kind in binding_by_key:
        if kind not in {
            "POST_VERIFY_EXTRACT",
            "VERIFIER_OPERATOR_AUTHORITY",
        }:
            raise PostVerifyCandidateDeltaError(
                f"source replay does not support source kind {kind!r}"
            )

    legacy_rows, legacy_debts, parsed = _legacy_rows(root)
    legacy_key = (
        str(parsed["source_artifact"]),
        "POST_VERIFY_EXTRACT",
    )
    if parsed["source_present"]:
        binding = binding_by_key.get(legacy_key)
        if binding is None:
            raise PostVerifyCandidateDeltaError(
                "source replay lacks the post-verify extract binding"
            )
        if binding["sha256"] != parsed["source_sha256"]:
            raise PostVerifyCandidateDeltaError(
                "post-verify extract replay digest mismatch"
            )
    elif legacy_key in binding_by_key:
        raise PostVerifyCandidateDeltaError(
            "source replay found a binding for an absent post-verify extract"
        )

    source_rows = list(legacy_rows)
    replayed_operator_artifacts: set[str] = set()
    operator_paths = sorted(
        (
            path for path in root.glob(
                "verification_operator_consumer_authority*.json"
            )
            if path.is_file() or path.is_symlink()
        ),
        key=lambda path: path.name,
    )
    for path in operator_paths:
        artifact = path.name
        _source, raw = _safe_source(root, artifact)
        source_sha = _sha(raw)
        derived = _operator_source_rows(
            root,
            source_artifact=artifact,
            source_artifact_sha256=source_sha,
        )
        replayed_operator_artifacts.add(artifact)
        key = (artifact, "VERIFIER_OPERATOR_AUTHORITY")
        binding = binding_by_key.get(key)
        if derived and binding is None:
            raise PostVerifyCandidateDeltaError(
                "source replay found unbound operator candidates in "
                f"{artifact}"
            )
        if binding is not None and binding["sha256"] != source_sha:
            raise PostVerifyCandidateDeltaError(
                f"operator source replay digest mismatch for {artifact}"
            )
        source_rows.extend(derived)

    # A safe relative authority name need not follow today's wave naming
    # convention.  It remains replayable when explicitly bound, but it cannot
    # bypass strict authority/source-receipt validation.
    for (artifact, kind), binding in sorted(binding_by_key.items()):
        if (
            kind != "VERIFIER_OPERATOR_AUTHORITY"
            or artifact in replayed_operator_artifacts
        ):
            continue
        source_rows.extend(_operator_source_rows(
            root,
            source_artifact=artifact,
            source_artifact_sha256=str(binding["sha256"]),
        ))

    occupied = {item.work_item_id for item in base_items}
    expected_rows: list[dict[str, Any]] = []
    for source in sorted(
        source_rows,
        key=lambda value: (
            value["source_artifact"],
            value["source_record_ordinal"],
            value["item"].work_item_id,
        ),
    ):
        item = _collision_safe_item(
            source["item"],
            occupied=occupied,
            source_record_digest=source["source_record_digest"],
        )
        occupied.add(item.work_item_id)
        expected_rows.append({
            "work_item": item.to_dict(),
            "work_item_digest": item.digest,
            "source_kind": source["source_kind"],
            "source_artifact": source["source_artifact"],
            "source_artifact_sha256": source["source_artifact_sha256"],
            "source_record_ordinal": source["source_record_ordinal"],
            "source_record_digest": source["source_record_digest"],
            "claim": dict(source["claim"]),
        })
    return expected_rows, legacy_debts


def _source_bindings(
    root: Path,
    rows: Iterable[dict[str, Any]],
    parsed: Mapping[str, Any],
) -> list[dict[str, Any]]:
    requested: dict[tuple[str, str], str] = {}
    if parsed["source_present"]:
        requested[(parsed["source_artifact"], "POST_VERIFY_EXTRACT")] = parsed[
            "source_sha256"
        ]
    for row in rows:
        key = (row["source_artifact"], row["source_kind"])
        previous = requested.get(key)
        if previous is not None and previous != row["source_artifact_sha256"]:
            raise PostVerifyCandidateDeltaError(
                f"conflicting source digests for {key[0]}"
            )
        requested[key] = row["source_artifact_sha256"]
    bindings: list[dict[str, Any]] = []
    for (artifact, kind), expected in sorted(requested.items()):
        _path, raw = _safe_source(root, artifact)
        actual = _sha(raw)
        if actual != expected:
            raise PostVerifyCandidateDeltaError(
                f"source digest mismatch for {artifact}: "
                f"declared {expected}, computed {actual}"
            )
        bindings.append({
            "artifact": artifact,
            "sha256": actual,
            "size_bytes": len(raw),
            "source_kind": kind,
        })
    return bindings


def _payload(
    root: Path,
    *,
    run_id: str,
    operator_proposals: Iterable[Mapping[str, Any]],
    authenticated_publication: AuthenticatedQueuePublication | None = None,
) -> dict[str, Any]:
    run = _text(run_id, "run_id")
    base_items, base_binding = _load_base(
        root,
        authenticated_publication=authenticated_publication,
    )
    rows, debts, parsed = _legacy_rows(root)
    operator_rows = [_operator_row(value) for value in operator_proposals]
    rows.extend(operator_rows)
    bindings = _source_bindings(root, rows, parsed)

    occupied = {item.work_item_id for item in base_items}
    normalized: list[dict[str, Any]] = []
    for row in sorted(
        rows,
        key=lambda value: (
            value["source_artifact"],
            value["source_record_ordinal"],
            value["item"].work_item_id,
        ),
    ):
        item = _collision_safe_item(
            row["item"],
            occupied=occupied,
            source_record_digest=row["source_record_digest"],
        )
        occupied.add(item.work_item_id)
        normalized.append({
            "work_item": item.to_dict(),
            "work_item_digest": item.digest,
            "source_kind": row["source_kind"],
            "source_artifact": row["source_artifact"],
            "source_artifact_sha256": row["source_artifact_sha256"],
            "source_record_ordinal": row["source_record_ordinal"],
            "source_record_digest": row["source_record_digest"],
            "claim": dict(row["claim"]),
        })
    delta_items = tuple(
        QueueWorkItem.from_dict(row["work_item"]) for row in normalized
    )
    union = validate_queue_work_items((*base_items, *delta_items))
    debts = sorted(
        debts,
        key=lambda row: (
            row["source_artifact"],
            row["source_record_identity"],
            row["reason_code"],
        ),
    )
    replayed_rows, replayed_debts = _replay_source_derived_rows(
        root,
        base_items=base_items,
        bindings=bindings,
    )
    replayed_debts = sorted(
        replayed_debts,
        key=lambda row: (
            row["source_artifact"],
            row["source_record_identity"],
            row["reason_code"],
        ),
    )
    if normalized != replayed_rows or debts != replayed_debts:
        raise PostVerifyCandidateDeltaError(
            "candidate delta proposal differs from source-derived replay"
        )
    source_candidate_count = len(normalized) + len(debts)
    unsigned = {
        "schema_version": SCHEMA,
        "run_id": run,
        "status": "COMPLETED_WITH_DEBT" if debts else "CLEAN",
        "base_queue_binding": base_binding,
        "source_binding_count": len(bindings),
        "source_bindings": bindings,
        "source_set_digest": _digest(bindings),
        "source_candidate_count": source_candidate_count,
        "row_count": len(normalized),
        "rows": normalized,
        "debt_count": len(debts),
        "debts": debts,
        "delta_record_set_digest": queue_record_set_digest(delta_items),
        "union_record_count": len(union),
        "union_record_set_digest": queue_record_set_digest(union),
        "terminal_authority": False,
    }
    return {**unsigned, "delta_digest": _digest(unsigned)}


def _atomic_write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    temp = Path(temporary)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    finally:
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass


def write_or_validate_post_verify_candidate_delta(
    scratchpad: Path,
    *,
    run_id: str,
    operator_proposals: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Build and atomically publish the exact additive candidate delta."""

    root = Path(scratchpad)
    publication = _select_current_queue_publication(
        root,
        run_id=run_id,
        project_root=root.parent,
    )
    expected = _payload(
        root,
        run_id=run_id,
        operator_proposals=tuple(operator_proposals),
        authenticated_publication=publication,
    )
    raw = _canonical(expected) + b"\n"
    path = root / ARTIFACT
    if not path.is_file() or path.read_bytes() != raw:
        _atomic_write(path, raw)
    # Validate the bytes just published through the independent read path.
    _load_delta(
        root,
        run_id=run_id,
        authenticated_publication=publication,
    )
    return expected


def _load_delta(
    root: Path,
    *,
    run_id: str | None,
    authenticated_publication: AuthenticatedQueuePublication | None = None,
) -> tuple[dict[str, Any], tuple[QueueWorkItem, ...]]:
    if authenticated_publication is None:
        authenticated_publication = _select_current_queue_publication(
            root,
            run_id=run_id,
            project_root=root.parent,
        )
    else:
        _require_publication_capability(
            root,
            authenticated_publication,
            run_id=run_id,
        )
    base_items, base_binding = _load_base(
        root,
        authenticated_publication=authenticated_publication,
    )
    _path, raw = _safe_source(root, ARTIFACT)
    payload = _exact(_strict_json(raw, ARTIFACT), _TOP_FIELDS, "delta")
    if payload["schema_version"] != SCHEMA:
        raise PostVerifyCandidateDeltaError("unsupported delta schema")
    _text(payload["run_id"], "delta run_id")
    if run_id is not None and payload["run_id"] != run_id:
        raise PostVerifyCandidateDeltaError("delta run_id mismatch")
    if payload["status"] not in _STATUSES:
        raise PostVerifyCandidateDeltaError("invalid delta status")
    if payload["terminal_authority"] is not False:
        raise PostVerifyCandidateDeltaError(
            "post-verification delta cannot be terminal authority"
        )
    declared_digest = _hex(payload["delta_digest"], "delta_digest")
    unsigned = {key: value for key, value in payload.items() if key != "delta_digest"}
    if declared_digest != _digest(unsigned):
        raise PostVerifyCandidateDeltaError("delta_digest mismatch")

    declared_base = _exact(
        payload["base_queue_binding"], _BASE_FIELDS, "base queue binding"
    )
    if declared_base != base_binding:
        raise PostVerifyCandidateDeltaError("base queue binding mismatch")

    bindings_value = payload["source_bindings"]
    if not isinstance(bindings_value, list):
        raise PostVerifyCandidateDeltaError("source_bindings must be an array")
    if _count(payload["source_binding_count"], "source_binding_count") != len(
        bindings_value
    ):
        raise PostVerifyCandidateDeltaError("source_binding_count mismatch")
    bindings: list[dict[str, Any]] = []
    binding_keys: set[tuple[str, str]] = set()
    for index, value in enumerate(bindings_value):
        binding = _exact(value, _SOURCE_FIELDS, f"source binding {index}")
        artifact = _text(binding["artifact"], "source artifact")
        kind = _text(binding["source_kind"], "source kind")
        expected_sha = _hex(binding["sha256"], "source sha256")
        expected_size = _count(binding["size_bytes"], "source size_bytes")
        if (artifact, kind) in binding_keys:
            raise PostVerifyCandidateDeltaError("duplicate source binding")
        binding_keys.add((artifact, kind))
        _source, source_raw = _safe_source(root, artifact)
        if _sha(source_raw) != expected_sha or len(source_raw) != expected_size:
            raise PostVerifyCandidateDeltaError(
                f"source binding changed: {artifact}"
            )
        bindings.append(binding)
    if bindings != sorted(
        bindings, key=lambda row: (row["artifact"], row["source_kind"])
    ):
        raise PostVerifyCandidateDeltaError("source bindings are not canonical")
    if _hex(payload["source_set_digest"], "source_set_digest") != _digest(
        bindings
    ):
        raise PostVerifyCandidateDeltaError("source_set_digest mismatch")

    rows_value = payload["rows"]
    if not isinstance(rows_value, list):
        raise PostVerifyCandidateDeltaError("rows must be an array")
    if _count(payload["row_count"], "row_count") != len(rows_value):
        raise PostVerifyCandidateDeltaError("row_count mismatch")
    delta_items: list[QueueWorkItem] = []
    source_records: set[tuple[str, int, str]] = set()
    for index, value in enumerate(rows_value):
        row = _exact(value, _ROW_FIELDS, f"delta row {index}")
        try:
            item = QueueWorkItem.from_dict(row["work_item"])
        except Exception as exc:
            raise PostVerifyCandidateDeltaError(
                f"delta row {index} work item is invalid: {exc}"
            ) from exc
        if _hex(
            row["work_item_digest"], "work_item_digest"
        ) != item.digest:
            raise PostVerifyCandidateDeltaError("work_item_digest mismatch")
        source_kind = _text(row["source_kind"], "source_kind")
        source_artifact = _text(row["source_artifact"], "source_artifact")
        source_sha = _hex(
            row["source_artifact_sha256"], "source_artifact_sha256"
        )
        ordinal = _count(
            row["source_record_ordinal"], "source_record_ordinal"
        )
        record_digest = _hex(
            row["source_record_digest"], "source_record_digest"
        )
        if (source_artifact, source_kind) not in binding_keys:
            raise PostVerifyCandidateDeltaError(
                "delta row lacks an exact source binding"
            )
        binding = next(
            value for value in bindings
            if value["artifact"] == source_artifact
            and value["source_kind"] == source_kind
        )
        if binding["sha256"] != source_sha:
            raise PostVerifyCandidateDeltaError(
                "delta row source digest does not match source binding"
            )
        record_key = (source_artifact, ordinal, record_digest)
        if record_key in source_records:
            raise PostVerifyCandidateDeltaError(
                "duplicate delta source-record binding"
            )
        source_records.add(record_key)
        claim = _exact(row["claim"], _CLAIM_FIELDS, "delta claim")
        for field in _CLAIM_FIELDS:
            _text(claim[field], f"claim.{field}")
        delta_items.append(item)
    try:
        delta_tuple = validate_queue_work_items(delta_items)
        union = validate_queue_work_items((*base_items, *delta_tuple))
    except Exception as exc:
        raise PostVerifyCandidateDeltaError(
            f"base-plus-delta identity universe is invalid: {exc}"
        ) from exc
    if _hex(
        payload["delta_record_set_digest"], "delta_record_set_digest"
    ) != queue_record_set_digest(delta_tuple):
        raise PostVerifyCandidateDeltaError("delta_record_set_digest mismatch")
    if _count(payload["union_record_count"], "union_record_count") != len(union):
        raise PostVerifyCandidateDeltaError("union_record_count mismatch")
    if _hex(
        payload["union_record_set_digest"], "union_record_set_digest"
    ) != queue_record_set_digest(union):
        raise PostVerifyCandidateDeltaError("union_record_set_digest mismatch")

    debts_value = payload["debts"]
    if not isinstance(debts_value, list):
        raise PostVerifyCandidateDeltaError("debts must be an array")
    if _count(payload["debt_count"], "debt_count") != len(debts_value):
        raise PostVerifyCandidateDeltaError("debt_count mismatch")
    debts: list[dict[str, Any]] = []
    for index, value in enumerate(debts_value):
        debt = _exact(value, _DEBT_FIELDS, f"delta debt {index}")
        for field in _DEBT_FIELDS:
            _text(debt[field], f"debt.{field}")
        debts.append(debt)
    if debts != sorted(
        debts,
        key=lambda row: (
            row["source_artifact"],
            row["source_record_identity"],
            row["reason_code"],
        ),
    ):
        raise PostVerifyCandidateDeltaError("delta debts are not canonical")
    if _count(
        payload["source_candidate_count"], "source_candidate_count"
    ) != len(delta_tuple) + len(debts):
        raise PostVerifyCandidateDeltaError(
            "source_candidate_count must equal row_count plus debt_count"
        )
    expected_status = "COMPLETED_WITH_DEBT" if debts else "CLEAN"
    if payload["status"] != expected_status:
        raise PostVerifyCandidateDeltaError("delta status/debt mismatch")
    expected_rows, expected_debts = _replay_source_derived_rows(
        root,
        base_items=base_items,
        bindings=bindings,
    )
    expected_debts = sorted(
        expected_debts,
        key=lambda row: (
            row["source_artifact"],
            row["source_record_identity"],
            row["reason_code"],
        ),
    )
    if rows_value != expected_rows:
        raise PostVerifyCandidateDeltaError(
            "delta rows differ from independent source replay"
        )
    if debts != expected_debts:
        raise PostVerifyCandidateDeltaError(
            "delta debts differ from independent source replay"
        )
    return payload, delta_tuple


def load_report_candidate_universe(
    scratchpad: Path,
    *,
    run_id: str | None = None,
    authenticated_publication: AuthenticatedQueuePublication | None = None,
) -> tuple[BoundReportCandidate, ...]:
    """Load the authenticated exact base-plus-post-verify candidate universe."""

    return load_candidate_universe_authority(
        scratchpad,
        run_id=run_id,
        authenticated_publication=authenticated_publication,
    ).candidates


def load_current_report_candidate_universe_authority(
    scratchpad: Path,
    *,
    run_id: str | None = None,
    project_root: Path | None = None,
) -> CandidateUniverseAuthority:
    """Load the report universe through T9 authority on every live-cutover run.

    Typed-only historical fixtures/runs predating the live transaction retain
    their compatibility path.  The presence of either live authority artifact
    commits the reader to the authenticated path; partial live state can never
    fall back to a plausible typed sidecar.
    """

    root = Path(scratchpad)
    publication = _select_current_queue_publication(
        root,
        run_id=run_id,
        project_root=project_root,
    )
    return load_candidate_universe_authority(
        root,
        run_id=run_id,
        authenticated_publication=publication,
    )


def load_candidate_universe_authority(
    scratchpad: Path,
    *,
    run_id: str | None = None,
    authenticated_publication: AuthenticatedQueuePublication | None = None,
) -> CandidateUniverseAuthority:
    """Load the denominator, transitive sources, debts, and bound candidates."""

    root = Path(scratchpad)
    if authenticated_publication is None:
        authenticated_publication = _select_current_queue_publication(
            root,
            run_id=run_id,
            project_root=root.parent,
        )
    else:
        _require_publication_capability(
            root,
            authenticated_publication,
            run_id=run_id,
        )
    effective_run = (
        authenticated_publication.run_id
        if authenticated_publication is not None
        else str(run_id or "")
    )
    base_items, base_binding = _load_base(
        root,
        authenticated_publication=authenticated_publication,
    )
    delta_path = root / ARTIFACT
    post_verify_evidence_present = (
        (root / "post_verify_extract.md").exists()
        or any(root.glob("verification_operator_consumer_authority*.json"))
        or (root / "post_verify_late_delivery.json").exists()
        or (root / "post_verify_late_verification_authority.json").exists()
    )
    if not delta_path.is_file():
        if post_verify_evidence_present:
            raise PostVerifyCandidateDeltaError(
                "post-verification evidence exists without candidate delta"
            )
        candidates = tuple(
            BoundReportCandidate(
                item=item,
                source_kind="BASE_VERIFICATION_QUEUE",
                source_artifact=base_binding["artifact"],
                source_artifact_sha256=base_binding["sha256"],
                source_record_ordinal=index,
                source_record_digest=item.digest,
                claim={
                    "premise": "",
                    "harm": "",
                    "evidence": base_binding["artifact"],
                },
                authority_artifact=base_binding["artifact"],
                authority_artifact_sha256=base_binding["sha256"],
                authority_record_digest=item.digest,
                claim_digest=_digest({
                    "premise": "",
                    "harm": "",
                    "evidence": base_binding["artifact"],
                }),
            )
            for index, item in enumerate(base_items, start=1)
        )
        return CandidateUniverseAuthority(
            run_id=effective_run,
            base_queue_binding=base_binding,
            delta_binding=None,
            union_record_count=len(candidates),
            union_record_set_digest=queue_record_set_digest(
                row.item for row in candidates
            ),
            source_debts=(),
            input_artifacts=tuple(sorted({
                base_binding["artifact"],
                *(
                    authenticated_publication.input_artifacts
                    if authenticated_publication is not None
                    else ()
                ),
            })),
            candidates=candidates,
        )
    payload, delta_items = _load_delta(
        root,
        run_id=effective_run or None,
        authenticated_publication=authenticated_publication,
    )
    delta_raw = (root / ARTIFACT).read_bytes()
    delta_binding = {
        "artifact": ARTIFACT,
        "sha256": _sha(delta_raw),
        "size_bytes": len(delta_raw),
        "delta_digest": payload["delta_digest"],
        "record_count": payload["row_count"],
        "record_set_digest": payload["delta_record_set_digest"],
    }
    bound: list[BoundReportCandidate] = [
        BoundReportCandidate(
            item=item,
            source_kind="BASE_VERIFICATION_QUEUE",
            source_artifact=base_binding["artifact"],
            source_artifact_sha256=base_binding["sha256"],
            source_record_ordinal=index,
            source_record_digest=item.digest,
            claim={
                "premise": "",
                "harm": "",
                "evidence": base_binding["artifact"],
            },
            authority_artifact=base_binding["artifact"],
            authority_artifact_sha256=base_binding["sha256"],
            authority_record_digest=item.digest,
            claim_digest=_digest({
                "premise": "",
                "harm": "",
                "evidence": base_binding["artifact"],
            }),
        )
        for index, item in enumerate(base_items, start=1)
    ]
    for item, row in zip(delta_items, payload["rows"]):
        claim = dict(row["claim"])
        bound.append(BoundReportCandidate(
            item=item,
            source_kind=row["source_kind"],
            source_artifact=row["source_artifact"],
            source_artifact_sha256=row["source_artifact_sha256"],
            source_record_ordinal=row["source_record_ordinal"],
            source_record_digest=row["source_record_digest"],
            claim=claim,
            authority_artifact=ARTIFACT,
            authority_artifact_sha256=delta_binding["sha256"],
            authority_record_digest=_digest(row),
            claim_digest=_digest(claim),
        ))
    if len(bound) != payload["union_record_count"]:
        raise PostVerifyCandidateDeltaError("loaded universe count mismatch")
    if queue_record_set_digest(row.item for row in bound) != payload[
        "union_record_set_digest"
    ]:
        raise PostVerifyCandidateDeltaError("loaded universe digest mismatch")
    inputs = {
        base_binding["artifact"],
        ARTIFACT,
        *(
            str(binding["artifact"])
            for binding in payload["source_bindings"]
        ),
        *(
            authenticated_publication.input_artifacts
            if authenticated_publication is not None
            else ()
        ),
    }
    return CandidateUniverseAuthority(
        run_id=str(payload["run_id"]),
        base_queue_binding=base_binding,
        delta_binding=delta_binding,
        union_record_count=int(payload["union_record_count"]),
        union_record_set_digest=str(payload["union_record_set_digest"]),
        source_debts=tuple(dict(row) for row in payload["debts"]),
        input_artifacts=tuple(sorted(inputs)),
        candidates=tuple(bound),
    )


def load_post_verify_candidate_delta(
    scratchpad: Path,
    *,
    run_id: str | None = None,
) -> dict[str, Any]:
    """Return the fully replay-validated post-verification delta payload."""

    root = Path(scratchpad)
    publication = _select_current_queue_publication(
        root,
        run_id=run_id,
        project_root=root.parent,
    )
    payload, _items = _load_delta(
        root,
        run_id=run_id,
        authenticated_publication=publication,
    )
    return payload


def load_post_verify_late_delivery_statuses(
    scratchpad: Path,
    *,
    run_id: str | None = None,
) -> Mapping[str, LateCandidateDeliveryStatus]:
    """Replay late delivery exactly, without granting negative authority.

    The v1 delivery receipt predates an explicit run/delta field.  This loader
    closes that gap by joining its exact candidate set and source-record
    digests to the already run-bound delta.  The resulting status may add
    report/reopen work but can never exclude a candidate.
    """

    from plamen_parsers import _verifier_status_from_text

    root = Path(scratchpad)
    authority = load_candidate_universe_authority(root, run_id=run_id)
    delta_candidates = {
        row.item.work_item_id: row
        for row in authority.candidates
        if row.source_kind != "BASE_VERIFICATION_QUEUE"
    }
    execution_authority_path = (
        root / "post_verify_late_verification_authority.json"
    )
    if execution_authority_path.is_file():
        from recovery_execution_authority import (
            load_late_verification_authority,
        )

        effective_run_id = run_id or authority.run_id
        if not effective_run_id:
            raise PostVerifyCandidateDeltaError(
                "late verification authority requires a run identity"
            )
        try:
            execution_authority = load_late_verification_authority(
                root,
                run_id=effective_run_id,
                repo_root=Path(__file__).resolve().parent.parent,
            )
        except Exception as exc:
            raise PostVerifyCandidateDeltaError(
                "late verification authority replay failed: "
                f"{type(exc).__name__}: {exc}"
            ) from exc
        execution_raw = execution_authority_path.read_bytes()
        result = {}
        for row in execution_authority["rows"]:
            candidate_id = str(row["candidate_id"])
            bound = delta_candidates.get(candidate_id)
            if bound is None or candidate_id in result:
                raise PostVerifyCandidateDeltaError(
                    "late verification authority candidate mismatch"
                )
            if (
                row["source_record_digest"]
                != bound.source_record_digest
                or row["terminal_negative_authority"] is not False
            ):
                raise PostVerifyCandidateDeltaError(
                    "late verification source or negative-authority mismatch"
                )
            result[candidate_id] = LateCandidateDeliveryStatus(
                candidate_id=candidate_id,
                delivery_state=str(row["delivery_state"]),
                verifier_status=str(row["verifier_status"]),
                verify_artifact=(
                    str(row["verify_artifact"])
                    if row["verify_artifact"] is not None
                    else None
                ),
                verify_sha256=(
                    str(row["verify_sha256"])
                    if row["verify_sha256"] is not None
                    else None
                ),
                delivery_artifact_sha256=_sha(execution_raw),
                source_candidate_digest=bound.source_record_digest,
            )
        if set(result) != set(delta_candidates):
            raise PostVerifyCandidateDeltaError(
                "late verification authority does not close exact delta set"
            )
        return result

    path, raw = _safe_source(root, "post_verify_late_delivery.json")
    payload = _strict_json(raw, "post_verify_late_delivery.json")
    expected_top = frozenset({
        "schema_version", "proof_authority", "row_count", "rows",
        "receipt_sha256",
    })
    expected_row = frozenset({
        "candidate_id", "delivery_state", "verify_artifact", "verify_sha256",
        "source_candidate_digest", "source_work_item_id",
        "source_operator_receipt", "source_operator_receipt_sha256",
        "source_operator_receipt_digest", "finding_lifecycle_obligation_id",
    })
    payload = _exact(payload, expected_top, "late delivery")
    if payload["schema_version"] != "plamen.post_verify_late_delivery.v1":
        raise PostVerifyCandidateDeltaError("late delivery schema mismatch")
    if payload["proof_authority"] != "NONE":
        raise PostVerifyCandidateDeltaError(
            "late delivery acquired proof authority"
        )
    rows = payload["rows"]
    if not isinstance(rows, list):
        raise PostVerifyCandidateDeltaError("late delivery rows must be an array")
    if _count(payload["row_count"], "late delivery row_count") != len(rows):
        raise PostVerifyCandidateDeltaError("late delivery row_count mismatch")
    unsigned = {
        key: value for key, value in payload.items()
        if key != "receipt_sha256"
    }
    if _hex(
        payload["receipt_sha256"], "late delivery receipt_sha256"
    ) != _digest(unsigned):
        raise PostVerifyCandidateDeltaError(
            "late delivery receipt digest mismatch"
        )
    result: dict[str, LateCandidateDeliveryStatus] = {}
    for index, value in enumerate(rows):
        row = _exact(value, expected_row, f"late delivery row {index}")
        candidate_id = _text(row["candidate_id"], "late candidate_id")
        bound = delta_candidates.get(candidate_id)
        if bound is None or candidate_id in result:
            raise PostVerifyCandidateDeltaError(
                "late delivery candidate denominator mismatch"
            )
        if row["delivery_state"] not in {
            "INDEPENDENT_VERIFICATION_RECORDED",
            "UNVERIFIED_HUMAN_REVIEW",
        }:
            raise PostVerifyCandidateDeltaError(
                "late delivery state is invalid"
            )
        verify_artifact = f"verify_{candidate_id}.md"
        if row["verify_artifact"] != verify_artifact:
            raise PostVerifyCandidateDeltaError(
                "late delivery verify artifact mismatch"
            )
        _verify_path, verify_raw = _safe_source(root, verify_artifact)
        verify_sha = _hex(row["verify_sha256"], "late verify_sha256")
        if _sha(verify_raw) != verify_sha:
            raise PostVerifyCandidateDeltaError(
                "late verifier output bytes changed"
            )
        source_digest = _hex(
            row["source_candidate_digest"],
            "late source_candidate_digest",
        )
        if source_digest != bound.source_record_digest:
            raise PostVerifyCandidateDeltaError(
                "late delivery source-record binding mismatch"
            )
        source_receipt = row["source_operator_receipt"]
        source_sha = row["source_operator_receipt_sha256"]
        source_authority_digest = row["source_operator_receipt_digest"]
        if source_receipt is None:
            if source_sha is not None or source_authority_digest is not None:
                raise PostVerifyCandidateDeltaError(
                    "late delivery source receipt binding is partial"
                )
        else:
            source_receipt = _text(
                source_receipt, "late source_operator_receipt"
            )
            _receipt_path, receipt_raw = _safe_source(root, source_receipt)
            if _hex(
                source_sha, "late source_operator_receipt_sha256"
            ) != _sha(receipt_raw):
                raise PostVerifyCandidateDeltaError(
                    "late source operator receipt changed"
                )
            _hex(
                source_authority_digest,
                "late source_operator_receipt_digest",
            )
        try:
            verify_text = verify_raw.decode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise PostVerifyCandidateDeltaError(
                "late verifier output is not strict UTF-8"
            ) from exc
        result[candidate_id] = LateCandidateDeliveryStatus(
            candidate_id=candidate_id,
            delivery_state=str(row["delivery_state"]),
            verifier_status=_verifier_status_from_text(verify_text),
            verify_artifact=verify_artifact,
            verify_sha256=verify_sha,
            delivery_artifact_sha256=_sha(raw),
            source_candidate_digest=source_digest,
        )
    if set(result) != set(delta_candidates):
        raise PostVerifyCandidateDeltaError(
            "late delivery does not close the exact delta candidate set"
        )
    return result


def candidate_universe_legacy_rows(
    scratchpad: Path,
    *,
    run_id: str | None = None,
    authenticated_publication: AuthenticatedQueuePublication | None = None,
) -> list[dict[str, Any]]:
    """Project the typed universe for legacy read-only report consumers."""

    authority = load_candidate_universe_authority(
        scratchpad,
        run_id=run_id,
        authenticated_publication=authenticated_publication,
    )
    rows: list[dict[str, Any]] = []
    for bound in authority.candidates:
        item = bound.item
        locations: list[str] = []
        for record in item.location_records:
            location = record.artifact
            if record.start_line is not None:
                location += f":{record.start_line}"
                if (
                    record.end_line is not None
                    and record.end_line != record.start_line
                ):
                    location += f"-{record.end_line}"
            if record.symbol:
                location += f":{record.symbol}"
            locations.append(location)
        rows.append({
            "finding id": item.work_item_id,
            "candidate identity": item.candidate_identity,
            "severity": item.severity_proposal.level,
            "title": item.title,
            "bug class": item.bug_class,
            "preferred tag": item.preferred_tag,
            "location": "; ".join(locations),
            "primary artifact": ", ".join(item.primary_artifacts),
            "poc class": item.poc_class,
            "expected output file": item.expected_output_file,
            "aliases": list(item.aliases),
            "constituents": list(item.constituents),
            "effective evidence scope": item.effective_evidence_scope,
            "effective proof scope": item.effective_proof_scope,
            "effective harm scope": item.effective_harm_scope,
            "required disposition": item.required_disposition,
            "source kind": bound.source_kind,
            "source artifact": bound.source_artifact,
            "source artifact sha256": bound.source_artifact_sha256,
            "source record digest": bound.source_record_digest,
            "authority artifact": bound.authority_artifact,
            "authority artifact sha256": bound.authority_artifact_sha256,
            "authority record digest": bound.authority_record_digest,
            "claim premise": str(bound.claim.get("premise") or ""),
            "claim harm": str(bound.claim.get("harm") or ""),
            "claim evidence": str(bound.claim.get("evidence") or ""),
            "claim digest": bound.claim_digest,
        })
    return rows


def current_report_candidate_universe_legacy_rows(
    scratchpad: Path,
    *,
    run_id: str | None = None,
    project_root: Path | None = None,
) -> list[dict[str, Any]]:
    """Project the current authenticated report universe for legacy readers."""

    root = Path(scratchpad)
    publication = _select_current_queue_publication(
        root,
        run_id=run_id,
        project_root=project_root,
    )
    return candidate_universe_legacy_rows(
        root,
        run_id=run_id,
        authenticated_publication=publication,
    )


__all__ = [
    "ARTIFACT",
    "AuthenticatedQueuePublication",
    "BASE_QUEUE",
    "BoundReportCandidate",
    "CandidateUniverseAuthority",
    "LateCandidateDeliveryStatus",
    "PostVerifyCandidateDeltaError",
    "SCHEMA",
    "authenticated_historical_typed_stage_scope",
    "load_candidate_universe_authority",
    "load_authenticated_queue_publication",
    "load_current_report_candidate_universe_authority",
    "candidate_universe_legacy_rows",
    "current_report_candidate_universe_legacy_rows",
    "load_report_candidate_universe",
    "load_post_verify_candidate_delta",
    "load_post_verify_late_delivery_statuses",
    "report_candidate_universe_requires_typed_authority",
    "write_or_validate_post_verify_candidate_delta",
]
