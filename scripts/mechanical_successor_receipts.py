"""Immutable successor authority for mechanical verifier annotations.

Verifier-authored Markdown is already bound by ``VerifierOutputReceipt``.  A
mechanical verifier may therefore not silently rewrite that file: it must emit
an append-only successor plus a receipt that binds both generations and the
exact mechanical evidence which justified the annotation.

The commit is intentionally two-file and repairable.  The receipt is written
first, then the transformed Markdown.  A crash at either boundary leaves one
of two deterministic partial states, both of which can be completed only when
the original verifier authority and every evidence digest still match.
"""
from __future__ import annotations

from dataclasses import dataclass, fields
from contextvars import ContextVar
import hashlib
import json
import math
import os
from pathlib import Path
import re
from typing import Any, Callable, Mapping
import uuid

from queue_work_items import (
    QueueWorkPlan,
    VerifierOutputIdentity,
    VerifierOutputReceipt,
)
from severity_decision_ledger import parse_severity_proposal


RECEIPT_SCHEMA_VERSION = "plamen.mechanical_successor_receipt.v2"
ANNOTATION_SCHEMA_VERSION = "plamen.mechanical_verify_annotation.v2"
_RECEIPT_SUFFIX = ".mechanical_successor.receipt.json"
_HEX_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_DRIVER_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)
_CODE_ID_RE = _DRIVER_ID_RE
_RUN_ID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.ASCII,
)
_RESERVED_MECHANICAL_FIELD_RE = re.compile(
    r"(?im)^\s*(?:[-*>]\s*)?\**(?:Mechanical-Verified|Mechanical-Command|"
    r"Mechanical-Tag)\**\s*:|mechanical-verify(?:-successor)?\s+v\d+"
)
_RESULT_KEYS = frozenset(
    {
        "verify_file",
        "finding_id",
        "language",
        "test_file_resolved",
        "test_function",
        "test_command_used",
        "status",
        "duration_s",
        "stdout_tail",
        "recommended_tag",
        "race_mode",
    }
)
_STATUSES = frozenset(
    {
        "PASS",
        "FAIL",
        "COMPILE_FAIL",
        "TIMEOUT",
        "NO_TEST_MATCH",
        "NO_TEST_FILE",
        "AMBIGUOUS",
        "TOOLCHAIN_UNAVAILABLE",
        "BUILD_FAILED",
        "EXEC_ERROR",
        "SKIPPED",
    }
)
_UNICODE_LINE_SEPARATORS = frozenset(("\x85", "\u2028", "\u2029"))
_POSITIVE_EXECUTION_RE = re.compile(
    r"(?:\b[1-9]\d*\s+passed\b|---\s+PASS\b|\bPASS(?:ED)?\b|"
    r"test result:\s*ok\.\s*[1-9]\d*\s*passed|\bok\s+[^\r\n]+)",
    re.IGNORECASE,
)
_ACTIVE_WRITE_GUARD: ContextVar[Callable[[], None] | None] = ContextVar(
    "mechanical_successor_write_guard", default=None
)


class MechanicalSuccessorError(RuntimeError):
    """The mechanical successor cannot be proven from authoritative inputs."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise MechanicalSuccessorError(f"value is not canonical JSON: {exc}") from exc


def _strict_json_object(raw: bytes, label: str) -> dict[str, Any]:
    def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in pairs:
            if key in out:
                raise MechanicalSuccessorError(
                    f"{label} contains duplicate JSON key {key!r}"
                )
            out[key] = value
        return out

    try:
        decoded = raw.decode("utf-8")
        value = json.loads(
            decoded,
            object_pairs_hook=_pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(
                MechanicalSuccessorError(
                    f"{label} contains non-finite JSON number {token}"
                )
            ),
        )
    except MechanicalSuccessorError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MechanicalSuccessorError(f"invalid {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise MechanicalSuccessorError(f"{label} must contain a JSON object")
    return value


def _require_text(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 512
        or any(
            ord(char) < 0x20
            or ord(char) == 0x7F
            or char in _UNICODE_LINE_SEPARATORS
            for char in value
        )
    ):
        raise MechanicalSuccessorError(f"{label} must be non-empty safe text")
    return value


def _code_identity(path: Path, label: str) -> str:
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise MechanicalSuccessorError(
            f"{label} code bytes are unavailable: {exc}"
        ) from exc
    return "sha256:" + _sha256(raw)


def _canonical_directory_entry(path: Path, label: str) -> None:
    """Reject case-aliased or duplicate ownership on every host OS.

    Windows will happily open ``VERIFY_H-01.RECEIPT.JSON`` through a request
    for the lower/mixed-case canonical name.  Authority must be tied to the
    directory entry actually present, not to the spelling used by ``Path``.
    Enumerating the parent also makes the same collision policy testable on
    case-sensitive hosts.
    """

    try:
        matches = [
            entry.name
            for entry in path.parent.iterdir()
            if entry.name.casefold() == path.name.casefold()
        ]
    except OSError as exc:
        raise MechanicalSuccessorError(
            f"cannot establish canonical {label} ownership: {exc}"
        ) from exc
    if matches != [path.name]:
        raise MechanicalSuccessorError(
            f"{label} has ambiguous or non-canonical case ownership: {matches!r}"
        )


def _reject_unknown_receipt_variants(verify_path: Path, finding_id: str) -> None:
    prefix = f"verify_{finding_id}.".casefold()
    allowed_exact = {
        f"verify_{finding_id}.receipt.json",
        f"verify_{finding_id}{_RECEIPT_SUFFIX}",
    }
    try:
        variants = [
            entry.name
            for entry in verify_path.parent.iterdir()
            if entry.name.casefold().startswith(prefix)
            and entry.name.casefold().endswith(".receipt.json")
            and entry.name not in allowed_exact
        ]
    except OSError as exc:
        raise MechanicalSuccessorError(
            f"cannot establish receipt variant cardinality: {exc}"
        ) from exc
    if variants:
        raise MechanicalSuccessorError(
            "unrecognized receipt variant or non-canonical case creates "
            "ambiguous authority: "
            + ", ".join(sorted(variants, key=lambda value: (value.casefold(), value)))
        )


def _require_digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _HEX_RE.fullmatch(value) is None:
        raise MechanicalSuccessorError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _require_size(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise MechanicalSuccessorError(f"{label} must be a non-negative integer")
    return value


def _recommended_tag(status: str) -> str:
    return {
        "PASS": "[POC-PASS]",
        "FAIL": "[POC-FAIL]",
        "COMPILE_FAIL": "[CODE-TRACE]",
        "TIMEOUT": "[CODE-TRACE]",
        "NO_TEST_MATCH": "[CODE-TRACE]",
        "NO_TEST_FILE": "[CODE-TRACE]",
    }.get(status, "")


def _annotation_text(value: Any, limit: int) -> str:
    """Render untrusted command/output as one inert Markdown field value."""
    text = str(value or "")[:limit]
    escaped: list[str] = []
    for char in text:
        if char == "\\":
            escaped.append("\\\\")
        elif char == "\r":
            escaped.append("\\r")
        elif char == "\n":
            escaped.append("\\n")
        elif char == "\t":
            escaped.append("\\t")
        elif char in _UNICODE_LINE_SEPARATORS:
            escaped.append(f"\\u{ord(char):04x}")
        elif char == "`":
            escaped.append("\\`")
        elif ord(char) < 0x20 or ord(char) == 0x7F:
            escaped.append(f"\\u{ord(char):04x}")
        else:
            escaped.append(char)
    return "".join(escaped)


def _normalize_result(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise MechanicalSuccessorError("mechanical result must be a mapping")
    if set(value) != _RESULT_KEYS:
        missing = sorted(_RESULT_KEYS - set(value))
        extra = sorted(set(value) - _RESULT_KEYS)
        raise MechanicalSuccessorError(
            f"mechanical result schema mismatch (missing={missing}, extra={extra})"
        )
    out = dict(value)
    for key in ("verify_file", "finding_id", "language", "status"):
        out[key] = _require_text(out[key], f"mechanical result {key}")
    for key in ("test_file_resolved", "test_function", "test_command_used"):
        if out[key] is not None and not isinstance(out[key], str):
            raise MechanicalSuccessorError(f"mechanical result {key} must be text or null")
    if not isinstance(out["stdout_tail"], str):
        raise MechanicalSuccessorError("mechanical result stdout_tail must be text")
    if not isinstance(out["recommended_tag"], str):
        raise MechanicalSuccessorError("mechanical result recommended_tag must be text")
    if not isinstance(out["race_mode"], bool):
        raise MechanicalSuccessorError("mechanical result race_mode must be boolean")
    duration = out["duration_s"]
    if (
        isinstance(duration, bool)
        or not isinstance(duration, (int, float))
        or not math.isfinite(float(duration))
        or float(duration) < 0
    ):
        raise MechanicalSuccessorError(
            "mechanical result duration_s must be finite and non-negative"
        )
    out["duration_s"] = float(duration)
    if out["status"] not in _STATUSES:
        raise MechanicalSuccessorError(
            f"unsupported mechanical result status {out['status']!r}"
        )
    expected_tag = _recommended_tag(out["status"])
    if out["recommended_tag"] != expected_tag:
        raise MechanicalSuccessorError(
            "mechanical result recommended_tag disagrees with status"
        )
    expected_file = f"verify_{out['finding_id']}.md"
    if out["verify_file"] != expected_file:
        raise MechanicalSuccessorError(
            "mechanical result verify_file disagrees with finding_id"
        )
    if out["status"] == "PASS":
        for key in ("test_file_resolved", "test_function", "test_command_used"):
            evidence = out[key]
            if (
                not isinstance(evidence, str)
                or not evidence.strip()
                or evidence != evidence.strip()
                or len(evidence) > 4096
                or any(
                    ord(char) < 0x20
                    or ord(char) == 0x7F
                    or char in _UNICODE_LINE_SEPARATORS
                    for char in evidence
                )
            ):
                raise MechanicalSuccessorError(
                    f"PASS requires bound safe execution evidence in {key}"
                )
        if (
            not out["stdout_tail"].strip()
            or _POSITIVE_EXECUTION_RE.search(out["stdout_tail"]) is None
        ):
            raise MechanicalSuccessorError(
                "PASS requires bound positive test execution output"
            )
    # Prove all nested values are in the canonical JSON subset now, rather
    # than discovering an unsupported value only after filesystem work.
    _canonical_json_bytes(out)
    return out


def _annotation_suffix(result: Mapping[str, Any]) -> bytes:
    status = str(result["status"])
    lines = [
        "",
        "<!-- mechanical-verify-successor v2; driver-stamped; do not hand-edit -->",
    ]
    if status in ("PASS", "FAIL"):
        lines.append(
            f"**Mechanical-Verified**: YES — Status: {status} "
            f"(duration: {float(result['duration_s']):.1f}s)"
        )
    else:
        lines.append(
            f"**Mechanical-Verified**: NO ({status}) — "
            f"{_annotation_text(result['stdout_tail'], 200)}"
        )
    command = result["test_command_used"]
    if command:
        lines.append(f"**Mechanical-Command**: `{_annotation_text(command, 1000)}`")
    tag = _recommended_tag(status)
    if tag:
        lines.append(f"**Mechanical-Tag**: {tag}")
    lines.append("")
    return "\n".join(lines).encode("utf-8")


@dataclass(frozen=True, slots=True)
class MechanicalSuccessorReceipt:
    schema_version: str
    annotation_schema_version: str
    finding_id: str
    verify_file: str
    original_verifier_receipt_file: str
    original_verifier_receipt_sha256: str
    original_verifier_receipt_size_bytes: int
    original_verifier_receipt_digest: str
    original_output_sha256: str
    original_output_size_bytes: int
    transformed_output_sha256: str
    transformed_output_size_bytes: int
    mechanical_result_sha256: str
    mechanical_manifest_file: str
    mechanical_manifest_sha256: str
    mechanical_manifest_size_bytes: int
    run_identity: str
    driver_identity: str
    executor_identity: str
    successor_identity: str

    def __post_init__(self) -> None:
        if self.schema_version != RECEIPT_SCHEMA_VERSION:
            raise MechanicalSuccessorError("unsupported successor receipt schema")
        if self.annotation_schema_version != ANNOTATION_SCHEMA_VERSION:
            raise MechanicalSuccessorError("unsupported annotation schema")
        _require_text(self.finding_id, "finding_id")
        if self.verify_file != f"verify_{self.finding_id}.md":
            raise MechanicalSuccessorError("successor verify_file identity mismatch")
        if self.original_verifier_receipt_file != f"verify_{self.finding_id}.receipt.json":
            raise MechanicalSuccessorError("original verifier receipt filename mismatch")
        if self.mechanical_manifest_file != "mechanical_verify_manifest.json":
            raise MechanicalSuccessorError("mechanical manifest filename mismatch")
        for name in (
            "original_verifier_receipt_sha256",
            "original_verifier_receipt_digest",
            "original_output_sha256",
            "transformed_output_sha256",
            "mechanical_result_sha256",
            "mechanical_manifest_sha256",
        ):
            _require_digest(getattr(self, name), name)
        for name in (
            "original_verifier_receipt_size_bytes",
            "original_output_size_bytes",
            "transformed_output_size_bytes",
            "mechanical_manifest_size_bytes",
        ):
            _require_size(getattr(self, name), name)
        if self.transformed_output_size_bytes <= self.original_output_size_bytes:
            raise MechanicalSuccessorError("successor must append bytes to original output")
        if not isinstance(self.run_identity, str) or _RUN_ID_RE.fullmatch(
            self.run_identity
        ) is None:
            raise MechanicalSuccessorError("run_identity must be a canonical UUIDv4")
        if not isinstance(self.driver_identity, str) or _DRIVER_ID_RE.fullmatch(
            self.driver_identity
        ) is None:
            raise MechanicalSuccessorError("driver_identity must be sha256:<digest>")
        for name in ("executor_identity", "successor_identity"):
            if (
                not isinstance(getattr(self, name), str)
                or _CODE_ID_RE.fullmatch(getattr(self, name)) is None
            ):
                raise MechanicalSuccessorError(f"{name} must be sha256:<digest>")

    def _unsigned_dict(self) -> dict[str, Any]:
        return {field.name: getattr(self, field.name) for field in fields(self)}

    @property
    def receipt_digest(self) -> str:
        return _sha256(_canonical_json_bytes(self._unsigned_dict()))

    def to_dict(self) -> dict[str, Any]:
        return {**self._unsigned_dict(), "receipt_digest": self.receipt_digest}

    def to_json(self) -> str:
        return _canonical_json_bytes(self.to_dict()).decode("utf-8")

    @classmethod
    def from_json(cls, text: str) -> "MechanicalSuccessorReceipt":
        raw = text.encode("utf-8")
        value = _strict_json_object(raw, "mechanical successor receipt")
        expected = {field.name for field in fields(cls)} | {"receipt_digest"}
        if set(value) != expected:
            raise MechanicalSuccessorError(
                "mechanical successor receipt has non-canonical fields"
            )
        declared = _require_digest(value.pop("receipt_digest"), "receipt_digest")
        try:
            receipt = cls(**value)
        except TypeError as exc:
            raise MechanicalSuccessorError(f"invalid successor receipt: {exc}") from exc
        if declared != receipt.receipt_digest:
            raise MechanicalSuccessorError("mechanical successor receipt digest mismatch")
        return receipt


@dataclass(frozen=True, slots=True)
class PreparedMechanicalSuccessor:
    verify_path: Path
    receipt_path: Path
    observed_output_bytes: bytes
    original_output_bytes: bytes
    transformed_bytes: bytes
    receipt: MechanicalSuccessorReceipt
    receipt_bytes: bytes
    original_verifier_receipt_bytes: bytes
    original_verifier_identity_bytes: bytes
    original_severity_proposal_bytes: bytes
    mechanical_manifest_bytes: bytes
    work_plan_path: Path | None
    work_plan_bytes: bytes | None
    executor_path: Path
    successor_path: Path


@dataclass(frozen=True, slots=True)
class MechanicalSuccessorOutcome:
    receipt_path: Path
    transformed_written: bool
    receipt_written: bool


def _load_original_authority(
    verify_path: Path,
) -> tuple[VerifierOutputReceipt, bytes, bytes, bytes]:
    finding_id = verify_path.stem.removeprefix("verify_")
    if not finding_id or verify_path.name != f"verify_{finding_id}.md":
        raise MechanicalSuccessorError("verify path is not a canonical finding file")
    _canonical_directory_entry(verify_path, "verifier output")
    _reject_unknown_receipt_variants(verify_path, finding_id)
    receipt_path = verify_path.with_name(f"verify_{finding_id}.receipt.json")
    identity_path = verify_path.with_name(f"verify_{finding_id}.identity.json")
    proposal_path = verify_path.with_name(
        f"verify_{finding_id}.severity_proposal.json"
    )
    for path, label in (
        (receipt_path, "verifier receipt"),
        (identity_path, "verifier identity"),
        (proposal_path, "severity proposal"),
    ):
        _canonical_directory_entry(path, label)
    try:
        receipt_raw = receipt_path.read_bytes()
        identity_raw = identity_path.read_bytes()
    except OSError as exc:
        raise MechanicalSuccessorError(
            f"missing original verifier authority for {finding_id}: {exc}"
        ) from exc
    try:
        receipt = VerifierOutputReceipt.from_json(receipt_raw.decode("utf-8"))
        identity_value = _strict_json_object(identity_raw, "verifier identity")
        identity = VerifierOutputIdentity.from_dict(identity_value)
    except (UnicodeDecodeError, TypeError, ValueError) as exc:
        raise MechanicalSuccessorError(
            f"invalid original verifier authority for {finding_id}: {exc}"
        ) from exc
    if receipt_raw != receipt.to_json().encode("utf-8"):
        raise MechanicalSuccessorError(
            "original verifier receipt bytes are not canonical"
        )
    canonical_identity = _canonical_json_bytes(identity.to_dict())
    if identity_raw != canonical_identity:
        raise MechanicalSuccessorError(
            "original verifier identity bytes are not canonical"
        )
    if identity != receipt.identity:
        raise MechanicalSuccessorError(
            "verifier identity sidecar disagrees with verifier receipt"
        )
    if receipt.identity.work_item_id != finding_id:
        raise MechanicalSuccessorError("verifier receipt finding identity mismatch")
    if receipt.identity.expected_output_file != verify_path.name:
        raise MechanicalSuccessorError("verifier receipt output filename mismatch")
    if receipt.severity_proposal_file != proposal_path.name:
        raise MechanicalSuccessorError(
            "verifier receipt severity proposal filename mismatch"
        )
    try:
        proposal = proposal_path.read_bytes()
    except OSError as exc:
        raise MechanicalSuccessorError(
            f"missing verifier severity proposal: {exc}"
        ) from exc
    if _sha256(proposal) != receipt.severity_proposal_sha256:
        raise MechanicalSuccessorError("verifier severity proposal digest mismatch")
    if len(proposal) != receipt.severity_proposal_size_bytes:
        raise MechanicalSuccessorError("verifier severity proposal size mismatch")
    try:
        parsed_proposal = parse_severity_proposal(proposal)
    except Exception as exc:
        raise MechanicalSuccessorError(
            f"verifier severity proposal is semantically invalid: {exc}"
        ) from exc
    if parsed_proposal.get("candidate_id") != finding_id:
        raise MechanicalSuccessorError(
            "verifier severity proposal candidate identity mismatch"
        )
    constituents = parsed_proposal.get("constituent_ids")
    if not isinstance(constituents, list) or finding_id not in constituents:
        raise MechanicalSuccessorError(
            "verifier severity proposal omits its candidate constituent"
        )
    return receipt, receipt_raw, identity_raw, proposal


def _load_optional_work_plan_authority(
    verify_path: Path,
    identity: VerifierOutputIdentity,
) -> tuple[Path | None, bytes | None]:
    """Validate the persisted plan when it is present.

    Legacy isolated fixtures predate the plan sidecar, so absence remains a
    loud limitation of that fixture rather than fabricated plan authority.
    Production verifier runs always have the plan and therefore receive the
    stronger semantic ownership validation below.
    """

    path = verify_path.parent / "verification_queue.work_plan.json"
    try:
        casefold_matches = [
            entry.name
            for entry in path.parent.iterdir()
            if entry.name.casefold() == path.name.casefold()
        ]
    except OSError as exc:
        raise MechanicalSuccessorError(
            f"cannot establish verification work-plan ownership: {exc}"
        ) from exc
    if not casefold_matches:
        queue_authorities = (
            verify_path.parent / "verification_queue.md",
            verify_path.parent / "verification_queue.work_items.json",
        )
        if any(candidate.exists() for candidate in queue_authorities):
            raise MechanicalSuccessorError(
                "verification work plan authority is missing for a live queue"
            )
        return None, None
    _canonical_directory_entry(path, "verification work plan")
    try:
        raw = path.read_bytes()
        # The production reader additionally validates the plan against the
        # typed queue sidecar when present.  Keep the local parser as the
        # isolated-fixture fallback, not as a way to bypass queue authority.
        if (verify_path.parent / "verification_queue.work_items.json").is_file():
            from plamen_parsers import read_queue_work_plan

            plan = read_queue_work_plan(verify_path.parent)
        else:
            plan = QueueWorkPlan.from_json(raw.decode("utf-8"))
    except Exception as exc:
        raise MechanicalSuccessorError(
            f"verification work plan is semantically invalid: {exc}"
        ) from exc
    canonical_forms = {
        plan.to_json().encode("utf-8"),
        (plan.to_json() + "\n").encode("utf-8"),
    }
    if raw not in canonical_forms:
        raise MechanicalSuccessorError(
            "verification work plan bytes are not canonical"
        )
    if plan.digest != identity.work_plan_digest:
        raise MechanicalSuccessorError(
            "verification work plan digest disagrees with verifier identity"
        )
    try:
        shard = plan.shard(identity.shard_id)
    except ValueError as exc:
        raise MechanicalSuccessorError(
            f"verifier shard is absent from verification work plan: {exc}"
        ) from exc
    if identity.work_item_id not in shard.ordered_work_item_ids:
        raise MechanicalSuccessorError(
            "verification work plan does not assign the verifier finding"
        )
    owners = [
        owner
        for owner in shard.output_ownership
        if owner.work_item_id == identity.work_item_id
    ]
    if len(owners) != 1:
        raise MechanicalSuccessorError(
            "verification work plan output ownership is not singular"
        )
    owner = owners[0]
    if (
        owner.work_item_digest != identity.queue_record_digest
        or owner.expected_output_file != identity.expected_output_file
        or owner.expected_output_identity != identity.expected_output_identity
    ):
        raise MechanicalSuccessorError(
            "verification work plan output ownership disagrees with verifier identity"
        )
    return path, raw


def _validate_manifest(
    manifest_path: Path, result: Mapping[str, Any]
) -> bytes:
    if manifest_path.name != "mechanical_verify_manifest.json":
        raise MechanicalSuccessorError("mechanical manifest must use canonical filename")
    _canonical_directory_entry(manifest_path, "mechanical manifest")
    try:
        raw = manifest_path.read_bytes()
    except OSError as exc:
        raise MechanicalSuccessorError(f"mechanical manifest is unavailable: {exc}") from exc
    value = _strict_json_object(raw, "mechanical manifest")
    if set(value) != {"generated_at", "counts", "results"}:
        raise MechanicalSuccessorError(
            "mechanical manifest has non-canonical top-level fields"
        )
    rows = value.get("results")
    if not isinstance(rows, list):
        raise MechanicalSuccessorError("mechanical manifest results must be a list")
    normalized_rows: list[dict[str, Any]] = []
    identities: set[tuple[str, str]] = set()
    computed_counts: dict[str, int] = {}
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise MechanicalSuccessorError(
                f"mechanical manifest result row {index} must be an object"
            )
        try:
            normalized = _normalize_result(row)
        except MechanicalSuccessorError as exc:
            raise MechanicalSuccessorError(
                f"mechanical manifest result row {index} is invalid: {exc}"
            ) from exc
        identity = (
            normalized["finding_id"].casefold(),
            normalized["verify_file"].casefold(),
        )
        if identity in identities:
            raise MechanicalSuccessorError(
                "mechanical manifest contains duplicate or casefold-colliding "
                "finding identity"
            )
        identities.add(identity)
        normalized_rows.append(normalized)
        status = normalized["status"]
        computed_counts[status] = computed_counts.get(status, 0) + 1
    counts = value.get("counts")
    if counts != computed_counts:
        raise MechanicalSuccessorError(
            "mechanical manifest status counts disagree with result rows"
        )
    matches = [
        row
        for row in normalized_rows
        if row["finding_id"] == result["finding_id"]
        and row["verify_file"] == result["verify_file"]
    ]
    if len(matches) != 1:
        raise MechanicalSuccessorError(
            "mechanical manifest must contain exactly one matching result row"
        )
    manifest_result = matches[0]
    if _canonical_json_bytes(manifest_result) != _canonical_json_bytes(result):
        raise MechanicalSuccessorError(
            "mechanical manifest result disagrees with executed result"
        )
    return raw


def prepare_mechanical_successor(
    verify_path: Path,
    mechanical_result: Mapping[str, Any],
    mechanical_manifest_path: Path,
    *,
    run_identity: str,
    driver_identity: str,
) -> PreparedMechanicalSuccessor:
    """Validate every authority and construct deterministic successor bytes."""
    verify_path = Path(verify_path)
    manifest_path = Path(mechanical_manifest_path)
    result = _normalize_result(mechanical_result)
    if verify_path.name != result["verify_file"]:
        raise MechanicalSuccessorError("verify path disagrees with mechanical result")
    if not isinstance(run_identity, str) or _RUN_ID_RE.fullmatch(run_identity) is None:
        raise MechanicalSuccessorError("run_identity must be a canonical UUIDv4")
    if _DRIVER_ID_RE.fullmatch(driver_identity or "") is None:
        raise MechanicalSuccessorError("driver_identity must be sha256:<digest>")

    (
        original_receipt,
        original_receipt_raw,
        original_identity_raw,
        original_proposal_raw,
    ) = _load_original_authority(verify_path)
    work_plan_path, work_plan_raw = _load_optional_work_plan_authority(
        verify_path, original_receipt.identity
    )
    manifest_raw = _validate_manifest(manifest_path, result)
    try:
        observed = verify_path.read_bytes()
    except OSError as exc:
        raise MechanicalSuccessorError(f"verifier output is unavailable: {exc}") from exc

    original_size = original_receipt.output_size_bytes
    if len(observed) < original_size:
        raise MechanicalSuccessorError("verifier output is shorter than original receipt")
    original = observed[:original_size]
    if len(original) != original_size or _sha256(original) != original_receipt.output_sha256:
        raise MechanicalSuccessorError(
            "transformed verifier output does not preserve exact original prefix"
        )
    try:
        original_text = original.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MechanicalSuccessorError(
            "original verifier output is not strict UTF-8 Markdown"
        ) from exc
    if _RESERVED_MECHANICAL_FIELD_RE.search(original_text):
        raise MechanicalSuccessorError(
            "original verifier output fabricates a reserved mechanical field"
        )
    transformed = original + _annotation_suffix(result)
    if observed not in (original, transformed):
        raise MechanicalSuccessorError(
            "verifier output is neither the exact original nor deterministic successor"
        )

    finding_id = str(result["finding_id"])
    successor_path = Path(__file__).resolve()
    executor_path = successor_path.with_name("mechanical_verify.py")
    receipt = MechanicalSuccessorReceipt(
        schema_version=RECEIPT_SCHEMA_VERSION,
        annotation_schema_version=ANNOTATION_SCHEMA_VERSION,
        finding_id=finding_id,
        verify_file=verify_path.name,
        original_verifier_receipt_file=f"verify_{finding_id}.receipt.json",
        original_verifier_receipt_sha256=_sha256(original_receipt_raw),
        original_verifier_receipt_size_bytes=len(original_receipt_raw),
        original_verifier_receipt_digest=original_receipt.digest,
        original_output_sha256=_sha256(original),
        original_output_size_bytes=len(original),
        transformed_output_sha256=_sha256(transformed),
        transformed_output_size_bytes=len(transformed),
        mechanical_result_sha256=_sha256(_canonical_json_bytes(result)),
        mechanical_manifest_file=manifest_path.name,
        mechanical_manifest_sha256=_sha256(manifest_raw),
        mechanical_manifest_size_bytes=len(manifest_raw),
        run_identity=run_identity,
        driver_identity=driver_identity,
        executor_identity=_code_identity(executor_path, "mechanical executor"),
        successor_identity=_code_identity(successor_path, "mechanical successor"),
    )
    receipt_path = verify_path.with_name(
        f"verify_{finding_id}{_RECEIPT_SUFFIX}"
    )
    return PreparedMechanicalSuccessor(
        verify_path=verify_path,
        receipt_path=receipt_path,
        observed_output_bytes=observed,
        original_output_bytes=original,
        transformed_bytes=transformed,
        receipt=receipt,
        receipt_bytes=receipt.to_json().encode("utf-8"),
        original_verifier_receipt_bytes=original_receipt_raw,
        original_verifier_identity_bytes=original_identity_raw,
        original_severity_proposal_bytes=original_proposal_raw,
        mechanical_manifest_bytes=manifest_raw,
        work_plan_path=work_plan_path,
        work_plan_bytes=work_plan_raw,
        executor_path=executor_path,
        successor_path=successor_path,
    )


def _atomic_write(path: Path, data: bytes) -> None:
    """Replace one successor output only if its original prefix is unchanged.

    The comparison intentionally lives inside this helper, immediately before
    ``os.replace``.  That closes the old check/use seam even when a caller or
    test wrapper intervenes after ``apply_mechanical_successor`` performed its
    outer read.
    """

    guard = _ACTIVE_WRITE_GUARD.get()
    if guard is not None:
        guard()
    marker = b"\n<!-- mechanical-verify-successor v2;"
    marker_at = data.find(marker)
    if marker_at < 0:
        raise MechanicalSuccessorError(
            "mechanical successor output is missing its reserved commit marker"
        )
    expected = data[:marker_at]
    try:
        current = path.read_bytes()
    except OSError as exc:
        raise MechanicalSuccessorError(
            f"mechanical successor compare-and-swap read failed: {exc}"
        ) from exc
    if current != expected:
        raise MechanicalSuccessorError(
            "verifier output changed concurrently before atomic successor write"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.tmp-{os.getpid()}-{uuid.uuid4().hex}")
    try:
        with temp.open("xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if guard is not None:
            guard()
        # Recheck the compare side after staging too: creating/fsyncing a
        # large successor can give another writer time to edit the source.
        if path.read_bytes() != expected:
            raise MechanicalSuccessorError(
                "verifier output changed concurrently during successor staging"
            )
        os.replace(temp, path)
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


def _atomic_create(path: Path, data: bytes) -> None:
    """Atomically create immutable receipt bytes without replacing a rival."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.tmp-{os.getpid()}-{uuid.uuid4().hex}")
    try:
        with temp.open("xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            # Same-directory hard-link creation is an atomic create-if-absent
            # operation on supported Windows and POSIX filesystems.
            os.link(temp, path)
        except FileExistsError as exc:
            raise MechanicalSuccessorError(
                "mechanical successor receipt appeared during commit"
            ) from exc
        except OSError as exc:
            # Do not fall back to replace: overwriting an independently-created
            # authority would turn a race or fabrication into a valid commit.
            raise MechanicalSuccessorError(
                f"atomic successor receipt creation failed: {exc}"
            ) from exc
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


def _validate_prepared_authorities(prepared: PreparedMechanicalSuccessor) -> None:
    """Reread every bound authority and code identity at the commit boundary."""

    finding_id = prepared.receipt.finding_id
    paths_and_bytes = (
        (
            prepared.verify_path.with_name(f"verify_{finding_id}.receipt.json"),
            prepared.original_verifier_receipt_bytes,
            "original verifier receipt",
        ),
        (
            prepared.verify_path.with_name(f"verify_{finding_id}.identity.json"),
            prepared.original_verifier_identity_bytes,
            "original verifier identity",
        ),
        (
            prepared.verify_path.with_name(
                f"verify_{finding_id}.severity_proposal.json"
            ),
            prepared.original_severity_proposal_bytes,
            "original severity proposal",
        ),
        (
            prepared.verify_path.with_name(
                prepared.receipt.mechanical_manifest_file
            ),
            prepared.mechanical_manifest_bytes,
            "mechanical manifest",
        ),
    )
    for path, expected, label in paths_and_bytes:
        _canonical_directory_entry(path, label)
        try:
            observed = path.read_bytes()
        except OSError as exc:
            raise MechanicalSuccessorError(
                f"{label} authority became unavailable: {exc}"
            ) from exc
        if observed != expected:
            raise MechanicalSuccessorError(
                f"{label} authority changed during successor commit"
            )
    if prepared.work_plan_path is not None:
        assert prepared.work_plan_bytes is not None
        _canonical_directory_entry(prepared.work_plan_path, "verification work plan")
        try:
            work_plan_after = prepared.work_plan_path.read_bytes()
        except OSError as exc:
            raise MechanicalSuccessorError(
                f"verification work plan authority became unavailable: {exc}"
            ) from exc
        if work_plan_after != prepared.work_plan_bytes:
            raise MechanicalSuccessorError(
                "verification work plan authority changed during successor commit"
            )
    if (
        _code_identity(prepared.executor_path, "mechanical executor")
        != prepared.receipt.executor_identity
    ):
        raise MechanicalSuccessorError(
            "mechanical executor code identity changed during successor commit"
        )
    if (
        _code_identity(prepared.successor_path, "mechanical successor")
        != prepared.receipt.successor_identity
    ):
        raise MechanicalSuccessorError(
            "mechanical successor code identity changed during successor commit"
        )


def apply_mechanical_successor(
    verify_path: Path,
    mechanical_result: Mapping[str, Any],
    mechanical_manifest_path: Path,
    *,
    run_identity: str,
    driver_identity: str,
) -> MechanicalSuccessorOutcome:
    """Commit or exactly replay one immutable mechanical successor.

    Existing bytes are never normalized or rewritten.  Any state other than
    original-only, receipt-only, transformed-only, or the exact committed pair
    is rejected without attempting a repair.
    """
    prepared = prepare_mechanical_successor(
        verify_path,
        mechanical_result,
        mechanical_manifest_path,
        run_identity=run_identity,
        driver_identity=driver_identity,
    )
    _validate_prepared_authorities(prepared)
    receipt_exists = prepared.receipt_path.exists()
    if receipt_exists:
        _canonical_directory_entry(
            prepared.receipt_path, "mechanical successor receipt"
        )
        try:
            existing_receipt_raw = prepared.receipt_path.read_bytes()
            existing_receipt = MechanicalSuccessorReceipt.from_json(
                existing_receipt_raw.decode("utf-8")
            )
        except (OSError, UnicodeDecodeError, MechanicalSuccessorError) as exc:
            raise MechanicalSuccessorError(
                f"invalid existing mechanical successor receipt: {exc}"
            ) from exc
        if existing_receipt != prepared.receipt:
            raise MechanicalSuccessorError(
                "existing mechanical successor receipt disagrees with authority"
            )
        if existing_receipt_raw != prepared.receipt_bytes:
            raise MechanicalSuccessorError(
                "existing mechanical successor receipt is not canonical bytes"
            )

    try:
        current = prepared.verify_path.read_bytes()
    except OSError as exc:
        raise MechanicalSuccessorError(
            f"verifier output became unavailable during successor commit: {exc}"
        ) from exc
    if current != prepared.observed_output_bytes:
        raise MechanicalSuccessorError("verifier output changed during successor commit")
    is_transformed = current == prepared.transformed_bytes
    is_original = current == prepared.original_output_bytes
    if not (is_transformed or is_original):
        raise MechanicalSuccessorError("unrecognized mechanical successor state")

    receipt_written = False
    transformed_written = False
    # Receipt-first makes a failed second replace a strictly verifiable,
    # repairable partial instead of an unreceipted mutation.
    if not receipt_exists:
        try:
            _atomic_create(prepared.receipt_path, prepared.receipt_bytes)
        except MechanicalSuccessorError:
            raise
        except OSError as exc:
            raise MechanicalSuccessorError(
                f"mechanical successor receipt commit failed: {exc}"
            ) from exc
        receipt_written = True
        # The immutable receipt was created from the prepared snapshot.  Do
        # not let a concurrent rewrite of any upstream authority reach the
        # mutable Markdown half of the transaction.
        _validate_prepared_authorities(prepared)
    if is_original:
        # Do not overwrite an intervening edit after the receipt commit.
        try:
            still_original = (
                prepared.verify_path.read_bytes() == prepared.original_output_bytes
            )
        except OSError as exc:
            raise MechanicalSuccessorError(
                f"verifier output became unavailable after receipt commit: {exc}"
            ) from exc
        if not still_original:
            raise MechanicalSuccessorError(
                "verifier output changed after successor receipt commit"
            )
        _validate_prepared_authorities(prepared)
        guard_token = _ACTIVE_WRITE_GUARD.set(
            lambda: _validate_prepared_authorities(prepared)
        )
        try:
            _atomic_write(prepared.verify_path, prepared.transformed_bytes)
        except MechanicalSuccessorError:
            raise
        except OSError as exc:
            raise MechanicalSuccessorError(
                f"mechanical successor output commit failed: {exc}"
            ) from exc
        finally:
            _ACTIVE_WRITE_GUARD.reset(guard_token)
        transformed_written = True

    _validate_prepared_authorities(prepared)

    try:
        output_after = prepared.verify_path.read_bytes()
        receipt_after = prepared.receipt_path.read_bytes()
    except OSError as exc:
        raise MechanicalSuccessorError(
            f"mechanical successor post-commit validation failed: {exc}"
        ) from exc
    if output_after != prepared.transformed_bytes:
        raise MechanicalSuccessorError("mechanical successor output commit did not persist")
    if receipt_after != prepared.receipt_bytes:
        raise MechanicalSuccessorError("mechanical successor receipt commit did not persist")
    return MechanicalSuccessorOutcome(
        receipt_path=prepared.receipt_path,
        transformed_written=transformed_written,
        receipt_written=receipt_written,
    )


__all__ = [
    "ANNOTATION_SCHEMA_VERSION",
    "RECEIPT_SCHEMA_VERSION",
    "MechanicalSuccessorError",
    "MechanicalSuccessorOutcome",
    "MechanicalSuccessorReceipt",
    "PreparedMechanicalSuccessor",
    "apply_mechanical_successor",
    "prepare_mechanical_successor",
]
