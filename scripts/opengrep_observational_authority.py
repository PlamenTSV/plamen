"""Replay authority for positive OpenGrep evidence from reduced isolation.

Compatibility execution cannot certify that a zero-result scan is complete.
That limitation must remain tool-coverage debt, but it does not make concrete,
schema-valid positive SARIF rows disappear.  This sidecar binds those rows to
the exact failed/debt outcome, compatibility execution receipt, and promoted
artifact bytes.  Consumers may route the candidates while retaining the debt.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping


SCHEMA = "plamen.opengrep-observational-positive.v1"
FILENAME = "opengrep_observational_positive.v1.json"
ARTIFACTS = ("opengrep_results.sarif", "opengrep_findings.md")
_HEX = re.compile(r"[0-9a-f]{64}")
_TOTAL_RE = re.compile(r"^> \*\*Total\*\*: (\d+) findings$", re.MULTILINE)
_ROW_RE = re.compile(r"^\|\s*(\d+)\s*\|", re.MULTILINE)
_REASON_PREFIX = "EXECUTED_OBSERVATIONAL_REDUCED_ISOLATION:"


class OpenGrepObservationalAuthorityError(ValueError):
    pass


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _sha_file(path: Path) -> tuple[str, int]:
    raw = path.read_bytes()
    return hashlib.sha256(raw).hexdigest(), len(raw)


def _positive_count(root: Path) -> int:
    try:
        sarif = json.loads((root / ARTIFACTS[0]).read_text(encoding="utf-8"))
        runs = sarif["runs"]
        if sarif.get("version") != "2.1.0" or not isinstance(runs, list):
            raise ValueError
        sarif_count = 0
        for run in runs:
            if not isinstance(run, dict) or not isinstance(run.get("results", []), list):
                raise ValueError
            sarif_count += len(run.get("results", []))
        markdown = (root / ARTIFACTS[1]).read_text(encoding="utf-8")
        total = _TOTAL_RE.search(markdown)
        rows = [int(match.group(1)) for match in _ROW_RE.finditer(markdown)]
    except (OSError, UnicodeError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise OpenGrepObservationalAuthorityError(
            "observational OpenGrep artifacts are malformed"
        ) from exc
    if (
        total is None
        or sarif_count <= 0
        or int(total.group(1)) != sarif_count
        or rows != list(range(1, sarif_count + 1))
    ):
        raise OpenGrepObservationalAuthorityError(
            "observational OpenGrep result counts disagree"
        )
    return sarif_count


def _validate_outcome_record(record: Mapping[str, Any]) -> dict[str, Any]:
    value = dict(record)
    if (
        value.get("capability_id") != "opengrep.static-analysis"
        or value.get("tool") != "opengrep"
        or value.get("state") != "FAILED"
        or not str(value.get("reason") or "").startswith(_REASON_PREFIX)
        or value.get("finding_count") is not None
        or value.get("schema_validated") is not False
        or value.get("artifacts") != []
    ):
        raise OpenGrepObservationalAuthorityError(
            "observational OpenGrep debt outcome is malformed"
        )
    try:
        evidence = json.loads(str(value.get("provider_ref") or ""))
    except (TypeError, json.JSONDecodeError) as exc:
        raise OpenGrepObservationalAuthorityError(
            "observational OpenGrep execution evidence is unreadable"
        ) from exc
    terminal = evidence.get("terminal") if isinstance(evidence, dict) else None
    if (
        not isinstance(evidence, dict)
        or evidence.get("schema") != "plamen.compat-static-analysis-execution.v1"
        or evidence.get("authority_tier") != "OBSERVATIONAL_REDUCED_ISOLATION"
        or evidence.get("can_certify_clean") is not False
        or evidence.get("tool_id") != "opengrep"
        or _HEX.fullmatch(str(evidence.get("workspace_receipt_sha256") or "")) is None
        or _HEX.fullmatch(str(evidence.get("policy_sha256") or "")) is None
        or _HEX.fullmatch(str(evidence.get("request_sha256") or "")) is None
        or _HEX.fullmatch(str(evidence.get("terminal_sha256") or "")) is None
        or not isinstance(terminal, dict)
        or evidence.get("terminal_sha256")
        != hashlib.sha256(_canonical(terminal or {})).hexdigest()
        or terminal.get("status") != "COMPLETED"
        or terminal.get("returncode") != 0
        or terminal.get("actual_tool_started") is not True
        or terminal.get("actual_tool_completion_observed") is not True
    ):
        raise OpenGrepObservationalAuthorityError(
            "observational OpenGrep execution evidence is incomplete"
        )
    return evidence


def build_receipt(
    root: Path,
    *,
    outcome_record: Mapping[str, Any],
) -> dict[str, Any]:
    root = Path(root)
    evidence = _validate_outcome_record(outcome_record)
    finding_count = _positive_count(root)
    artifact_rows = []
    for name in ARTIFACTS:
        digest, size = _sha_file(root / name)
        if size <= 0:
            raise OpenGrepObservationalAuthorityError(
                f"observational OpenGrep artifact is empty: {name}"
            )
        artifact_rows.append({"path": name, "sha256": digest, "bytes": size})
    unsigned = {
        "schema": SCHEMA,
        "capability_id": "opengrep.static-analysis",
        "authority_tier": "OBSERVATIONAL_REDUCED_ISOLATION",
        "can_certify_clean": False,
        "finding_count": finding_count,
        "workspace_receipt_sha256": evidence["workspace_receipt_sha256"],
        "execution_evidence_sha256": hashlib.sha256(
            _canonical(evidence)
        ).hexdigest(),
        "outcome_record_sha256": hashlib.sha256(
            _canonical(dict(outcome_record))
        ).hexdigest(),
        "artifacts": artifact_rows,
    }
    return {
        **unsigned,
        "receipt_sha256": hashlib.sha256(_canonical(unsigned)).hexdigest(),
    }


def write_receipt(
    root: Path,
    *,
    outcome_record: Mapping[str, Any],
) -> dict[str, Any]:
    root = Path(root)
    receipt = build_receipt(root, outcome_record=outcome_record)
    target = root / FILENAME
    temporary = root / f".{FILENAME}.tmp"
    try:
        temporary.write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(target)
    finally:
        temporary.unlink(missing_ok=True)
    return receipt


def load_receipt(
    root: Path,
    *,
    outcome_record: Mapping[str, Any],
) -> dict[str, Any]:
    root = Path(root)
    try:
        observed = json.loads((root / FILENAME).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise OpenGrepObservationalAuthorityError(
            "observational OpenGrep receipt is unreadable"
        ) from exc
    expected = build_receipt(root, outcome_record=outcome_record)
    if observed != expected:
        raise OpenGrepObservationalAuthorityError(
            "observational OpenGrep receipt does not replay"
        )
    return expected


__all__ = [
    "FILENAME",
    "OpenGrepObservationalAuthorityError",
    "load_receipt",
    "write_receipt",
]
