"""Typed, recall-safe authority for the confidence Consensus axis.

Consensus is independent analytical corroboration.  A single observation,
location collision, assigned skill, repeated prose, or stale worker artifact is
not agreement.  This module derives the signal only from current depth worker
dispatches whose findings explicitly name the same upstream finding identity.

The authority is deliberately conservative.  An absent or malformed binding
produces a zero consensus score and visible debt; it never removes a finding,
changes severity, or asserts/refutes a vulnerability.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import uuid
from typing import Any, Iterable, Mapping

from finding_producer_registry import producer_for_artifact, producer_patterns
from methodology_application import (
    phase_dispatch_sha256,
    worker_dispatch_contract_sha256,
)
from plamen_parsers import _extract_finding_ids_from_text
from plamen_types import FINDING_BLOCK_HEADING_RE


AUTHORITY_SCHEMA = "plamen.confidence_consensus_authority.v1"
AUTHORITY_NAME = "confidence_consensus_authority.json"
MARKDOWN_NAME = "consensus_map.md"
ASSURANCE = "INDEPENDENT_CORROBORATION_SIGNAL_ONLY"

_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_SOURCE_LABEL_RE = re.compile(
    r"(?im)^[ \t]*(?:[-*][ \t]+)?\*{0,2}(?:"
    r"Source[ \t]+Finding(?:s|\(s\))?|Source[ \t]+IDs?|"
    r"Original[ \t]+Finding(?:s|\(s\))?|Inventory[ \t]+Finding(?:s|\(s\))?"
    r")\*{0,2}[ \t]*:[ \t]*(?P<value>[^\r\n]+?)[ \t]*\r?$"
)
_TARGET_HEADING_RE = re.compile(r"(?im)^#{2,4}[ \t]+Target\b.*$")
_MARKER_PATTERNS = {
    "phase": re.compile(
        r"<!--\s*PLAMEN_DISPATCH_PHASE\s*:\s*([^>]*?)\s*-->", re.I
    ),
    "worker": re.compile(
        r"<!--\s*PLAMEN_DISPATCH_WORKER\s*:\s*([^>]*?)\s*-->", re.I
    ),
    "output": re.compile(
        r"<!--\s*PLAMEN_DISPATCH_OUTPUT\s*:\s*([^>]*?)\s*-->", re.I
    ),
    "contract": re.compile(
        r"<!--\s*PLAMEN_DISPATCH_CONTRACT_SHA256\s*:\s*([^>]*?)\s*-->",
        re.I,
    ),
    "owner": re.compile(r"<!--\s*PLAMEN_OWNER\s*:\s*([^>]*?)\s*-->", re.I),
}
_FINAL_COMPLETE_RE = re.compile(
    r"<!--\s*PLAMEN_STATUS\s*:\s*COMPLETE\s*-->\s*\Z", re.I
)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _digest(value: Any) -> str:
    return _sha(
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )


def _atomic_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    tmp.write_text(text, encoding="utf-8", newline="\n")
    os.replace(tmp, path)


def _read_json(path: Path) -> tuple[dict[str, Any], str | None]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return {}, f"{path.name} unavailable or malformed: {exc}"
    if not isinstance(value, dict):
        return {}, f"{path.name} root is not an object"
    return value, None


def _single_marker(text: str, key: str) -> tuple[str, str | None]:
    values = _MARKER_PATTERNS[key].findall(text)
    if len(values) != 1:
        return "", f"artifact has {len(values)} {key} dispatch markers"
    return str(values[0]).strip(), None


def _source_artifact_names(scratchpad: Path) -> list[str]:
    names: set[str] = set()
    for pattern in producer_patterns(
        "pre_dedup_promotion", owner_phase="depth"
    ):
        for path in scratchpad.glob(pattern):
            if path.is_file() and path.name.endswith("_findings.md"):
                names.add(path.name)
    return sorted(names)


def _finding_blocks(text: str) -> Iterable[tuple[str, int, int, str, str]]:
    """Yield ID, bounds, block, and bounded pre-block target context."""

    matches = list(FINDING_BLOCK_HEADING_RE.finditer(text))
    target_starts = [match.start() for match in _TARGET_HEADING_RE.finditer(text)]
    previous_end = 0
    for index, match in enumerate(matches):
        start = match.start()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        target_start = max(
            (value for value in target_starts if previous_end <= value < start),
            default=previous_end,
        )
        context = text[target_start:start]
        yield match.group(1).strip(), start, end, text[start:end], context
        previous_end = end


def _source_identity(
    block: str, context: str
) -> tuple[tuple[str, ...], str]:
    """Return explicit upstream identities and their binding quality.

    Multiple identities in one plural source field are an exact one-to-many
    binding.  Multiple source fields are accepted only when they repeat the
    same identity set; conflicting fields are ambiguous.  A present field
    from which no registered finding identity can be extracted is malformed,
    rather than being collapsed into the same state as an omitted field.
    """

    # A field inside the finding is strongest.  The role templates historically
    # put it in the immediately enclosing Target section, which remains an
    # accepted bounded compatibility form.
    matches = list(_SOURCE_LABEL_RE.finditer(block))
    if not matches:
        matches = list(_SOURCE_LABEL_RE.finditer(context))
    if not matches:
        return (), "MISSING"

    identity_sets: list[tuple[str, ...]] = []
    for match in matches:
        identities = tuple(
            sorted(
                {
                    value.upper()
                    for value in _extract_finding_ids_from_text(
                        match.group("value")
                    )
                }
            )
        )
        if not identities:
            return (), "MALFORMED"
        identity_sets.append(identities)
    if len(set(identity_sets)) != 1:
        return (), "AMBIGUOUS"
    return identity_sets[0], "EXACT"


def _source_ids(block: str, context: str) -> tuple[str, ...]:
    """Compatibility projection used by older in-module callers/tests."""

    return _source_identity(block, context)[0]


def _identity_debt_type(identity_status: str) -> str:
    return {
        "MISSING": "MISSING_UPSTREAM_IDENTITY",
        "MALFORMED": "MALFORMED_UPSTREAM_IDENTITY",
        "AMBIGUOUS": "AMBIGUOUS_UPSTREAM_IDENTITY",
    }.get(identity_status, "PRODUCER_AUTHORITY_UNBOUND")


def _identity_debt(observation: Mapping[str, Any]) -> dict[str, Any]:
    candidate_ref = {
        "source_artifact": str(observation.get("source_artifact") or ""),
        "source_artifact_sha256": str(
            observation.get("source_artifact_sha256") or ""
        ),
        "finding_id": str(observation.get("finding_id") or ""),
        "source_byte_start": int(observation.get("source_byte_start") or 0),
        "source_byte_end": int(observation.get("source_byte_end") or 0),
        "claim_block_sha256": str(observation.get("claim_block_sha256") or ""),
        "observation_digest": str(observation.get("observation_digest") or ""),
    }
    debt_seed = {
        "debt_type": _identity_debt_type(
            str(observation.get("identity_status") or "")
        ),
        "candidate_ref": candidate_ref,
    }
    return {
        "debt_id": "CID-DEBT-" + _digest(debt_seed)[:24].upper(),
        "debt_type": debt_seed["debt_type"],
        "identity_status": str(observation.get("identity_status") or ""),
        "resolution_status": "OPEN",
        "required_action": "RETAIN_PENDING_IDENTITY_RECONCILIATION",
        "negative_or_drop_authority": False,
        "proof_authority": "NONE",
        "candidate_ref": candidate_ref,
        "authority_issues": list(observation.get("authority_issues") or []),
    }


def _dispatch_state(
    scratchpad: Path,
) -> tuple[dict[str, dict[str, Any]], dict[str, str], list[str]]:
    """Return output->entry, output->job owner, and global authority issues."""

    issues: list[str] = []
    dispatch_path = scratchpad / "skill_dispatch.json"
    contract_path = scratchpad / "_depth_worker_pool_contract.json"
    dispatch, issue = _read_json(dispatch_path)
    if issue:
        issues.append(issue)
    contract, issue = _read_json(contract_path)
    if issue:
        issues.append(issue)

    phase = dispatch.get("phases", {}).get("depth", {}) if dispatch else {}
    if not isinstance(phase, dict):
        issues.append("skill_dispatch depth phase is not an object")
        phase = {}
    stored_dispatch_digest = str(phase.get("dispatch_sha256") or "")
    if not _SHA_RE.fullmatch(stored_dispatch_digest):
        issues.append("depth dispatch digest is missing or malformed")
    elif phase_dispatch_sha256(phase) != stored_dispatch_digest:
        issues.append("depth dispatch digest mismatch")

    if contract.get("phase") != "depth" or contract.get("version") != 2:
        issues.append("depth worker-pool contract is not current version 2")
    if str(contract.get("skill_dispatch_sha256") or "") != stored_dispatch_digest:
        issues.append("worker-pool contract does not bind current depth dispatch")

    entries: dict[str, dict[str, Any]] = {}
    raw_entries = phase.get("entries") if isinstance(phase, dict) else None
    if not isinstance(raw_entries, list):
        issues.append("depth dispatch entries are missing")
        raw_entries = []
    for raw in raw_entries:
        if not isinstance(raw, dict):
            issues.append("depth dispatch contains a non-object entry")
            continue
        output = str(raw.get("output") or "").strip()
        if not output or output in entries:
            issues.append(f"depth dispatch output is missing or duplicated: {output!r}")
            continue
        entries[output] = dict(raw)

    owners: dict[str, str] = {}
    raw_jobs = contract.get("jobs") if isinstance(contract, dict) else None
    if not isinstance(raw_jobs, list):
        issues.append("depth worker-pool jobs are missing")
        raw_jobs = []
    for raw in raw_jobs:
        if not isinstance(raw, dict):
            issues.append("depth worker-pool contains a non-object job")
            continue
        output = str(raw.get("output") or "").strip()
        owner = str(raw.get("agent_id") or "").strip()
        if not output or not owner or output in owners:
            issues.append(f"depth worker-pool job is missing or duplicated: {output!r}")
            continue
        owners[output] = owner
    if set(entries) != set(owners):
        issues.append("depth dispatch and worker-pool output denominators differ")

    # A broken global digest invalidates every individual entry.  Keep the
    # entries for exact debt enumeration but never let them corroborate.
    return entries, owners, sorted(set(issues))


def _entry_issues(
    scratchpad: Path,
    *,
    output: str,
    text: str,
    entry: Mapping[str, Any] | None,
    expected_owner: str,
    global_issues: list[str],
) -> list[str]:
    issues = list(global_issues)
    if entry is None:
        return sorted(set([*issues, "artifact has no depth dispatch entry"]))
    worker = str(entry.get("worker_id") or entry.get("agent_id") or "").strip()
    prompt_sha = str(entry.get("prompt_sha256") or "")
    contract_sha = str(entry.get("dispatch_contract_sha256") or "")
    if not worker or worker != expected_owner:
        issues.append("dispatch worker does not match worker-pool owner")
    if not _SHA_RE.fullmatch(prompt_sha):
        issues.append("dispatch prompt digest is missing or malformed")
    if not _SHA_RE.fullmatch(contract_sha):
        issues.append("dispatch contract digest is missing or malformed")
    elif worker_dispatch_contract_sha256("depth", dict(entry)) != contract_sha:
        issues.append("dispatch contract digest mismatch")

    if _SHA_RE.fullmatch(prompt_sha):
        stem = Path(output).stem
        candidates = sorted(
            scratchpad.glob(f"_prompt_depth_worker_{stem}.attempt*.md")
        )
        if not candidates:
            issues.append("output-specific prompt snapshot is missing")
        elif not any(_sha(path.read_bytes()) == prompt_sha for path in candidates):
            issues.append("no output-specific prompt snapshot matches dispatch")

    expected_markers = {
        "phase": "depth",
        "worker": worker,
        "output": output,
        "contract": contract_sha,
        "owner": worker,
    }
    for key, expected in expected_markers.items():
        observed, marker_issue = _single_marker(text, key)
        if marker_issue:
            issues.append(marker_issue)
        elif observed != expected:
            issues.append(f"artifact {key} marker does not match dispatch")
    if not _FINAL_COMPLETE_RE.search(text):
        issues.append("artifact completion marker is absent or not final")
    return sorted(set(issues))


def _observation_digest(row: Mapping[str, Any]) -> str:
    return _digest(
        {
            key: row[key]
            for key in row
            if key not in {"observation_digest"}
        }
    )


def _independent_peers(
    observation: Mapping[str, Any], observations: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Return a deterministic decorrelated subset including ``observation``.

    Distinct output files are insufficient: retries can restate one worker's
    conclusion, and identical prompts remain correlated.  A corroborator must
    have a distinct worker identity, prompt digest, dispatch contract, and an
    explicit directly-overlapping semantic anchor.
    """

    if observation.get("authority_status") != "CURRENT":
        return []
    anchors = set(observation.get("source_finding_ids") or [])
    if not anchors:
        return []
    chosen = [dict(observation)]
    used_workers = {str(observation.get("worker_id") or "")}
    used_prompts = {str(observation.get("prompt_sha256") or "")}
    used_contracts = {str(observation.get("dispatch_contract_sha256") or "")}
    candidates = sorted(
        (
            row
            for row in observations
            if row.get("observation_digest") != observation.get("observation_digest")
            and row.get("authority_status") == "CURRENT"
            and anchors.intersection(row.get("source_finding_ids") or [])
        ),
        key=lambda row: str(row.get("observation_digest") or ""),
    )
    for row in candidates:
        worker = str(row.get("worker_id") or "")
        prompt = str(row.get("prompt_sha256") or "")
        contract = str(row.get("dispatch_contract_sha256") or "")
        if worker in used_workers or prompt in used_prompts or contract in used_contracts:
            continue
        chosen.append(row)
        used_workers.add(worker)
        used_prompts.add(prompt)
        used_contracts.add(contract)
    return chosen


def _score_for_count(count: int) -> tuple[float, str]:
    if count <= 0:
        return 0.0, "UNBOUND_OR_NO_SEMANTIC_ANCHOR"
    if count == 1:
        return 0.0, "SINGLE_OBSERVER_NO_AGREEMENT"
    if count == 2:
        return 0.5, "ONE_INDEPENDENT_CORROBORATOR"
    if count == 3:
        return 0.75, "TWO_INDEPENDENT_CORROBORATORS"
    return 1.0, "THREE_PLUS_INDEPENDENT_CORROBORATORS"


def build_confidence_consensus_authority(scratchpad: Path) -> dict[str, Any]:
    scratchpad = Path(scratchpad)
    entries, owners, global_issues = _dispatch_state(scratchpad)
    observations: list[dict[str, Any]] = []
    input_bindings: list[dict[str, str]] = []
    for name in ("skill_dispatch.json", "_depth_worker_pool_contract.json"):
        path = scratchpad / name
        if path.is_file():
            input_bindings.append({"path": name, "sha256": _sha(path.read_bytes())})

    for name in _source_artifact_names(scratchpad):
        path = scratchpad / name
        try:
            data = path.read_bytes()
            text = data.decode("utf-8", errors="replace")
        except OSError:
            continue
        producer = producer_for_artifact(name, consumer="pre_dedup_promotion")
        entry = entries.get(name)
        entry_issues = _entry_issues(
            scratchpad,
            output=name,
            text=text,
            entry=entry,
            expected_owner=owners.get(name, ""),
            global_issues=global_issues,
        )
        artifact_sha = _sha(data)
        input_bindings.append({"path": name, "sha256": artifact_sha})
        if entry is not None:
            prompt_sha = str(entry.get("prompt_sha256") or "")
            for prompt in sorted(
                scratchpad.glob(f"_prompt_depth_worker_{Path(name).stem}.attempt*.md")
            ):
                if prompt.is_file() and _sha(prompt.read_bytes()) == prompt_sha:
                    input_bindings.append(
                        {"path": prompt.name, "sha256": prompt_sha}
                    )
                    break
        for finding_id, start, end, block, context in _finding_blocks(text):
            anchors, identity_status = _source_identity(block, context)
            issues = list(entry_issues)
            if identity_status == "MISSING":
                issues.append("finding lacks an explicit upstream source identity")
            elif identity_status == "MALFORMED":
                issues.append("finding upstream source identity is malformed")
            elif identity_status == "AMBIGUOUS":
                issues.append("finding upstream source identity is ambiguous")
            row: dict[str, Any] = {
                "finding_id": finding_id,
                "source_artifact": name,
                "source_artifact_sha256": artifact_sha,
                "source_byte_start": len(text[:start].encode("utf-8")),
                "source_byte_end": len(text[:end].encode("utf-8")),
                "producer_key": producer.key if producer else "UNREGISTERED",
                "worker_id": str((entry or {}).get("worker_id") or ""),
                "prompt_sha256": str((entry or {}).get("prompt_sha256") or ""),
                "dispatch_contract_sha256": str(
                    (entry or {}).get("dispatch_contract_sha256") or ""
                ),
                "source_finding_ids": list(anchors),
                "identity_status": identity_status,
                "authority_status": "CURRENT" if not issues else "UNBOUND",
                "authority_issues": sorted(set(issues)),
                "claim_block_sha256": _sha(block.encode("utf-8")),
            }
            row["observation_digest"] = _observation_digest(row)
            observations.append(row)

    observations.sort(
        key=lambda row: (
            row["source_artifact"],
            row["finding_id"].upper(),
            row["source_byte_start"],
        )
    )
    scores: list[dict[str, Any]] = []
    for row in observations:
        peers = _independent_peers(row, observations)
        score, basis = _score_for_count(len(peers))
        scores.append(
            {
                "finding_id": row["finding_id"],
                "source_artifact": row["source_artifact"],
                "observation_digest": row["observation_digest"],
                "semantic_anchors": list(row["source_finding_ids"]),
                "independent_observer_count": len(peers),
                "independent_observation_digests": [
                    peer["observation_digest"] for peer in peers
                ],
                "score": score,
                "basis": basis,
                # Consensus is additive telemetry.  In particular, an
                # unbound producer identity is never a negative finding
                # disposition and cannot authorize a drop.
                "negative_or_drop_authority": False,
                "preservation_required": row["authority_status"] != "CURRENT",
                "identity_status": row["identity_status"],
                # Skill assignment/application belongs to analysis-quality and
                # application assurance, never the agreement numerator.
                "specialized_methodology_bonus": 0.0,
            }
        )

    identity_debts = [
        _identity_debt(row)
        for row in observations
        if row["authority_status"] != "CURRENT"
    ]
    current_count = sum(
        row["authority_status"] == "CURRENT" for row in observations
    )
    all_unbound = bool(observations) and current_count == 0
    if identity_debts:
        authority_state = "RECONCILIATION_REQUIRED"
    elif observations:
        authority_state = "CURRENT"
    else:
        authority_state = "EMPTY_DENOMINATOR"

    payload: dict[str, Any] = {
        "schema_version": AUTHORITY_SCHEMA,
        "assurance": ASSURANCE,
        "policy": {
            "single_observer_score": 0.0,
            "location_only_agreement": False,
            "skill_assignment_is_consensus": False,
            "unbound_negative_or_drop_authority": False,
            "unbound_candidate_disposition": (
                "RETAIN_PENDING_IDENTITY_RECONCILIATION"
            ),
            "corroboration_scale": {
                "1": 0.0,
                "2": 0.5,
                "3": 0.75,
                "4+": 1.0,
            },
        },
        "input_bindings": sorted(
            {row["path"]: row for row in input_bindings}.values(),
            key=lambda row: row["path"],
        ),
        "global_authority_issues": global_issues,
        "observation_count": len(observations),
        "observations": observations,
        "score_count": len(scores),
        "scores": scores,
        "identity_accounting": {
            "candidate_denominator": len(observations),
            "exact_bound_count": current_count,
            "identity_debt_count": len(identity_debts),
            "all_unbound": all_unbound,
            "authority_state": authority_state,
            "negative_or_drop_authority": False,
        },
        "authority_debt_codes": (
            ["CONFIDENCE_CONSENSUS_AUTHORITY_DEBT"]
            if identity_debts
            else []
        ),
        "identity_debts": identity_debts,
    }
    payload["authority_digest"] = _digest(payload)
    return payload


def validate_confidence_consensus_authority(
    scratchpad: Path, payload: Mapping[str, Any]
) -> list[str]:
    issues: list[str] = []
    if not isinstance(payload, Mapping):
        return ["confidence consensus authority is not an object"]
    if payload.get("schema_version") != AUTHORITY_SCHEMA:
        issues.append("confidence consensus authority schema mismatch")
    stored = str(payload.get("authority_digest") or "")
    body = {key: value for key, value in payload.items() if key != "authority_digest"}
    if not _SHA_RE.fullmatch(stored) or _digest(body) != stored:
        issues.append("confidence consensus authority digest mismatch")
    try:
        expected = build_confidence_consensus_authority(Path(scratchpad))
    except Exception as exc:  # validation fails closed, pipeline caller may degrade
        issues.append(f"could not rederive confidence consensus authority: {exc}")
    else:
        if dict(payload) != expected:
            issues.append("confidence consensus authority is stale or non-canonical")
    return sorted(set(issues))


def consensus_score_map(
    payload: Mapping[str, Any],
) -> dict[tuple[str, str], float]:
    result: dict[tuple[str, str], float] = {}
    for raw in payload.get("scores", []) if isinstance(payload, Mapping) else []:
        if not isinstance(raw, Mapping):
            continue
        result[(str(raw.get("source_artifact") or ""), str(raw.get("finding_id") or "").upper())] = float(
            raw.get("score") or 0.0
        )
    return result


def render_consensus_map(payload: Mapping[str, Any]) -> str:
    accounting = (
        payload.get("identity_accounting", {})
        if isinstance(payload, Mapping)
        else {}
    )
    lines = [
        "# Consensus Map (driver-derived)",
        "",
        f"> Schema: `{payload.get('schema_version', '')}`",
        f"> Authority digest: `{payload.get('authority_digest', '')}`",
        f"> Assurance: `{payload.get('assurance', '')}`",
        "> A single observer receives 0.00. Location coincidence and skill assignment are not agreement.",
        "> Unbound identity is additive-only debt: the candidate must remain visible pending reconciliation and receives no proof or drop authority.",
        f"> Identity authority: `{accounting.get('authority_state', '')}` "
        f"({int(accounting.get('exact_bound_count') or 0)}/"
        f"{int(accounting.get('candidate_denominator') or 0)} exact-bound; "
        f"{int(accounting.get('identity_debt_count') or 0)} debt).",
        "",
        "| Finding ID | Source Artifact | Consensus | Independent Observers | Basis | Semantic Anchors |",
        "|---|---|---:|---:|---|---|",
    ]
    for raw in payload.get("scores", []) if isinstance(payload, Mapping) else []:
        if not isinstance(raw, Mapping):
            continue
        anchors = ", ".join(str(value) for value in raw.get("semantic_anchors", [])) or "NONE"
        lines.append(
            f"| {raw.get('finding_id', '')} | {raw.get('source_artifact', '')} | "
            f"{float(raw.get('score') or 0.0):.2f} | "
            f"{int(raw.get('independent_observer_count') or 0)} | "
            f"{raw.get('basis', '')} | {anchors} |"
        )
    if not payload.get("scores"):
        lines.append("| - | - | 0.00 | 0 | NO_SCOREABLE_FINDINGS | NONE |")
    lines.extend(
        [
            "",
            "## Identity Reconciliation Debt",
            "",
            "| Debt ID | Candidate | Source Artifact | Type | Required Action | Drop Authority |",
            "|---|---|---|---|---|---|",
        ]
    )
    debts = payload.get("identity_debts", [])
    if isinstance(debts, list):
        for raw in debts:
            if not isinstance(raw, Mapping):
                continue
            candidate = raw.get("candidate_ref", {})
            if not isinstance(candidate, Mapping):
                candidate = {}
            lines.append(
                f"| {raw.get('debt_id', '')} | "
                f"{candidate.get('finding_id', '')} | "
                f"{candidate.get('source_artifact', '')} | "
                f"{raw.get('debt_type', '')} | "
                f"{raw.get('required_action', '')} | NONE |"
            )
    if not debts:
        lines.append("| - | - | - | NONE | NONE | NONE |")
    lines.append("")
    return "\n".join(lines)


def write_confidence_consensus_artifacts(scratchpad: Path) -> dict[str, Any]:
    scratchpad = Path(scratchpad)
    payload = build_confidence_consensus_authority(scratchpad)
    _atomic_text(
        scratchpad / AUTHORITY_NAME,
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
    )
    _atomic_text(scratchpad / MARKDOWN_NAME, render_consensus_map(payload))
    return payload


def validate_confidence_consensus_artifacts(scratchpad: Path) -> list[str]:
    scratchpad = Path(scratchpad)
    path = scratchpad / AUTHORITY_NAME
    payload, issue = _read_json(path)
    if issue:
        return [issue]
    issues = validate_confidence_consensus_authority(scratchpad, payload)
    markdown = scratchpad / MARKDOWN_NAME
    try:
        observed = markdown.read_text(encoding="utf-8")
    except OSError as exc:
        issues.append(f"{MARKDOWN_NAME} unavailable: {exc}")
    else:
        if observed != render_consensus_map(payload):
            issues.append("consensus_map.md is not the exact authority projection")
    return sorted(set(issues))
