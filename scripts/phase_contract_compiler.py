"""Compile one typed phase I/O contract into a compact final prompt block."""
from __future__ import annotations

import json
import re
from typing import Any

from phase_io_contracts import PhaseIOContract


BEGIN = "<!-- PLAMEN_PHASE_IO_CONTRACT_BEGIN -->"
END = "<!-- PLAMEN_PHASE_IO_CONTRACT_END -->"


class PromptContractError(ValueError):
    pass


_MUTATION_RE = re.compile(
    r"\b(?:write|update|modify|append|edit|overwrite|replace|create|emit)\b",
    re.I,
)
_NEGATION_RE = re.compile(
    r"\b(?:do\s+not|don't|must\s+not|never|read[- ]only|immutable|without\s+writing)\b",
    re.I,
)
_PATH_LED_MUTATION_RE = re.compile(
    r"^\s*(?:(?:must|shall|should|needs?\s+to|is\s+to)\s+)?"
    r"(?:be\s+)?(?:write|written|update|updated|modify|modified|append|"
    r"appended|edit|edited|overwrite|overwritten|replace|replaced|create|"
    r"created|emit|emitted)\b",
    re.I,
)
_PATH_ANAPHORIC_MUTATION_RE = re.compile(
    r"^[^.!?]{0,160}?(?:[,;]\s*|\bthen\s+)"
    r"(?:(?:you\s+)?(?:must|shall|should|need\s+to|are\s+to)\s+)?"
    r"(?:write|update|modify|append|edit|overwrite|replace|create|emit)"
    r"\s+(?:it|the\s+(?:file|artifact))\b",
    re.I,
)


def _line_targets_immutable_path(line: str, path: str) -> bool:
    """Return whether one line directs a mutation *at* ``path``.

    Mutation vocabulary may describe data represented by an immutable input
    (for example, findings that ``write`` a state variable).  Treating any
    verb and filename co-occurrence as a file mutation rejects valid read-only
    methodology.  Imperative mutation remains fail-closed when the verb leads
    the filename, while common path-led passive forms remain covered too.
    """

    path_re = re.compile(
        rf"(?<![A-Za-z0-9_.-]){re.escape(path)}(?![A-Za-z0-9_.-])"
    )
    for path_match in path_re.finditer(line):
        for mutation in _MUTATION_RE.finditer(line, 0, path_match.start()):
            between = line[mutation.end():path_match.start()]
            # A prior output directive on the same Markdown line must not be
            # rebound to an immutable filename in a later sentence/clause.
            if ";" in between or re.search(r"[.!?](?:[`*_\])]+)?\s+", between):
                continue
            prefix = line[:mutation.start()]
            clause_start = max(
                prefix.rfind(";"),
                prefix.rfind(". "),
                prefix.rfind("! "),
                prefix.rfind("? "),
            ) + 1
            directive = re.sub(
                r"[*_]", "", line[clause_start:path_match.start()]
            )
            if _NEGATION_RE.search(directive):
                continue
            return True

        suffix = line[path_match.end():].lstrip("`*_]) ")
        if _PATH_LED_MUTATION_RE.match(suffix):
            return True
        # Catch path-led anaphora such as
        # "`confidence_scores.md` is missing, write it".  The basic
        # path-led matcher intentionally accepts only a verb immediately
        # after the path; repair prompts commonly put a condition first and
        # then refer to the artifact as "it".  Requiring an imperative after
        # a comma/semicolon keeps ordinary prose such as "the driver writes
        # it" out of the MODEL mutation detector.
        if (
            _PATH_ANAPHORIC_MUTATION_RE.match(suffix)
            and not _NEGATION_RE.search(suffix)
        ):
            return True
    return False


def prompt_contract_conflicts(
    prompt: str,
    contract: PhaseIOContract,
    *,
    actor: str | None = None,
) -> list[str]:
    """Find mutation instructions that contradict the typed I/O authority.

    Immutable inputs are never writable.  When an actor is supplied, outputs
    assigned to the other actor are read-only too; appending an authoritative
    ``allowed_outputs`` block must not retroactively sanitize a conflicting
    methodology instruction earlier in the prompt.
    """
    conflicts: list[str] = []
    immutable_paths = {
        identity.split(":", 1)[1] for identity in contract.immutable_inputs
    }
    actor_n = str(actor or "").strip().upper()
    if actor_n and actor_n not in {"MODEL", "DRIVER"}:
        raise PromptContractError("actor must be MODEL or DRIVER")
    foreign_outputs = {
        spec.path: spec.writer
        for spec in contract.outputs
        if actor_n and spec.writer != actor_n
    }
    for number, line in enumerate(str(prompt).splitlines(), 1):
        for path in sorted(immutable_paths):
            if _line_targets_immutable_path(line, path):
                conflicts.append(
                    f"line {number}: prompt instructs mutation of immutable input {path}"
                )
        for path, writer in sorted(foreign_outputs.items()):
            if (
                path not in immutable_paths
                and _line_targets_immutable_path(line, path)
            ):
                conflicts.append(
                    f"line {number}: prompt instructs mutation of "
                    f"{writer}-owned output {path}"
                )
    return conflicts


def compile_phase_io_prompt(
    prompt: str,
    contract: PhaseIOContract,
    *,
    actor: str,
) -> str:
    if not isinstance(contract, PhaseIOContract):
        raise PromptContractError("contract must be a PhaseIOContract")
    actor_n = str(actor or "").strip().upper()
    if actor_n not in {"MODEL", "DRIVER"}:
        raise PromptContractError("actor must be MODEL or DRIVER")
    if BEGIN in prompt or END in prompt:
        raise PromptContractError("prompt already contains a phase I/O contract block")
    conflicts = prompt_contract_conflicts(prompt, contract, actor=actor_n)
    if conflicts:
        raise PromptContractError("; ".join(conflicts))
    actor_outputs = [
        spec.identity for spec in contract.outputs if spec.writer == actor_n
    ]
    payload: dict[str, Any] = {
        "schema": "plamen.compiled-phase-io.v1",
        "contract_digest": contract.digest,
        "work_unit_key": contract.key,
        "actor": actor_n,
        "allowed_outputs": sorted(actor_outputs),
        "immutable_inputs": list(contract.immutable_inputs),
        "bounded_lookup_inputs": list(contract.bounded_lookup_inputs),
    }
    compact = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    block = (
        f"{BEGIN}\n"
        "The following driver-owned contract is authoritative for file I/O. "
        "Write only allowed_outputs; immutable_inputs are read-only.\n"
        f"```json\n{compact}\n```\n"
        f"{END}"
    )
    return str(prompt).rstrip() + "\n\n" + block + "\n"


def extract_compiled_phase_io(prompt: str) -> dict[str, Any]:
    text = str(prompt)
    if text.count(BEGIN) != 1 or text.count(END) != 1:
        raise PromptContractError("prompt must contain exactly one compiled contract block")
    start = text.index(BEGIN) + len(BEGIN)
    end = text.index(END, start)
    body = text[start:end]
    match = re.search(r"```json\s*(\{.*?\})\s*```", body, re.S)
    if not match:
        raise PromptContractError("compiled contract JSON block missing")
    try:
        payload = json.loads(match.group(1))
    except json.JSONDecodeError as exc:
        raise PromptContractError("compiled contract JSON is malformed") from exc
    if not isinstance(payload, dict):
        raise PromptContractError("compiled contract payload must be an object")
    return payload


def validate_compiled_phase_io(
    prompt: str,
    contract: PhaseIOContract,
    *,
    actor: str,
) -> list[str]:
    try:
        payload = extract_compiled_phase_io(prompt)
    except PromptContractError as exc:
        return [str(exc)]
    actor_n = str(actor or "").strip().upper()
    expected_outputs = sorted(
        spec.identity for spec in contract.outputs if spec.writer == actor_n
    )
    expected = {
        "contract_digest": contract.digest,
        "work_unit_key": contract.key,
        "actor": actor_n,
        "allowed_outputs": expected_outputs,
        "immutable_inputs": list(contract.immutable_inputs),
        "bounded_lookup_inputs": list(contract.bounded_lookup_inputs),
    }
    issues = [
        f"compiled {key} mismatch"
        for key, value in expected.items()
        if payload.get(key) != value
    ]
    issues.extend(
        prompt_contract_conflicts(
            prompt[:prompt.index(BEGIN)],
            contract,
            actor=actor_n,
        )
    )
    return issues


__all__ = [
    "BEGIN",
    "END",
    "PromptContractError",
    "compile_phase_io_prompt",
    "extract_compiled_phase_io",
    "prompt_contract_conflicts",
    "validate_compiled_phase_io",
]
