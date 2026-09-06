"""Plamen V2 driver — shared types, constants, and phase definitions.

Layer 0: no internal plamen_* imports. All other modules depend on this.
"""
import functools
import hashlib
import json
import logging
import os
import re
import shutil
import time
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Iterable, Mapping, Optional

__all__ = [
    "CLAUDE_BIN", "CODEX_BIN", "Checkpoint",
    "GateFailure", "GateClearance", "PhaseCommit", "RetryReceipt",
    "PHASE_COMMIT_STATES", "GATE_FAILURE_CLASSES",
    "GATE_FALLBACK_POLICIES", "RETRY_RECEIPT_STATUSES",
    "plamen_home",
    "EVIDENCE_TAGS_PROOF", "EVIDENCE_TAGS_TRACE", "EVIDENCE_TAGS_FAIL",
    "EVIDENCE_TAGS_PROD", "has_proof_grade_evidence",
    "canonical_verification_status", "canonical_status_sort_key",
    "CANONICAL_VERIFICATION_STATUSES",
    "EVIDENCE_TAGS_ALL", "EVIDENCE_TAG_DEFAULT", "EVIDENCE_TAG_NAMES_RE",
    "DEPTH_EVIDENCE_TAG_NAMES", "DEPTH_EVIDENCE_TAG_RE",
    "FINDING_BLOCK_HEADING_RE",
    "EXIT_CONFIG_MISSING", "EXIT_DEGRADED", "EXIT_ERROR",
    "EXIT_STARTUP_DECISION",
    "EXIT_HIBERNATING", "EXIT_RATE_LIMITED", "EXIT_SUCCESS",
    "CODEX_MULTI_AGENT_PHASES",
    "L1_NEVER_CUT_ARTIFACT_GROUPS", "L1_PHASES",
    "L1_VERIFY_CRITHIGH_PHASE_NAMES", "L1_VERIFY_PHASE_NAMES",
    "L1_VERIFY_SHARD_MANIFESTS", "PLAMEN_OPUS_MODEL", "PLAMEN_SONNET_MODEL",
    "PLAMEN_HAIKU_MODEL", "PLAMEN_THOROUGH_OPUS_MODEL", "Phase",
    "resolve_claude_recovery_model", "validate_model_routing_authority",
    "SC_NEVER_CUT_BASE", "SC_NEVER_CUT_CORE_EXTRAS",
    "SC_NEVER_CUT_THOROUGH_EXTRAS", "SC_PHASES",
    "SC_VERIFY_CRITHIGH_PHASE_NAMES", "SC_VERIFY_PHASE_NAMES",
    "SC_VERIFY_SHARD_MANIFESTS",
    "SC_DEPTH_SKILL_ROLE_SPECS", "SC_DEPTH_SKILL_ROLES",
    "SC_DEPTH_SKILL_DESTINATIONS", "canonical_sc_depth_skill_role",
    "SOURCE_SUFFIXES_BY_ECOSYSTEM", "L1_SOURCE_SUFFIXES",
    "ALL_AUDIT_SOURCE_SUFFIXES", "source_suffixes_for",
    "normalize_scope_match_mode", "parse_exact_scope_text",
    "validate_exact_scope_authority",
    "attention_queue_binding_sha256",
    "SEVERITY_ORDER", "SEVERITY_LETTER", "SEVERITY_FROM_LETTER",
    "_CODEX_MODEL_MAP", "_CODEX_FALLBACK_MODEL_ORDER",
    "_NEVER_CUT_SKIP_REASONS", "_PHASE_NAME_RE",
    "_VALID_MODES", "_VALID_PIPELINES", "_valid_report_shard_suffix",
    "_resolve_claude_bin", "_resolve_codex_bin", "_resolve_codex_model_alias",
    "_resolve_model_alias",
    "_EXPANDABLE_TIERS",
    "expand_shard_phases",
    "has_mechanical_proof", "normalize_severity", "try_normalize_severity",
    "severity_letter_from_name", "severity_rank",
    "l1_never_cut_groups",
    "log", "phase_model", "sc_never_cut_groups", "validate_phase_graph",
]

# --- Constants ---

SOURCE_SUFFIXES_BY_ECOSYSTEM = {
    "evm": (".sol", ".vy"),
    "solana": (".rs",),
    "soroban": (".rs",),
    "aptos": (".move",),
    "sui": (".move",),
    "daml": (".daml",),
    "go": (".go",),
    "rust": (".rs",),
}
L1_SOURCE_SUFFIXES = (".go", ".rs", ".move", ".proto")
ALL_AUDIT_SOURCE_SUFFIXES = tuple(sorted(
    {
        suffix
        for values in SOURCE_SUFFIXES_BY_ECOSYSTEM.values()
        for suffix in values
    }
    | set(L1_SOURCE_SUFFIXES)
))


def attention_queue_binding_sha256(
    rows: Iterable[Mapping[str, object]],
) -> str:
    """Bind the complete semantic content of an attention-repair queue."""

    payload = [
        {
            "row": int(row["row"]),
            "kind": str(row["kind"]),
            "target": str(row["target"]),
            "reason": str(row["reason"]),
            "source": str(row["source"]),
            "evidence": str(row.get("evidence", "")),
        }
        for row in rows
    ]
    return hashlib.sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()


def source_suffixes_for(
    pipeline: str,
    ecosystem: str,
    *,
    strict: bool = False,
) -> tuple[str, ...]:
    """Return the central auditable-source suffix denominator."""

    pipeline_n = str(pipeline or "").strip().lower()
    ecosystem_n = str(ecosystem or "").strip().lower()
    if pipeline_n == "l1":
        return L1_SOURCE_SUFFIXES
    if strict and pipeline_n != "sc":
        raise ValueError(f"unsupported audit pipeline: {pipeline!r}")
    if strict and ecosystem_n not in SOURCE_SUFFIXES_BY_ECOSYSTEM:
        raise ValueError(f"unsupported exact-scope ecosystem: {ecosystem!r}")
    return SOURCE_SUFFIXES_BY_ECOSYSTEM.get(
        ecosystem_n,
        ALL_AUDIT_SOURCE_SUFFIXES,
    )


def normalize_scope_match_mode(value: object) -> str:
    """Return the supported scope-authority mode or fail closed."""

    mode = str(value or "legacy").strip().lower()
    if mode not in {"legacy", "exact"}:
        raise ValueError(f"unsupported scope_match_mode: {value!r}")
    return mode


def parse_exact_scope_text(
    text: str,
    *,
    pipeline: str = "sc",
    ecosystem: str = "",
) -> tuple[str, ...]:
    """Parse a portable, project-relative, exact source-file authority.

    Exact mode intentionally accepts no path aliases, globs, directories,
    absolute paths, traversal, or Windows separators.  The same parser is
    consumed by snapshotting, coverage gates, and private acquisition
    wrappers so those boundaries cannot silently disagree about scope.
    """

    suffixes = frozenset(
        source_suffixes_for(pipeline, ecosystem, strict=True)
    )
    paths: set[str] = set()
    portable_identities: dict[str, str] = {}
    invalid: list[str] = []
    meaningful_rows = 0
    for line_number, line in enumerate(str(text or "").splitlines(), start=1):
        candidate = line.strip()
        if not candidate or candidate.startswith(("#", "<!--")):
            continue
        if candidate.startswith(("- ", "* ", "+ ")):
            candidate = candidate[2:].strip()
        if candidate.startswith("|"):
            cells = [cell.strip() for cell in candidate.strip("|").split("|")]
            source_cells = [
                cell.strip("`\"' ")
                for cell in cells
                if PurePosixPath(cell.strip("`\"' ")).suffix.lower()
                in suffixes
            ]
            if not source_cells:
                if all(
                    not cell
                    or re.fullmatch(r":?-{3,}:?", cell)
                    or cell.casefold() in {
                        "file", "path", "source", "lines", "description",
                    }
                    for cell in cells
                ):
                    continue
                invalid.append(f"line {line_number}")
                continue
            if len(source_cells) != 1:
                invalid.append(f"line {line_number}")
                continue
            candidate = source_cells[0]
        candidate = candidate.strip("`\"' ")
        meaningful_rows += 1
        if (
            not candidate
            or "\\" in candidate
            or "\x00" in candidate
            or any(ord(char) < 32 for char in candidate)
            or candidate.startswith(("/", "./", "../", "~"))
            or re.match(r"^[A-Za-z]:", candidate)
            or any(char in candidate for char in '<>:"|?*[]')
            or unicodedata.normalize("NFC", candidate) != candidate
        ):
            invalid.append(f"line {line_number}")
            continue
        portable = PurePosixPath(candidate)
        parts = portable.parts
        windows_reserved = {
            "con", "prn", "aux", "nul",
            *(f"com{index}" for index in range(1, 10)),
            *(f"lpt{index}" for index in range(1, 10)),
        }
        if (
            not parts
            or any(part in {"", ".", ".."} for part in parts)
            or any(part.endswith((".", " ")) for part in parts)
            or any(
                part.split(".", 1)[0].casefold() in windows_reserved
                for part in parts
            )
            or portable.as_posix() != candidate
            or portable.suffix.lower() not in suffixes
        ):
            invalid.append(f"line {line_number}")
            continue
        portable_identity = unicodedata.normalize(
            "NFC", candidate
        ).casefold()
        prior = portable_identities.get(portable_identity)
        if prior is not None and prior != candidate:
            invalid.append(
                f"line {line_number} (portable collision with {prior!r})"
            )
            continue
        portable_identities[portable_identity] = candidate
        paths.add(candidate)

    if invalid:
        raise ValueError(
            "exact scope_file contains non-portable or unsupported path "
            "rows: " + ", ".join(invalid[:20])
        )
    if not str(text or "").strip() or meaningful_rows == 0:
        raise ValueError("exact scope_file is empty")
    if not paths:
        raise ValueError("exact scope_file contains no auditable source paths")
    return tuple(sorted(paths))


def validate_exact_scope_authority(
    project_root: str | Path,
    scope_file: str | Path,
    *,
    pipeline: str = "sc",
    ecosystem: str = "",
) -> tuple[str, ...]:
    """Validate exact scope syntax and bind every row to one source file."""

    root = Path(project_root).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(
            f"exact scope project_root is missing or not a directory: {root}"
        )
    raw_scope = str(scope_file or "").strip()
    if not raw_scope:
        raise ValueError("exact scope matching requires a scope_file")
    scope_path = Path(raw_scope).expanduser()
    if not scope_path.is_absolute():
        scope_path = root / scope_path
    try:
        text = scope_path.read_text(encoding="utf-8-sig", errors="strict")
    except (OSError, UnicodeError) as exc:
        raise ValueError(
            f"exact scope_file is unreadable UTF-8: {scope_path}"
        ) from exc
    rows = parse_exact_scope_text(
        text,
        pipeline=pipeline,
        ecosystem=ecosystem,
    )
    for row in rows:
        lexical = root
        for component in PurePosixPath(row).parts:
            try:
                sibling_names = [
                    entry.name for entry in os.scandir(lexical)
                ]
            except OSError as exc:
                raise ValueError(
                    f"exact scope target parent is unreadable: {row}"
                ) from exc
            component_identity = unicodedata.normalize(
                "NFC", component
            ).casefold()
            portable_aliases = [
                name for name in sibling_names
                if unicodedata.normalize("NFC", name).casefold()
                == component_identity
            ]
            if component not in sibling_names:
                if portable_aliases:
                    raise ValueError(
                        "exact scope path spelling/case differs from disk: "
                        f"{row} (disk component {portable_aliases[0]!r})"
                    )
                raise ValueError(
                    f"exact scope target is missing or unreadable: {row}"
                )
            if len(portable_aliases) != 1:
                raise ValueError(
                    "exact scope target has a cross-OS case/Unicode collision: "
                    f"{row}"
                )
            lexical = lexical / component
            try:
                metadata = os.lstat(lexical)
            except OSError as exc:
                raise ValueError(
                    f"exact scope target is missing or unreadable: {row}"
                ) from exc
            is_junction = bool(
                getattr(lexical, "is_junction", lambda: False)()
            )
            is_reparse = bool(
                getattr(metadata, "st_file_attributes", 0) & 0x400
            )
            if lexical.is_symlink() or is_junction or is_reparse:
                raise ValueError(
                    "exact scope target traverses a symbolic link, junction, "
                    f"or reparse point: {row}"
                )
        target = lexical.resolve()
        try:
            target.relative_to(root)
        except ValueError as exc:
            raise ValueError(
                f"exact scope target escapes project_root: {row}"
            ) from exc
        if not target.is_file():
            raise ValueError(f"exact scope target is missing or not a file: {row}")
    return rows

def _resolve_claude_bin() -> str:
    """Return the platform-appropriate claude binary path.

    Windows npm installs `claude.cmd`, not `claude`. Python's subprocess
    without shell=True does NOT auto-append `.cmd`, so we have to find it.
    """
    override = os.environ.get("CLAUDE_BIN")
    if override:
        return override
    import shutil
    # Try each candidate; first one found wins.
    for name in ("claude", "claude.cmd", "claude.exe"):
        found = shutil.which(name)
        if found:
            return found
    # Last resort — let the caller's FileNotFoundError propagate with a
    # clear message.
    return "claude"

CLAUDE_BIN = _resolve_claude_bin()


def _resolve_codex_bin() -> str:
    """Find the Codex CLI binary. Returns empty string if not installed."""
    override = os.environ.get("CODEX_BIN")
    if override:
        return override
    import shutil
    for name in ("codex", "codex.cmd", "codex.exe"):
        found = shutil.which(name)
        if found:
            return found
    return ""


CODEX_BIN = _resolve_codex_bin()


@functools.lru_cache(maxsize=1)
def plamen_home() -> Path:
    """Plamen installation root. Single source of truth for all path resolution.

    Resolution: PLAMEN_HOME env -> script-relative -> ~/.claude fallback.
    """
    env = os.environ.get("PLAMEN_HOME", "").strip()
    if env:
        p = Path(env)
        if p.is_dir():
            return p
    candidate = Path(__file__).resolve().parent.parent
    for marker in ("scripts", "rules", "prompts"):
        if (candidate / marker).is_dir():
            return candidate
    return Path.home() / ".claude"


# Pin every Claude tier to an admitted canonical model ID. Audit provenance
# must not silently follow an old/arbitrary environment override: upgrades are
# an explicit reviewed source change, not a per-machine routing decision.
_CLAUDE_OPUS_MODEL = "claude-opus-5"
_CLAUDE_SONNET_MODEL = "claude-sonnet-5"
_CLAUDE_ADMITTED_OPUS_SONNET_MODELS = frozenset({
    _CLAUDE_OPUS_MODEL,
    _CLAUDE_SONNET_MODEL,
})


def _admit_claude_tier_model(value: object, *, tier: str) -> str:
    expected = {
        "opus": _CLAUDE_OPUS_MODEL,
        "sonnet": _CLAUDE_SONNET_MODEL,
    }.get(tier)
    if expected is None:
        raise ValueError(f"unknown Claude model tier: {tier!r}")
    if not isinstance(value, str) or value != expected:
        raise ValueError(
            f"{tier} model must be the admitted current ID {expected!r}"
        )
    return expected


PLAMEN_OPUS_MODEL = _admit_claude_tier_model(
    os.environ.get("PLAMEN_OPUS_MODEL", _CLAUDE_OPUS_MODEL), tier="opus"
)
PLAMEN_SONNET_MODEL = _admit_claude_tier_model(
    os.environ.get("PLAMEN_SONNET_MODEL", _CLAUDE_SONNET_MODEL), tier="sonnet"
)
# Claude's nested ``haiku`` alias is executable launch authority too.  The
# audit mode contract admits only Opus 5 and Sonnet 5, so deliberately bind
# that compatibility alias to Sonnet rather than allowing a hidden Haiku
# route through Claude's ANTHROPIC_DEFAULT_HAIKU_MODEL environment variable.
PLAMEN_HAIKU_MODEL = _admit_claude_tier_model(
    os.environ.get("PLAMEN_HAIKU_MODEL", _CLAUDE_SONNET_MODEL), tier="sonnet"
)

# v2.8.11: Thorough-mode promotion target. Reasoning-critical roles (discovery
# = breadth+depth, verification shards, skeptic-judge) run on Opus 5 in
# THOROUGH ONLY (opus resolves to the pinned default; Light stays Sonnet) to bound plan
# usage. Rationale: <70% strict recall traces to reasoning-hard miss-classes
# (cross-VM encoding, swap mechanics), and verification quality is model-bound.
PLAMEN_THOROUGH_OPUS_MODEL = _admit_claude_tier_model(
    os.environ.get("PLAMEN_THOROUGH_OPUS_MODEL", PLAMEN_OPUS_MODEL),
    tier="opus",
)


def _resolve_claude_breadth_override(model: object) -> str:
    """Resolve a user breadth override without widening Claude authority."""
    if not isinstance(model, str):
        raise ValueError("Claude breadth model override must be a string")
    resolved = model
    if resolved not in _CLAUDE_ADMITTED_OPUS_SONNET_MODELS:
        raise ValueError(
            "Claude breadth model override must resolve to "
            f"{_CLAUDE_OPUS_MODEL!r} or {_CLAUDE_SONNET_MODEL!r}"
        )
    return resolved


def resolve_claude_recovery_model(model: object) -> str:
    """Resolve one recovery model through the closed reviewed Claude set."""
    if not isinstance(model, str):
        raise ValueError("Claude verification recovery model must be a string")
    aliases = {
        "opus": _CLAUDE_OPUS_MODEL,
        "sonnet": _CLAUDE_SONNET_MODEL,
    }
    resolved = aliases.get(model, model)
    admitted = {
        _CLAUDE_OPUS_MODEL,
        _CLAUDE_SONNET_MODEL,
    }
    if resolved not in admitted:
        raise ValueError(
            "Claude verification recovery model must be an admitted current "
            "ID or exact tier alias"
        )
    return resolved


def validate_model_routing_authority(config: object) -> None:
    """Validate every externally supplied model route before driver startup."""
    if not isinstance(config, dict):
        raise ValueError("model routing config must be an object")
    backend = config.get("cli_backend") or "claude"
    if not isinstance(backend, str):
        raise ValueError("model routing backend must be a string")
    backend = backend.strip().lower()

    recovery_present = "_verification_recovery_model" in config
    recovery = config.get("_verification_recovery_model")
    if backend == "codex":
        if recovery_present and recovery not in (None, ""):
            if not isinstance(recovery, str) or recovery != recovery.strip():
                raise ValueError("Codex verification recovery model is noncanonical")
            _resolve_codex_model_alias(recovery)
        return
    if backend != "claude":
        raise ValueError(f"unsupported model routing backend: {backend!r}")

    for name, expected, tier in (
        ("PLAMEN_OPUS_MODEL", _CLAUDE_OPUS_MODEL, "opus"),
        ("PLAMEN_SONNET_MODEL", _CLAUDE_SONNET_MODEL, "sonnet"),
        ("PLAMEN_HAIKU_MODEL", _CLAUDE_SONNET_MODEL, "sonnet"),
        ("PLAMEN_THOROUGH_OPUS_MODEL", _CLAUDE_OPUS_MODEL, "opus"),
    ):
        _admit_claude_tier_model(os.environ.get(name, expected), tier=tier)

    if "breadth_model_override" in config:
        configured_breadth = config.get("breadth_model_override")
        if configured_breadth not in (None, ""):
            _resolve_claude_breadth_override(configured_breadth)
    environment_breadth = os.environ.get("PLAMEN_BREADTH_MODEL_OVERRIDE")
    if environment_breadth is not None and environment_breadth != "":
        _resolve_claude_breadth_override(environment_breadth)

    if recovery_present and recovery not in (None, ""):
        resolve_claude_recovery_model(recovery)


def _resolve_model_alias(model: str) -> str:
    m = (model or "").strip()
    aliases = {
        "opus": PLAMEN_OPUS_MODEL or "claude-opus-5",
        "sonnet": PLAMEN_SONNET_MODEL or "claude-sonnet-5",
        "haiku": PLAMEN_HAIKU_MODEL or "claude-sonnet-5",
    }
    return aliases.get(m, m or aliases["sonnet"])


_CODEX_MODEL_MAP: dict[str, str] = {
    "opus": os.environ.get("PLAMEN_CODEX_OPUS_MODEL", "gpt-5.6-sol"),
    "sonnet": os.environ.get("PLAMEN_CODEX_SONNET_MODEL", "gpt-5.6-terra"),
    "haiku": os.environ.get("PLAMEN_CODEX_HAIKU_MODEL", "gpt-5.6-luna"),
}

_CODEX_FALLBACK_MODEL_ORDER: tuple[str, ...] = tuple(dict.fromkeys(
    m.strip()
    for m in (
        os.environ.get("PLAMEN_CODEX_FALLBACK_MODELS", "")
        or ",".join([
            _CODEX_MODEL_MAP["sonnet"],
            _CODEX_MODEL_MAP["haiku"],
            "gpt-5.6-terra",
            "gpt-5.6-luna",
        ])
    ).split(",")
    if m.strip()
))


def _resolve_codex_model_alias(model: str) -> str:
    """Map Plamen tier aliases (opus/sonnet/haiku) to Codex-compatible models.

    Concrete OpenAI model IDs pass through unchanged. Unknown tier aliases
    fail closed so a typo cannot silently route an audit to another model.
    """
    m = (model or "").strip().lower()
    if m in _CODEX_MODEL_MAP:
        return _CODEX_MODEL_MAP[m]
    configured = {value.strip().lower() for value in _CODEX_MODEL_MAP.values() if value.strip()}
    if m in configured or re.fullmatch(r"(?:gpt|codex)-[a-z0-9._-]+|o\d[a-z0-9._-]*", m):
        return model.strip()
    raise ValueError(f"unknown Codex model alias: {model!r}")

EXIT_SUCCESS = 0
EXIT_ERROR = 1
EXIT_RATE_LIMITED = 2    # user should re-run when quota refreshes
EXIT_DEGRADED = 3        # pipeline finished with >N degraded phases
EXIT_CONFIG_MISSING = 4
EXIT_STARTUP_DECISION = 5  # startup stopped pending an explicit safe decision
EXIT_HIBERNATING = 42    # long wait detected; resume after wake_at_utc

log = logging.getLogger("plamen")

# ── Evidence tag vocabulary (v2.6.0) ──────────────────────────────────────
# Single source of truth. Adding a new evidence tag means ONE edit here.
EVIDENCE_TAGS_PROOF: frozenset[str] = frozenset({
    "[POC-PASS]", "[MEDUSA-PASS]", "[FUZZ-PASS]",
    "[NON-DET-PASS]", "[DIFF-PASS]", "[CONFORMANCE-PASS]",
})
EVIDENCE_TAGS_TRACE: frozenset[str] = frozenset({"[CODE-TRACE]", "[LSP-TRACE]"})
EVIDENCE_TAGS_FAIL: frozenset[str] = frozenset({"[POC-FAIL]"})
# Production / on-chain proof-grade tags (confidence model rates these 0.9-1.0).
# Verifiers emit these when a finding is confirmed against forked or live
# on-chain state. Kept SEPARATE from EVIDENCE_TAGS_PROOF so the narrow
# "a mechanical test passed" semantics of has_mechanical_proof stay intact;
# proof-GRADE checks (has_proof_grade_evidence) OR these in.
EVIDENCE_TAGS_PROD: frozenset[str] = frozenset({
    "[PROD-ONCHAIN]", "[PROD-SOURCE]", "[PROD-FORK]",
})
EVIDENCE_TAGS_ALL: frozenset[str] = EVIDENCE_TAGS_PROOF | EVIDENCE_TAGS_TRACE | EVIDENCE_TAGS_FAIL
EVIDENCE_TAG_DEFAULT = "CODE-TRACE"
EVIDENCE_TAG_NAMES_RE = "|".join(sorted(t.strip("[]") for t in EVIDENCE_TAGS_ALL))


def has_mechanical_proof(text: str) -> bool:
    """True if *text* contains any proof-grade evidence tag."""
    return any(tag in text for tag in EVIDENCE_TAGS_PROOF)


def has_proof_grade_evidence(text: str) -> bool:
    """True if *text* carries proof-GRADE evidence: a mechanical-test-pass tag
    OR a production/on-chain verification tag ([PROD-ONCHAIN/SOURCE/FORK]).

    Proven-only severity gating must use THIS, not has_mechanical_proof: a
    finding confirmed against forked/live state is proof-grade and must not be
    capped at Low. has_mechanical_proof stays narrow (test-pass only) for the
    callers that genuinely mean "a test executed and passed"."""
    return has_mechanical_proof(text) or any(
        tag in text for tag in EVIDENCE_TAGS_PROD
    )


# ── Canonical verification-status token (Fix 1, single source of truth) ────
# The report_index Verification column and the body finding-header tag used to
# be derived by DIFFERENT rules (index: verdict-only → 71 "VERIFIED"; body:
# mechanical-proof-only → 12 "VERIFIED"; PoC-pass count: 17). That collision
# made the label meaningless. This ONE pure function maps
# (verifier_verdict, best_evidence_proof_grade) to a single canonical token so
# every downstream consumer reads the same word.
#
#   VERIFIED  = verdict CONFIRMED AND best evidence is proof-grade
#               ([POC-PASS]/[MEDUSA-PASS]/[PROD-*]/other proof tag)
#   CONFIRMED = verdict CONFIRMED but best evidence is only [CODE-TRACE]
#   CONTESTED = disputed (verifier CONTESTED / UNRESOLVED / PARTIAL)
#   UNVERIFIED = refuted / false-positive / duplicate / none
#
# Sort key (VERIFIED > CONFIRMED > CONTESTED > UNVERIFIED) lets callers order
# findings by evidence strength without re-deriving the ternary.
CANONICAL_VERIFICATION_STATUSES: tuple[str, ...] = (
    "VERIFIED", "CONFIRMED", "CONTESTED", "UNVERIFIED",
)
_CANONICAL_STATUS_SORT: dict[str, int] = {
    s: i for i, s in enumerate(CANONICAL_VERIFICATION_STATUSES)
}


def canonical_verification_status(verifier_status: str, proof_grade: bool) -> str:
    """Map (verifier verdict token, proof-grade?) → ONE canonical status token.

    `verifier_status` is the token from `_verifier_status_from_text` (already
    normalized: PARTIAL→UNRESOLVED, TRUE_POSITIVE/VALID→CONFIRMED, etc.).
    `proof_grade` is `has_proof_grade_evidence(verify_text)`.

    Pure/side-effect-free so validators, the driver status_binding writer, the
    mechanical report_index renderer, and tests all share ONE mapping.
    """
    s = (verifier_status or "").strip().upper().replace("-", "_")
    s = re.sub(r"\s+", "_", s)
    if s in ("CONFIRMED", "TRUE_POSITIVE", "VALID"):
        return "VERIFIED" if proof_grade else "CONFIRMED"
    if s in ("CONTESTED", "UNRESOLVED", "PARTIAL"):
        return "CONTESTED"
    # REFUTED / FALSE_POSITIVE / INFEASIBLE / DUPLICATE / DROP_* / empty / etc.
    return "UNVERIFIED"


def canonical_status_sort_key(status: str) -> int:
    """Rank a canonical status by evidence strength (0 = strongest)."""
    return _CANONICAL_STATUS_SORT.get(
        (status or "").strip().upper(), len(CANONICAL_VERIFICATION_STATUSES)
    )


# ── Depth evidence tag vocabulary (Ship A — single source of truth) ────────
# The depth-analysis evidence tags ([BOUNDARY:...], [TRACE:...], etc.). Before
# Ship A this regex existed in THREE divergent copies (plamen_parsers.py,
# plamen_driver.py, plamen_validators.py); the driver copy silently dropped
# NON-DET / ASYMMETRIC / MEDUSA-PASS / etc. so L1 + network depth findings
# scored lower than identical SC findings (swarm SW07-4). One name list now;
# all consumers import it. SUPERSET of all three former copies (incl. DST).
DEPTH_EVIDENCE_TAG_NAMES: tuple[str, ...] = (
    "BOUNDARY", "VARIATION", "TRACE", "REGRESS", "PERTURBATION",
    "NON-DET", "PRE-AUTH-PANIC", "ASYMMETRIC", "SCORE-DRAIN",
    "REORG-DIVERGE", "DECODE-UNBOUNDED", "CROSS-DOMAIN-DEP",
    "MEDUSA-PASS", "DST",
)
# Delimiter class is the UNION of the three former copies' delimiters
# (colon / space / close-bracket / hyphen) so every real tag form matches:
#   [BOUNDARY:val]  [TRACE path]  [MEDUSA-PASS]  [DST-token]
# Capturing group 1 = the tag name (consumers read m.group(1) for histograms).
DEPTH_EVIDENCE_TAG_RE = re.compile(
    r"\[(" + "|".join(DEPTH_EVIDENCE_TAG_NAMES) + r")[:\]\- ]",
    re.IGNORECASE,
)

# ── Finding-block heading (Ship D — single source of truth) ────────────────
# Breadth uses `## Finding [ID]`, depth uses `### Finding [ID]` (the v2 depth
# prompt mandates H3). Several consumers had H2-ONLY copies (driver confidence
# synth, validators stub re-check) that silently saw ZERO depth findings on the
# prompt-mandated H3 form (swarm SW07-1/3/5). One regex now; accepts H2 OR H3,
# captures the bracketed ID. Disjoint from a `## Findings` SECTION heading
# ("Findings" has no whitespace+"[" after "Finding").
FINDING_BLOCK_HEADING_RE = re.compile(
    r"(?im)^#{2,3}\s+Finding\s+\[([^\]\n]+)\]"
)


# ── Severity vocabulary (v2.6.0) ──────────────────────────────────────────
SEVERITY_ORDER: tuple[str, ...] = (
    "Critical", "High", "Medium", "Low", "Informational",
)
SEVERITY_LETTER: dict[str, str] = {s: s[0] for s in SEVERITY_ORDER}
SEVERITY_FROM_LETTER: dict[str, str] = {v: k for k, v in SEVERITY_LETTER.items()}
_SEVERITY_ALIASES: dict[str, str] = {
    "info": "Informational",
    "informational": "Informational",
    "low": "Low",
    "medium": "Medium",
    "med": "Medium",
    "high": "High",
    "critical": "Critical",
    "crit": "Critical",
}


def _clean_severity_text(raw: str) -> str:
    """Strip Markdown/table noise around a possible severity label."""
    s = str(raw or "").strip()
    s = re.sub(r"^\s*(?:[-*+]\s+)+", "", s)
    s = re.sub(r"^\s*\*{1,3}\s*", "", s)
    s = re.sub(r"\s*\*{1,3}\s*$", "", s)
    s = s.strip(" \t\r\n`'\"[]()")
    label_m = re.match(r"(?i)^(?:severity|final severity|resulting tier)\s*[:=-]\s*(.+)$", s)
    if label_m:
        s = label_m.group(1).strip(" \t\r\n`'\"[]()")
        s = re.sub(r"^\s*\*{1,3}\s*", "", s)
        s = re.sub(r"\s*\*{1,3}\s*$", "", s)
        s = s.strip(" \t\r\n`'\"[]()")
    return s


def try_normalize_severity(raw: str) -> str | None:
    """Canonicalize only strings that actually present a severity label."""
    s = _clean_severity_text(raw)
    if not s:
        return None
    if re.fullmatch(r"[-\u2010-\u2015]+", s):
        return None
    sl = s.lower()
    exact = _SEVERITY_ALIASES.get(sl)
    if exact:
        return exact
    lead = re.match(r"(?i)^(critical|crit|high|medium|med|low|informational|info)\b", s)
    if lead:
        return _SEVERITY_ALIASES[lead.group(1).lower()]
    return None


def _looks_like_nonseverity_prose(s: str) -> bool:
    """True for status/provenance prose accidentally supplied as severity."""
    sl = (s or "").lower()
    if not sl:
        return False
    if sl in {"various", "mixed", "multiple", "mixed severity", "various severities"}:
        return True
    if re.fullmatch(r"(?:n/?a|not\s+available|unknown)(?:\s*\([^)]*\))?", sl):
        return True
    if len(re.findall(r"[a-z0-9]+", sl)) > 1:
        return True
    if re.search(r"[.;:]|\b(?:inv|h|ch|cc|ac|tf|de|dx)-?\d+\b", sl, re.IGNORECASE):
        return True
    return False


# NOISE-2: distinct unrecognized severity tokens already debug-logged, so the
# fallback message fires at most once per token per process.
_NORMALIZE_SEVERITY_SEEN: set[str] = set()


def normalize_severity(raw: str) -> str:
    """Canonicalize a severity string to one of SEVERITY_ORDER values."""
    s = str(raw or "").strip()
    if not s:
        return "Medium"
    if re.fullmatch(r"[-\u2010-\u2015]+", s):
        return "Medium"
    parsed = try_normalize_severity(s)
    if parsed:
        return parsed
    if _looks_like_nonseverity_prose(s):
        return "Informational"
    # LLM/table output often leaks Markdown decorations into a cell value:
    # `** Low`, `**Low**`, `` `Informational` ``, `- High`, or
    # `Severity: **High**`. Strip presentation syntax before severity routing
    # so cosmetic formatting never changes triage or phase scope.
    s = re.sub(r"^\s*(?:[-*+]\s+)+", "", s)
    s = re.sub(r"^\s*\*{1,3}\s*", "", s)
    s = re.sub(r"\s*\*{1,3}\s*$", "", s)
    s = s.strip(" \t\r\n`'\"“”‘’[]()")
    label_m = re.match(r"(?i)^(?:severity|final severity|resulting tier)\s*[:=-]\s*(.+)$", s)
    if label_m:
        s = label_m.group(1).strip(" \t\r\n`'\"“”‘’[]()")
        s = re.sub(r"^\s*\*{1,3}\s*", "", s)
        s = re.sub(r"\s*\*{1,3}\s*$", "", s)
        s = s.strip(" \t\r\n`'\"“”‘’[]()")
    sl = s.lower()
    if re.search(
        r"\b(?:not\s+applicable|refuted|false[_\s-]*positive|infeasible|"
        r"absorbed(?:\s+into)?|duplicate|deduplicated|merged(?:\s+into)?|"
        r"subsumed(?:\s+by)?|already\s+captured|already\s+reported|"
        r"captured\s+in|not\s+re-?reported|not\s+reported\s+separately|"
        r"not\s+independently\s+reported|not\s+reportable|no\s+finding)\b",
        sl,
    ):
        return "Informational"
    if re.fullmatch(r"(?:n/?a|not\s+available|unknown)(?:\s*\([^)]*\))?", sl):
        return "Informational"
    exact = _SEVERITY_ALIASES.get(sl)
    if exact:
        return exact
    for canonical in SEVERITY_ORDER:
        if sl.startswith(canonical[:3].lower()):
            return canonical
    # NOISE-2: this is a fully-recoverable default (-> Medium), not a fault. A
    # WARNING per malformed cell floods logs on messy LLM-authored severity
    # columns (60-row table = 60 lines). Emit at DEBUG, once per distinct
    # unrecognized token, preserving the diagnostic value without the noise.
    if raw not in _NORMALIZE_SEVERITY_SEEN:
        _NORMALIZE_SEVERITY_SEEN.add(raw)
        log.debug(
            f"normalize_severity: unrecognized severity {raw!r}, defaulting to Medium"
        )
    return "Medium"


def severity_letter_from_name(raw: str) -> str:
    """Return the single-letter code for a severity name."""
    return SEVERITY_LETTER.get(normalize_severity(raw), "M")


def severity_rank(raw: str) -> int:
    """Return an integer rank (4=Critical .. 0=Informational, -1=unknown)."""
    sev = normalize_severity(raw)
    try:
        return len(SEVERITY_ORDER) - 1 - SEVERITY_ORDER.index(sev)
    except ValueError:
        return -1


_NEVER_CUT_SKIP_REASONS = {
    "NO_APPLICABLE_FLAG",
    "LANGUAGE_LANE_NOT_DETECTED",
    "EMPTY_SCOPE_AFTER_MANIFEST",
}

# v2.3.4 — `depth_`-prefixed aliases. Orchestrators legitimately group
# iteration-1 supplementary outputs (perturbation, design stress) under the
# `depth_*_findings.md` naming convention to align with the 5 standard depth
# agents. Pre-v2.3.4 the never-cut gate hard-failed on the prefix drift,
# halting the pipeline despite the agent having spawned and produced output.
# Same nondeterminism class as v2.3.1 coverage-fill drift — the gate's
# canonical-name expectation collided with a valid orchestrator filename
# choice. Each group accepts either the canonical or `depth_`-prefixed form.
L1_NEVER_CUT_ARTIFACT_GROUPS = [
    ["depth_consensus_invariant_findings.md"],
    ["depth_network_surface_findings.md"],
    ["depth_state_trace_findings.md"],
    ["depth_external_findings.md"],
    ["depth_edge_case_findings.md"],
    # L1-4: scanner floor (kept in sync with L1_NEVER_CUT_CORE_EXTRAS below so
    # this legacy flat default still mirrors the full mode-aware thorough set).
    ["blind_spot_a_findings.md"],
    ["blind_spot_b_findings.md"],
    ["blind_spot_c_findings.md"],
    ["validation_sweep_findings.md", "scanner_validation_findings.md"],
    ["design_stress_findings.md", "depth_design_stress_findings.md"],
    ["perturbation_findings.md", "depth_perturbation_findings.md"],
    ["confidence_scores.md"],
    ["skill_execution_gaps.md", "skill_execution_checklist.md"],
]

# v2.6.3 — L1 mode-aware never-cut groups (mirrors SC 3-tier pattern).
# Light requires only the 5 standard depth agents (no confidence scoring).
# Core adds confidence_scores.md (2-axis scoring).
# Thorough adds design stress, perturbation, and skill execution checklist.
L1_NEVER_CUT_BASE = [
    ["depth_consensus_invariant_findings.md"],
    ["depth_network_surface_findings.md"],
    ["depth_state_trace_findings.md"],
    ["depth_external_findings.md"],
    ["depth_edge_case_findings.md"],
]
L1_NEVER_CUT_CORE_EXTRAS = [
    # L1-4: scanner floor, mirrors SC_NEVER_CUT_CORE_EXTRAS exactly (same
    # canonical filenames — the depth-promotion feeder globs and the scanner
    # never-cut gate are pipeline-agnostic by construction).
    ["blind_spot_a_findings.md"],
    ["blind_spot_b_findings.md"],
    ["blind_spot_c_findings.md"],
    ["validation_sweep_findings.md", "scanner_validation_findings.md"],
    ["confidence_scores.md"],
]
L1_NEVER_CUT_THOROUGH_EXTRAS = [
    ["design_stress_findings.md", "depth_design_stress_findings.md"],
    ["perturbation_findings.md", "depth_perturbation_findings.md"],
    ["skill_execution_gaps.md", "skill_execution_checklist.md"],
]


def l1_never_cut_groups(mode: str) -> list:
    """Return the never-cut artifact groups for L1 depth phase by mode."""
    groups = list(L1_NEVER_CUT_BASE)
    if mode in ("core", "thorough"):
        groups = groups + L1_NEVER_CUT_CORE_EXTRAS
    if mode == "thorough":
        groups = groups + L1_NEVER_CUT_THOROUGH_EXTRAS
    return groups

# SC (smart-contract) never-cut groups are mode-aware. The 4 standard
# depth agents run in every SC mode (Light/Core/Thorough) per the AUDIT
# MODES table; validation sweep + 2-axis confidence scoring run in
# Core/Thorough; design stress + perturbation + skill execution +
# 3-code-axis confidence run only in Thorough. The Light set is the recall-
# floor — catches the "orchestrator merged depth agents to save
# context" failure mode mechanically.
SC_NEVER_CUT_BASE = [
    ["depth_token_flow_findings.md"],
    ["depth_state_trace_findings.md"],
    ["depth_edge_case_findings.md"],
    ["depth_external_findings.md"],
]
SC_NEVER_CUT_CORE_EXTRAS = [
    ["blind_spot_a_findings.md"],
    ["blind_spot_b_findings.md"],
    ["blind_spot_c_findings.md"],
    ["validation_sweep_findings.md", "scanner_validation_findings.md"],
    ["confidence_scores.md"],
]
SC_NEVER_CUT_THOROUGH_EXTRAS = [
    # v2.3.4: same `depth_`-prefix tolerance as L1.
    ["design_stress_findings.md", "depth_design_stress_findings.md"],
    ["perturbation_findings.md", "depth_perturbation_findings.md"],
    ["skill_execution_gaps.md", "skill_execution_checklist.md"],
]


def sc_never_cut_groups(mode: str) -> list:
    """Return the never-cut artifact groups for SC depth phase by mode."""
    groups = list(SC_NEVER_CUT_BASE)
    if mode in ("core", "thorough"):
        groups = groups + SC_NEVER_CUT_CORE_EXTRAS
    if mode == "thorough":
        groups = groups + SC_NEVER_CUT_THOROUGH_EXTRAS
    return groups


# Closed backend-neutral registry for the only SC depth roles that may inherit
# a recon-selected SKILL.md. Driver scheduling, producer validation, binding
# parsing, and prompt construction all consume this same finite contract.
SC_DEPTH_SKILL_ROLE_SPECS: tuple[dict[str, str], ...] = (
    {
        "agent_id": "depth-token-flow", "role": "token_flow",
        "output": "depth_token_flow_findings.md", "category": "standard",
        "focus": "Token/value flow, accounting, transfers, fees, share conversions",
    },
    {
        "agent_id": "depth-state-trace", "role": "state_trace",
        "output": "depth_state_trace_findings.md", "category": "standard",
        "focus": "Cross-function state mutation and invariant enforcement",
    },
    {
        "agent_id": "depth-edge-case", "role": "edge_case",
        "output": "depth_edge_case_findings.md", "category": "standard",
        "focus": "Boundary values, zero/max state, rounding, empty state",
    },
    {
        "agent_id": "depth-external", "role": "external",
        "output": "depth_external_findings.md", "category": "standard",
        "focus": "External calls, callbacks, MEV, oracle and cross-chain boundaries",
    },
)
SC_DEPTH_SKILL_ROLES = frozenset(
    str(spec["role"]) for spec in SC_DEPTH_SKILL_ROLE_SPECS
)
SC_DEPTH_SKILL_DESTINATIONS = {
    str(spec["agent_id"]): str(spec["role"])
    for spec in SC_DEPTH_SKILL_ROLE_SPECS
}


def canonical_sc_depth_skill_role(value: str) -> str | None:
    """Resolve an exact scheduled skill-bearing SC role, else ``None``."""
    normalized = str(value or "").strip().strip("`*").lower()
    if normalized in SC_DEPTH_SKILL_DESTINATIONS:
        return SC_DEPTH_SKILL_DESTINATIONS[normalized]
    if normalized in SC_DEPTH_SKILL_ROLES:
        return normalized
    return None


L1_VERIFY_SHARD_MANIFESTS = {
    "verify_crithigh": "verification_queue_crithigh.md",
    "verify_high_b": "verification_queue_high_b.md",
    "verify_high_c": "verification_queue_high_c.md",
    "verify_high_d": "verification_queue_high_d.md",
    "verify_high_e": "verification_queue_high_e.md",
    "verify_high_f": "verification_queue_high_f.md",
    "verify_high_g": "verification_queue_high_g.md",
    "verify_high_h": "verification_queue_high_h.md",
    "verify_high_i": "verification_queue_high_i.md",
    "verify_high_j": "verification_queue_high_j.md",
    "verify_medium_a": "verification_queue_medium_a.md",
    "verify_medium_b": "verification_queue_medium_b.md",
    "verify_medium_c": "verification_queue_medium_c.md",
    "verify_medium_d": "verification_queue_medium_d.md",
    "verify_medium_e": "verification_queue_medium_e.md",
    "verify_medium_f": "verification_queue_medium_f.md",
    "verify_low_a": "verification_queue_low_a.md",
    "verify_low_b": "verification_queue_low_b.md",
    "verify_low_c": "verification_queue_low_c.md",
    "verify_low_d": "verification_queue_low_d.md",
}
L1_VERIFY_PHASE_NAMES = tuple(L1_VERIFY_SHARD_MANIFESTS.keys())
L1_VERIFY_CRITHIGH_PHASE_NAMES = (
    "verify_crithigh", "verify_high_b", "verify_high_c",
    "verify_high_d", "verify_high_e", "verify_high_f",
    "verify_high_g", "verify_high_h", "verify_high_i", "verify_high_j",
)

# SC verify shards: SC projects can still produce many High hypotheses in
# thorough mode. Keep Critical/High shards small enough that each verification
# subprocess can write progress before long-context API failures.
SC_VERIFY_SHARD_MANIFESTS = {
    "sc_verify_crithigh": "verification_queue_crithigh.md",
    "sc_verify_high_b": "verification_queue_high_b.md",
    "sc_verify_high_c": "verification_queue_high_c.md",
    "sc_verify_high_d": "verification_queue_high_d.md",
    "sc_verify_high_e": "verification_queue_high_e.md",
    "sc_verify_high_f": "verification_queue_high_f.md",
    "sc_verify_high_g": "verification_queue_high_g.md",
    "sc_verify_high_h": "verification_queue_high_h.md",
    "sc_verify_high_i": "verification_queue_high_i.md",
    "sc_verify_high_j": "verification_queue_high_j.md",
    "sc_verify_medium_a": "verification_queue_medium_a.md",
    "sc_verify_medium_b": "verification_queue_medium_b.md",
    "sc_verify_medium_c": "verification_queue_medium_c.md",
    "sc_verify_medium_d": "verification_queue_medium_d.md",
    "sc_verify_medium_e": "verification_queue_medium_e.md",
    "sc_verify_medium_f": "verification_queue_medium_f.md",
    "sc_verify_medium_g": "verification_queue_medium_g.md",
    "sc_verify_medium_h": "verification_queue_medium_h.md",
    "sc_verify_medium_i": "verification_queue_medium_i.md",
    "sc_verify_medium_j": "verification_queue_medium_j.md",
    "sc_verify_low_a": "verification_queue_low_a.md",
    "sc_verify_low_b": "verification_queue_low_b.md",
    "sc_verify_low_c": "verification_queue_low_c.md",
    "sc_verify_low_d": "verification_queue_low_d.md",
    "sc_verify_low_e": "verification_queue_low_e.md",
    "sc_verify_low_f": "verification_queue_low_f.md",
    "sc_verify_low_g": "verification_queue_low_g.md",
    "sc_verify_low_h": "verification_queue_low_h.md",
    "sc_verify_low_i": "verification_queue_low_i.md",
    "sc_verify_low_j": "verification_queue_low_j.md",
}
SC_VERIFY_PHASE_NAMES = tuple(SC_VERIFY_SHARD_MANIFESTS.keys())
SC_VERIFY_CRITHIGH_PHASE_NAMES = (
    "sc_verify_crithigh", "sc_verify_high_b",
    "sc_verify_high_c", "sc_verify_high_d",
    "sc_verify_high_e", "sc_verify_high_f",
    "sc_verify_high_g", "sc_verify_high_h",
    "sc_verify_high_i", "sc_verify_high_j",
)

# Phases where the Codex backend should use spawn_agent for parallel sub-agents
# instead of running everything sequentially as a single agent. These are the
# orchestrator phases that spawn multiple analysis agents in the Claude pipeline.
CODEX_MULTI_AGENT_PHASES: frozenset[str] = frozenset({
    "recon",
    "breadth",
    "rescan",
    "depth",
})


# --- Dataclasses ---

PHASE_COMMIT_STATES: frozenset[str] = frozenset({
    "CLEAN",
    "COMPLETED_WITH_DEBT",
    "DEGRADED_WITH_OUTPUT",
    "INCOMPLETE_WITH_DEBT",
})

GATE_FAILURE_CLASSES: frozenset[str] = frozenset({
    "ARTIFACT_PRESENCE",
    "SCHEMA",
    "SEMANTIC_IDENTITY",
    "METHODOLOGY_SELECTION",
    "METHODOLOGY_APPLICATION",
    "EVIDENCE_INTEGRITY",
    "INDEPENDENT_DISPOSITION",
    "DELIVERED_PROJECTION",
    "CONTAINMENT",
    "ADVISORY_QUALITY",
    "REPORT_INTEGRITY",
})

GATE_FALLBACK_POLICIES: frozenset[str] = frozenset({
    "NONE",
    "CONSUME_WITH_DEBT",
    "BLOCK_AS_AUTHORITY",
    "UNPROVEN_ONLY",
    "RETAIN_UNDISPOSED",
    "HUMAN_REVIEW_DELIVERY",
    "NO_SHIP_QUARANTINE",
})

RETRY_RECEIPT_STATUSES: frozenset[str] = frozenset({
    "CLEARED", "PROGRESSED", "NO_PROGRESS", "FAILED",
})


def _required_nonempty_string(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RuntimeError(f"{field_name} must be a non-empty string")
    return value.strip()


def _optional_string(value: object, field_name: str) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise RuntimeError(f"{field_name} must be a string")
    return value


def _string_tuple(value: object, field_name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, (list, tuple)):
        raise RuntimeError(f"{field_name} must be a list of strings")
    if not all(isinstance(item, str) and item.strip() for item in value):
        raise RuntimeError(f"{field_name} entries must be non-empty strings")
    return tuple(str(item).strip() for item in value)


@dataclass(frozen=True)
class GateFailure:
    """One unresolved predicate at a phase boundary.

    Gate classes are intentionally explicit: an artifact-presence fallback may
    not clear a methodology, identity, evidence, containment, disposition, or
    delivery failure merely because some Markdown exists on disk.
    """

    gate_id: str
    gate_class: str
    message: str
    affected_identities: tuple[str, ...] = ()
    input_digest: str = ""
    output_digest: str = ""
    contract_digest: str = ""
    evidence_paths: tuple[str, ...] = ()
    repair_owner: str = ""
    fallback_policy: str = "NONE"
    allowed_fallback: str = ""
    schema_id: str = "legacy-validator-string"
    schema_version: int = 1
    denominator_count: Optional[int] = None
    denominator_digest: str = ""
    predicate_digest: str = ""
    failure_instance_id: str = ""

    def __post_init__(self) -> None:
        _required_nonempty_string(self.gate_id, "gate_id")
        if self.gate_class not in GATE_FAILURE_CLASSES:
            raise RuntimeError(
                f"gate_class must be one of {sorted(GATE_FAILURE_CLASSES)}"
            )
        _required_nonempty_string(self.message, "message")
        _string_tuple(self.affected_identities, "affected_identities")
        _string_tuple(self.evidence_paths, "evidence_paths")
        for name in (
            "input_digest", "output_digest", "contract_digest",
            "repair_owner", "allowed_fallback", "denominator_digest",
        ):
            _optional_string(getattr(self, name), name)
        if self.fallback_policy not in GATE_FALLBACK_POLICIES:
            raise RuntimeError(
                "fallback_policy must be one of "
                f"{sorted(GATE_FALLBACK_POLICIES)}"
            )
        _required_nonempty_string(self.schema_id, "schema_id")
        if type(self.schema_version) is not int or self.schema_version < 1:
            raise RuntimeError("schema_version must be a positive integer")
        if self.denominator_count is not None and (
            type(self.denominator_count) is not int
            or self.denominator_count < 0
        ):
            raise RuntimeError("denominator_count must be null or non-negative")
        predicate_digest = self.predicate_digest or hashlib.sha256(
            json.dumps(
                {
                    "gate_id": self.gate_id,
                    "message": self.message,
                    "affected_identities": list(self.affected_identities),
                    "denominator_count": self.denominator_count,
                    "denominator_digest": self.denominator_digest,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        object.__setattr__(self, "predicate_digest", predicate_digest)
        failure_instance_id = self.failure_instance_id or hashlib.sha256(
            "\0".join((
                self.gate_id,
                self.input_digest,
                self.output_digest,
                self.contract_digest,
                predicate_digest,
            )).encode("utf-8")
        ).hexdigest()
        object.__setattr__(self, "failure_instance_id", failure_instance_id)

    def to_dict(self) -> dict:
        return {
            "gate_id": self.gate_id,
            "gate_class": self.gate_class,
            "message": self.message,
            "affected_identities": list(self.affected_identities),
            "input_digest": self.input_digest,
            "output_digest": self.output_digest,
            "contract_digest": self.contract_digest,
            "evidence_paths": list(self.evidence_paths),
            "repair_owner": self.repair_owner,
            "fallback_policy": self.fallback_policy,
            "allowed_fallback": self.allowed_fallback,
            "schema_id": self.schema_id,
            "schema_version": self.schema_version,
            "denominator_count": self.denominator_count,
            "denominator_digest": self.denominator_digest,
            "predicate_digest": self.predicate_digest,
            "failure_instance_id": self.failure_instance_id,
        }

    @classmethod
    def from_dict(cls, data: object) -> "GateFailure":
        if not isinstance(data, dict):
            raise RuntimeError("gate failure must be an object")
        return cls(
            gate_id=_required_nonempty_string(data.get("gate_id"), "gate_id"),
            gate_class=_required_nonempty_string(
                data.get("gate_class"), "gate_class"
            ),
            message=_required_nonempty_string(data.get("message"), "message"),
            affected_identities=_string_tuple(
                data.get("affected_identities", []), "affected_identities"
            ),
            input_digest=_optional_string(
                data.get("input_digest", ""), "input_digest"
            ),
            output_digest=_optional_string(
                data.get("output_digest", ""), "output_digest"
            ),
            contract_digest=_optional_string(
                data.get("contract_digest", ""), "contract_digest"
            ),
            evidence_paths=_string_tuple(
                data.get("evidence_paths", []), "evidence_paths"
            ),
            repair_owner=_optional_string(
                data.get("repair_owner", ""), "repair_owner"
            ),
            fallback_policy=_required_nonempty_string(
                data.get("fallback_policy", "NONE"), "fallback_policy"
            ),
            allowed_fallback=_optional_string(
                data.get("allowed_fallback", ""), "allowed_fallback"
            ),
            schema_id=_required_nonempty_string(
                data.get("schema_id", "legacy-validator-string"), "schema_id"
            ),
            schema_version=data.get("schema_version", 1),
            denominator_count=data.get("denominator_count"),
            denominator_digest=_optional_string(
                data.get("denominator_digest", ""), "denominator_digest"
            ),
            predicate_digest=_optional_string(
                data.get("predicate_digest", ""), "predicate_digest"
            ),
            failure_instance_id=_optional_string(
                data.get("failure_instance_id", ""), "failure_instance_id"
            ),
        )


@dataclass(frozen=True)
class GateClearance:
    """Explicit evidence that discharges one previously failed predicate."""

    gate_id: str
    clearing_gate_id: str
    evidence_digest: str
    authority: str
    cleared_at: str = ""

    def __post_init__(self) -> None:
        _required_nonempty_string(self.gate_id, "gate_id")
        _required_nonempty_string(self.clearing_gate_id, "clearing_gate_id")
        _required_nonempty_string(self.evidence_digest, "evidence_digest")
        _required_nonempty_string(self.authority, "authority")
        _optional_string(self.cleared_at, "cleared_at")

    def to_dict(self) -> dict:
        return {
            "gate_id": self.gate_id,
            "clearing_gate_id": self.clearing_gate_id,
            "evidence_digest": self.evidence_digest,
            "authority": self.authority,
            "cleared_at": self.cleared_at,
        }

    @classmethod
    def from_dict(cls, data: object) -> "GateClearance":
        if not isinstance(data, dict):
            raise RuntimeError("gate clearance must be an object")
        return cls(
            gate_id=_required_nonempty_string(data.get("gate_id"), "gate_id"),
            clearing_gate_id=_required_nonempty_string(
                data.get("clearing_gate_id"), "clearing_gate_id"
            ),
            evidence_digest=_required_nonempty_string(
                data.get("evidence_digest"), "evidence_digest"
            ),
            authority=_required_nonempty_string(
                data.get("authority"), "authority"
            ),
            cleared_at=_optional_string(
                data.get("cleared_at", ""), "cleared_at"
            ),
        )


@dataclass(frozen=True)
class PhaseCommit:
    """Immutable semantic completion record for one resolved work unit."""

    phase_name: str
    state: str
    run_id: str
    work_unit_id: str = "phase"
    contract_digest: str = ""
    launch_digest: str = ""
    artifact_digest: str = ""
    unresolved_failures: tuple[GateFailure, ...] = ()
    clearance_events: tuple[GateClearance, ...] = ()
    committed_at: str = ""

    def __post_init__(self) -> None:
        _required_nonempty_string(self.phase_name, "phase_name")
        _required_nonempty_string(self.work_unit_id, "work_unit_id")
        if self.state not in PHASE_COMMIT_STATES:
            raise RuntimeError(
                f"state must be one of {sorted(PHASE_COMMIT_STATES)}"
            )
        if re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
            r"[89ab][0-9a-f]{3}-[0-9a-f]{12}",
            self.run_id,
        ) is None:
            raise RuntimeError("run_id must be a canonical UUIDv4")
        if self.state == "CLEAN" and self.unresolved_failures:
            raise RuntimeError("CLEAN phase commit cannot carry unresolved failures")
        if self.state != "CLEAN" and not self.unresolved_failures:
            raise RuntimeError(
                f"{self.state} phase commit must carry at least one failure"
            )
        if not all(isinstance(item, GateFailure) for item in self.unresolved_failures):
            raise RuntimeError("unresolved_failures must contain GateFailure records")
        if not all(isinstance(item, GateClearance) for item in self.clearance_events):
            raise RuntimeError("clearance_events must contain GateClearance records")
        for name in (
            "contract_digest", "launch_digest", "artifact_digest", "committed_at"
        ):
            _optional_string(getattr(self, name), name)

    def to_dict(self) -> dict:
        return {
            "phase_name": self.phase_name,
            "state": self.state,
            "run_id": self.run_id,
            "work_unit_id": self.work_unit_id,
            "contract_digest": self.contract_digest,
            "launch_digest": self.launch_digest,
            "artifact_digest": self.artifact_digest,
            "unresolved_failures": [
                failure.to_dict() for failure in self.unresolved_failures
            ],
            "clearance_events": [
                clearance.to_dict() for clearance in self.clearance_events
            ],
            "committed_at": self.committed_at,
        }

    @classmethod
    def from_dict(cls, data: object) -> "PhaseCommit":
        if not isinstance(data, dict):
            raise RuntimeError("phase commit must be an object")
        failures = data.get("unresolved_failures", [])
        if not isinstance(failures, list):
            raise RuntimeError("unresolved_failures must be a list")
        clearances = data.get("clearance_events", [])
        if not isinstance(clearances, list):
            raise RuntimeError("clearance_events must be a list")
        return cls(
            phase_name=_required_nonempty_string(
                data.get("phase_name"), "phase_name"
            ),
            state=_required_nonempty_string(data.get("state"), "state"),
            run_id=_required_nonempty_string(data.get("run_id"), "run_id"),
            work_unit_id=_required_nonempty_string(
                data.get("work_unit_id", "phase"), "work_unit_id"
            ),
            contract_digest=_optional_string(
                data.get("contract_digest", ""), "contract_digest"
            ),
            launch_digest=_optional_string(
                data.get("launch_digest", ""), "launch_digest"
            ),
            artifact_digest=_optional_string(
                data.get("artifact_digest", ""), "artifact_digest"
            ),
            unresolved_failures=tuple(
                GateFailure.from_dict(item) for item in failures
            ),
            clearance_events=tuple(
                GateClearance.from_dict(item) for item in clearances
            ),
            committed_at=_optional_string(
                data.get("committed_at", ""), "committed_at"
            ),
        )


@dataclass(frozen=True)
class RetryReceipt:
    """Predicate-aware result of one bounded producer repair attempt."""

    run_id: str
    phase_name: str
    work_unit_id: str
    attempt: int
    status: str
    failure_instance_ids_before: tuple[str, ...]
    failure_instance_ids_after: tuple[str, ...]
    gate_ids_before: tuple[str, ...]
    gate_ids_after: tuple[str, ...]
    schema_id: str
    schema_version: int
    denominator_count: Optional[int]
    denominator_digest: str
    input_digest: str
    output_digest_before: str
    output_digest_after: str
    predicate_digest_before: str
    predicate_digest_after: str
    repair_owner: str
    prompt_digest: str
    launch_digest: str
    contract_digest: str
    quarantine_lineage: tuple[str, ...] = ()
    created_at: str = ""

    def __post_init__(self) -> None:
        if re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
            r"[89ab][0-9a-f]{3}-[0-9a-f]{12}",
            self.run_id,
        ) is None:
            raise RuntimeError("run_id must be a canonical UUIDv4")
        for name in (
            "phase_name", "work_unit_id", "schema_id", "input_digest",
            "output_digest_before", "output_digest_after",
            "predicate_digest_before", "predicate_digest_after",
            "repair_owner", "prompt_digest", "launch_digest", "contract_digest",
        ):
            _required_nonempty_string(getattr(self, name), name)
        if type(self.attempt) is not int or self.attempt < 1:
            raise RuntimeError("attempt must be a positive integer")
        if self.status not in RETRY_RECEIPT_STATUSES:
            raise RuntimeError(
                f"status must be one of {sorted(RETRY_RECEIPT_STATUSES)}"
            )
        if type(self.schema_version) is not int or self.schema_version < 1:
            raise RuntimeError("schema_version must be a positive integer")
        if self.denominator_count is not None and (
            type(self.denominator_count) is not int
            or self.denominator_count < 0
        ):
            raise RuntimeError("denominator_count must be null or non-negative")
        for name in (
            "failure_instance_ids_before", "failure_instance_ids_after",
            "gate_ids_before", "gate_ids_after", "quarantine_lineage",
        ):
            _string_tuple(getattr(self, name), name)

    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "phase_name": self.phase_name,
            "work_unit_id": self.work_unit_id,
            "attempt": self.attempt,
            "status": self.status,
            "failure_instance_ids_before": list(self.failure_instance_ids_before),
            "failure_instance_ids_after": list(self.failure_instance_ids_after),
            "gate_ids_before": list(self.gate_ids_before),
            "gate_ids_after": list(self.gate_ids_after),
            "schema_id": self.schema_id,
            "schema_version": self.schema_version,
            "denominator_count": self.denominator_count,
            "denominator_digest": self.denominator_digest,
            "input_digest": self.input_digest,
            "output_digest_before": self.output_digest_before,
            "output_digest_after": self.output_digest_after,
            "predicate_digest_before": self.predicate_digest_before,
            "predicate_digest_after": self.predicate_digest_after,
            "repair_owner": self.repair_owner,
            "prompt_digest": self.prompt_digest,
            "launch_digest": self.launch_digest,
            "contract_digest": self.contract_digest,
            "quarantine_lineage": list(self.quarantine_lineage),
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: object) -> "RetryReceipt":
        if not isinstance(data, dict):
            raise RuntimeError("retry receipt must be an object")
        return cls(
            run_id=_required_nonempty_string(data.get("run_id"), "run_id"),
            phase_name=_required_nonempty_string(
                data.get("phase_name"), "phase_name"
            ),
            work_unit_id=_required_nonempty_string(
                data.get("work_unit_id"), "work_unit_id"
            ),
            attempt=data.get("attempt"),
            status=_required_nonempty_string(data.get("status"), "status"),
            failure_instance_ids_before=_string_tuple(
                data.get("failure_instance_ids_before", []),
                "failure_instance_ids_before",
            ),
            failure_instance_ids_after=_string_tuple(
                data.get("failure_instance_ids_after", []),
                "failure_instance_ids_after",
            ),
            gate_ids_before=_string_tuple(
                data.get("gate_ids_before", []), "gate_ids_before"
            ),
            gate_ids_after=_string_tuple(
                data.get("gate_ids_after", []), "gate_ids_after"
            ),
            schema_id=_required_nonempty_string(
                data.get("schema_id"), "schema_id"
            ),
            schema_version=data.get("schema_version"),
            denominator_count=data.get("denominator_count"),
            denominator_digest=_optional_string(
                data.get("denominator_digest", ""), "denominator_digest"
            ),
            input_digest=_required_nonempty_string(
                data.get("input_digest"), "input_digest"
            ),
            output_digest_before=_required_nonempty_string(
                data.get("output_digest_before"), "output_digest_before"
            ),
            output_digest_after=_required_nonempty_string(
                data.get("output_digest_after"), "output_digest_after"
            ),
            predicate_digest_before=_required_nonempty_string(
                data.get("predicate_digest_before"), "predicate_digest_before"
            ),
            predicate_digest_after=_required_nonempty_string(
                data.get("predicate_digest_after"), "predicate_digest_after"
            ),
            repair_owner=_required_nonempty_string(
                data.get("repair_owner"), "repair_owner"
            ),
            prompt_digest=_required_nonempty_string(
                data.get("prompt_digest"), "prompt_digest"
            ),
            launch_digest=_required_nonempty_string(
                data.get("launch_digest"), "launch_digest"
            ),
            contract_digest=_required_nonempty_string(
                data.get("contract_digest"), "contract_digest"
            ),
            quarantine_lineage=_string_tuple(
                data.get("quarantine_lineage", []), "quarantine_lineage"
            ),
            created_at=_optional_string(
                data.get("created_at", ""), "created_at"
            ),
        )

@dataclass
class Phase:
    name: str                          # "recon", "breadth", etc.
    section_markers: list              # Headings to tell the LLM to run, e.g. ["## Step 1", "## Step 2"]
    expected_artifacts: list           # Glob patterns, e.g. ["recon_summary.md", "depth_*_findings.md"]
    base_timeout_s: int                # Base wall-clock timeout for this phase
    model: str = "sonnet"              # claude -p --model value for Core/Thorough. Light forces sonnet.
    needs_mcp: bool = False            # Only rag_sweep
    modes: set = field(default_factory=lambda: {"light", "core", "thorough"})
    min_artifact_bytes: int = 100      # Gate fails if any matched file is smaller
    min_artifacts_count: int = 1       # For glob patterns: require at least N substantial
                                       # matches. Default 1 (any match passes). Set >1 on
                                       # phases where one solo artifact would be a silent
                                       # degradation (e.g. only one analysis_*.md when
                                       # Thorough requested 5-9 breadth agents).
    critical: bool = False             # If True, pipeline HALTS on degrade (not continues).
                                       # Set on phases whose output is a hard prerequisite for
                                       # the rest of the pipeline (breadth/depth/verify — no
                                       # findings = no report).
    any_of: list = field(default_factory=list)
                                       # List of OR-groups. Each inner list is a set of glob
                                       # patterns where AT LEAST ONE must match (OR within the
                                       # group). ALL outer groups must be satisfied (AND across
                                       # groups). Evaluated by gate_passes() in addition to
                                       # expected_artifacts. Use for naming-convention flux
                                       # (e.g. verify_F_*.md vs verify_F-*.md) where either
                                       # shape alone should count as complete.
    appends_existing_artifact: bool = False
                                       # True when this phase's expected_artifacts are written
                                       # by an earlier phase and this phase only APPENDS new
                                       # sections to them. Disables the rate-limit-retry savings
                                       # guard for this phase, because the guard's gate_passes()
                                       # check sees the file already on disk and would skip the
                                       # retry — but the file is missing this phase's content.
                                       # Set on Phase 4a.5 Pass 2 (`invariants_p2`), which
                                       # appends a `## Pass 2:` section onto `semantic_invariants.md`
                                       # produced by the earlier `invariants` phase.
    example_tokens: list = field(default_factory=list)
                                       # Per-phase authoritative substitution tokens for `*` in
                                       # expected_artifacts globs. When set, `_render_expected_
                                       # output_block` emits example filenames using these tokens
                                       # INSTEAD of numeric-shard defaults. Fixes the v2.1.3-
                                       # observed drift class where depth agents produced
                                       # `depth_01_token_flow_findings.md` because the driver's
                                       # auto-generated examples were `depth_01_findings.md`.
                                       # Per LLM instruction-following research (Min et al. 2022
                                       # "Rethinking the Role of Demonstrations", Lu et al. 2022
                                       # "Fantastically Ordered Prompts"), few-shot examples
                                       # anchor output format more strongly than declarative
                                       # rules, so accurate examples beat any amount of "MUST
                                       # NOT DRIFT" prose. Leave empty for phases where numeric
                                       # shards are the intended convention (breadth, rescan).


def phase_model(phase: Phase, mode: str, config: Optional[dict] = None) -> str:
    """Resolve effective model for this phase under the given audit mode.

    Light mode forces all phases to sonnet regardless of phase.model
    (Light is a Pro-plan-compatible budget; opus is Max-plan).
    Core/Thorough honor the phase-level model.
    For Codex backend, maps tier aliases to OpenAI model IDs.
    """
    def _breadth_override() -> str:
        if config and phase.name == "breadth":
            value = (
                config.get("breadth_model_override")
                or os.environ.get("PLAMEN_BREADTH_MODEL_OVERRIDE")
                or ""
            )
            if not isinstance(value, str):
                raise ValueError("Claude breadth model override must be a string")
            return value
        return ""

    # THOROUGH model promotion to pinned Opus 5 for the
    # reasoning-critical roles — discovery (breadth + depth) + SC verification
    # shards (sc_verify_*) + skeptic-judge. Depth/critical-writer are already
    # `opus` and ride the pinned resolution below; breadth (normally Sonnet), the
    # sc_verify shards, and skeptic are force-promoted to the opus tier here.
    # Queue/aggregate verify phases (routing/summary, not reasoning) are NOT
    # promoted. Applies to SC AND L1 Thorough: breadth + skeptic + the opus-tier
    # reasoning phases (depth/critical-writer) promote to Opus 5. L1 verify shards
    # are named `verify_*` (not `sc_verify_*`) and are Sonnet-tier, so they do
    # NOT match the promotion below — L1's deliberate verify cost cap (Sonnet
    # shards, Haiku queue/aggregate) is preserved automatically. Core/Light are
    # untouched. Rescan/per-contract stay Sonnet (model-diversity + cost).
    # Env override: PLAMEN_THOROUGH_OPUS_MODEL.
    promoted_to_opus = False
    if mode == "thorough" and config and config.get("pipeline") in ("sc", "l1"):
        name = phase.name
        is_sc_verify_shard = (
            name.startswith("sc_verify_")
            and not name.endswith("_queue")
            and not name.endswith("_aggregate")
        )
        # L1 verify shards are named verify_* (not sc_verify_*) and were left at
        # Sonnet as a deliberate cost cap. But Sonnet drops the mandatory PoC
        # Attempt/Execution Result ledger for some findings under load, failing
        # the verify PoC-contract gate and degrading findings to unverified. SC
        # Thorough verify shards already promote to Opus and do NOT exhibit this.
        # Promote L1 Thorough verify SHARDS to Opus for parity. Queue/aggregate
        # are routing/summary phases (verify_queue, verify_aggregate) and stay
        # unpromoted. Scoped to pipeline == "l1" so SC verify_* (if any) untouched.
        is_l1_verify_shard = (
            (config.get("pipeline") if config else None) == "l1"
            and name.startswith("verify_")
            and not name.endswith("_queue")
            and not name.endswith("_aggregate")
        )
        # SC Thorough report_index (the LLM Index Agent) → Opus. Indexing a large
        # Thorough report (100+ findings, 300+ ID coverage seed) is consolidation
        # + completeness accounting over the full ID set; the stronger model
        # reduces dropped IDs / mis-consolidation that trip the completeness and
        # coverage gates (and force the post-gate mechanical repair). L1
        # report_index is deterministic (mechanical, no agent), so this is SC-only.
        is_sc_report_index = (
            (config.get("pipeline") if config else None) == "sc"
            and name == "report_index"
        )
        # SC Thorough semantic dedup (Phase 4e) → Opus. In-context-clustering
        # MERGE/KEEP adjudication is precision-critical (a false merge HIDES a
        # finding), so the stronger model improves decision quality; Opus's
        # larger budget also comfortably absorbs the bounded clustering-block
        # input. SC-only (L1 has its own dedup path); Core/Light stay on sonnet.
        is_sc_semantic_dedup = (
            (config.get("pipeline") if config else None) == "sc"
            and name == "sc_semantic_dedup"
        )
        # SC Thorough chain analysis (Phase 4c: chain agent 1, chain agent 2,
        # chain iter2) → Opus. Chain matching reasons over the full hypothesis /
        # composition / candidate-pair set and reads large compact ledgers;
        # Earlier Sonnet generations autocompact-thrashed on big bounties
        # (observed: chain_agent2 thrash → idle-prompt zombie hang on a
        # ~99-finding bounty). The Opus tier's reasoning budget absorbs the bounded
        # ledgers and improves match precision. SC-only (L1 has no chain phase —
        # Phase 4c is removed for L1). Core/Light stay sonnet.
        is_sc_chain = (
            (config.get("pipeline") if config else None) == "sc"
            and name in ("chain", "chain_agent2", "chain_iter2")
        )
        # SC Thorough inventory synthesis (chunks + merge) → Opus (bloat fix #3).
        # The inventory merge ingests ~all breadth+depth findings (100KB+) and
        # decides what survives consolidation; Sonnet-at-volume preserves-rather-
        # than-judges (the master inventory can come out LARGER than its chunks —
        # barely dedup'd), and that bloated inventory is inherited by every
        # downstream phase. SC-only; Core/Light stay sonnet.
        is_sc_inventory = (
            (config.get("pipeline") if config else None) == "sc"
            and name in ("inventory", "inventory_chunk_a",
                         "inventory_chunk_b", "inventory_chunk_c")
        )
        # SC Thorough report body-writers (the shard-expanded report_body_writer_*
        # tier authors) → Opus (bloat fix #3). They bulk-read the full inventory
        # and author the client-facing sections — the precision/bloat decision
        # point where most non-GT findings get written into the body. Prefix-
        # match the sentinel AND every expanded shard. SC-only.
        is_sc_tier_writer = (
            (config.get("pipeline") if config else None) == "sc"
            and name.startswith("report_body_writer_")
        )
        promoted_to_opus = (
            name in ("breadth", "skeptic")
            or is_sc_verify_shard
            or is_l1_verify_shard
            or is_sc_report_index
            or is_sc_semantic_dedup
            or is_sc_chain
            or is_sc_inventory
            or is_sc_tier_writer
        )
    breadth_override = _breadth_override()
    tier = (
        "sonnet"
        if mode == "light"
        else ("opus" if promoted_to_opus else (phase.model or "sonnet").strip())
    )

    # Resolve the shared phase-tier policy only after promotions have been
    # computed. Claude's opus tier becomes Opus 5; Codex's becomes Sol.
    if config and config.get("cli_backend") == "codex":
        resolved = _resolve_codex_model_alias(tier)
        phase_fallbacks = config.get("_codex_phase_model_fallbacks") or {}
        if isinstance(phase_fallbacks, dict) and phase.name in phase_fallbacks:
            return phase_fallbacks[phase.name]
        # If a model was found unavailable, downgrade only phases that would
        # use it — sonnet/haiku-tier phases keep their natural model.
        unavail = config.get("_codex_model_unavailable")
        if unavail and resolved == unavail:
            return config.get(
                "_codex_model_fallback",
                _CODEX_MODEL_MAP.get("sonnet", "gpt-5.6-terra"),
            )
        return resolved

    if breadth_override:
        # Validate even in Light mode so a stale/arbitrary config cannot hide
        # dormant authority. A valid override is deliberately ignored in
        # Light: its defining contract is that every phase uses Sonnet.
        admitted_breadth_override = _resolve_claude_breadth_override(
            breadth_override
        )
        if mode != "light":
            return admitted_breadth_override
    if tier == "opus" and mode == "thorough":
        return PLAMEN_THOROUGH_OPUS_MODEL or _resolve_model_alias("opus")
    return _resolve_model_alias(tier)


_RUNTIME_DEBT_ID_RE = re.compile(
    r"[A-Z][A-Z0-9]*(?:[-_.][A-Z0-9]+)*"
)
_SHA256_HEX_RE = re.compile(r"[0-9a-f]{64}")


def _valid_runtime_debt_entry(debt_id: object, receipt_sha256: object) -> bool:
    """Return whether one runtime-debt binding is canonical.

    Runtime debt is process-level state, not a phase projection.  Its identity
    therefore uses a deliberately phase-agnostic, bounded symbolic name and
    binds to the exact lowercase SHA-256 digest of the evidence receipt that
    established the debt.
    """
    return (
        isinstance(debt_id, str)
        and 0 < len(debt_id) <= 128
        and _RUNTIME_DEBT_ID_RE.fullmatch(debt_id) is not None
        and isinstance(receipt_sha256, str)
        and _SHA256_HEX_RE.fullmatch(receipt_sha256) is not None
    )


def _validate_runtime_debt_identity(
    debt_id: object,
    receipt_sha256: object,
) -> None:
    if (
        not isinstance(debt_id, str)
        or not debt_id
        or len(debt_id) > 128
        or _RUNTIME_DEBT_ID_RE.fullmatch(debt_id) is None
    ):
        raise ValueError(
            "runtime debt ID must be a canonical non-empty symbolic name"
        )
    if (
        not isinstance(receipt_sha256, str)
        or _SHA256_HEX_RE.fullmatch(receipt_sha256) is None
    ):
        raise ValueError(
            "runtime debt receipt must be a lowercase SHA-256 digest"
        )


@dataclass
class Checkpoint:
    completed: list = field(default_factory=list)
    degraded: list = field(default_factory=list)
    rate_limited_at: Optional[str] = None
    config: Optional[dict] = None
    audit_snapshot: Optional[dict] = None
    run_id: Optional[str] = None
    phase_commits: dict[str, PhaseCommit] = field(default_factory=dict)
    semantic_mutation_acks: dict[str, str] = field(default_factory=dict)
    runtime_debts: dict[str, str] = field(default_factory=dict)

    @classmethod
    def load(cls, scratchpad: Path) -> "Checkpoint":
        p = scratchpad / "_v2_checkpoint.json"
        if not p.exists():
            return cls()
        try:
            data = json.loads(p.read_text(encoding="utf-8-sig"))
        except Exception as exc:
            # A corrupt checkpoint is not equivalent to a fresh run. Treating
            # it as empty causes resume to replay phases against stale
            # artifacts and can silently mix old/new state. Preserve the bad
            # file for forensics and force the operator to choose --fresh or
            # repair it explicitly.
            backup = p.with_suffix(f".corrupt-{int(time.time())}.json")
            try:
                shutil.copy2(p, backup)
            except Exception:
                backup = p
            try:
                (scratchpad / "_v2_checkpoint.corrupt").write_text(
                    f"Corrupt checkpoint preserved at {p}\n"
                    f"Forensic copy: {backup}\n",
                    encoding="utf-8",
                )
            except Exception:
                pass
            raise RuntimeError(
                f"Corrupt checkpoint {p}; forensic copy written to {backup}. "
                "The corrupt checkpoint was left in place to block unsafe "
                "resume. Restart with --fresh/clean scratchpad or restore a "
                "valid checkpoint."
            ) from exc
        if not isinstance(data, dict):
            raise RuntimeError(f"Invalid checkpoint {p}: root must be an object")

        def _string_list(key: str) -> list[str]:
            value = data.get(key, [])
            if not isinstance(value, list):
                raise RuntimeError(f"Invalid checkpoint {p}: {key} must be a list")
            if not all(isinstance(item, str) and item for item in value):
                raise RuntimeError(
                    f"Invalid checkpoint {p}: {key} entries must be non-empty strings"
                )
            if len(set(value)) != len(value):
                raise RuntimeError(f"Invalid checkpoint {p}: {key} contains duplicates")
            return list(value)

        rate_limited_at = data.get("rate_limited_at")
        if rate_limited_at is not None and not isinstance(rate_limited_at, str):
            raise RuntimeError(
                f"Invalid checkpoint {p}: rate_limited_at must be null or string"
            )
        cfg = data.get("config")
        if cfg is not None and not isinstance(cfg, dict):
            cfg = None
        audit_snapshot = data.get("audit_snapshot")
        if audit_snapshot is not None and not isinstance(audit_snapshot, dict):
            raise RuntimeError(
                f"Invalid checkpoint {p}: audit_snapshot must be null or an object"
            )
        run_id = data.get("run_id")
        if run_id is not None and (
            not isinstance(run_id, str)
            or re.fullmatch(
                r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
                r"[89ab][0-9a-f]{3}-[0-9a-f]{12}",
                run_id,
            ) is None
        ):
            raise RuntimeError(
                f"Invalid checkpoint {p}: run_id must be a canonical UUIDv4"
            )
        raw_phase_commits = data.get("phase_commits", {})
        if not isinstance(raw_phase_commits, dict):
            raise RuntimeError(
                f"Invalid checkpoint {p}: phase_commits must be an object"
            )
        phase_commits: dict[str, PhaseCommit] = {}
        for key, raw_commit in raw_phase_commits.items():
            if not isinstance(key, str) or not key:
                raise RuntimeError(
                    f"Invalid checkpoint {p}: phase_commits keys must be strings"
                )
            try:
                commit = PhaseCommit.from_dict(raw_commit)
            except RuntimeError as exc:
                raise RuntimeError(
                    f"Invalid checkpoint {p}: phase_commits[{key!r}]: {exc}"
                ) from exc
            expected_key = (
                commit.phase_name if commit.work_unit_id == "phase"
                else f"{commit.phase_name}::{commit.work_unit_id}"
            )
            if expected_key != key:
                raise RuntimeError(
                    f"Invalid checkpoint {p}: phase_commits[{key!r}] has "
                    f"canonical key {expected_key!r}"
                )
            if run_id is not None and commit.run_id != run_id:
                raise RuntimeError(
                    f"Invalid checkpoint {p}: phase_commits[{key!r}] run_id "
                    "does not match checkpoint run_id"
                )
            phase_commits[key] = commit
        raw_mutation_acks = data.get("semantic_mutation_acks", {})
        if not isinstance(raw_mutation_acks, dict) or any(
            not isinstance(key, str)
            or re.fullmatch(r"SMUT-[A-F0-9]{24}", key) is None
            or not isinstance(value, str)
            or re.fullmatch(r"[0-9a-f]{64}", value) is None
            for key, value in raw_mutation_acks.items()
        ):
            raise RuntimeError(
                f"Invalid checkpoint {p}: semantic_mutation_acks must map "
                "canonical event IDs to SHA-256 digests"
            )
        raw_runtime_debts = data.get("runtime_debts", {})
        if not isinstance(raw_runtime_debts, dict) or any(
            not _valid_runtime_debt_entry(debt_id, receipt_sha256)
            for debt_id, receipt_sha256 in (
                raw_runtime_debts.items()
                if isinstance(raw_runtime_debts, dict)
                else ()
            )
        ):
            raise RuntimeError(
                f"Invalid checkpoint {p}: runtime_debts must map canonical "
                "non-empty debt IDs to lowercase SHA-256 receipt digests"
            )
        return cls(
            completed=_string_list("completed"),
            degraded=_string_list("degraded"),
            rate_limited_at=rate_limited_at,
            config=cfg,
            audit_snapshot=audit_snapshot,
            run_id=run_id,
            phase_commits=phase_commits,
            semantic_mutation_acks=dict(sorted(raw_mutation_acks.items())),
            runtime_debts=dict(sorted(raw_runtime_debts.items())),
        )

    def validate_phase_names(self, phase_names: set[str]) -> list[str]:
        """Return checkpoint entries that do not belong to the active graph."""
        unknown: list[str] = []
        for key, values in (("completed", self.completed), ("degraded", self.degraded)):
            for name in values:
                if name not in phase_names:
                    unknown.append(f"{key}:{name}")
        if self.rate_limited_at and self.rate_limited_at not in phase_names:
            unknown.append(f"rate_limited_at:{self.rate_limited_at}")
        debt_by_phase = {
            commit.phase_name: any(
                sibling.phase_name == commit.phase_name
                and sibling.state != "CLEAN"
                for sibling in self.phase_commits.values()
            )
            for commit in self.phase_commits.values()
        }
        for commit_key, commit in self.phase_commits.items():
            name = commit.phase_name
            if name not in phase_names:
                unknown.append(f"phase_commits:{commit_key}")
            if commit.work_unit_id == "phase":
                is_incomplete = commit.state == "INCOMPLETE_WITH_DEBT"
                if is_incomplete and name in self.completed:
                    unknown.append(
                        f"phase_commits_incomplete_but_completed:{commit_key}"
                    )
                if not is_incomplete and name not in self.completed:
                    unknown.append(f"phase_commits_not_completed:{commit_key}")
            # Degraded is a phase projection, whereas typed commits may be
            # per-child.  A clean sibling cannot contradict another child's
            # debt, and cannot demand that the shared phase marker be cleared.
            should_be_degraded = debt_by_phase.get(name, False)
            if should_be_degraded and name not in self.degraded:
                unknown.append(f"phase_commits_debt_not_degraded:{commit_key}")
            if not should_be_degraded and name in self.degraded:
                unknown.append(f"phase_commits_clean_but_degraded:{commit_key}")
        return unknown

    def save(self, scratchpad: Path):
        # v2.3.6 F1: atomic write via temp + rename. Pre-v2.3.6 a SIGKILL /
        # OOM-kill / power loss between `open()` and `close()` could leave
        # the JSON file truncated. `Checkpoint.load()` then catches the
        # parse error and returns a fresh empty checkpoint → resume re-runs
        # every prior phase from scratch. `os.replace()` is atomic on POSIX
        # and same-volume on Windows since Python 3.3.
        p = scratchpad / "_v2_checkpoint.json"
        tmp = p.with_suffix(".json.tmp")
        data: dict = {
            "completed": self.completed,
            "degraded": self.degraded,
            "rate_limited_at": self.rate_limited_at,
        }
        if self.config is not None:
            data["config"] = self.config
        if self.audit_snapshot is not None:
            if not isinstance(self.audit_snapshot, dict):
                raise RuntimeError("audit_snapshot must be an object before checkpoint save")
            data["audit_snapshot"] = self.audit_snapshot
        if self.run_id is not None:
            if re.fullmatch(
                r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
                r"[89ab][0-9a-f]{3}-[0-9a-f]{12}",
                self.run_id,
            ) is None:
                raise RuntimeError("run_id must be a canonical UUIDv4 before save")
            data["run_id"] = self.run_id
        if self.phase_commits:
            if self.run_id is None:
                raise RuntimeError(
                    "phase_commits cannot be saved without a checkpoint run_id"
                )
            serialized_commits: dict[str, dict] = {}
            for key, commit in self.phase_commits.items():
                if not isinstance(key, str) or not key:
                    raise RuntimeError("phase_commits keys must be non-empty strings")
                if not isinstance(commit, PhaseCommit):
                    raise RuntimeError("phase_commits values must be PhaseCommit records")
                expected_key = (
                    commit.phase_name if commit.work_unit_id == "phase"
                    else f"{commit.phase_name}::{commit.work_unit_id}"
                )
                if expected_key != key:
                    raise RuntimeError(
                        f"phase_commits key {key!r} disagrees with canonical "
                        f"key {expected_key!r}"
                    )
                if commit.run_id != self.run_id:
                    raise RuntimeError(
                        f"phase_commits[{key!r}] run_id does not match checkpoint"
                    )
                serialized_commits[key] = commit.to_dict()
            data["phase_commits"] = serialized_commits
        if self.semantic_mutation_acks:
            if any(
                re.fullmatch(r"SMUT-[A-F0-9]{24}", str(key)) is None
                or re.fullmatch(r"[0-9a-f]{64}", str(value)) is None
                for key, value in self.semantic_mutation_acks.items()
            ):
                raise RuntimeError(
                    "semantic_mutation_acks contains a malformed identity/digest"
                )
            data["semantic_mutation_acks"] = dict(
                sorted(self.semantic_mutation_acks.items())
            )
        if not isinstance(self.runtime_debts, dict) or any(
            not _valid_runtime_debt_entry(debt_id, receipt_sha256)
            for debt_id, receipt_sha256 in (
                self.runtime_debts.items()
                if isinstance(self.runtime_debts, dict)
                else ()
            )
        ):
            raise RuntimeError(
                "runtime_debts must map canonical non-empty debt IDs to "
                "lowercase SHA-256 receipt digests before checkpoint save"
            )
        if self.runtime_debts:
            data["runtime_debts"] = dict(sorted(self.runtime_debts.items()))
        payload = json.dumps(data, indent=2)
        try:
            tmp.write_text(payload, encoding="utf-8")
            tmp.replace(p)
        except Exception:
            try:
                tmp.unlink(missing_ok=True)
            except Exception:
                pass
            raise

    def record_runtime_debt(
        self,
        debt_id: str,
        receipt_sha256: str,
    ) -> None:
        """Bind one process-level debt to its exact evidence receipt.

        Re-recording the same binding is idempotent.  Re-recording an existing
        identity with a newer receipt replaces only that identity; unrelated
        debts remain intact.
        """
        _validate_runtime_debt_identity(debt_id, receipt_sha256)
        if not isinstance(self.runtime_debts, dict):
            raise ValueError("runtime_debts must be a mapping")
        self.runtime_debts[debt_id] = receipt_sha256
        self.runtime_debts = dict(sorted(self.runtime_debts.items()))

    def clear_runtime_debt(
        self,
        debt_id: str,
        receipt_sha256: str,
    ) -> bool:
        """Compare-and-clear one exact debt binding.

        A stale repair receipt cannot clear a newer debt recorded under the
        same identity.  Missing or changed bindings are a harmless no-op.
        """
        _validate_runtime_debt_identity(debt_id, receipt_sha256)
        if not isinstance(self.runtime_debts, dict):
            raise ValueError("runtime_debts must be a mapping")
        if self.runtime_debts.get(debt_id) != receipt_sha256:
            return False
        del self.runtime_debts[debt_id]
        self.runtime_debts = dict(sorted(self.runtime_debts.items()))
        return True

    def mark_completed(self, phase_name: str):
        """Record a successful phase commit. Clears any stale `degraded`
        entry for the same phase so resume-after-degrade runs don't leave
        false-positive markers in the final checkpoint."""
        typed_commit = self.phase_commits.get(phase_name)
        if (
            typed_commit is not None
            and typed_commit.state == "INCOMPLETE_WITH_DEBT"
        ):
            # A failed attempt is durable evidence, not a completion token.
            # Legacy callers cannot make resume skip the phase merely by
            # projecting ``mark_completed`` after typed authority rejected it.
            self.completed = [
                name for name in self.completed if name != phase_name
            ]
            if phase_name not in self.degraded:
                self.degraded.append(phase_name)
            return
        if phase_name not in self.completed:
            self.completed.append(phase_name)
        if typed_commit is not None and typed_commit.state != "CLEAN":
            # Legacy completion is only a projection once typed authority
            # exists. It cannot erase unresolved debt recorded by the commit.
            if phase_name not in self.degraded:
                self.degraded.append(phase_name)
            return
        if phase_name in self.degraded:
            self.degraded = [d for d in self.degraded if d != phase_name]
        if self.rate_limited_at == phase_name:
            self.rate_limited_at = None

    def clear_degraded_sentinel(self, scratchpad: Path, phase_name: str):
        """Delete stale on-disk degrade markers after a successful retry.

        Shutdown reconciles `*.degraded` sentinels back into the checkpoint.
        Without deleting phase sentinels on success, a run can complete
        cleanly and still exit degraded because an old marker is re-synced.

        v2.5.5: also removes compound sentinels (e.g. `.body_writer.degraded`)
        that would otherwise be re-synced at shutdown.
        """
        for suffix in (f"{phase_name}.degraded", f"{phase_name}.body_writer.degraded"):
            try:
                (scratchpad / suffix).unlink(missing_ok=True)
            except Exception:
                pass


# --- Phase graph validator ---


_VALID_PIPELINES = {"sc", "l1"}
_VALID_MODES = {"light", "core", "thorough"}
_PHASE_NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")


def validate_phase_graph(phases: list, mode: str, pipeline: str) -> list[str]:
    """Static validation of a (phases, mode, pipeline) triple.

    Closes the architectural defect where a mode/language combination could
    ship a broken phase list and the bug only manifests mid-audit. Catches:
      - duplicate phase names
      - phase names with bad characters
      - phase whose `modes` set excludes the active mode (handled by caller
        skip, but warned if set is empty entirely)
      - phase with no expected_artifacts AND no any_of (silent-pass risk)
      - phase with negative or absurd timeouts
      - pipeline name not in the canonical set
      - mode not in the canonical set
      - empty phase list

    Verify-shard phases (`verify_crithigh`, `verify_high_*`, `verify_medium_*`,
    `verify_low_*`) are exempt from the empty-artifacts check because their
    contract is manifest-driven: artifacts are declared in the per-shard
    `verify_*_manifest.md` files written by `ensure_verify_shard_manifests`,
    not statically in the Phase dataclass. Their downstream gate is the
    `_collect_verify_promotion_receipts` + `_validate_verification_queue_inventory_parity`
    pair which enforces the actual contract.

    Returns a list of issue strings. Empty list = graph is valid.
    """
    # Verify shards are manifest-driven (empty expected_artifacts by design).
    # Exempt them via BOTH (a) the explicit manifest sets and (b) a convention
    # regex. The set keeps the exemption exact as the SC/L1 slot pools grow
    # (verify-shard sizing root fix); the regex is the robust fallback that also
    # covers L1-style names (verify_high_a, no sc_ prefix) and any convention-
    # named shard not yet listed — the prior set-only check regressed by missing
    # those. Ranges widened to [a-j] to cover the expanded medium/low slot pools.
    _verify_shard_names = set(SC_VERIFY_SHARD_MANIFESTS) | set(L1_VERIFY_SHARD_MANIFESTS)
    _verify_shard_re = re.compile(
        r"^(?:sc_)?verify_(crithigh|high_[a-j]|medium_[a-j]|low_[a-j])$"
    )
    issues: list[str] = []
    if pipeline not in _VALID_PIPELINES:
        issues.append(f"pipeline={pipeline!r} not in {_VALID_PIPELINES}")
    if mode not in _VALID_MODES:
        issues.append(f"mode={mode!r} not in {_VALID_MODES}")
    if not phases:
        issues.append("phase list is empty")
        return issues

    seen_names: dict[str, int] = {}
    any_phase_in_mode = False
    for idx, phase in enumerate(phases):
        name = getattr(phase, "name", None)
        if not name or not isinstance(name, str):
            issues.append(f"phase[{idx}] has invalid name: {name!r}")
            continue
        if not _PHASE_NAME_RE.match(name):
            issues.append(f"phase[{idx}] name {name!r} not [a-z][a-z0-9_]*")
        if name in seen_names:
            issues.append(
                f"duplicate phase name {name!r} at indices "
                f"{seen_names[name]} and {idx}"
            )
        seen_names[name] = idx

        modes_set = getattr(phase, "modes", None)
        if not modes_set:
            issues.append(f"phase {name!r} has empty modes set")
        elif mode in modes_set:
            any_phase_in_mode = True

        timeout = getattr(phase, "base_timeout_s", None)
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            issues.append(f"phase {name!r} has invalid timeout: {timeout!r}")
        elif timeout > 14400:  # 4 hours upper bound for any single phase
            issues.append(
                f"phase {name!r} timeout {timeout}s exceeds 4-hour ceiling"
            )

        expected = getattr(phase, "expected_artifacts", []) or []
        any_of = getattr(phase, "any_of", []) or []
        if (not expected and not any_of
                and name not in _verify_shard_names
                and not _verify_shard_re.match(name)):
            issues.append(
                f"phase {name!r} declares no expected_artifacts AND no any_of"
                " (silent-pass risk)"
            )

        # Each expected_artifacts entry should be a non-empty string with no
        # unsanitized whitespace.
        for art in expected:
            if not isinstance(art, str) or not art.strip():
                issues.append(
                    f"phase {name!r} expected_artifact {art!r} is invalid"
                )
                break

        # any_of must be a list of lists/tuples of strings (OR-groups).
        for grp_idx, grp in enumerate(any_of):
            if not isinstance(grp, (list, tuple)) or not grp:
                issues.append(
                    f"phase {name!r} any_of[{grp_idx}] is not a non-empty list"
                )
                continue
            for art in grp:
                if not isinstance(art, str) or not art.strip():
                    issues.append(
                        f"phase {name!r} any_of[{grp_idx}] has invalid entry {art!r}"
                    )
                    break

        sec_markers = getattr(phase, "section_markers", []) or []
        if not sec_markers:
            issues.append(
                f"phase {name!r} has no section_markers (LLM cannot locate phase)"
            )

    if not any_phase_in_mode:
        issues.append(
            f"no phase in {pipeline!r} pipeline runs in mode {mode!r}"
        )

    return issues


_EXPANDABLE_TIERS = ("critical_high", "medium", "low_info")


def _valid_report_shard_suffix(suffix: str) -> bool:
    """True for generated body-writer shard suffixes only.

    Body manifest discovery is a phase graph contract, not a free-form glob.
    Accept only the shard names emitted by the report index splitter (`a`,
    `b`, ...). Files such as `report_medium_assignments.json` are support
    artifacts and must never expand into runnable phases.
    """
    return bool(re.fullmatch(r"[a-z]", suffix or ""))


def expand_shard_phases(phases: list, scratchpad: Path) -> list:
    """Replace sentinel tier phases with per-shard phases based on actual manifests.

    Called by the driver after report_index completes (which creates
    body_manifests/). For each expandable tier (critical_high, medium,
    low_info), scans body_manifests/ for report_{tier}_*.json files and
    generates one body-writer + one confirmation phase per shard.  The
    merge sentinel is kept as-is (driver handles merge at runtime).

    Tiers whose manifest is unsuffixed (finding count within cap) are
    left as-is.
    """
    manifest_dir = scratchpad / "body_manifests"
    tier_suffixes: dict[str, list[str]] = {}
    for tier in _EXPANDABLE_TIERS:
        suffixes: list[str] = []
        if manifest_dir.is_dir():
            prefix = f"report_{tier}_"
            for f in sorted(manifest_dir.glob(f"report_{tier}_*.json")):
                suffix = f.stem[len(prefix):]
                if _valid_report_shard_suffix(suffix):
                    suffixes.append(suffix)
        if not suffixes and (manifest_dir / f"report_{tier}.json").exists():
            continue
        if suffixes:
            tier_suffixes[tier] = suffixes

    if not tier_suffixes:
        return phases

    bw_sentinels = {f"report_body_writer_{t}" for t in tier_suffixes}
    confirm_sentinels = {f"report_{t}" for t in tier_suffixes}

    result: list = []
    for phase in phases:
        matched_tier = None
        for t in tier_suffixes:
            if phase.name == f"report_body_writer_{t}":
                matched_tier = t
                for s in tier_suffixes[t]:
                    result.append(Phase(
                        f"report_body_writer_{t}_{s}",
                        list(phase.section_markers),
                        [f"report_{t}_{s}.md"],
                        base_timeout_s=phase.base_timeout_s,
                        model=phase.model or "sonnet",
                        critical=True,
                    ))
                break
            elif phase.name == f"report_{t}" and phase.name not in (
                f"report_{t}_merge" for _ in [0]
            ):
                is_confirm = any(
                    "6b.1" in m or "6b" in m
                    for m in phase.section_markers
                )
                if is_confirm:
                    matched_tier = t
                    for s in tier_suffixes[t]:
                        result.append(Phase(
                            f"report_{t}_{s}",
                            list(phase.section_markers),
                            [f"report_{t}_{s}.md"],
                            base_timeout_s=phase.base_timeout_s,
                            model=phase.model or "haiku",
                            critical=True,
                        ))
                    break
        if matched_tier is None:
            result.append(phase)

    expanded = ", ".join(
        f"{t}={len(ss)}" for t, ss in tier_suffixes.items()
    )
    log.info(f"[expand_shard_phases] expanded tiers: {expanded}")
    return result


# --- Phase lists ---

SC_PHASES = [
    # SC uses `## Phase N` for pipeline phases, `## Step N` for wizard/setup.
    # Recon groups Step 1 (language detect) + Step 1.5 (scratchpad) + Phase 1 (recon).
    Phase("recon", ["Step 1: Language Detection", "Step 1.5: Scratchpad",
                    "Phase 1: Reconnaissance"],
          ["recon_summary.md", "design_context.md", "attack_surface.md",
           "state_variables.md", "function_list.md", "contract_inventory.md",
           "template_recommendations.md", "detected_patterns.md",
           "setter_list.md", "emit_list.md", "build_status.md"],
          base_timeout_s=3000, critical=True),
    Phase("instantiate", ["Phase 2: Orchestrator Instantiation"],
          ["spawn_manifest.md"],
          base_timeout_s=600, min_artifact_bytes=50, model="sonnet", critical=True),
    Phase("breadth", ["Phase 3: Parallel Analysis"],
          ["analysis_*.md"],
          base_timeout_s=10800, model="sonnet", critical=True,
          min_artifacts_count=3),
    # Cheap mechanical planning step (mirrors inventory_prepare): the driver
    # writes rescan_manifest.md before any rescan worker spawns, so the rescan
    # phase below stays a pure bounded worker-pool executor and never has to
    # plan-and-execute in one overloaded coordinator on large codebases.
    Phase("rescan_prepare", ["Phase 3b: Breadth Re-Scan (+ Phase 3c per-contract sub-step)"],
          ["rescan_manifest.md"],
          base_timeout_s=60, modes={"thorough"}, critical=True, model="haiku"),
    # Per-contract/scope-review output is part of the rescan phase contract
    # in Thorough mode; inventory consumes both families in one build.
    Phase("rescan", ["Phase 3b: Breadth Re-Scan (+ Phase 3c per-contract sub-step)"],
          ["analysis_rescan_*.md", "analysis_percontract_*.md"],
          base_timeout_s=4800, modes={"thorough"}, critical=True),
    Phase("inventory_prepare", ["Phase 4: Synthesis, Adaptive Depth, Chain Analysis"],
          ["inventory_shard_plan.md"],
          base_timeout_s=60, critical=True, model="haiku"),
    Phase("inventory_chunk_a", ["Phase 4: Synthesis, Adaptive Depth, Chain Analysis"],
          ["findings_inventory_chunk_a.md"],
          base_timeout_s=4800, critical=True, model="sonnet"),
    Phase("inventory_chunk_b", ["Phase 4: Synthesis, Adaptive Depth, Chain Analysis"],
          ["findings_inventory_chunk_b.md"],
          base_timeout_s=4800, critical=True, model="sonnet"),
    Phase("inventory_chunk_c", ["Phase 4: Synthesis, Adaptive Depth, Chain Analysis"],
          ["findings_inventory_chunk_c.md"],
          base_timeout_s=4800, critical=True, model="sonnet"),
    Phase("inventory", ["Phase 4: Synthesis, Adaptive Depth, Chain Analysis"],
          ["findings_inventory.md"],
          base_timeout_s=4800, critical=True),
    Phase("invariants", ["Phase 4a.5: Semantic Invariant"],
          ["semantic_invariants.md"],
          base_timeout_s=4800, modes={"core", "thorough"}, critical=False),
    # v2.8.8: Pass 2 recursive gap trace. Thorough only. Reads Pass 1's
    # semantic_invariants.md and appends a `## Pass 2:` section with
    # CONFIRMED_GAP / GUARDED_GAP / BRANCH_ASYMMETRY classifications.
    # Soft phase (critical=False) — Pass 2 enriches depth-agent priming;
    # if it times out, depth still runs against Pass 1 data only.
    # Mode-gated to Thorough because the recursive trace adds ~$2-4 of
    # sonnet time and the bug class it catches (branch asymmetries,
    # cross-field gaps) is most valuable on full-depth audits.
    Phase("invariants_p2", ["Phase 4a.5 Pass 2: Recursive Semantic Gap Trace"],
          ["semantic_invariants.md"],
          base_timeout_s=2400, modes={"thorough"}, critical=False,
          model="sonnet", appends_existing_artifact=True),
    Phase("depth", ["Phase 4b: Adaptive Depth Loop"],
          ["depth_*_findings.md"],
          base_timeout_s=7200, model="opus", critical=True,
          min_artifacts_count=4,
          example_tokens=[
              "token_flow", "state_trace", "edge_case", "external",
          ]),
    Phase("attention_repair", ["Phase 4b.4: Attention Repair"],
          ["attention_repair_summary.md"],
          base_timeout_s=3000, model="sonnet", critical=True,
          modes={"thorough"}),
    # Phase 4b.6: Independent exploration-completeness verifier. Thorough
    # only. Recall-positive / ADDITIVE — may add, upgrade, or re-open
    # findings; may never drop, merge, or downgrade. Runs AFTER the depth
    # loop and its post-depth sub-phases (attention_repair, rag_sweep) and
    # BEFORE dedup/chain, so any added/upgraded/re-opened finding propagates
    # through dedup -> chain -> verify -> report. Soft phase (critical=False):
    # a timeout/degrade continues, never halts — identical Thorough-only-soft
    # mechanism as `skeptic`. Stays sonnet (not in the Thorough opus-promotion
    # set, which only covers breadth/sc_verify shards/skeptic).
    Phase("exploration_skeptic", ["Phase 4b.6: Exploration Completeness"],
          ["exploration_skeptic_findings.md"],
          base_timeout_s=3600, modes={"thorough"}, critical=False,
          model="sonnet"),
    # Phase 4b.7: Enumeration-Obligation Exploration. The post-depth enumeration
    # gate flags mechanical OBLIGATIONS (shared-symbol co-refs, asset-mover,
    # array-uniqueness, unbounded-input). Previously those went STRAIGHT TO
    # VERIFY as raw low-confidence candidates and were dismissed wholesale —
    # verify refutes a stated claim, it does not investigate a hint. This phase
    # routes each obligation to a depth EXPLORATION agent that TRACES it
    # (boundary/variation/trace) and writes a real finding OR a reasoned clear;
    # the driver then promotes those findings into the inventory so they flow
    # through dedup -> chain -> verify normally. Soft (critical=False) + skipped
    # when there are no obligations, so it always degrades to the prior
    # candidate->verify fallback — never halts, never loses an obligation.
    # Placed AFTER the depth post-hook (where the gate fires) and BEFORE
    # sc_semantic_dedup so its findings are deduped + chained + verified.
    Phase("enumgap_exploration", ["Phase 4b.7: Enumeration-Obligation Exploration"],
          ["enumgap_exploration_findings.md"],
          base_timeout_s=3600, modes={"core", "thorough"}, critical=False,
          model="sonnet"),
    # Phase 4b.8: Multi-Axis Coverage Meta-Pass (M2). Thorough only. The
    # driver owns the exact function x axis worklist; the model must publish
    # both candidate prose and a strict AXW disposition ledger. Placed before
    # application_skeptic so axis negatives enter the independent challenge
    # denominator, and before semantic dedup so promoted findings follow the
    # normal chain -> verify -> report lifecycle. Soft/degrade-and-continue.
    Phase("axis_coverage", ["Phase 4b.8: Multi-Axis Coverage Meta-Pass"],
          ["axis_coverage_findings.md",
           "axis_coverage_dispositions.json"],
          base_timeout_s=3600, modes={"thorough"}, critical=False,
          model="sonnet"),
    # Independent discriminator for producer-authored methodology-step
    # NEGATIVE/NOT_APPLICABLE outcomes.  Driver-planned and sharded from the
    # exact breadth/rescan/depth original+repair typed queues; disagreement is
    # additive and enters the registered candidate lifecycle before dedup.
    Phase("application_skeptic", ["Phase 4b.7.5: Application Skeptic"],
          ["application_skeptic_work_plan.json",
           "application_skeptic_receipt.json",
           "application_skeptic_proposals.md",
           "candidate_negative_skeptic_work_plan.json",
           "candidate_negative_skeptic_receipt.json",
           "candidate_negative_skeptic_proposals.md",
           "candidate_negative_denominator.json"],
          base_timeout_s=2400, modes={"core", "thorough"}, critical=False,
          model="sonnet"),
    Phase("sc_semantic_dedup", ["Phase 4e: Semantic Dedup"],
          ["dedup_decisions.md", "findings_inventory_deduped.md"],
          base_timeout_s=1200, model="sonnet", critical=True),
    # External precedent is reconciled only after every additive discovery
    # phase and the canonical inventory dedup commit. Its typed denominator is
    # therefore the final candidate freeze consumed by chain/report. This
    # phase is context-only and cannot change confidence, verdict, severity,
    # proof, or remaining depth.
    Phase("rag_sweep", ["Phase 4b.5: Post-Freeze Precedent Context"],
          ["rag_validation.md"],
          base_timeout_s=2400, needs_mcp=True, model="sonnet",
          modes={"core", "thorough"}, critical=True),
    Phase("chain", ["Phase 4: Synthesis, Adaptive Depth, Chain Analysis"],
          ["hypotheses.md", "finding_mapping.md", "enabler_results.md"],
          base_timeout_s=3000, critical=True),
    Phase("chain_agent2", ["Phase 4: Synthesis, Adaptive Depth, Chain Analysis"],
          ["chain_hypotheses.md", "composition_coverage.md", "synthesis_full.md"],
          base_timeout_s=3600, critical=True),
    # v2.8.8: Iteration 2 chain composition. Thorough only. Skipped via
    # driver pre-check when composition_coverage.md has zero unexplored
    # cross-class Medium+ pairs. Soft phase — failure → log, proceed.
    # The model writes only chain_iteration2.md.  A deterministic, digest-bound
    # driver merge owns the recall-monotonic append into chain_hypotheses.md and
    # composition_coverage.md after the delta passes its semantic gates.
    Phase("chain_iter2", ["Phase 4c Iteration 2: Chain Composition Re-evaluation"],
          ["chain_iteration2.md"],
          base_timeout_s=1800, modes={"thorough"}, critical=False,
          model="sonnet"),
    # v2.4.1: SC verify sharded like L1. Monolithic verify phase hit 2700s
    # ceiling on 81 hypotheses (3 .sol files, Thorough mode), verifying only
    # ~32/81 before timeout -> parity check failure -> pipeline halt. Sharding
    # gives each severity tier its own subprocess + timeout budget.
    Phase("sc_verify_queue", ["Phase 5: Verification"],
          ["verification_queue.md"],
          base_timeout_s=600, critical=True, model="haiku"),
    Phase("sc_verify_crithigh", ["Phase 5: Verification"],
          [],
          base_timeout_s=4200, critical=True, model="sonnet"),
    Phase("sc_verify_high_b", ["Phase 5: Verification"],
          [],
          base_timeout_s=4200, critical=True, model="sonnet"),
    Phase("sc_verify_high_c", ["Phase 5: Verification"],
          [],
          base_timeout_s=4200, critical=True, model="sonnet"),
    Phase("sc_verify_high_d", ["Phase 5: Verification"],
          [],
          base_timeout_s=4200, critical=True, model="sonnet"),
    Phase("sc_verify_high_e", ["Phase 5: Verification"],
          [],
          base_timeout_s=4200, critical=True, model="sonnet"),
    Phase("sc_verify_high_f", ["Phase 5: Verification"],
          [],
          base_timeout_s=4200, critical=True, model="sonnet"),
    Phase("sc_verify_high_g", ["Phase 5: Verification"],
          [],
          base_timeout_s=4200, critical=True, model="sonnet"),
    Phase("sc_verify_high_h", ["Phase 5: Verification"],
          [],
          base_timeout_s=4200, critical=True, model="sonnet"),
    Phase("sc_verify_high_i", ["Phase 5: Verification"],
          [],
          base_timeout_s=4200, critical=True, model="sonnet"),
    Phase("sc_verify_high_j", ["Phase 5: Verification"],
          [],
          base_timeout_s=4200, critical=True, model="sonnet"),
    Phase("sc_verify_medium_a", ["Phase 5: Verification"],
          [],
          base_timeout_s=4800, critical=True, model="sonnet"),
    Phase("sc_verify_medium_b", ["Phase 5: Verification"],
          [],
          base_timeout_s=4800, critical=True, model="sonnet"),
    Phase("sc_verify_medium_c", ["Phase 5: Verification"],
          [],
          base_timeout_s=4800, critical=True, model="sonnet"),
    Phase("sc_verify_medium_d", ["Phase 5: Verification"],
          [],
          base_timeout_s=4800, critical=True, model="sonnet"),
    Phase("sc_verify_medium_e", ["Phase 5: Verification"],
          [],
          base_timeout_s=4800, critical=True, model="sonnet"),
    Phase("sc_verify_medium_f", ["Phase 5: Verification"],
          [],
          base_timeout_s=4800, critical=True, model="sonnet"),
    Phase("sc_verify_medium_g", ["Phase 5: Verification"],
          [],
          base_timeout_s=4800, critical=True, model="sonnet"),
    Phase("sc_verify_medium_h", ["Phase 5: Verification"],
          [],
          base_timeout_s=4800, critical=True, model="sonnet"),
    Phase("sc_verify_medium_i", ["Phase 5: Verification"],
          [],
          base_timeout_s=4800, critical=True, model="sonnet"),
    Phase("sc_verify_medium_j", ["Phase 5: Verification"],
          [],
          base_timeout_s=4800, critical=True, model="sonnet"),
    Phase("sc_verify_low_a", ["Phase 5: Verification"],
          [],
          base_timeout_s=3600, critical=True, modes={"thorough"}, model="sonnet"),
    Phase("sc_verify_low_b", ["Phase 5: Verification"],
          [],
          base_timeout_s=3600, critical=True, modes={"thorough"}, model="sonnet"),
    Phase("sc_verify_low_c", ["Phase 5: Verification"],
          [],
          base_timeout_s=3600, critical=True, modes={"thorough"}, model="sonnet"),
    Phase("sc_verify_low_d", ["Phase 5: Verification"],
          [],
          base_timeout_s=3600, critical=True, modes={"thorough"}, model="sonnet"),
    Phase("sc_verify_low_e", ["Phase 5: Verification"],
          [],
          base_timeout_s=3600, critical=True, modes={"thorough"}, model="sonnet"),
    Phase("sc_verify_low_f", ["Phase 5: Verification"],
          [],
          base_timeout_s=3600, critical=True, modes={"thorough"}, model="sonnet"),
    Phase("sc_verify_low_g", ["Phase 5: Verification"],
          [],
          base_timeout_s=3600, critical=True, modes={"thorough"}, model="sonnet"),
    Phase("sc_verify_low_h", ["Phase 5: Verification"],
          [],
          base_timeout_s=3600, critical=True, modes={"thorough"}, model="sonnet"),
    Phase("sc_verify_low_i", ["Phase 5: Verification"],
          [],
          base_timeout_s=3600, critical=True, modes={"thorough"}, model="sonnet"),
    Phase("sc_verify_low_j", ["Phase 5: Verification"],
          [],
          base_timeout_s=3600, critical=True, modes={"thorough"}, model="sonnet"),
    Phase("sc_verify_aggregate", ["Phase 5: Verification"],
          ["verify_core.md"],
          base_timeout_s=900, critical=True, model="haiku"),
    # Phase 5b: Mechanical PoC verification (Python-native, ON by default).
    # Runs the LLM-written PoC tests via forge/cargo/aptos/sui/go and stamps
    # mechanical evidence tags into verify_*.md BEFORE skeptic/crossbatch read.
    # No LLM cost — pure subprocess invocation. Opt-out via
    # MECHANICAL_VERIFY=false env or config["mechanical_verify"]=False.
    # Failure mode: DEGRADED (warning), never HALT — LLM tags are preserved
    # when the toolchain is unavailable.
    Phase("sc_mechanical_verify", ["Phase 5b: Mechanical PoC Verification"],
          ["mechanical_verify_manifest.md"],
          base_timeout_s=2400, critical=False, model="sonnet",
          min_artifacts_count=1),
    # v2.8.8: Phase 5.5 post-verification finding extraction. Thorough
    # only. Soft phase — scans verify_*.md for [VER-NEW-*] observations
    # and dedupes vs existing inventory/hypotheses. New observations
    # promoted to hypotheses.md (Verdict: NEW_FROM_VERIFY). NOT re-queued
    # for verification — original verifier's evidence stands. If no
    # [VER-NEW-*] observations exist, the agent returns DONE: 0 quickly.
    # Runs BEFORE skeptic so promoted findings can be skeptic-reviewed.
    Phase("post_verify_extract", ["Phase 5.5: Post-Verification Finding Extraction"],
          ["post_verify_extract.md"],
          base_timeout_s=1200, modes={"thorough"}, critical=False,
          model="sonnet"),
    # LIFECYCLE-1: skeptic and crossbatch are severity-calibration / consistency
    # ENRICHMENT on top of an already-complete verify_core.md; report_index/tier
    # writers consume their output conditionally. Per the Phase.critical contract
    # (critical = a hard prerequisite without which downstream cannot run), they
    # are NOT critical -- a timeout must degrade-and-continue on the verifier's
    # own severities, not halt the whole audit. (No recall risk: they adjust
    # severity/consistency, they do not discover or drop findings.)
    Phase("skeptic", ["Phase 5.1: Skeptic-Judge"],
          ["skeptic_findings.md", "skeptic_judge_decisions.md"],
          base_timeout_s=3600, modes={"thorough"},
          critical=False,
          example_tokens=["H-01", "C-01", "CH-01"]),
    Phase("crossbatch", ["Phase 5.2: Cross-Batch Consistency"],
          ["cross_batch_consistency.md"],
          # v2.3.14: upgraded from haiku to sonnet. Haiku fails to
          # enumerate all verify IDs on large audits (7/124 on a large L1 run).
          base_timeout_s=900, model="sonnet",
          modes={"core", "thorough"},
          critical=False),
    Phase(
        "severity_adjudication_shadow",
        ["Phase 5.3: Independent Severity Adjudication"],
        [
            "severity_adjudication_work_manifest.json",
            "severity_adjudication_work_plan.json",
            "severity_adjudication_work_reconciliation.json",
            "trust_evidence_authority.json",
            "trust_evidence_provider_receipt.json",
        ],
        base_timeout_s=3600,
        model="opus",
        critical=False,
    ),
    Phase("report_index", ["Step 6a: Index Agent", "Step 6a.1: Index Completeness"],
          ["report_index.md", "report_coverage.md"],
          base_timeout_s=3000, model="sonnet", critical=True),
    Phase("report_body_writer_critical_high", ["Step 6b: Tier Writers"],
          ["report_critical_high.md"],
          base_timeout_s=4800, model="sonnet", critical=True),
    Phase("report_body_writer_medium", ["Step 6b: Tier Writers"],
          ["report_medium.md"],
          base_timeout_s=4800, model="sonnet", critical=True),
    Phase("report_body_writer_low_info", ["Step 6b: Tier Writers"],
          ["report_low_info.md"],
          base_timeout_s=4800, model="sonnet", critical=True),
    Phase("report_critical_high", ["Step 6b: Tier Writers"],
          ["report_critical_high.md"],
          base_timeout_s=300, model="haiku", critical=True),
    Phase("report_critical_high_merge", ["Step 6b: Tier Writers"],
          ["report_critical_high.md"],
          base_timeout_s=120, model="haiku", critical=True),
    Phase("report_medium", ["Step 6b: Tier Writers"],
          ["report_medium.md"],
          base_timeout_s=300, model="haiku", critical=True),
    Phase("report_medium_merge", ["Step 6b: Tier Writers"],
          ["report_medium.md"],
          base_timeout_s=120, model="haiku", critical=True),
    Phase("report_low_info", ["Step 6b: Tier Writers"],
          ["report_low_info.md"],
          base_timeout_s=300, model="haiku", critical=True),
    Phase("report_low_info_merge", ["Step 6b: Tier Writers"],
          ["report_low_info.md"],
          base_timeout_s=120, model="haiku", critical=True),
    Phase("report_assemble", ["Step 6c: Assembler"],
          ["AUDIT_REPORT.md"],
          base_timeout_s=3600, model="sonnet", critical=True),
    # LLM consolidation PROPOSER. Reads the assembled AUDIT_REPORT.md and
    # proposes cross-tier / no-location MERGES and Quality-Observation
    # reclassifications that the mechanical signals cannot pair. Writes a
    # decisions file ONLY — it never edits the report; the Python report_dedup
    # phase below evaluates proposals through applied-alias authority and the
    # zero-data-loss gate.
    # critical=False is LOAD-BEARING: a crash/timeout/degrade here MUST NOT
    # halt the run — report_dedup then runs its mechanical-only pass exactly as
    # before this phase existed.
    Phase("report_dedup_agent", ["Step 6d: Report Dedup"],
          ["report_dedup_agent_decisions.md"],
          base_timeout_s=900, model="sonnet", critical=False),
    # Python-native cross-tier dedup. critical=False is LOAD-BEARING: a
    # crash/timeout/data-loss-veto here MUST NOT halt the run or corrupt the
    # delivered AUDIT_REPORT.md. Gate artifacts are the transaction-written
    # mapping + applied-alias receipt, never AUDIT_REPORT.md itself.
    # Consumes report_dedup_agent_decisions.md (when present) as additional
    # MERGE candidate pairs + QO reclassification IDs.
    Phase("report_dedup", ["Step 6d: Report Dedup"],
          ["report_dedup_mapping.md", "report_dedup_applied_alias_receipt.json"],
          base_timeout_s=900, model="sonnet", critical=False),
    # Phase 6e LLM material-harm disposition PROPOSER. Reads the final deduped
    # AUDIT_REPORT.md and writes disposition.md (BODY/APPENDIX per finding) using
    # the recall-safe material-harm rule. PROPOSES ONLY; the Python report_floor
    # phase below executes relocation. critical=False is LOAD-BEARING: a
    # crash/timeout/degrade MUST NOT halt the run — report_floor falls back to
    # the keyword classifier when disposition.md is absent/unusable.
    Phase("report_disposition", ["Step 6e: Material-Harm Disposition"],
          ["disposition.md"],
          base_timeout_s=900, model="sonnet", critical=False),
    # Phase 6e Python-native material-harm FLOOR. FINAL report mutation: reads
    # disposition.md (keyword fallback if missing) and relocates APPENDIX
    # findings to Appendix C + decrements the Summary table. critical=False is
    # LOAD-BEARING: never halts; degrades to current behaviour on any problem.
    Phase("report_floor", ["Step 6e: Material-Harm Floor"],
          ["material_harm_floor.md"],
          base_timeout_s=120, model="sonnet", critical=False),
]

L1_PHASES = [
    Phase("bake", ["Step 1.5: Phase 0.5 Bake"],
          ["primitive_status.md"],
          base_timeout_s=3600),
    Phase("recon", ["Step 2: L1 Recon"],
          ["recon_summary.md", "threat_model.md", "subsystem_map.md",
           "attack_surface.md", "trust_boundaries.md", "template_recommendations.md",
           "scope_leftover.md"],
          base_timeout_s=3000, model="opus", critical=True),
    Phase("breadth", ["Step 3: Breadth"],
          ["analysis_*.md"],
          base_timeout_s=10800, model="sonnet", critical=True,
          min_artifacts_count=3),
    Phase("graph_sweeps", ["Step 4a.6: Graph-Sharded Audit Sweeps"],
          ["graph_sweep_summary.md"],
          base_timeout_s=3600, model="sonnet", critical=True,
          modes={"thorough"}),
    Phase("inventory_prepare", ["Step 4a: Finding Inventory"],
          ["inventory_shard_plan.md"],
          base_timeout_s=60, critical=True, model="haiku"),
    Phase("inventory_chunk_a", ["Step 4a: Finding Inventory"],
          ["findings_inventory_chunk_a.md"],
          base_timeout_s=3600, critical=True, model="sonnet"),
    Phase("inventory_chunk_b", ["Step 4a: Finding Inventory"],
          ["findings_inventory_chunk_b.md"],
          base_timeout_s=3600, critical=True, model="sonnet"),
    Phase("inventory_chunk_c", ["Step 4a: Finding Inventory"],
          ["findings_inventory_chunk_c.md"],
          base_timeout_s=3600, critical=True, model="sonnet"),
    Phase("inventory", ["Step 4a: Finding Inventory"],
          ["findings_inventory.md"],
          # LIFECYCLE-3: the merge consumes inventory_chunk_a/b/c (3600s each)
          # and must be bounded BELOW a single chunk -- an over-large ceiling
          # turns a stuck consolidation into a tens-of-minutes silent stall. If a
          # huge audit needs more, raise inventory_max_shards (more, smaller
          # chunks), not this merge ceiling.
          base_timeout_s=3000, critical=True, model="sonnet"),
    Phase("location_recovery", ["Step 4a: Finding Inventory"],
          ["location_recovery.md"],
          base_timeout_s=900, critical=True, model="sonnet",
          modes={"thorough"}),
    Phase("invariants", ["Step 4a.5: Semantic Invariants"],
          ["semantic_invariants.md"],
          base_timeout_s=4800, critical=False, modes={"core", "thorough"}),
    # v2.8.8: Pass 2 — same rationale as SC; see SC_PHASES comment above.
    Phase("invariants_p2", ["Step 4a.5 Pass 2: Recursive Semantic Gap Trace"],
          ["semantic_invariants.md"],
          base_timeout_s=2400, modes={"thorough"}, critical=False,
          model="sonnet", appends_existing_artifact=True),
    Phase("depth", ["Step 4b: Depth Loop"],
          ["depth_*_findings.md"],
          base_timeout_s=7200, model="opus", critical=True,
          min_artifacts_count=3,
          example_tokens=[
              "consensus_invariant", "network_surface", "state_trace",
              "edge_case", "external",
          ]),
    Phase("attention_repair", ["Step 4b.5: Attention Repair"],
          ["attention_repair_summary.md"],
          base_timeout_s=3000, model="sonnet", critical=True,
          modes={"thorough"}),
    # Step 4b.7: Enumeration-Obligation Exploration (L1 parity with SC). The
    # post-depth enumeration gate fires for L1 too; this routes each flagged
    # obligation to a depth EXPLORATION agent that TRACES it before verify
    # instead of dismissing it as a raw candidate. Soft + skipped when there are
    # no obligations (degrades to the prior candidate->verify fallback). Placed
    # BEFORE semantic_dedup and verify_queue so its promoted findings enter the
    # same precision and verification boundaries. (L1 has no chain phase.)
    Phase("enumgap_exploration", ["Step 4b.7: Enumeration-Obligation Exploration"],
          ["enumgap_exploration_findings.md"],
          base_timeout_s=3600, modes={"core", "thorough"}, critical=False,
          model="sonnet"),
    Phase("application_skeptic", ["Step 4b.7.5: Application Skeptic"],
          ["application_skeptic_work_plan.json",
           "application_skeptic_receipt.json",
           "application_skeptic_proposals.md",
           "candidate_negative_skeptic_work_plan.json",
           "candidate_negative_skeptic_receipt.json",
           "candidate_negative_skeptic_proposals.md",
           "candidate_negative_denominator.json"],
          base_timeout_s=2400, modes={"core", "thorough"}, critical=False,
          model="sonnet"),
    # L1 semantic dedup is an inventory precision boundary, not a queue
    # mutator. It must run after every ordinary additive inventory producer
    # and before precedent context / the authenticated T0--T9 queue
    # transaction.
    Phase("semantic_dedup", ["Step 4e: Semantic Dedup"],
          ["dedup_decisions.md"],
          base_timeout_s=3000, model="sonnet", critical=True),
    # L1 precedent consumes the receipt-authorized post-dedup inventory and
    # completes before queue T0. It has context authority only.
    Phase("rag_sweep", ["Step 4b.6: Post-Freeze Precedent Context"],
          ["rag_validation.md"],
          base_timeout_s=2400, needs_mcp=True, model="sonnet", critical=True,
          modes={"core", "thorough"}),
    Phase("verify_queue", ["Step 4d: Verification Queue Manifest"],
          ["verification_queue.md"],
          base_timeout_s=600, critical=True, model="haiku"),
    Phase("verify_crithigh", ["Step 5: Verification"],
          [],
          base_timeout_s=4200, critical=True, model="sonnet"),
    Phase("verify_high_b", ["Step 5: Verification"],
          [],
          base_timeout_s=4200, critical=True, model="sonnet"),
    Phase("verify_high_c", ["Step 5: Verification"],
          [],
          base_timeout_s=4200, critical=True, model="sonnet"),
    Phase("verify_high_d", ["Step 5: Verification"],
          [],
          base_timeout_s=4200, critical=True, model="sonnet"),
    Phase("verify_high_e", ["Step 5: Verification"],
          [],
          base_timeout_s=4200, critical=True, model="sonnet"),
    Phase("verify_high_f", ["Step 5: Verification"],
          [],
          base_timeout_s=4200, critical=True, model="sonnet"),
    Phase("verify_high_g", ["Step 5: Verification"],
          [],
          base_timeout_s=4200, critical=True, model="sonnet"),
    Phase("verify_high_h", ["Step 5: Verification"],
          [],
          base_timeout_s=4200, critical=True, model="sonnet"),
    Phase("verify_high_i", ["Step 5: Verification"],
          [],
          base_timeout_s=4200, critical=True, model="sonnet"),
    Phase("verify_high_j", ["Step 5: Verification"],
          [],
          base_timeout_s=4200, critical=True, model="sonnet"),
    Phase("verify_medium_a", ["Step 5: Verification"],
          [],
          base_timeout_s=4200, critical=True, model="sonnet"),
    Phase("verify_medium_b", ["Step 5: Verification"],
          [],
          base_timeout_s=4200, critical=True, model="sonnet"),
    Phase("verify_medium_c", ["Step 5: Verification"],
          [],
          base_timeout_s=4200, critical=True, model="sonnet"),
    Phase("verify_medium_d", ["Step 5: Verification"],
          [],
          base_timeout_s=4200, critical=True, model="sonnet"),
    Phase("verify_medium_e", ["Step 5: Verification"],
          [],
          base_timeout_s=4200, critical=True, model="sonnet"),
    Phase("verify_medium_f", ["Step 5: Verification"],
          [],
          base_timeout_s=4200, critical=True, model="sonnet"),
    Phase("verify_low_a", ["Step 5: Verification"],
          [],
          base_timeout_s=3600, critical=True, modes={"thorough"}, model="sonnet"),
    Phase("verify_low_b", ["Step 5: Verification"],
          [],
          base_timeout_s=3600, critical=True, modes={"thorough"}, model="sonnet"),
    Phase("verify_low_c", ["Step 5: Verification"],
          [],
          base_timeout_s=3600, critical=True, modes={"thorough"}, model="sonnet"),
    Phase("verify_low_d", ["Step 5: Verification"],
          [],
          base_timeout_s=3600, critical=True, modes={"thorough"}, model="sonnet"),
    Phase("verify_aggregate", ["Step 5.6: Aggregate verify_core.md"],
          ["verify_core.md"],
          base_timeout_s=900, critical=True, model="haiku"),
    # Phase 5b: Mechanical PoC verification (Python-native, ON by default).
    # L1 mirror of sc_mechanical_verify. Routes via l1_go / l1_rust registry
    # overlay entries (added at module load by mechanical_verify._ensure_l1_*).
    # Opt-out via MECHANICAL_VERIFY=false env or
    # config["mechanical_verify"]=False.
    Phase("mechanical_verify", ["Step 5.6b: Mechanical PoC Verification"],
          ["mechanical_verify_manifest.md"],
          base_timeout_s=2400, critical=False, model="sonnet",
          min_artifacts_count=1),
    # v2.8.8: L1 mirror of post_verify_extract (same rationale as SC).
    Phase("post_verify_extract", ["Step 5.5b: Post-Verification Finding Extraction"],
          ["post_verify_extract.md"],
          base_timeout_s=1200, modes={"thorough"}, critical=False,
          model="sonnet"),
    # LIFECYCLE-1: enrichment phases, not hard prerequisites -> degrade-and-
    # continue on timeout instead of halting the audit (see SC note above).
    Phase("skeptic", ["Step 5.5: Skeptic-Judge"],
          ["skeptic_findings.md", "skeptic_judge_decisions.md"],
          base_timeout_s=3600, modes={"thorough"}, critical=False),
    Phase("crossbatch", ["Step 5.4: Cross-batch Consistency"],
          ["cross_batch_consistency.md"],
          base_timeout_s=900, model="sonnet", critical=False,
          modes={"core", "thorough"}),
    Phase(
        "severity_adjudication_shadow",
        ["Step 5.7: Independent Severity Adjudication"],
        [
            "severity_adjudication_work_manifest.json",
            "severity_adjudication_work_plan.json",
            "severity_adjudication_work_reconciliation.json",
            "trust_evidence_authority.json",
            "trust_evidence_provider_receipt.json",
        ],
        base_timeout_s=3600,
        model="opus",
        critical=False,
    ),
    Phase("report_index", ["6a. Index Agent", "6a.1: Index Completeness Gate"],
          ["report_index.md", "report_coverage.md"],
          base_timeout_s=3000, model="sonnet", critical=True),
    # Body writer + confirmation + merge sentinels for all three tiers.
    # expand_shard_phases() replaces sentinels with per-shard phases when
    # the manifest builder splits a tier beyond its _BODY_SHARD_CAPS cap.
    Phase("report_body_writer_critical_high", ["6b. Tier Writers"],
          ["report_critical_high.md"],
          base_timeout_s=4800, model="sonnet", critical=True),
    Phase("report_body_writer_medium", ["6b. Tier Writers"],
          ["report_medium.md"],
          base_timeout_s=4800, model="sonnet", critical=True),
    Phase("report_body_writer_low_info", ["6b. Tier Writers"],
          ["report_low_info.md"],
          base_timeout_s=4800, model="sonnet", critical=True),
    Phase("report_critical_high", ["6b. Tier Writers", "6b.1: Tier File Completeness Gate"],
          ["report_critical_high.md"],
          base_timeout_s=300, model="haiku", critical=True),
    Phase("report_critical_high_merge", ["6b.1: Tier File Completeness Gate"],
          ["report_critical_high.md"],
          base_timeout_s=120, model="haiku", critical=True),
    Phase("report_medium", ["6b. Tier Writers", "6b.1: Tier File Completeness Gate"],
          ["report_medium.md"],
          base_timeout_s=300, model="haiku", critical=True),
    Phase("report_medium_merge", ["6b.1: Tier File Completeness Gate"],
          ["report_medium.md"],
          base_timeout_s=120, model="haiku", critical=True),
    Phase("report_low_info", ["6b. Tier Writers", "6b.1: Tier File Completeness Gate"],
          ["report_low_info.md"],
          base_timeout_s=300, model="haiku", critical=True),
    Phase("report_low_info_merge", ["6b.1: Tier File Completeness Gate"],
          ["report_low_info.md"],
          base_timeout_s=120, model="haiku", critical=True),
    Phase("report_assemble", ["6c. Assembler",
                              "Step 6.5: Mechanical Report Gates",
                              "Step 6.6: Report Preservation"],
          ["AUDIT_REPORT.md"],
          base_timeout_s=4800, model="sonnet", critical=True),
    # Python-native cross-tier dedup (L1 parity). critical=False is
    # LOAD-BEARING: a crash/timeout/data-loss-veto MUST NOT halt the run or
    # corrupt the delivered AUDIT_REPORT.md. Gate artifacts are the mapping and
    # applied-alias receipt, never AUDIT_REPORT.md itself.
    Phase("report_dedup", ["6d. Report Dedup"],
          ["report_dedup_mapping.md", "report_dedup_applied_alias_receipt.json"],
          base_timeout_s=900, model="sonnet", critical=False),
    # Phase 6e LLM material-harm disposition PROPOSER (L1 parity). Reads the
    # final deduped AUDIT_REPORT.md and writes disposition.md (BODY/APPENDIX per
    # finding). PROPOSES ONLY. critical=False: degrade never halts; report_floor
    # falls back to the keyword classifier when disposition.md is absent.
    Phase("report_disposition", ["6e. Material-Harm Disposition"],
          ["disposition.md"],
          base_timeout_s=900, model="sonnet", critical=False),
    # Phase 6e Python-native material-harm FLOOR (L1 parity). FINAL report
    # mutation: relocates APPENDIX findings to Appendix C + decrements Summary.
    # critical=False is LOAD-BEARING: never halts.
    Phase("report_floor", ["6e. Material-Harm Floor"],
          ["material_harm_floor.md"],
          base_timeout_s=120, model="sonnet", critical=False),
]
