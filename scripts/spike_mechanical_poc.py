"""Pattern 3 spike — measure the LLM-self-tagging problem.

This spike is READ-ONLY against an existing audit scratchpad and PROJECT.
It does NOT modify any pipeline behavior. For each verify_*.md file in the
scratchpad, it:

  1. Parses the Test File field to locate the LLM-written .t.sol
  2. Runs `forge test --match-test <name> --match-path <file>` with a 120 s
     per-test timeout
  3. Records: did the file exist, did it compile, did the test pass / fail,
     what was the actual outcome
  4. Compares the mechanical execution result against the LLM's self-assigned
     Evidence Tag in the verify file
  5. Writes a comparison report and a recommended Pattern 3 ship priority
     based on the match percentage

Usage:
    python spike_mechanical_poc.py \
        --scratchpad "D:/.../contracts/.scratchpad" \
        --project "D:/.../omni-chain-contracts" \
        [--limit N]            # spike only N findings (smoke run)
        [--timeout-s 120]      # per-test forge timeout
        [--output report.md]   # output path; default = scratchpad/spike_poc_report.md

Exit codes:
    0 — spike completed (any combination of pass / fail / timeout per finding)
    1 — fatal setup error (scratchpad missing, project missing, forge missing)
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from owned_process_runner import run_owned_process


# --- Data model -------------------------------------------------------------


@dataclass
class FindingProbe:
    """One verify_*.md → forge test execution record."""
    verify_file: str
    finding_id: str
    llm_tag: str
    llm_verdict: str
    poc_class: str
    test_file_field: str  # raw value from "**Test File**" field
    test_file_resolved: Optional[str] = None  # absolute path if locatable
    test_function: Optional[str] = None  # extracted from Test File or Command
    test_command: Optional[str] = None
    # v2.8.x cargo PoC discovery: parsed HINTS from the Command field only —
    # never used to shell-exec the raw Command string. mechanical_verify uses
    # these to thread a workspace-member `-p <package>` / feature set even
    # when the captured test path alone doesn't resolve. All optional; absent
    # unless the Command field actually named them.
    package: Optional[str] = None       # -p / --package <pkg>
    test_target: Optional[str] = None   # --test <target>
    features: list[str] = field(default_factory=list)  # --features a,b,c
    # Mechanical execution
    forge_status: str = "NOT_RUN"  # NOT_RUN | NO_TEST_FILE | COMPILE_FAIL |
                                    # TIMEOUT | PASS | FAIL | NO_TEST_MATCH |
                                    # EXEC_ERROR
    forge_duration_s: float = 0.0
    forge_stdout_tail: str = ""
    # Comparison
    match: str = "UNDETERMINED"  # MATCH | MISMATCH | UNDETERMINED
    recommended_tag: str = ""    # what the mechanical result implies


# --- Verify file parser -----------------------------------------------------


_ID_HEADER_RE = re.compile(
    r"^#\s*Verification\s*:\s*([A-Z]{1,8}-\d+(?:[A-Z\d-]*)?)",
    re.MULTILINE,
)
_FINDING_ID_FIELD_RE = re.compile(
    r"^[-*]?\s*(?:\*\*)?Finding\s*ID(?:\*\*)?\s*:\s*([A-Z]{1,8}-\d+\S*)",
    re.MULTILINE,
)
_VERDICT_RE = re.compile(
    r"^[-*]?\s*(?:\*\*)?Verdict(?:\*\*)?\s*:\s*([A-Z_]+)",
    re.MULTILINE,
)
_EVIDENCE_TAG_RE = re.compile(
    r"^[-*]?\s*(?:\*\*)?(?:Evidence|Preferred)\s+Tag(?:\*\*)?\s*:\s*\**\s*(\[[A-Z\-]+\])",
    re.MULTILINE,
)
# Two layouts: bullet form or bold form
_TEST_FILE_RE = re.compile(
    r"^[-*]?\s*(?:\*\*)?Test\s*File(?:\*\*)?\s*:\s*(.+?)$",
    re.MULTILINE,
)
_COMMAND_RE = re.compile(
    r"^[-*]?\s*(?:\*\*)?Command(?:\*\*)?\s*:\s*(.+?)$",
    re.MULTILINE,
)
_POC_CLASS_RE = re.compile(
    r"^[-*]?\s*(?:\*\*)?PoC\s*Class(?:\*\*)?\s*:\s*(\w+)",
    re.MULTILINE,
)
# Inside Test File: extract path (.t.sol) and function (test_xxx())
_PATH_IN_TEST_FILE_RE = re.compile(r"(test/[A-Za-z0-9_.\-/]+\.t\.sol)")
_FUNC_IN_TEST_FILE_RE = re.compile(
    r"function\s+`?(test_?[A-Za-z0-9_]+)`?\s*\(\s*\)|"
    r"`(test_?[A-Za-z0-9_]+)\s*\(\s*\)`"
)
# Inside Command: extract --match-test and --match-path
_MATCH_TEST_RE = re.compile(
    r"--match-test\s+[\"']?([A-Za-z0-9_]+)[\"']?"
)
_MATCH_PATH_RE = re.compile(
    r"--match-path\s+[\"']?([^\"'\s]+)[\"']?"
)
# Cargo Command hints (solana/soroban/l1_rust) — parsed as HINTS only. NEVER
# used to shell-exec the raw Command string; mechanical_verify re-derives its
# own argv from the registry template and only consults these fields.
_CMD_PACKAGE_RE = re.compile(
    r"(?:^|\s)(?:-p|--package)(?:[=\s]+)([A-Za-z0-9_][A-Za-z0-9_\-]*)"
)
_CMD_TEST_TARGET_RE = re.compile(
    r"(?:^|\s)--test(?:[=\s]+)([A-Za-z0-9_][A-Za-z0-9_.\-]*)"
)
_CMD_FEATURES_RE = re.compile(
    r"--features(?:[=\s]+)([A-Za-z0-9_,]+)"
)

# v2.8.16 Phase 1 (#1d + adversarial-review must-fix #3): ecosystem-agnostic,
# test-DIR-ANCHORED path extraction. The EVM-only `.t.sol`-under-`test/` regex
# above made every non-EVM finding resolve to None → NO_TEST_FILE → it could
# never reach PASS. These patterns are anchored to test directories so a bare
# `src/lib.rs` / `build.rs` token is never mistaken for the harm test (the
# reviewer's #3). Go test files self-anchor via the `_test.go` suffix.
# v2.8.x cargo PoC discovery fix: for the three cargo ecosystems, an
# unanchored `re.search` starting the match AT the `tests?/` segment DROPS
# any workspace-member crate-directory prefix (e.g. on
# `principal-token/tests/poc_h09.rs` it captured only `tests/poc_h09.rs`),
# and the truncated path then has no crate prefix left for
# `mechanical_verify._resolve_test_path_for` to resolve against a multi-crate
# workspace -> NO_TEST_FILE before cargo ever runs. Prepend an OPTIONAL
# repeated crate-directory-segment group so the FULL crate-relative path is
# captured when present, while a bare `tests/foo.rs` (no crate prefix) still
# matches exactly as before via the zero-repetition case. EVM is unaffected
# (byte-identical) — Foundry projects are single-root, not multi-crate.
#
# The same truncation applies to Move (aptos/sui): a Move package is its own
# `Move.toml` root with a sibling `sources/`+`tests/` pair, and a repo with
# multiple packages (Sui "local dependencies" / Aptos workspace members) puts
# each package under its own directory, e.g. `packages/foo/tests/bar.move`.
# The unanchored `re.search` for `(?:sources/)?tests?/...` starts matching AT
# `tests/` and drops the `packages/foo/` package-directory prefix exactly like
# the cargo case. Mirror the same optional-repeated-segment group here; the
# `.move` extension and the `sources/` option are unchanged. Neither `sui move
# test <filter>` nor `aptos move test --filter <name>` take a cargo-style `-p`
# package flag — both run against the package rooted at the invocation cwd, so
# resolving the FULL package-relative path (for cwd selection) is sufficient;
# no package-flag threading analog is needed here (follow-up only if a
# multi-package cd-selection gap surfaces in practice).
_TEST_PATH_BY_LANG: dict[str, re.Pattern] = {
    "evm":     re.compile(r"((?:test|tests)/[\w.\-/]+\.t\.sol)"),
    "solana":  re.compile(r"((?:[\w.\-]+/)*(?:tests?/|trident-tests/)[\w.\-/]+\.rs)"),
    "soroban": re.compile(r"((?:[\w.\-]+/)*(?:src/)?tests?/[\w.\-/]+\.rs)"),
    "l1_rust": re.compile(r"((?:[\w.\-]+/)*(?:src/[\w.\-/]*?)?tests?/[\w.\-/]+\.rs)"),
    "aptos":   re.compile(r"((?:[\w.\-]+/)*(?:sources/)?tests?/[\w.\-/]+\.move)"),
    "sui":     re.compile(r"((?:[\w.\-]+/)*(?:sources/)?tests?/[\w.\-/]+\.move)"),
    "l1_go":   re.compile(r"([\w.\-/]+_test\.go)"),
}
_TEST_EXT_BY_LANG: dict[str, tuple[str, ...]] = {
    "evm": (".t.sol",), "solana": (".rs",), "soroban": (".rs",),
    "l1_rust": (".rs",), "aptos": (".move",), "sui": (".move",),
    "l1_go": ("_test.go",),
}
# Source files that end in a test extension but are never the harm test.
_NON_TEST_BASENAMES = {"lib.rs", "build.rs", "main.rs", "mod.rs"}
# Driver-dictated explicit function field (most reliable, language-agnostic).
_TEST_FUNC_FIELD_RE = re.compile(
    r"^[-*]?\s*(?:\*\*)?Test\s*Function(?:\*\*)?\s*:\s*`?([A-Za-z_][\w]*)`?",
    re.MULTILINE,
)
# Broadened decl regex: Solidity `function`, Rust `fn`, Move `fun`, Go `func`.
_FUNC_DECL_ANY_RE = re.compile(
    r"(?:function|fn|fun|func)\s+`?((?:test|Test)[\w]*)`?\s*[(<]"
)


def _normalize_lang_for_paths(language: Optional[str]) -> str:
    """Map a raw config language to a registry/path key (L1 stores raw go/rust)."""
    lang = (language or "evm").lower().strip()
    if lang == "go":
        return "l1_go"
    if lang == "rust":
        return "l1_rust"
    return lang or "evm"


def _extract_test_path(test_file_field: str, command: str,
                       language: Optional[str]) -> Optional[str]:
    """Ecosystem-keyed test-file path extraction (v2.8.16 Phase 1)."""
    lang = _normalize_lang_for_paths(language)
    rx = _TEST_PATH_BY_LANG.get(lang, _TEST_PATH_BY_LANG["evm"])
    for src in (test_file_field, command):
        if not src:
            continue
        m = rx.search(src.replace("\\", "/"))
        if m:
            return m.group(1)
    # Fallback: a bare path token ending in the language test extension,
    # excluding known non-test source files. The author/executor split has the
    # driver dictate an explicit path, which lands here even outside a test/ dir.
    exts = _TEST_EXT_BY_LANG.get(lang, (".t.sol",))
    for src in (test_file_field, command):
        if not src:
            continue
        for tok in re.split(r"[\s`'\"(),]+", src.replace("\\", "/")):
            if any(tok.endswith(e) for e in exts) and Path(tok).name not in _NON_TEST_BASENAMES:
                return tok
    return None


def parse_verify_file(verify_path: Path,
                      language: Optional[str] = None) -> FindingProbe:
    try:
        text = verify_path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        return FindingProbe(
            verify_file=verify_path.name,
            finding_id=verify_path.stem.replace("verify_", ""),
            llm_tag="",
            llm_verdict="",
            poc_class="",
            test_file_field="",
            forge_status="EXEC_ERROR",
            forge_stdout_tail=f"read error: {exc}",
        )

    # Finding ID: prefer the **Finding ID** field, fallback to filename / header
    fid_match = _FINDING_ID_FIELD_RE.search(text)
    if fid_match:
        finding_id = fid_match.group(1)
    else:
        h_match = _ID_HEADER_RE.search(text)
        finding_id = (
            h_match.group(1)
            if h_match
            else verify_path.stem.replace("verify_", "")
        )

    tag_m = _EVIDENCE_TAG_RE.search(text)
    verdict_m = _VERDICT_RE.search(text)
    poc_class_m = _POC_CLASS_RE.search(text)
    test_file_m = _TEST_FILE_RE.search(text)
    command_m = _COMMAND_RE.search(text)

    test_file_field = test_file_m.group(1).strip() if test_file_m else ""
    command = command_m.group(1).strip() if command_m else ""

    # Extract function name. Priority: driver-dictated `Test Function:` field
    # (language-agnostic, most reliable under the author/executor split) →
    # EVM `--match-test` in Command → inline decl in the Test File field.
    test_function = None
    func_field_m = _TEST_FUNC_FIELD_RE.search(text)
    if func_field_m:
        test_function = func_field_m.group(1)
    if not test_function and test_file_field:
        f_match = _FUNC_IN_TEST_FILE_RE.search(test_file_field)
        if f_match:
            test_function = f_match.group(1) or f_match.group(2)
    if not test_function and command:
        f_match = _MATCH_TEST_RE.search(command)
        if f_match:
            test_function = f_match.group(1)
    if not test_function:
        # Broadened: Rust `fn test_*` / Move `fun test_*` / Go `func Test*`.
        # Last resort — also scan the body, since for Go/Move the function name
        # frequently appears only inside the embedded test code, not a field.
        for src in (test_file_field, command, text):
            if not src:
                continue
            d_match = _FUNC_DECL_ANY_RE.search(src)
            if d_match:
                test_function = d_match.group(1)
                break

    # Extract path: prefer Command's --match-path (EVM), then the ecosystem-
    # keyed, test-dir-anchored extractor across the Test File field + Command.
    test_path = None
    if command:
        p_match = _MATCH_PATH_RE.search(command)
        if p_match:
            test_path = p_match.group(1).strip("`")
    if not test_path:
        test_path = _extract_test_path(test_file_field, command, language)

    # Cargo Command hints (HINTS only — see the regex comments above).
    pkg_m = _CMD_PACKAGE_RE.search(command) if command else None
    target_m = _CMD_TEST_TARGET_RE.search(command) if command else None
    feat_m = _CMD_FEATURES_RE.search(command) if command else None
    features = feat_m.group(1).split(",") if feat_m else []

    return FindingProbe(
        verify_file=verify_path.name,
        finding_id=finding_id,
        llm_tag=(tag_m.group(1) if tag_m else ""),
        llm_verdict=(verdict_m.group(1) if verdict_m else ""),
        poc_class=(poc_class_m.group(1) if poc_class_m else ""),
        test_file_field=test_file_field,
        test_file_resolved=test_path,
        test_function=test_function,
        test_command=command,
        package=(pkg_m.group(1) if pkg_m else None),
        test_target=(target_m.group(1) if target_m else None),
        features=features,
    )


# --- Forge invocation -------------------------------------------------------


def _forge_available() -> bool:
    return shutil.which("forge") is not None


def _resolve_test_path(probe: FindingProbe, project: Path) -> Optional[Path]:
    if not probe.test_file_resolved:
        return None
    candidate = project / probe.test_file_resolved
    if candidate.exists() and candidate.is_file():
        return candidate
    # Try without the "test/" prefix
    alt = project / Path(probe.test_file_resolved).name
    if (project / "test" / Path(probe.test_file_resolved).name).exists():
        return project / "test" / Path(probe.test_file_resolved).name
    return None


def run_forge_test(
    probe: FindingProbe, project: Path, timeout_s: int = 120
) -> FindingProbe:
    """Execute forge test against probe's test_file_resolved + test_function.

    Updates probe in-place with forge_status, forge_duration_s, forge_stdout_tail.
    Never raises; classifies all errors into forge_status.
    """
    if not probe.test_file_resolved or not probe.test_function:
        probe.forge_status = "NO_TEST_FILE" if not probe.test_file_resolved else "NO_TEST_MATCH"
        return probe
    resolved = _resolve_test_path(probe, project)
    if resolved is None:
        probe.forge_status = "NO_TEST_FILE"
        probe.forge_stdout_tail = (
            f"test file referenced ({probe.test_file_resolved}) but does not "
            f"exist under {project}"
        )
        return probe

    cmd = [
        "forge", "test",
        "--match-test", probe.test_function,
        "--match-path", str(resolved.relative_to(project)).replace("\\", "/"),
        "-vv",
    ]
    # On Windows the binary is forge.cmd; let shutil.which find it
    forge_bin = shutil.which("forge")
    if forge_bin:
        cmd[0] = forge_bin

    t0 = time.time()
    try:
        result = run_owned_process(
            cmd,
            cwd=str(project),
            encoding="utf-8",
            errors="replace",
            timeout=timeout_s,
            # This standalone spike is intentionally mutation-capable only
            # inside the audited project copy. Its result is diagnostic and
            # cannot authorize a finding.
            writable_roots=(project,),
        )
        probe.forge_duration_s = time.time() - t0
        stdout = (result.stdout or "") + "\n" + (result.stderr or "")
        # Keep only the last ~3000 chars to bound report size
        probe.forge_stdout_tail = stdout[-3000:]

        if result.returncode == 0 and "[PASS]" in stdout:
            probe.forge_status = "PASS"
        elif "[FAIL" in stdout or "FAIL." in stdout or "Encountered" in stdout:
            probe.forge_status = "FAIL"
        elif "Compiler run failed" in stdout or "Error:" in stdout and "[PASS]" not in stdout:
            probe.forge_status = "COMPILE_FAIL"
        elif "No tests match" in stdout or "No matching tests" in stdout:
            probe.forge_status = "NO_TEST_MATCH"
        elif result.returncode != 0:
            probe.forge_status = "FAIL"  # default to FAIL on nonzero rc
        else:
            probe.forge_status = "FAIL"
    except subprocess.TimeoutExpired:
        probe.forge_duration_s = float(timeout_s)
        probe.forge_status = "TIMEOUT"
        probe.forge_stdout_tail = f"forge test exceeded {timeout_s}s timeout"
    except Exception as exc:
        probe.forge_duration_s = time.time() - t0
        probe.forge_status = "EXEC_ERROR"
        probe.forge_stdout_tail = f"unexpected error: {exc}"
    return probe


# --- Comparison logic -------------------------------------------------------


def classify_match(probe: FindingProbe) -> tuple[str, str]:
    """Compare LLM tag against mechanical execution. Returns (match, recommended_tag)."""
    llm = (probe.llm_tag or "").upper()
    fstat = probe.forge_status

    if fstat == "PASS":
        recommended = "[POC-PASS]"
    elif fstat == "FAIL":
        recommended = "[POC-FAIL]"
    elif fstat in ("NO_TEST_FILE", "NO_TEST_MATCH"):
        recommended = "[CODE-TRACE]"
    elif fstat == "COMPILE_FAIL":
        recommended = "[POC-FAIL]"  # broken test code is a verifier failure
    elif fstat == "TIMEOUT":
        recommended = "[CODE-TRACE]"  # can't conclude
    elif fstat == "EXEC_ERROR":
        recommended = "[CODE-TRACE]"
    else:
        recommended = ""

    if not llm or not recommended:
        return "UNDETERMINED", recommended
    if recommended in llm:
        return "MATCH", recommended
    # Special case: LLM had POC-PASS but integrity-validator already downgraded
    # to CODE-TRACE. If mechanical confirms PASS, that's still useful info.
    if "POC-PASS" in llm and recommended == "[POC-PASS]":
        return "MATCH", recommended
    return "MISMATCH", recommended


# --- Report writer ----------------------------------------------------------


def write_report(
    probes: list[FindingProbe],
    output_path: Path,
    scratchpad: Path,
    project: Path,
    timeout_s: int,
) -> None:
    total = len(probes)
    by_status: dict[str, int] = {}
    by_match: dict[str, int] = {}
    for p in probes:
        by_status[p.forge_status] = by_status.get(p.forge_status, 0) + 1
        by_match[p.match] = by_match.get(p.match, 0) + 1

    findings_with_test = sum(1 for p in probes if p.test_file_resolved)
    actually_ran = sum(
        1 for p in probes
        if p.forge_status in ("PASS", "FAIL", "COMPILE_FAIL", "TIMEOUT")
    )
    real_pass = by_status.get("PASS", 0)
    real_fail = by_status.get("FAIL", 0)

    # Decision criteria based on the spike plan
    # "match rate" = of findings where forge actually ran AND LLM tag was non-empty,
    # how many matched
    determined = sum(
        1 for p in probes if p.match in ("MATCH", "MISMATCH")
    )
    match_count = by_match.get("MATCH", 0)
    match_pct = (match_count / determined * 100.0) if determined > 0 else 0.0

    if match_pct >= 70:
        decision = "A: LLM is mostly honest. Ship Pattern 3 deferred; ship Pattern 2 alone."
    elif match_pct >= 30:
        decision = "B: Pattern 3 is highest-leverage next ship. Re-run audit AFTER Pattern 3 lands."
    else:
        decision = "C: Pattern 3 is URGENT. Block audit re-run until Pattern 3 ships."

    lines: list[str] = [
        "# Pattern 3 Spike — Mechanical PoC Execution Report",
        "",
        f"**Generated**: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"**Scratchpad**: `{scratchpad}`",
        f"**Project**: `{project}`",
        f"**Per-test timeout**: {timeout_s}s",
        "",
        "## Decision",
        "",
        f"**Match rate (of forge-executed findings with LLM tag)**: {match_pct:.1f}% "
        f"({match_count} / {determined})",
        "",
        f"**Recommendation**: {decision}",
        "",
        "## Summary statistics",
        "",
        f"- Total verify_*.md files: {total}",
        f"- Findings with a resolvable Test File: {findings_with_test}",
        f"- Findings where forge actually ran a test: {actually_ran}",
        f"- Mechanical PASS: {real_pass}",
        f"- Mechanical FAIL: {real_fail}",
        f"- Mechanical TIMEOUT: {by_status.get('TIMEOUT', 0)}",
        f"- Mechanical COMPILE_FAIL: {by_status.get('COMPILE_FAIL', 0)}",
        f"- No test file referenced or located: "
        f"{by_status.get('NO_TEST_FILE', 0) + by_status.get('NO_TEST_MATCH', 0)}",
        f"- EXEC_ERROR: {by_status.get('EXEC_ERROR', 0)}",
        "",
        "## Per-finding results",
        "",
        "| Finding | LLM Tag | LLM Verdict | PoC Class | Test File | Forge | Match | Recommended |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for p in sorted(probes, key=lambda x: x.finding_id):
        path_short = (
            (p.test_file_resolved or "—")
            if len(p.test_file_resolved or "") < 40
            else "…" + (p.test_file_resolved or "")[-37:]
        )
        lines.append(
            f"| {p.finding_id} | {p.llm_tag or '—'} | {p.llm_verdict or '—'} "
            f"| {p.poc_class or '—'} | {path_short} | {p.forge_status} "
            f"| {p.match} | {p.recommended_tag or '—'} |"
        )

    # Most interesting cases first (mismatches)
    mismatches = [p for p in probes if p.match == "MISMATCH"]
    if mismatches:
        lines.extend(["", "## Mismatches (LLM tag vs mechanical execution)", ""])
        for p in mismatches[:20]:
            lines.append(
                f"### {p.finding_id} — LLM said {p.llm_tag}, mechanical says {p.recommended_tag}"
            )
            lines.append(f"- Test file: `{p.test_file_resolved}`")
            lines.append(f"- Test function: `{p.test_function}`")
            lines.append(f"- Forge status: `{p.forge_status}` (after {p.forge_duration_s:.1f}s)")
            lines.append(f"- Stdout tail:")
            lines.append("```")
            lines.append((p.forge_stdout_tail or "")[-1500:])
            lines.append("```")
            lines.append("")

    output_path.write_text("\n".join(lines), encoding="utf-8")

    # Also drop a JSON sidecar for programmatic consumption
    json_path = output_path.with_suffix(".json")
    json_path.write_text(
        json.dumps(
            {
                "summary": {
                    "total": total,
                    "with_test_file": findings_with_test,
                    "actually_ran": actually_ran,
                    "match_pct": match_pct,
                    "decision_path": decision,
                    "by_status": by_status,
                    "by_match": by_match,
                },
                "probes": [asdict(p) for p in probes],
            },
            indent=2,
        ),
        encoding="utf-8",
    )


# --- Main -------------------------------------------------------------------


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--scratchpad", required=True, type=Path,
                        help="Path to the audit scratchpad")
    parser.add_argument("--project", required=True, type=Path,
                        help="Path to the project root (contains foundry.toml)")
    parser.add_argument("--limit", type=int, default=None,
                        help="Spike only N findings (for smoke runs)")
    parser.add_argument("--timeout-s", type=int, default=120,
                        help="Per-test forge timeout (default 120s)")
    parser.add_argument("--output", type=Path, default=None,
                        help="Output report path (default: <scratchpad>/spike_poc_report.md)")
    args = parser.parse_args(argv)

    if not args.scratchpad.is_dir():
        print(f"FATAL: scratchpad not found: {args.scratchpad}", file=sys.stderr)
        return 1
    if not args.project.is_dir():
        print(f"FATAL: project not found: {args.project}", file=sys.stderr)
        return 1
    if not (args.project / "foundry.toml").exists():
        print(f"WARNING: no foundry.toml at {args.project} — forge may not work",
              file=sys.stderr)
    if not _forge_available():
        print("FATAL: forge binary not on PATH", file=sys.stderr)
        return 1

    output = args.output or (args.scratchpad / "spike_poc_report.md")

    verify_files = sorted(args.scratchpad.glob("verify_*.md"))
    # Skip mechanical aggregate files — they're not per-finding verifier output
    skip_names = {"verify_core.md", "verify_core_full.md", "verify_aggregate.md"}
    verify_files = [f for f in verify_files if f.name not in skip_names]
    if args.limit:
        verify_files = verify_files[: args.limit]

    print(f"[spike] {len(verify_files)} verify file(s) to probe", file=sys.stderr)

    probes: list[FindingProbe] = []
    for i, vf in enumerate(verify_files, 1):
        probe = parse_verify_file(vf)
        if probe.test_file_resolved and probe.test_function:
            print(f"[spike] {i}/{len(verify_files)} {probe.finding_id} "
                  f"→ forge test {probe.test_function}", file=sys.stderr)
            run_forge_test(probe, args.project, timeout_s=args.timeout_s)
        else:
            probe.forge_status = "NO_TEST_FILE" if not probe.test_file_resolved else "NO_TEST_MATCH"
        probe.match, probe.recommended_tag = classify_match(probe)
        probes.append(probe)

    write_report(probes, output, args.scratchpad, args.project, args.timeout_s)
    print(f"[spike] report written: {output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
