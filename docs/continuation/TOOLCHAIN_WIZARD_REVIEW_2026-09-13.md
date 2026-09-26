# Toolchain wizard review — 2026-09-13

## 2026-09-14 cross-OS hardening follow-up

Selectable setup recipes now validate the tool's own version field with a
tool-specific line grammar, then bind the observed executable bytes in the
existing local receipt. A dependency, compiler, advisory-database or other
secondary semver in `--version` output can no longer satisfy a pinned tool's
postcondition. Mismatch diagnostics include the expected version and a bounded
list of observed versions; unparseable output fails closed.

PATH updates preserve the declared install-destination precedence, compare
whole normalized components, remove duplicates, reject invalid separator/NUL/
newline entries, and safely quote persisted POSIX shell/fish paths. Host search
paths no longer mix Windows, Linux and macOS-only locations, and the duplicate
`cargo-fuzz` recipe shared by Soroban and L1 Rust executes only once when both
groups are selected. Claude Code and Codex remain outside the frozen setup-tool
version map and continue to use the separately governed latest-at-install/update
policy.

Focused toolchain/setup tests pass on macOS. Native CI on Windows and Linux is
still required before cross-platform release qualification; these hermetic
tests exercise all three command branches but do not substitute for clean-host
installation evidence.

## 2026-09-14 follow-up (source only)

Truthful setup outcomes, visibility and RAG result fixes passed 47 targeted
governed tests in 110.71s (run77669, 0c94ab), after closure 1ed9ae.
The earlier pre-RAG-fix run passed 43 tests; these counts overlap.
`run_setup` now aggregates selected action failures,
rejects invalid identity controls instead of treating them as empty healthy
results, and checks required dependencies again before returning success.
Skipping selection returns zero, and the interactive menu remains available
after a printed failure summary. No acquisition policy or version pin changed.

The visibility report no longer promises complete audits from PATH presence.
Foundry visibility requires forge, cast and anvil; compatibility installations
no longer recommend their disabled setup command. Full dependency display now
checks the running launcher interpreter rather than ambient Python aliases,
consistent with the existing quick check. Tests use local mocked installer
effects: no downloads, installations, provider calls or audits were performed.

An additional review found that `_build_rag_db` could return success after an
indexing step failed if other sources supplied enough entries. It now aggregates
final step outcomes and applies the already-existing minimum-entry predicate
without changing acquisition, retries or data handling. Tests cover a failed
source with a high count, a low count, complete success, and a recovered retry.

The first governed attempt ran no tests: an edited historical test was rejected
by the exact-source test manifest. That test was restored byte-for-byte to
SHA256 dd275953fc96aa2d4c92e0e4fd2eca2e3922cf88afa38fd4ff71341c176985e6.
No test governance or version controls were changed to admit the rerun.

The remaining recipe, version validation, architecture and clean-host gaps in
this review are still open. These changes are not installed in public plamen.

## Original review

This is a source-backed review, not a clean-install qualification. No tools were
downloaded or installed for the review. The requested policy is current
Claude/Codex CLI versions by default unless explicitly bound, while audit
dependencies retain reviewed safety pins. These are different policies.
The new POSIX Claude source path implements current-version observation;
legacy Windows/native release-gate migration is still pending.

## Conclusion

The wizard is not yet an operational cross-platform toolchain installer.
Windows has a reachable Setup flow. Authenticated macOS/Linux compatibility
installations deliberately hide and reject Setup. Presence-based readiness
checks and incomplete acquisition recipes must not be presented as proof that
every audit mode can run end to end.

## Highest-priority defects

1. `plamen.py::run_setup` does not aggregate selected install/probe failures
   into its return value. `main` can therefore return success after failures,
   missing prerequisites, or unsuccessful adapter/RAG setup.
2. `run_setup` catches a failed `_locked_toolchain_identity_report` and uses an
   empty result, potentially turning invalid governance into “All tools
   installed.” Unknown or invalid identity must not count as healthy.
3. `_report_toolchain_visibility` claims full audit readiness from a small
   representative binary-presence census. It does not prove versions, provider
   readiness, complete tool families, or working pipelines. Its `plamen setup`
   remediation is unreachable on installed POSIX compatibility runtimes.
4. Most recipe checks accept any executable on PATH, including an incorrect or
   broken version. `_probe_tool_runtime` checks a successful version command,
   but usually does not compare the result with the recipe's expected version.
5. The “install everything” choice includes manual-only/empty recipes. Foundry
   checks only `forge` despite describing `forge/anvil/cast`; Solana checks only
   `solana` despite describing its build tools. Partial installs can look complete.
6. CPython 3.12 is mandatory but is not acquired by the wizard. Quick checks use
   the working launcher interpreter, while full dependency display still tests
   ambient `python`/`python3`. Node/npm prerequisites are similarly inconsistent
   with the existence of managed JS assets.
7. Windows Stellar setup runs Cargo but does not declare Cargo as a prerequisite.

## Acquisition and pin coverage

- Major manual-only or absent recipes include Foundry, OpenGrep, Solana CLI,
  Anchor, Trident, Aptos, Sui, DAML and rust-analyzer. Rust, Go, OpenSSL and a C
  compiler are operator-provided prerequisites. Slither belongs to the private
  hash-locked Python runtime, not an ambient pip installation.
- Active Cargo/Go recipes specify exact releases for Medusa, Stellar, Scout,
  cargo-fuzz, ast-grep, OSV Scanner, govulncheck, cargo-audit, Fender and scip-go.
  Those command pins are not equivalent to reviewed binary/build closures.
- `verification_policy/toolchain_version_lock.v1.json` centrally covers Slither
  0.11.5, scip-go 0.2.7 and protobuf 7.35.1. It is not a universal tool census.
- The JS policy pins Node 24.20.0 for Windows/Linux/macOS x64 and arm64, plus
  Yarn 1.22.22. All seven archives are present. Production materializer wiring
  remains incomplete; dependency authority supports Yarn lockfiles, not npm or
  pnpm lockfiles. Ambient recon installation paths are not the same authority.
- Managed EVM policy has exact wheel/solc assets for macOS arm64, Linux x86_64
  and Windows amd64. macOS x64, Linux arm64 and Windows arm64 coverage is missing.
  These assets alone do not prove integration into actual setup/audit consumers.
- Foundry, project-selected solc and the OpenGrep scanner lack complete active
  reviewed cross-platform acquisition/execution authority.
- Native runtime bindings remain `CANDIDATE_BLOCKED`; successful compatibility
  execution is not native macOS/Linux qualification.

## Validation priorities

First test truthful outcomes: aggregate exit status, invalid-lock refusal,
wrong-version rejection, partial-install repair and manual/unsupported recipe
classification. Then connect existing pinned assets to production consumers,
complete missing recipes/architectures, and run actual clean-host installations
on Windows, macOS and Linux.

Relevant existing suites include `test_toolchain_acquisition_security.py`,
`test_toolchain_version_lock_p0.py`, `test_toolchain_authority_blocker_repairs.py`,
`test_managed_evm_python_toolchain.py`, the JS authority/materializer tests,
`test_posix_v2_compat_install.py`, `test_cross_os_toolchain_pre_handoff_gate.py`
and `test_toolchain_crossos_adversarial_reds.py`. They were identified, not run,
as part of this read-only toolchain review.
