# Plamen private bug-bounty wrapper hardening handoff

Date: 2026-07-27

## Frozen artifact

- Archive: `<LOCAL_USER_ROOT>\Downloads\Plamen_BB_Wrapper_Hardened_2026-07-27.zip`
- Size: 316,696 bytes
- SHA-256: `087281F0D3E6DCD76A134D3795D23FFCA790CBBA9B5B81B6B92F2E5FDA03B649`
- Entries: 64
- Source tree: `<LOCAL_USER_ROOT>\.plamen\scripts\bounty`
- The private bounty tree is gitignored/untracked. This hash-stamped archive is the immutable handoff.

The compatibility boundary was tested against:

- Staged Plamen repository HEAD: `67a0f85adc7a8169d79a286908b00bef7adb764a`
- `scripts/plamen_driver.py` SHA-256: `6A1B430BD72FDF6CE6FCF3AC94A9EA134E92AEBDF506B8A3846D11A2CAF72FB4`

Recompute the archive hash with:

```powershell
Get-FileHash -Algorithm SHA256 -LiteralPath '<LOCAL_USER_ROOT>\Downloads\Plamen_BB_Wrapper_Hardened_2026-07-27.zip'
```

## Verification evidence

- Full private suite: **394 passed, 2 skipped** in 10.96 seconds with the pytest cache disabled.
- Independent adversarial replay of the full private suite: **394 passed, 2 skipped** in 10.38 seconds with the pytest cache disabled.
- Private-to-staged-runtime contract: **9 passed**.
- Public exact-scope-authority and typed-document suites: **53 passed**.
- Python `compileall`: passed.
- Archive name scan: zero forbidden entries.
- Credential-like archive-content scan: zero hits.
- One protocol-name hit is an intentional negative test canary in `test_formatter.py`; it verifies that protocol names do not leak into generic formatter output.

The two skipped tests are intentional live-network tests. No live Immunefi acquisition, provider call, or production audit was executed during this hardening pass.

## What was hardened

1. **Exact source authority**
   - Repository byte ledgers and projections are content-bound.
   - Exact selected paths authorize reporting; analysis-only helpers cannot.
   - Lexical path, link/reparse, traversal, Unicode, Windows portability, LFS, and submodule cases are handled explicitly.
   - Mixed selected ecosystems fail closed until a multi-lane design exists.

2. **Pipeline compatibility**
   - Typed exact-scope and typed-document inputs are carried through launch, resume, finalization, and terminal authority.
   - Required authority documents fail closed before spawning the audit.
   - The wrapper independently validates terminal exact-scope authority instead of trusting model prose or draft markdown.
   - The current staged Plamen driver contract is covered by integration fixtures.

3. **Report containment**
   - Finding locations must resolve to exact scoped files; basename fallback is forbidden.
   - Common terminal line/range forms are normalized without broadening file authority.
   - Missing, invalid, stale, or tampered exact-scope authority demotes `READY` to `REVIEW`; drafts remain visible.

4. **Coverage semantics**
   - `COMPLETE` is a run-level assertion that every exact-scope file was either cited or accounted for by the neutral coverage machinery.
   - A structurally valid `INCOMPLETE` authority does not silently discard an individually proof/source/scope/severity-authorized finding. That finding may remain claim-locally `READY`, but its packet receives a loud run-scope limitation and the exact authority hash.
   - Invalid or unverifiable authority never permits `READY`.

5. **Operational safety**
   - Full noninteractive launches default to `thorough`; dry runs remain light.
   - Resume and lease behavior is tested.
   - Provider/toolchain child environments are allowlisted.
   - Local Foundry toolchain inspection, explicit approval, and offline smoke testing bind exact executable bytes and reject path/link/mutation ambiguity.
   - Local document paths with spaces and mixed local/remote inputs are preserved. Remote documents use HTTPS, DNS/IP checks, pinned resolution, and redirect revalidation.

## Deliberate exclusions

The archive excludes:

- `.env` and `_realdata/`
- pytest and bytecode caches
- one-off protocol/run-specific helpers:
  - `_prove_fork.py`
  - `_validate_build.py`
  - `_validate_clean_rebuild.py`
  - `_validate_e2e.py`
  - `_reformat_finished_run.py`

These exclusions keep credentials, downloaded program data, generated state, user-specific paths, and protocol-specific maintenance code out of the reusable handoff.

## Residual boundaries

- This is offline-validated compatibility, not evidence from a live bounty run.
- The toolchain smoke test suppresses application-level network use but is not a kernel-enforced egress sandbox.
- Selected Git submodules or selected Git-LFS source pointers block until their exact bytes are acquired; unrelated dependency debt degrades loudly rather than authorizing findings from absent bytes.
- Mixed repository/address or mixed-ecosystem scope blocks pending explicit multi-lane orchestration.
- Codex-backed bounty postprocessors require an explicitly injected classifier/verifier. CLI operation fails closed when those components are absent.
- The staged runtime remains a moving target. If `plamen_driver.py` changes from the hash above, rerun the staged contract and public exact-scope/typed-document suites before a live audit.

## Acceptance boundary

This artifact is suitable for installation and offline reproduction after the independent snapshot review clears it. The first user acceptance should be a disposable, non-sensitive program fixture followed by a bounded live acquisition/audit under normal credential isolation. Regular-audit validation remains a separate prerequisite for accepting the new Plamen runtime itself.
