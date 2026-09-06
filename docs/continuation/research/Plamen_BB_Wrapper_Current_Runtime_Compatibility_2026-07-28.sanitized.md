# Plamen BB Wrapper — Current-Runtime Compatibility Review

Date: 2026-07-28  
Review scope: `<LOCAL_USER_ROOT>\.plamen\scripts\bounty` against
`<LOCAL_USER_ROOT>\plamen-codex-implementation`  
Implementation baseline observed: branch
`codex/recall-app-benchmark-r10_1`, commit
`67a0f85adc7a8169d79a286908b00bef7adb764a` plus a large, actively changing
uncommitted program tree.

## Disposition

The private BB wrapper remains broadly compatible with Plamen's current
repository-acquisition, scope-normalization, ecosystem-selection, policy, and
terminal-state contracts. It is **not yet ready to be represented as a seamless
current-runtime integration**.

The main blocker is architectural: BB postprocessors import and execute an
ambient private copy of `scripts\pty_exec.py`, rather than a provider authority
from the selected, closure-bound Plamen runtime. This bypasses the current
startup/attempt-arm/profile-lease/worker-receipt work. A narrow private import
rewrite would conceal rather than close that boundary, so the correct cutover is
to a stable public provider API after that API is finalized.

No network acquisition, live audit, installation, commit, push, or destructive
operation was performed during this review.

## Narrow hardening implemented

Files changed:

- `<LOCAL_USER_ROOT>\.plamen\scripts\bounty\run_bounty.py`
- `<LOCAL_USER_ROOT>\.plamen\scripts\bounty\test_bb_current_runtime_terminal_contract_20260728.py`

`_terminal_driver_state` now independently fails closed when the public
checkpoint contains:

1. any phase with terminal status `degraded`;
2. a malformed `runtime_debts` authority; or
3. any unresolved runtime debt.

This prevents the BB wrapper from converting a degraded or debt-bearing public
run into a private READY/terminal-success claim even if a return-code regression
occurs upstream.

SHA-256 at review time:

| File | SHA-256 |
|---|---|
| `run_bounty.py` | `1E7AB72D724FC22EEADF2888B073E8BF959461AB9853967C122F97EFB7A2900D` |
| `test_bb_current_runtime_terminal_contract_20260728.py` | `E2571CB32C5968C39FC985A2F2DB456E03096451B55D78EE2D36AFA8BD30B7E7` |

## Test evidence

Before the narrow terminal hardening, the full private offline suite passed:

```text
561 passed, 4 skipped
```

The skips are intentional platform/live-network cases. After the change, all
directly affected contracts passed:

```text
test_bb_current_runtime_terminal_contract_20260728.py     4 passed
test_bb_staged_runtime_contract_20260727.py              10 passed
test_bounty_resume.py                                    12 passed
test_evm_exact_resume_20260727.py                         2 passed
test_path_smoke.py                                        4 passed
                                                        ----------
                                                         32 passed
```

An additional focused realistic-checkpoint pairing passed 5/5.

A post-change aggregate rerun was attempted twice while a separate full public
Plamen test run was consuming the same runtime. The aggregate commands exceeded
their 60-second and 180-second command windows without emitting a failure. The
slowest affected file was then isolated and passed 12/12 in 111 seconds; the
remaining affected files passed 20/20. Therefore this review records the
aggregate as interrupted/unstamped, not failed. A clean final aggregate should
be rerun after the actively changing core test wave quiesces.

Current public BB-named compatibility tests produced 184 passes and one expected
red during the moving core integration. The red was
`test_attention_repair_sharding_bb.py::test_real_transactional_shards...`:
current `execute_headless_worker` requires the new auxiliary-startup binding.
That is an in-progress public runtime integration contract, not a private
wrapper regression.

## Compatibility matrix

| Area | Current evidence | Disposition |
|---|---|---|
| Repository acquisition and immutable scope | Private offline suite and exact-scope fixtures green | Compatible |
| EVM repository BB flow | Exact-resume and proof-extension fixtures green | Compatible below provider boundary |
| Solana repository BB flow | Registry/scope/proof-extension fixtures green | Compatible below provider boundary |
| Soroban repository BB flow | Registry/scope/proof-extension fixtures green | Compatible below provider boundary |
| Aptos repository BB flow | Registry/scope/proof-extension fixtures green | Compatible below provider boundary |
| Sui repository BB flow | Registry/scope/proof-extension fixtures green | Compatible below provider boundary |
| DAML repository BB flow | Registry/scope/proof-extension fixtures green | Compatible below provider boundary |
| Go L1 repository BB flow | Dynamic L1 and `.go` proof scope covered | Compatible below provider boundary |
| Rust L1 repository BB flow | Dynamic L1 and `.rs` proof scope covered | Compatible below provider boundary |
| Mixed Go/Rust L1 | Fails closed; public depth binding does not currently accept `mixed` | Deliberately unsupported |
| Cross-family SC + L1 composite | Partial composition exists; wrapper does not issue READY | Deliberately incomplete |
| Claude backend | Driver and private postprocessor path exist | Not closure-bound to current provider runtime |
| Codex backend | Driver supported; classification/fork steps require injected Codex callbacks | Not CLI end-to-end |
| `claude-headless` backend alias | Present in moving core, absent from private BB CLI schema | Defer until public alias/stream cutover stabilizes |
| Windows | Executed locally | Supported by current evidence |
| Linux/macOS | Platform guards and simulated fixtures exist; no WSL or Docker available | Final native CI required |

The wrapper supports repository acquisition for the listed smart-contract
ecosystems. It does not generally implement address-only deployed-target
acquisition for Solana, Soroban, Aptos, or Sui. That limitation is acceptable
for the requested Immunefi repository-pulling/organizing use case, but must not
be described as universal deployed-target support.

## Blocking seam: ambient PTY provider

`<LOCAL_USER_ROOT>\.plamen\scripts\bounty\_pty_spawn.py` prepends its ambient
parent scripts directory and imports:

```text
<LOCAL_USER_ROOT>\.plamen\scripts\pty_exec.py
```

That file is not the selected public runtime copy:

| Runtime file | SHA-256 |
|---|---|
| Ambient private `<LOCAL_USER_ROOT>\.plamen\scripts\pty_exec.py` | `67EA692B4BD6FA3DD1962E6964E2672B7A9A3933BE13126777ED9A01E9EE37EE` |
| Selected `<LOCAL_USER_ROOT>\plamen-codex-implementation\scripts\pty_exec.py` | `156964012D2542F1EFB882A60AED4F4FE86D75AC89816F9D6905A588707440A7` |

The public runtime closure hashes the selected copy. The private wrapper closure
hashes `_pty_spawn.py`, but does not bind the ambient parent `pty_exec.py`.
Consequently the runtime whose identity is attested is not the runtime actually
used by `vsc_classify.py` and `fork_verify.py`.

Required public-core integration:

1. expose a stable provider/worker execution API that accepts the selected
   runtime authority and public startup permit;
2. bind backend profile, executable identity, attempt arm, writable-root lease,
   process ownership, stream policy, receipt schema, and terminal observation;
3. thread that authority into VSC classification and fork verification;
4. revalidate the selected runtime closure after all private postprocessing, not
   only immediately after the public driver;
5. reject READY if provider receipts or runtime closure no longer match.

This should be implemented once in public core and consumed by the BB wrapper.
Vendoring another PTY implementation into the private tree would increase drift
and weaken the closure claim.

## Additional hardening requirements

### Codex postprocessing

The BB CLI explicitly blocks Codex completion unless callers inject
Codex-bound classification and, for a full EVM flow, fork-verification
functions. This is honest fail-closed behavior, but it means “backend=codex” is
driver-only rather than a seamless end-to-end BB workflow. The future public
provider interface should supply both backends through the same typed boundary.

### Runtime drift after the driver

`_default_run_audit` recomputes the selected runtime closure after the public
driver. VSC and fork postprocessors run later. Terminal authority validates
network/toolchain authorities and the private wrapper closure, but does not
recompute the selected public runtime closure after these provider calls. The
final terminal handshake must cover the complete end-to-end execution interval.

### Toolchain identity is not vulnerability freshness

The current toolchain authority binds exact Forge/solc/forge-std bytes, versions,
trees, and a manual authority. It does not encode issuance time, review expiry,
security-advisory status, or an update policy. Exact identity is valuable, but
does not establish that a pinned tool version remains safe.

Use a separately signed/updateable compatibility and advisory manifest with:

- exact tool and dependency identities;
- supported ecosystem/OS combinations;
- review and expiry timestamps;
- known-bad and minimum-safe constraints;
- an explicit override authority and audit trail.

Keep this policy outside model prompts.

### Git acquisition provenance

The acquisition sandbox restricts protocols, hooks, environment, and output
identity, but resolves `git` from PATH without binding its executable bytes and
version. Output OID/tree hashing limits downstream ambiguity, but does not fully
bind the acquisition tool. Add the selected Git executable identity to the
source-fetch receipt.

### Native cross-OS acceptance

This host has neither WSL nor Docker, so no genuine POSIX execution was possible.
Before handoff, execute the same frozen fixture corpus on:

- current Windows;
- current Ubuntu LTS;
- macOS, including case-insensitive filesystem behavior.

Test symlink/reparse escape rejection, process-tree termination, signal handling,
atomic replacement, path length, executable discovery, permissions, locale, and
line-ending behavior. Simulated parity is not a substitute for native runs.

## Frozen artifact warning

The prior frozen artifact is no longer a complete representation of the live
private wrapper:

```text
<LOCAL_USER_ROOT>\Downloads\Plamen_BB_Wrapper_Hardened_2026-07-27.zip
SHA-256: 087281F0D3E6DCD76A134D3795D23FFCA790CBBA9B5B81B6B92F2E5FDA03B649
```

The archive contains 64 entries and omits current production modules including
`attestation_admin.py`, `bb_runtime_closure.py`,
`capability_preflight.py`, `chain_registry.py`, `composite_admin.py`,
`network_sandbox.py`, `network_sandbox_admin.py`,
`public_policy_terminal.py`, and `runtime_closure.py`, plus many tests. More
than twenty archived files have changed in the live tree.

Do not distribute or restore that ZIP as the current wrapper. Regenerate the
archive and manifest only after public provider cutover, a clean aggregate
suite, and native OS acceptance.

## Recommended cutover order

1. Stabilize the public startup/worker/provider interfaces already under active
   implementation.
2. Add the public provider boundary needed by private VSC/fork postprocessors.
3. Migrate Claude and Codex BB postprocessing to that single boundary.
4. Bind provider executable/version, process tree, attempt/lease, receipts, and
   final public closure.
5. Run the full private suite without concurrent core mutation.
6. Run public BB compatibility tests and resolve the auxiliary-startup expected
   red against the finalized API.
7. Execute native Windows/Linux/macOS fixtures.
8. Regenerate and hash the private archive/manifest.
9. Only then run user acceptance bug-bounty audits.

## Final engineering verdict

The BB wrapper does not need a second independent orchestration architecture.
Its acquisition, scope, ecosystem, resume, policy, and terminal machinery are
useful and currently well covered. It does need to stop owning an ambient,
unattested provider execution path. Reusing one finalized public execution
authority is the smallest architecture that improves robustness across regular
audits and BB runs without duplicating backend- and OS-specific logic.
