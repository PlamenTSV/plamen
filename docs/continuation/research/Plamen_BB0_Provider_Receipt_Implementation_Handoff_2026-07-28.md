# Plamen BB-0 provider receipt implementation handoff

Date: 2026-07-28

Disposition: implementation candidate frozen for independent review. This
document is not an acceptance verdict and does not authorize a live audit,
provider/model execution, network access, publication, merge, push, or cutover.

## Implemented contract

- The selected public runtime must expose a closure-bound
  `scripts/bb_wrapper_provider_adapter.py` with the v2 adapter and invocation
  schemas.
- The private BB bridge imports the complete statically reachable local adapter
  closure under guarded module resolution. Ambient/preloaded conflicts fail
  closed.
- Provider request, prompt, backend, model, working directory, writable/add-dir
  roots, inherited and explicit environment values, executable, argv, attempt,
  output, WER completion, and PhaseIO incorporation are committed by immutable
  authorities.
- The bridge retains exact provider output bytes and requires adapter replay.
  VSC classification, fork verification, review projection, and publication
  carry and independently replay the invocation receipt. Drift becomes
  explicit non-submittable authority debt; it does not erase a finding.
- Credentials are materialized only after immutable-run, wrapper,
  scope/capability, and provider-adapter preflight. A gate-only resume returns
  before credentials or provider access.
- Adapter, request, prompt, closure manifest, and referenced authority reads
  reject symlink/reparse/hardlink-backed or unstable files.
- Provider identity is not inferred: VSC and fork receipts use the selected
  backend and model. The Codex default is `gpt-5.6-sol` with `xhigh`, never
  `max`.
- The accepted public adapter uses the public WER/headless execution,
  startup-permit replay, completion validation, ArtifactLedger, and PhaseIO
  APIs. It does not self-authorize a substitute provider path.
- The public adapter advertises Codex only. Claude deliberately fails
  preflight until the public runtime has an accepted unified Claude
  provider-preparation authority. This is a bounded missing capability, not a
  claim that Claude BB execution is complete.
- Native Python, Windows CMD, and POSIX `sh` entrypoints route to the same
  `python -m bounty.cli` implementation.

## Validation evidence

- Full private BB suite:
  `617 passed, 4 skipped in 139.09s`.
- Previously failing targeted replay:
  `15 passed in 14.98s`.
- Provider receipt hardening file is included in the full run and contains nine
  fixtures, including hardlink rejection.
- Public adapter actual offline WER/PhaseIO execution and replay:
  `2 passed in 1.65s`.
- Public selected-runtime closure build and binding replay succeeded at the
  observed shared-tree state:
  - runtime closure:
    `16964dc8570eeac1d9e5f79ed687876616360f5ec7243b0dd394ae2970d28615`
  - adapter:
    `ef46f6183982b7188dc05f3fdc484764e5ddfc0119129613dd495433e09dee19`
  - binding:
    `ecc8b28ef3c7b0815e134f50c3e47943ed84e40b869ae22dc805a0ec40539659`
  - advertised backend: `codex`
- Python compilation succeeded for the private bridge, VSC/fork/run/CLI
  modules and the public adapter/test.
- `plamen-bb.py --help` and `plamen-bb.cmd --help` succeeded. POSIX launcher
  behavior is fixture-covered in the private suite; this Windows host has no
  `bash`, so a native POSIX shell execution remains an independent-review/CI
  check.
- A broader public subset produced 117 passes and 17 failures. All 17 fail
  before the BB adapter in the concurrently edited Claude executable
  observation authority (`observation field denominator drifted`). This is an
  external shared-tree baseline blocker also observed by another lane; it was
  not hidden or weakened here. The BB public adapter test itself remains green.
- No live provider, model, network, repository acquisition, or audit was run.

## Frozen private file hashes

```text
f57f52e088000b4cfe0925631ab0791a29c8496ef7b9b3c3cbbfa4a952effbf1  plamen-bb
246e3ce4c2023fe762b4b964d706000d3d946456be14fc6644241cc0995c6a08  plamen-bb.cmd
92d07d90f44a937531339bca89be995b2f67cac576c143e384f654d20752f63d  plamen-bb.py
968d8b2736510bb553a23292fd7813bdfa081c7e2dc869b44c0def8f96fdf2d9  scripts/bounty/README.md
090882e1e5c4e577cb461443319fca3e1fad28a311f94edc5fce8100ca44a2a4  scripts/bounty/cli.py
dc1a6a15261577db684f352c4fa795db93837af68680cf94c152d097e7682deb  scripts/bounty/_pty_spawn.py
c53d971e966cba28149d3cf767dcc16fefcd01cc056f4a1f459983b84aac22e2  scripts/bounty/vsc_classify.py
60e8afa0ab7f253cf62123975ebb79cfc59da7e78e1c13092348bf920a8ad8c1  scripts/bounty/fork_verify.py
8bb24bc4c7e006322c27b5dccd095cf83af8cd52b201add73ca5209916582c53  scripts/bounty/run_bounty.py
63e9d1ab24757459217dae31a8e67c96e321c0c067fbc01bf39378b5b8803f18  scripts/bounty/test_bb0_provider_receipt_hardening_20260728.py
b99e71ba0f9ee1df6b37fc2669512cdabd3845b64d0808881e76bf165ba1400c  scripts/bounty/test_bb0_selected_runtime_adapter_20260728.py
ffde4b23d32c14b96ec53d495a829c6b8fb68a5aeb5d60d31edf53d4972cecf2  scripts/bounty/test_bb0_startup_semantic_20260728.py
116f0fd943ffa6ed39e6331d1355dc6c0b4192b3216d34c47885341bbc016f0a  scripts/bounty/test_bb_attestation_lifecycle_20260727.py
0e19dc82a0d447db8ec121f6d8e1158e59547118b23e7b45002e93c1bb502c1c  scripts/bounty/test_bb_cli_exit_contract_20260727.py
be99f995b4d0ef6b877cd92032396ff89dd841ccb5b711b43e962ba01746e934  scripts/bounty/test_runtime_closure_20260727.py
cbc4b2de4d62d33b0c1c0833f370e45f4391b8f6f1a680ddc3e0408fb10f78c4  scripts/bounty/test_provider_toolchain_hardening_20260727.py
fd932dce63663f0608ca25a8f329cf7e2f3eb78a88da9520571830e66b5681a8  scripts/bounty/test_bounty_resume.py
ee5039a9ca2895bd13cc1cfd5730b5290570f53722c9f5ae2f5d1658d4904349  scripts/bounty/test_bb_toolchain_trust_root_20260727.py
cda2f87b9e4215c8479db9ead7b9f46bc38db8412fbd38d48ec56288c3a8ad5b  scripts/bounty/test_evm_exact_resume_20260727.py
2f89e82967dbe0dc86befb17459bcc2207a06a2aa14a302d66c64d28fc89f6dc  scripts/bounty/test_bb_staged_runtime_contract_20260727.py
```

`test_bb_deployment_quantifier_20260727.py` was also used as an unchanged
dependent regression fixture; its observed hash is
`dc359a57bd8d49b19c482708cd6329beb593c23d08db7b693f1aa0ab42b4c4cf`.

## Frozen public BB file hashes

```text
ef46f6183982b7188dc05f3fdc484764e5ddfc0119129613dd495433e09dee19  scripts/bb_wrapper_provider_adapter.py
18dc66bfcbcb50626b54334e4fc1610245d25b072c38b0315151f5910efa4440  scripts/test_bb_wrapper_provider_adapter_20260728.py
```

The shared public `.gitignore` contains
`!scripts/bb_wrapper_provider_adapter.py`, otherwise the production adapter
would remain structurally ignored. The whole `.gitignore` is intentionally not
frozen here because it is a shared file concurrently edited by other program
lanes; the reviewer must confirm that exact allowlist row survives integration.

## Required independent review

The reviewer should:

1. verify every frozen hash before reading conclusions;
2. attack the adapter import closure, hardlink/reparse checks, request and
   environment value commitments, replay path containment, and exact-output
   binding;
3. prove VSC, fork, review projection, and final publication cannot accept a
   PASS/submittable result without a replayable provider receipt;
4. verify credentials are absent on capability/provider-preflight failure and
   gate-only resume;
5. rerun the full private suite and public adapter fixture;
6. execute the POSIX launcher on Linux/macOS or CI;
7. distinguish the external Claude authority-schema failures from BB adapter
   regressions, while keeping Claude BB execution fail-closed;
8. issue an explicit `PASS`, `PASS WITH HARDENING`, or `BLOCK` verdict. The
   implementer does not self-certify this candidate.
