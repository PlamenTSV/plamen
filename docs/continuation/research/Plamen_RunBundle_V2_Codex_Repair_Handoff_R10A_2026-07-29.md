# Plamen RunBundle V2 Codex Repair Handoff R10A

Date: 2026-07-29
Artifact type: corrective successor collateral
Author lane: Codex RunBundle R10 repair author
Review state: INDEPENDENT COLLATERAL REVIEW REQUIRED
Implementation state: unchanged from the frozen R10 boundary
Commit/push state: no commit, merge, push, provider run, benchmark, or audit performed

This ASCII-only artifact corrects three evidence statements in the immutable
R10 handoff. It does not modify or expand the implementation, assurance
model, publication ceiling, freeze, or author claims.

## 0. Bound predecessor artifacts

Original R10 handoff:

`Downloads/Plamen_RunBundle_V2_Codex_Repair_Handoff_R10_2026-07-29.md`

- bytes: `18927`
- raw SHA-256:
  `2b7ed5795e2f5c015d4e8e50a8126e2806a5bdf0c36e8703018f13e9fb99aea8`

Independent R10 review:

`plamen-codex-implementation/review_fixtures/runbundle_v2_independent_review_r10_20260729.md`

- disposition: `AMEND`
- implementation-security disposition:
  `PASS within the adjudicated local-integrity scope`
- bytes: `18635`
- raw SHA-256:
  `fb2cbe254c6b553de39134ed5d8ab80174c809f6ff3d82797cc9a80982d55b69`
- embedded zero-stamp content SHA-256:
  `11813e09b322e8ecd8822154c4d88fb296649365836b96b52c2acfce648fcd99`

Frozen implementation:

`Downloads/Plamen_RunBundle_V2_Local_Freeze_R10_2026-07-29.json`

- bytes: `70085`
- raw SHA-256:
  `689d570c0456f79c28e5c4f2aef915ff8b262a4266562a32699a58785af3a8df`
- embedded freeze-manifest SHA-256:
  `7b5e2086b63b5d342990eecdfe8a1eef3c14ad68bf21af46d404a42ec95c6f5d`
- independent final replay: `REPLAYED`

R10A and the original R10 handoff form the successor handoff set. R10A
overrides only the three statements below. Every other R10 statement and
limit remains unchanged.

## 1. Correction: R10 design embedded digest

The R10 handoff correctly recorded the design file raw SHA-256 as:

`76c87aa0b6f464714e3c95f46cca093221db86b33819cbf86a8e1a688f017771`

Its embedded payload SHA-256 was transcribed incorrectly. The exact embedded
stamp and independently recomputed payload SHA-256 are:

`f7f89382fd3f820f65faf20a335c8c316d3808867d85b556c6f9929dec15489d`

This value replaces the `f7f89382c9db...` value in R10 Section 0.

## 2. Correction: cleanup-debt schema and closed fields

The implemented schema is:

`plamen.runbundle-promotion-cleanup-debt.v1`

This replaces
`plamen.runbundle-publication-cleanup-debt.v1` in R10 Section 3.

The closed receipt field set does not contain `operation`. The semantic
discriminator fields are:

- `status=CLEANUP_DEBT`
- `debt_type=PROMOTION_JOURNAL_CLEANUP`

The receipt additionally binds the run, authorized target, bundle seal,
READY name and digest, promotion-journal name and digest, exporter code and
policy identities, one allowed bounded failure class, creation time, and its
embedded canonical digest, exactly as validated by the frozen source.

## 3. Correction: failure-class tamper claim and threat model

The R10 statement that all failure-class tamper is rejected was overbroad.

The actual local-integrity property is:

- the canonical debt receipt structurally commits to one allowed
  `failure_class` at creation;
- an invalid failure class is rejected;
- run, output, seal, READY, journal, exporter-code, and exporter-policy
  substitutions remain contextually bound and reject when they do not match
  the verified transaction; but
- a malicious writer with the same output-parent write authority can replace
  an allowed failure class with the other allowed value and recompute the
  unsigned receipt digest.

That same-writer substitution does not:

- authorize any operation beyond exact promotion-journal cleanup;
- skip source replay where recovery is required;
- satisfy `AUTHENTICATED_EXPORT_ATTESTATION`;
- raise the USER_RUN publication ceiling;
- create authenticated provenance; or
- bypass RETIRED denial.

This limitation is within the governing `UNSIGNED_LOCAL_INTEGRITY` threat
model. Authenticating failure provenance against a malicious same-OS-user
writer requires the separately deferred governed signer/verifier-owned
authority design. R10A makes no claim that unsigned READY, debt, retirement,
or sibling controls resist that writer.

## 4. Independent evidence retained

The independent review's fresh PoCs and broad results remain unchanged:

- all three R9 blocker counterexamples closed;
- assurance and state-machine PoCs passed;
- cleanup-before-unlink and cleanup-after-unlink debt recovery passed;
- debt transaction-binding and invalid-field tamper tests passed;
- partial retirement and deterministic quarantine recovery passed;
- atomic control publication attacks passed;
- production exact denominator: `567 passed`;
- evaluator full denominator: `232 passed, 6 subtests passed`;
- packaging: `9 passed`;
- current cross-OS gate: `26 passed`;
- native Windows physical focus: `4 passed`;
- native Windows no-replace and long-path focus: `2 passed`;
- frozen Python compilation: `71 files, PASS`; and
- final R10 freeze replay: `REPLAYED`.

The allowed failure-class substitution described in Section 3 is retained as
a precise local-integrity limitation, not misreported as a rejected attack.

## 5. R10A disposition

The frozen R10 implementation is unchanged. This successor artifact closes
only the three collateral inaccuracies identified by the independent review.

R10A does not authorize cutover, commit, merge, push, provider execution,
benchmark publication, recall or precision claims, or an audit. An
independent reviewer must verify this correction against the bound original
handoff, review receipt, frozen source, and freeze replay before the combined
R10 plus R10A handoff set may receive a collateral PASS.
