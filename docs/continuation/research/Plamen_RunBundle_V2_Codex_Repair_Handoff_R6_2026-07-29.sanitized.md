# RunBundle V2 independent-authority repair handoff R6

Date: 2026-07-29  
Author role: repair implementer; **not** acceptance authority  
Disposition: **IMPLEMENTATION COMPLETE — FRESH INDEPENDENT BLOCKING REVIEW REQUIRED**  
Claim scope: local implementation, deterministic replay, packaging, and fixture validation only  
B1 effectiveness claim: **NONE**

## 0. Incoming blocked boundary

This implementation responds to:

`<LOCAL_USER_ROOT>\plamen-codex-implementation\review_fixtures\runbundle_v2_independent_review_r5.md`

SHA-256:

`ee2076e8c8583bc4cd7f77553bc92b10514be2f34b97e65a5a9caae39a5a37fe`

The independent R5 disposition was `BLOCK` for three exact failures:

1. the Pashov retained lock, pin, inventory, bytes, and every unkeyed digest
   could be replaced together because validation had no trust root outside the
   submitted receipt;
2. bidi override/embedding controls could render a reversed confidential ID in
   its forward visual order while the privacy fold scanned only the reversed
   logical order; and
3. the private token roster could be pruned, re-digested, and paired with
   re-frozen votes because unblinding did not rederive roster completeness from
   pre-render authorities or authenticate the private map.

The repair author does not clear these blockers. This handoff submits an exact
new boundary for an independent adversarial verdict.

Repository HEADs remain context only because both worktrees are shared and
dirty:

| Repository | HEAD |
|---|---|
| production | `67a0f85adc7a8169d79a286908b00bef7adb764a` |
| evaluator | `345d016d0c86b6201e90cec908c37c6a66f739c3` |

No commit, push, merge, provider launch, benchmark campaign, or live audit was
performed.

## 1. Fixture-first evidence

Before implementation changes, the new exact fixture set produced:

- one accepted Pashov receipt with no external authority;
- a `TypeError` because `validate_document()` had no trusted authority input
  for the joint pin/lock/source-relabel forgery;
- a `TypeError` for the retained-lock `case_id` replacement authority;
- nine `TypeError` failures for LRE/RLE/PDF/LRO/RLO/LRI/RLI/FSI/PDI controls;
- one `TypeError` for the RLO-plus-reversed-ID visual leak; and
- one `TypeError` because render/unblind had no external case authority or
  pre-render candidate authority.

The red checkpoint was therefore **14 failed**. The failures were implementation
absences, not tests accidentally passing through stale-digest checks.

The final focused R6 authority/privacy/CLI suite is:

`69 passed`

## 2. B04 closure design — Pashov external validation authority

### 2.1 New fail-closed API boundary

For a `plamen.pashov-v3-parse-receipt.v1` document,
`validate_document()` now requires both keyword-only authorities:

```python
trusted_pashov_public_case_lock_raw: bytes
trusted_pashov_inventory_roster_sha256: str
```

Validation fails closed if either is absent, malformed, or supplied for a
different document kind.

The first input is the exact canonical public case-lock file bytes from a
trusted location outside the submitted parse receipt. The validator:

1. strictly parses and schema-validates those external bytes;
2. requires canonical JSON plus exactly one LF;
3. decodes the retained lock from the receipt;
4. requires byte-for-byte equality with the trusted external lock;
5. separately requires exact parsed-value equality;
6. recomputes raw-file and canonical-value hashes; and
7. reconstructs the adapter pin and checks it against the externally anchored
   lock's allowed-document roster.

The second input is the expected roster digest from an independently trusted
capture/source authority. The validator reconstructs the retained inventory
from exact base64 bytes and paths, recomputes its roster, and requires equality
with that external digest before parser replay.

The existing pure `replay_pashov_v3()` remains the one derivation for
candidates, occurrences, alias edges, debts, events, and final-report
projection. All six families must exactly equal replay from the externally
anchored retained inventory.

### 2.2 CLI and harness migration

Generic parse-receipt validation now requires:

```text
plamen-eval validate pashov_v3_parse_receipt_v1 RECEIPT \
  --pashov-public-case-lock-authority TRUSTED_PUBLIC_LOCK \
  --pashov-inventory-roster-authority TRUSTED_CAPTURE_ROSTER_SHA256
```

`harvest-external pashov-v3` already has both authorities at capture time. Its
self-check passes the exact case-lock file bytes and the immutable captured
inventory roster into the validator.

Deriving either “trusted” argument from the submitted parse receipt would
collapse the trust boundary and is explicitly forbidden. The evaluator cannot
prove that caller governance is honest; it only makes the required authority
separation explicit and mechanically fail-closed.

### 2.3 Exact adversarial fixtures

The new fixtures:

- require failure when external authority is omitted;
- mutate adapter release;
- reconstruct the changed adapter pin;
- replace the retained lock's allowed-document digest;
- relabel the retained source path;
- rederive all six projection families from the relabelled inventory;
- update diagnostics, inventory roster, adapter payload, adapter receipt, and
  outer receipt digests; and
- validate the forged receipt against the original out-of-band lock bytes and
  capture roster.

That joint forgery now rejects on the external authority boundary.

A separate fixture changes only the retained lock `case_id`, recomputes every
unkeyed binding, and validates against the original external lock. It also
rejects.

## 3. B05 closure design — display safety and authenticated identity authority

### 3.1 Explicit bidi rejection

Every visible string leaf in the closed blind projection is inspected before
render. The following Unicode bidi classes are rejected rather than normalized
away:

- `LRE`, `RLE`
- `LRO`, `RLO`
- `PDF`
- `LRI`, `RLI`, `FSI`
- `PDI`

The same check runs again over the final packet during unblinding.

Fixtures cover all nine controls individually and the exact RLO + reversed
confidential-ID visual counterexample.

### 3.2 External case authority

Blind render and unblind now require the same evaluator-held
`case_authority_key` of at least 32 bytes. CLI callers select it from a
file-backed key registry:

```text
--case-authority-key-registry PATH
--case-authority-key-id KEY_ID
```

The secret key is never stored in the packet or private map.

A fresh 256-bit nonce prevents deterministic case-commitment linkability. The
nonce is retained only in the authenticated private map. The packet's case
commitment is:

```text
HMAC-SHA256(
  case_authority_key,
  "plamen.blind-case-commitment.v1\0" || nonce || case_id
)
```

### 3.3 Complete pre-render authority commitments

One shared derivation is used at render and unblind. It validates the complete
`plamen.real-audit-candidate-set.v2` and rederives:

- the versioned 12-path canonical candidate identity universe;
- defense-in-depth nested private candidate values;
- `case_id`;
- explicit confidential identities;
- every private-context string; and
- every external identity-context string.

The private map records exact canonical commitments to:

- the complete candidate-set document;
- the private context, or explicit `null`;
- the ordered external identity-context roster; and
- the ordered explicit confidential-identity roster.

It also records the exact sorted private-token set and policy bindings.

### 3.4 Authenticated private map and packet

The complete closed private-map payload is MAC-bound:

```text
HMAC-SHA256(
  case_authority_key,
  "plamen.blind-private-map.v1\0" || canonical_private_map_payload
)
```

The authenticated payload includes:

- exact packet SHA-256;
- permutation and private candidate mapping;
- case ID, case commitment algorithm, and nonce;
- identity-policy version and digest;
- all pre-render authority commitments;
- the sorted private-token roster and its digest; and
- the private-map authentication algorithm.

Unblinding:

1. requires the exact closed field roster;
2. verifies the private-map MAC under the external case key;
3. requires the authenticated packet hash;
4. verifies the case commitment;
5. rederives all tokens and context commitments from externally supplied
   pre-render authorities;
6. requires exact equality with the authenticated roster; and
7. rescans the packet for every rederived private token and bidi control.

The R5 prune attack fixture removes `run-secret`, recomputes the adjacent token
digest, injects `Visible run-secret`, re-freezes votes, updates the packet hash,
and even recomputes a valid private-map MAC with the test authority key. It
still rejects because the original candidate-set authority rederives
`run-secret`.

A separate fixture renders with private, external, and explicit confidential
contexts. Omission of those authorities at unblind rejects; supplying the
exact original contexts succeeds.

### 3.5 CLI migration

`render-blind-review` newly requires the case-authority key registry and key ID.
It supports repeatable `--confidential-identity`.

`adjudicate-v2` newly requires:

```text
--candidate-set-authority PATH
--case-id-authority CASE_ID
--case-authority-key-registry PATH
--case-authority-key-id KEY_ID
```

If render used them, adjudication must also receive the exact:

```text
--private-case-lock PATH
--identity-context PATH        # repeatable
--confidential-identity VALUE  # repeatable
```

There is no permissive legacy fallback.

## 4. Exact R6 freeze authority

Manifest:

`<LOCAL_USER_ROOT>\Downloads\Plamen_RunBundle_V2_Local_Freeze_R6_2026-07-29.json`

| Binding | Value |
|---|---|
| Raw manifest SHA-256 | `b7f97a8b2e47e442681bf2fec5d53a2b01c36ea8d7f386a8153b285438534b50` |
| Embedded canonical self-digest | `003821e0b8bdea645b98558b6b4d25eb54e5f6f5bff4b43a1bb131e1839a26cd` |
| Schema | `plamen.runbundle-v2-local-freeze.v2` |
| Claim scope | `LOCAL_IMPLEMENTATION_AND_FIXTURE_VALIDATION_ONLY` |
| `not_B1_effectiveness_evidence` | `true` |

Final replay:

```json
{"freeze_manifest_sha256":"003821e0b8bdea645b98558b6b4d25eb54e5f6f5bff4b43a1bb131e1839a26cd","status":"REPLAYED"}
```

### Source/API/protocol hashes

| Source set | Files | Tree SHA-256 |
|---|---:|---|
| production runtime | 7 | `89f8b180f421c5079bb35b5fe21227778a8a9a57c4d4cd80da5697f0a93c53e2` |
| production tests | 6 | `31be45ad9521c54feefb80ff2da289be0d1453780450867fd4c75069f7266e67` |
| evaluator source | 28 | `705cc95c0f11fb9bcb2cb4f33a099312a46c9a714a413b1599ad89656499ea8a` |
| evaluator schemas | 47 | `2423f116380205e01c6d7114112c2b95d24081a0fb7f09aa8a113ccc6484cad8` |
| evaluator tests | 29 | `ac513c2dafd31f5d77ef8d8753889a525a935c0276b9558c2bc503a00e3989e4` |
| evaluator packaging | 2 | `1fbf284fde3ee079b166b3d4ae69d4e8b82eaf501d822dc90b187e68861c1aca` |
| freeze tooling | 2 | `c2da52a8119de79a09458ebaa7082e642da9dc2d333e9bec5c4061cdd273d393` |

| Public API | Symbols | SHA-256 |
|---|---:|---|
| production runtime | 107 | `dd507961432faa427d6a20f917ea78dabb6aa08e42e246357fbb673a48e664a3` |
| evaluator source | 103 | `f9284041b26a4ff2108b729ba21e24ef6e03a1bd2755d3e180b744c71ab2f801` |

Protocol hashes remain:

- smart-contract: `28779f0e8bfb0358f0b496661b61918f7b837530c05ff1295f63e83d5d5ac9ae`
- L1: `1eb129d128fc47427b1de2d0502aa82f3162546246f57d6d738090d441c526a6`

## 5. Immutable wheels

### Prior R3 wheel, unchanged

`dist/frozen-v2/plamen_eval_control-0.2.0-py3-none-any.whl`

SHA-256:

`b51883f100137115523794561711132a7040526d4e27df58d9fd2460fc09fb67`

### Prior R5 wheel, unchanged

`dist/frozen-v4/plamen_eval_control-0.2.0-py3-none-any.whl`

SHA-256:

`19023fba9fbf4f786b185c50a6de495cecb976bed278e84faa0e873064d8b1fd`

### R6 source wheel

`dist/frozen-v6/plamen_eval_control-0.2.0-py3-none-any.whl`

| Binding | Value |
|---|---|
| SHA-256 | `f2f3e618ad241655b519a4f8ceb210b4c9bf01844240f1d6d27e8338fa7acedb` |
| Size | 161,608 bytes |
| Members | 80 |
| Member-roster SHA-256 | `c05d262c4dd2e27fb98fe509b110b30a81ae56c2e4f11067188c68b99a5794cf` |

The full evaluator suite invokes the clean wheel builder twice from independent
external temporary copies, requires byte equality, and requires equality with
this preserved wheel.

The exact V6 wheel was installed offline using `--no-index --no-deps` into a
fresh environment and invoked with `python -I`, empty `HOME`/`USERPROFILE`,
`PYTHONNOUSERSITE=1`, and no `PYTHONPATH`. Version `0.2.0`, blinding/contracts
modules, and all 47 installed schemas loaded. The temporary environment was
removed after verification.

## 6. R6 repair-file hashes

Paths are relative to `<LOCAL_USER_ROOT>\<PRIVATE_EVALUATOR_REPO>`.

| File | SHA-256 |
|---|---|
| `src/plamen_eval/contracts.py` | `1143c8535f474ba25b8990160c6be911a457e6bc610f1691d5734ec6eec5e679` |
| `src/plamen_eval/cli.py` | `60bf33972eb0376e0e2a2e706bb48efb539e6468042f4abc7239e55146d44daa` |
| `src/plamen_eval/blinding.py` | `4bd5d7d14017d4d1b2587ebc08a7355ad9a217687f08107debf57dc75364995b` |
| `tests/test_pashov_v3_adapter.py` | `cd3913e77b4917f25a88f9f42445c513a3f71055ed741ae03f007e0029d38994` |
| `tests/test_real_v2_blinding_comparison.py` | `dbd3231f7f7f1092cfd6c329e6b8fead2079ec10c48b469f40cf950b20b4c66c` |
| `tests/test_real_v2_cli.py` | `26cfcf5d780f4ddf7bd8e86585066e7f39ac4996e3dbb77946713272ffb2d1a1` |
| `tools/runbundle_v2_freeze.py` | `069fe9341c75c53a9d2425433d86b1b9928419fff0d90b2142e05e0b850b4fec` |
| `docs/runbundle-v2-freeze.md` | `9c4f17c2914524fb1c9b2b2544a6a0690e2aba76d5552661e40858db84fb16d8` |
| `README.md` | `cdcda406f3d77d36cbeeaf400c42e63e66fdc0f6d1724cffad607dbeecce8a7e` |

No parse-receipt or blind-packet public schema change was necessary. The new
authority inputs and private-map fields are evaluator-private API/CLI
boundaries.

## 7. Final validation denominators

| Validation | Result |
|---|---:|
| R6 Pashov/blinding/CLI focused | **69 passed** |
| Full neutral evaluator | **219 passed, 6 subtests passed** |
| Production RunBundle exact six-file suite | **509 passed** |
| Production Python + public packaging/fresh archive | **9 passed** |
| Cross-OS/toolchain pre-handoff gate | **22 passed** |
| Native Windows RunBundle ADS/ABI/junction focus | **4 passed, 120 deselected** |
| V6 double clean build and preserved equality | **PASS** |
| V6 isolated offline install/import | **PASS** |
| R6 exact freeze replay | **REPLAYED** |
| `python -m compileall -q src tests tools` | **PASS** |
| `git diff --check` | **PASS**; only pre-existing line-ending warnings |

No production RunBundle source was changed by this R5-to-R6 repair. The
previously reported fresh-archive packaging drift is no longer present in the
tested shared-tree state: the combined packaging denominator passed 9/9.

## 8. Explicit limits

This implementation establishes consistency relative to externally supplied
authorities. It does not govern those authorities:

- a caller who derives the Pashov “trusted” lock or inventory roster from the
  submitted receipt defeats the intended separation;
- a compromised case-authority key can authenticate a forged private map;
- the candidate set and contexts supplied at unblind must come from the exact
  evaluator-private pre-render authority, not from the map under review;
- HMAC proves possession of a key, not organizational independence;
- frozen review votes retain their separate reviewer/governance trust model;
- local structural tests do not establish recall, precision, audit quality, or
  external-comparator effectiveness; and
- this boundary does not authorize production cutover.

## 9. Required independent R6 review

The fresh reviewer should not use this document or this author's tests as the
oracle. At minimum:

1. verify the raw R6 handoff/freeze hashes and embedded freeze self-digest;
2. replay every source/API/protocol/key-file/toolchain/wheel preimage;
3. reproduce the R5 joint pin+lock replacement, then also mutate retained
   bytes, paths, inventory, and every derived projection while recomputing all
   public digests; validate only against the original external lock/capture
   authorities;
4. replace only retained lock `case_id`, raw/value hashes, diagnostics, adapter
   payload/receipt, and outer receipt;
5. test missing, half-supplied, malformed, wrong-kind, and receipt-derived
   external Pashov authorities;
6. independently enumerate every visible blind string and exercise
   embedding/override/isolate/pop controls, including nested location,
   precondition, quality, and severity fields;
7. prune any canonical candidate/context token, recompute its adjacent digest,
   mutate/refreeze the packet/votes, and attempt both stale-MAC and valid-MAC
   private maps;
8. omit, reorder, replace, and add private/external identity contexts at
   unblind;
9. substitute the case ID, key, nonce, packet, permutation, mapping, policy,
   authority commitments, and closed map field roster independently;
10. repeat clean double wheel builds, isolated install, full evaluator,
    production RunBundle, packaging, and cross-OS denominators; and
11. issue a new hash-stamped blocking disposition.

The repair author requests independent review and makes no acceptance claim.
