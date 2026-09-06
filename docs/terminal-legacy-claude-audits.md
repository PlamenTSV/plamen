# Terminal Claude audit preparation (contained headless only)

This is the repository-side launch contract for a fresh Claude audit when the
source checkout already contains earlier Plamen runs.  It is intentionally a
two-step boundary: the preparation utility never launches a model, and the
shared deterministic driver remains the sole owner of every audit phase.

Claude audit execution is supported here only for Smart Contract Thorough with
explicit authenticated contained headless. Other modes, L1, and platforms where
the contained-worker capability check fails must use Codex or a distinct clean
supported configuration. There is no automatic transport fallback.

Do not create an alternate scratchpad such as `.scratchpad-run-2` inside the
source checkout.  Some ecosystem walkers exclude the canonical `.scratchpad`
name exactly; a differently named live run directory can enter the audited
source universe and cause input drift.  Do not move, rename, delete, archive, or
overwrite the existing run in place.

## 1. Prepare and seal

Run from the repository being validated, using a previously nonexistent
out-of-tree workspace and external receipt paths:

```text
python scripts/terminal_audit_launch.py \
  --source-project <ORIGINAL_PROJECT> \
  --workspace-project <NEW_ISOLATED_PROJECT> \
  --prior-evidence-receipt <EXTERNAL_RECEIPT_DIR>/prior-evidence.json \
  --preparation-receipt <EXTERNAL_RECEIPT_DIR>/prepared-run.json \
  --driver <THIS_REPOSITORY>/scripts/plamen_driver.py \
  --language <ECOSYSTEM> \
  --mode thorough \
  --pipeline sc \
  --cli-backend claude-headless \
  --claude-exec-mode headless \
  --forbidden-input <EXTERNAL_GROUND_TRUTH_PATH>
```

The forbidden path is resolved as an identity only.  Its basename, bytes, and
deterministic path hash are not read, copied, placed in `config.json`, or
written to either receipt.  Any
ground truth located inside the source tree is a hard preparation error; make a
sanitized source destination rather than weakening the blind boundary.

Preparation performs these deterministic operations in order:

1. Hash-seal every conventionally named prior scratchpad, stale-snapshot tree,
   legacy sibling archive, generated audit report/RCA, and prior audit harness
   to the external evidence receipt.
2. Copy source bytes into the new destination, omitting those sealed audit
   artifacts. The original project remains read-only.
3. Create only `<NEW_ISOLATED_PROJECT>/.scratchpad/config.json` with
   `"cli_backend": "claude-headless"` and `"claude_exec_mode": "headless"`.
4. Write a hash-bound preparation receipt containing `fresh_argv` and
   `resume_argv`, while leaving `launched: false`.

Do not adapt this Claude command to L1, Light, or Core. Those combinations do
not have an authenticated contained Claude route. Select Codex through the
public wizard, or prepare a separate clean configuration supported by the
chosen backend.

This utility preserves only relative, exact-target, in-tree file symlinks. It
fails closed on absolute or escaping links, links into excluded prior evidence,
directory links, junctions/reparse points, forbidden-input aliases (including
hardlinks), and linked output parents. A failed copy is left as an explicit
partial destination; it is never silently deleted or reused. Choose another
clean destination after reviewing the error.

## 2. Launch only the shared driver

Run `verify_preparation_receipt` (or equivalently review the utility's exact
receipt verifier result) immediately before launch: it replays the prior seal,
the complete isolated source-copy manifest, config containment/schema, and the
canonical driver digest. Unexpected workspace input is a hard verification
failure.

Review both receipts, then execute the `fresh_argv` array exactly. Its semantic
form is:

```text
python <THIS_REPOSITORY>/scripts/plamen_driver.py --startup-intent START_NEW_RUN <NEW_ISOLATED_PROJECT>/.scratchpad/config.json
```

The config is backend-bound before the process starts, so all model phases take
the explicit contained-headless Claude route. No Codex skill or installed
adapter is involved in this repository-side command. The driver itself
sequences recon through report and enforces artifact gates; the launcher does
not sequence phases or agents.

On interruption, execute the receipt's `resume_argv` exactly:

```text
python <THIS_REPOSITORY>/scripts/plamen_driver.py --startup-intent RESUME_EXISTING <NEW_ISOLATED_PROJECT>/.scratchpad/config.json
```

Resume reuses the unchanged config and run identity.  It does not pass a new-run
intent and does not rewrite the existing config.  If snapshot validation finds
drift, the driver stops with a decision receipt rather than converting resume
into a fresh run.

Never rewrite or auto-migrate an existing run from an unsupported Claude route
to headless or Codex in place. Preserve the evidence and run identity, then use
the typed decision to restore the exact original state or create a distinct
clean supported configuration.

The repository's Codex adapter generator also packages both wizard resources
beside `skills/plamen/SKILL.md`.  An older installed skill may still lack those
resources until a later approved reinstall; that stale installed copy is not a
dependency of this Claude terminal path.
