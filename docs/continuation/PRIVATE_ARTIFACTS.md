# Private artifacts during machine migration

This document is a handling policy, not an inventory. Do not add secret values,
private filesystem paths, audit contents, customer or contest names, findings,
or credential-bearing URLs to this file or any Git-tracked manifest.

The source branch and the private migration archive serve different purposes:

- the source branch must be sufficient to install and continue development;
- the private archive preserves selected non-source evidence that cannot be
  reproduced or is still needed for an active audit; and
- credentials and machine identity should normally be recreated, not copied.

## Private-state classes

| Class | Examples | Migration treatment |
| --- | --- | --- |
| Recreate | access tokens, login sessions, signing keys, browser profiles, local user configuration | Do not put in Git or the general archive. Re-authenticate and rotate or recreate on the destination. |
| Rebuild | managed runtimes, dependency caches, indexes, virtual environments, installed projections | Do not archive by default. Rebuild from the verified clone and lock files. |
| Retain privately | active audit state, irreplaceable run evidence, provenance receipts, unpublished reports | Freeze consistently, encrypt outside Git, checksum, and validate on the destination. |
| Retain temporarily | installer transactions, rollback snapshots, diagnostic logs, historical worktree copies | Keep until destination acceptance, then review for disposal using a recorded retention decision. |
| External reference | benchmark repositories, third-party research, licensed corpora | Record immutable public references where permitted; transfer privately only when access and licensing allow it. |

No class permits committing audit contents or secrets to the Plamen repository.

## Hash-only inventory

The migration inventory records identity and retention decisions without
recording file contents or private locations. Store it with the private archive,
not in Git. Use opaque artifact identifiers so a filename cannot disclose a
project, finding, account, or local directory.

One JSON Lines record per archive item is recommended:

```json
{"schema":"plamen.private-artifact.v1","artifact_id":"PA-0001","class":"retain-private","sha256":"<64-lowercase-hex-characters>","bytes":0,"archive_id":"<opaque-archive-id>","created_utc":"<RFC3339 timestamp>","retention":"until-destination-acceptance","verified_source":true,"verified_destination":false}
```

Allowed fields are:

- `artifact_id`: a migration-local opaque identifier;
- `class`: `recreate`, `rebuild`, `retain-private`, `retain-temporary`, or
  `external-reference`;
- `sha256`: the digest of the exact archived bytes;
- `bytes`: the exact byte count;
- `archive_id`: an opaque container identifier, not a path;
- `created_utc`: an RFC 3339 timestamp;
- `retention`: a policy label rather than free-form audit information; and
- `verified_source` and `verified_destination`: explicit integrity states.

Do not include absolute or relative source paths, filenames that reveal audit
scope, command lines, environment variables, usernames, machine identifiers,
remote account names, encryption keys, passwords, tokens, report excerpts, or
finding summaries. Keep any necessary identifier-to-location map outside Git
and protect it at least as strongly as the archive itself.

SHA-256 is the minimum digest. Compute it from the closed archive, copy the
archive and inventory independently where practical, and recompute the digest
on the destination. A copied checksum string without recomputing the destination
bytes is not verification.

## Safe Windows-to-macOS sequence

1. **Quiesce mutable state.** Let an active audit reach a safe terminal or
   resumable boundary. Stop writers cleanly before capturing its state. Do not
   archive files while workers are still modifying them.
2. **Freeze source in Git.** Reconcile source changes into the migration branch,
   review the diff for secrets and generated artifacts, commit, and push it.
   Record the expected commit identifier outside the working tree.
3. **Create a fresh private archive.** Include only items classified
   `retain-private` or deliberately `retain-temporary`. Exclude credentials,
   browser/session state, caches, managed runtimes, and rebuildable dependency
   trees. Use authenticated encryption and keep its recovery material separate.
4. **Create the hash-only inventory.** Hash each closed archive item, record its
   byte count and retention class, then verify the source-side archive before
   transport.
5. **Clone on macOS.** Make a fresh clone from the remote branch. Do not copy the
   Windows `.git` directory, installed tree, virtual environment, or package
   cache into the clone.
6. **Verify source identity.** Confirm the branch and expected commit, inspect
   submodule or external-artifact revisions, and ensure the clone contains no
   private inventory or audit material.
7. **Bootstrap source development.** Follow `docs/development/macos.md` from the
   fresh clone. Do not run the unsupported production installer or copy its
   Windows launchers, runtimes, skills, or agent projections.
8. **Run source acceptance checks.** Rebuild the isolated development state and
   run the documented source-validation suite. Native macOS install/E2E remains
   an explicit continuation-goal gate and must not be simulated with copied
   Windows runtime state.
9. **Verify private retention.** Transfer the encrypted archive separately,
   recompute every digest on macOS, mark `verified_destination` only after an
   exact match, and confirm that required retained material can be opened.
10. **Resume deliberately.** Restore only the minimum non-secret state needed
    for unfinished work. Re-authenticate through supported tools and create new
    machine-local keys. Never restore a private archive into the Git checkout.
11. **Observe a retention window.** Keep the old machine and source archives
    unchanged until the destination installation and continuation workflow have
    remained usable for the agreed period.
12. **Approve cleanup separately.** Produce a final keep/archive/dispose list
    and obtain explicit operator approval before changing the old machine.

## No deletion before a verified clone

No cleanup operation is authorized merely because the branch was created or
pushed. The minimum deletion gate is all-green:

- remote branch visible;
- fresh macOS clone at the expected commit;
- source integrity checked;
- native installation successful;
- required tests and backend smoke checks successful;
- private archive digests recomputed and matched;
- retained items confirmed readable; and
- explicit cleanup approval recorded.

If any item is unknown, failed, or not yet run, the gate is closed.

## Cleanup order after acceptance

When the gate is open, cleanup should remain recoverable and narrowly scoped:

1. quarantine or use the operating system's recoverable trash mechanism;
2. remove reproducible caches, dependency trees, and test temporaries first;
3. remove obsolete installed runtimes and completed installer transactions only
   after confirming the supported installer works on both machines;
4. deduplicate historical source snapshots only after their unique Git and
   hash identities have been reconciled;
5. review logs and audit evidence against their retention obligations; and
6. dispose of the final old-machine recovery copy last.

Never use a broad recursive delete rooted at a home directory, drive root,
workspace root, or unresolved environment variable. Resolve and review every
target as an explicit absolute path at cleanup time, but keep those paths out of
Git and public documentation.

If deletion is interrupted or the target list changes, stop and rebuild the
inventory. Do not infer that similarly named directories have identical
contents.
