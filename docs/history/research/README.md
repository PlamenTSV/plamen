# Historical Research Archive

> **Status: NON-NORMATIVE**

This directory retains selected, sanitized research that explains how Plamen's
architecture and methodology evolved. It is an engineering history and review
aid. It is not executable methodology, an implementation backlog, a release
gate, evidence that a current requirement is complete, or an authority for
audit behavior.

## Precedence

When historical material disagrees with the current repository, the current
implementation and its governed artifacts win. Consult, in order:

1. executable code and tests;
2. machine-readable policy, schemas, registries, and dependency locks;
3. current prompts, agent definitions, rules, and command methodology;
4. current user and architecture documentation;
5. this historical archive.

An old plan, review verdict, acceptance ledger, or validation receipt does not
remain true merely because it is retained here. Revalidate any proposal against
the current branch before implementing it.

## What belongs here

Suitable material includes superseded architecture proposals, research
summaries, implementation crosswalks, independent reviews, and historical
decision records that provide durable context. Retain a document only when it
helps explain a current design or prevents a known mistake from being repeated.

Raw scratchpads, complete audit outputs, provider transcripts, runtime logs,
temporary diagnostics, caches, generated environments, binaries, and redundant
archives do not belong here. Experimental source that remains useful should be
promoted into an owned source or test directory and reviewed as code; placing it
in history must not cause the installer, driver, or test suite to execute it.

## Sanitization requirements

Every imported document must be reviewed before publication. Remove or
generalize:

- credentials, tokens, cookies, authentication state, and environment values;
- private client or contest material and non-public findings;
- usernames, absolute host paths, machine identifiers, and local process data;
- proprietary source excerpts and third-party material that cannot be
  redistributed;
- large generated payloads that can be represented by a compact explanation or
  reproducible fixture.

Use neutral placeholders such as `<source-checkout>`, `<audit-target>`, and
`<scratch-root>` where a path or identity is needed to understand the document.
Sanitization changes the bytes, so any retained checksum must identify the
sanitized artifact and must not be presented as the hash of a private original.

## Required document header

Each retained research document should begin with metadata equivalent to:

```text
Status: Historical / Non-normative
Original date: YYYY-MM-DD
Imported date: YYYY-MM-DD
Sanitization: Summary of material removed or generalized
Current references: Paths to the current code, policy, or documentation, if any
Superseded by: Current design or decision, if known
```

Dates and provenance provide context, not authority. Avoid claims such as
"complete", "accepted", or "validated" without stating the historical scope
and pointing to current reproducible evidence.

## Retention and maintenance

- Prefer one final or representative document over every intermediate draft.
- Deduplicate identical material and preserve meaningful chronology in Git.
- Keep research assets out of installer manifests and runtime lookup paths.
- Do not make production code depend on a file in this directory.
- Link forward to current documentation when a historical conclusion has been
  implemented or superseded.
- Remove a document if it cannot be published safely or no longer provides
  durable engineering value; preserve restricted evidence in an appropriate
  non-public archive instead.

The purpose of this archive is traceability without ambiguity: it preserves why
decisions were explored while leaving the current repository as the only source
of operational truth.
