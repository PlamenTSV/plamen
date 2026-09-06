"""TASK C — report_index tier-shard COMPLETION + seed-reconciliation.

LIVE FLAW (prior run): even with the bounded-ledger scope ban, report_index thrashed
~27 min because the LLM did whole-set STEP 1.5 consolidation + STEP 5/5.5
coverage over 30 hypotheses + a 121-finding mapping in ONE turn. The fix shards
the working set by report tier so no single turn holds the whole set, and wires
the driver-written coverage seed (the authoritative SUPERSET) into the
completeness gate so a sharded index can never let a finding fall between shards.

This module ships BOTH required fixtures:

  (1) FLAW-NOW-RESOLVED — the driver partitions the coverage seed into bounded
      per-tier shards whose UNION equals the full seed (zero drops, zero
      overlap), and a correctly-sharded index that disposes every seed ID PASSES
      the seed-reconciliation completeness gate.

  (2) NEGATIVE CONTROL — an index where a finding falls BETWEEN shards (a real
      seed ID left with no disposition) is STILL CAUGHT by the gate. The fix
      must not become a rubber-stamp: a genuine dropout still hard-fails.
"""
import plamen_driver as D
import plamen_validators as V


# ── shared builders ───────────────────────────────────────────────────────────

def _write_queue(tmp_path, finding_ids):
    header = (
        "# Verification Queue Manifest\n"
        "| Queue # | Finding ID | Expected Output File | Severity | Title | "
        "Bug Class | Preferred Tag | Location | Primary Artifact | PoC Class |\n"
        "|---|---|---|---|---|---|---|---|---|---|\n"
    )
    body = ""
    for i, (fid, sev) in enumerate(finding_ids, start=1):
        body += (
            f"| {i} | {fid} | verify_{fid}.md | {sev} | T{i} | logic | "
            f"CODE-TRACE | Foo.sol:L{i} | depth | structural |\n"
        )
    (tmp_path / "verification_queue.md").write_text(header + body, encoding="utf-8")


def _write_index(tmp_path, master_rows, excluded_rows=None):
    """Write a minimal report_index.md with a Master Finding Index + Excluded."""
    lines = [
        "# Report Index",
        "",
        "## Master Finding Index",
        "",
        "| Report ID | Title | Severity | Location | Verification | Trust Adj. | Internal Hypothesis |",
        "|-----------|-------|----------|----------|--------------|-----------|--------------------|",
    ]
    lines.extend(master_rows)
    lines += ["", "## Excluded Findings", "",
              "| Internal ID | Severity | Title | Exclusion Reason |",
              "|---|---|---|---|"]
    lines.extend(excluded_rows or [])
    (tmp_path / "report_index.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


# A representative large-ish multi-tier set (mirrors an observed shape: many tiers,
# a finding-mapping, and a dedup merge so the seed superset is exercised fully).
_FINDINGS = [
    ("INV-001", "Critical"), ("INV-002", "High"), ("INV-003", "High"),
    ("INV-004", "Medium"), ("INV-005", "Medium"), ("INV-006", "Medium"),
    ("INV-007", "Low"), ("INV-008", "Low"), ("INV-009", "Informational"),
]


def _seed_everything(tmp_path):
    _write_queue(tmp_path, _FINDINGS)
    # finding_mapping adds an ID present ONLY here (superset behavior).
    (tmp_path / "finding_mapping.md").write_text(
        "# Finding Mapping\n| Source | Hyp |\n|---|---|\n"
        "| INV-001 | H-1 |\n| VS-1 | H-7 |\n",
        encoding="utf-8",
    )
    # dedup merges INV-006 into INV-005 (both must still be accounted for).
    (tmp_path / "dedup_decisions.md").write_text(
        "# Dedup Decisions\n\n| INV-006 | MERGED into INV-005 | coupled | n |\n",
        encoding="utf-8",
    )
    return D._write_report_index_coverage_seed(tmp_path)


# ── FIXTURE 1: FLAW-NOW-RESOLVED ──────────────────────────────────────────────

def test_seed_shards_partition_full_seed_with_zero_drops(tmp_path):
    """The shards are a PARTITION: union == full seed, no ID in two shards."""
    _seed_everything(tmp_path)
    full = V._collect_report_index_seed_ids(tmp_path)
    assert full, "precondition: full seed must enumerate IDs"

    # Driver writes the per-tier shards as a side effect of the seed write.
    shard_ids = {}
    for tier in ("critical_high", "medium", "low_info"):
        p = tmp_path / f"report_index_seed_{tier}.md"
        assert p.exists(), f"missing tier shard report_index_seed_{tier}.md"
        # Reuse the same bounded parser; shard tables share the seed schema.
        text = p.read_text(encoding="utf-8")
        # Repoint the collector at the shard by name via a temp copy.
        (tmp_path / "report_index_coverage_seed.md").write_text(text, encoding="utf-8")
        shard_ids[tier] = V._collect_report_index_seed_ids(tmp_path)
    # restore the real full seed for downstream
    _seed_everything(tmp_path)

    union = set().union(*shard_ids.values())
    assert union == full, (
        "shard union must equal the full seed (no finding falls between shards)"
    )
    # Disjoint: no ID assigned to two tiers.
    pairs = [("critical_high", "medium"), ("critical_high", "low_info"),
             ("medium", "low_info")]
    for a, b in pairs:
        assert not (shard_ids[a] & shard_ids[b]), (
            f"tiers {a} and {b} share IDs — partition must be disjoint"
        )


def test_seed_shards_route_by_severity(tmp_path):
    """Findings land in the correct tier shard by their (more-severe) severity."""
    _write_queue(tmp_path, [
        ("INV-001", "Critical"), ("INV-002", "High"),
        ("INV-003", "Medium"),
        ("INV-004", "Low"), ("INV-005", "Informational"),
    ])
    D._write_report_index_coverage_seed(tmp_path)

    def _ids(tier):
        body = (tmp_path / f"report_index_seed_{tier}.md").read_text(encoding="utf-8")
        return [l.split("|")[1].strip() for l in body.splitlines()
                if l.startswith("| INV")]

    assert _ids("critical_high") == ["INV-001", "INV-002"]
    assert _ids("medium") == ["INV-003"]
    assert _ids("low_info") == ["INV-004", "INV-005"]


def test_tier_severity_routing_is_total_and_recall_safe():
    """Every severity routes to exactly one tier; unknown -> low_info (never lost)."""
    assert D._report_index_tier_for_severity("Critical") == "critical_high"
    assert D._report_index_tier_for_severity("High") == "critical_high"
    assert D._report_index_tier_for_severity("Medium") == "medium"
    assert D._report_index_tier_for_severity("Low") == "low_info"
    assert D._report_index_tier_for_severity("Informational") == "low_info"
    assert D._report_index_tier_for_severity("Info") == "low_info"
    # Blank / unknown severities are routed (not dropped) so the partition stays total.
    assert D._report_index_tier_for_severity("") == "low_info"
    assert D._report_index_tier_for_severity("weird") == "low_info"


def test_correctly_sharded_index_disposing_every_seed_id_passes(tmp_path):
    """A merged index that gives EVERY seed ID exactly one disposition PASSES.

    This is the resolved-flaw case: sharding completes and reconciles cleanly.
    """
    _seed_everything(tmp_path)
    full = sorted(V._collect_report_index_seed_ids(tmp_path))
    # Promote each ID (one report row apiece — the simplest complete disposition).
    counters = {"C": 0, "H": 0, "M": 0, "L": 0, "I": 0}
    rows = []
    for fid in full:
        # Every ID gets a row; report-tier prefix is immaterial to the gate.
        counters["H"] += 1
        rows.append(
            f"| H-{counters['H']:02d} | T | High | Foo.sol | VERIFIED | - | {fid} |"
        )
    _write_index(tmp_path, rows)
    issues = V._check_index_completeness(tmp_path, str(tmp_path), write_retry_hint=False)
    assert issues == [], f"complete sharded index must pass; got: {issues}"


# ── FIXTURE 2: NEGATIVE CONTROL ───────────────────────────────────────────────

def test_dropout_between_shards_is_still_caught(tmp_path):
    """A seed ID left with NO disposition is STILL flagged — not rubber-stamped.

    Simulates a finding falling between tier-batches: every seed ID is indexed
    EXCEPT one Medium ID that the LLM forgot when it stopped after the Crit/High
    batch. The seed-reconciliation gate must catch it.
    """
    _seed_everything(tmp_path)
    full = sorted(V._collect_report_index_seed_ids(tmp_path))
    assert "INV-004" in full
    dropped = "INV-004"
    counters = {"H": 0}
    rows = []
    for fid in full:
        if fid == dropped:
            continue  # the finding that fell between shards
        counters["H"] += 1
        rows.append(
            f"| H-{counters['H']:02d} | T | High | Foo.sol | VERIFIED | - | {fid} |"
        )
    _write_index(tmp_path, rows)
    issues = V._check_index_completeness(tmp_path, str(tmp_path), write_retry_hint=False)
    assert issues, "a dropped seed ID must hard-fail the completeness gate"
    assert any("dropout" in i for i in issues)
    assert any(dropped in i for i in issues), (
        f"the gate must NAME the dropped ID {dropped}; got: {issues}"
    )


def test_seed_only_id_absent_from_verify_files_is_caught(tmp_path):
    """A seed ID that has NO verify_*.md (mapping/dedup-only) is still required.

    Before the fix, the gate reconciled only against verify_*.md filenames, so a
    finding present only in finding_mapping / dedup could vanish silently. The
    seed superset closes that hole. VS-1 here exists ONLY in finding_mapping.
    """
    _seed_everything(tmp_path)
    full = sorted(V._collect_report_index_seed_ids(tmp_path))
    assert "VS-1" in full, "VS-1 should be in the seed via finding_mapping"
    # Index everything EXCEPT the mapping-only VS-1.
    counters = {"H": 0}
    rows = []
    for fid in full:
        if fid == "VS-1":
            continue
        counters["H"] += 1
        rows.append(
            f"| H-{counters['H']:02d} | T | High | Foo.sol | VERIFIED | - | {fid} |"
        )
    _write_index(tmp_path, rows)
    issues = V._check_index_completeness(tmp_path, str(tmp_path), write_retry_hint=False)
    assert issues, "a mapping-only seed ID dropout must be caught (no rubber-stamp)"
    assert any("VS-1" in i for i in issues)


def test_prose_only_excluded_disposition_does_not_satisfy_gate(tmp_path):
    """An Excluded Findings row is a proposal, not terminal authority.

    Confirms the gate accepts ALL valid dispositions, not just report-ID
    promotion — so the negative control is targeting genuine drops, not
    legitimate exclusions.  Bare FALSE_POSITIVE prose is not a replayed
    provider decision and therefore cannot remove a candidate.
    """
    _seed_everything(tmp_path)
    full = sorted(V._collect_report_index_seed_ids(tmp_path))
    excluded = full[-1]
    counters = {"H": 0}
    rows = []
    for fid in full[:-1]:
        counters["H"] += 1
        rows.append(
            f"| H-{counters['H']:02d} | T | High | Foo.sol | VERIFIED | - | {fid} |"
        )
    excl_rows = [f"| {excluded} | Low | T | FALSE_POSITIVE - verified safe |"]
    _write_index(tmp_path, rows, excluded_rows=excl_rows)
    issues = V._check_index_completeness(tmp_path, str(tmp_path), write_retry_hint=False)
    assert issues, "prose-only exclusion must not authorize candidate loss"
    assert any(excluded in issue for issue in issues), issues


def test_retry_hint_names_dropped_seed_ids(tmp_path):
    """When write_retry_hint=True, the hint file names the dropped seed IDs."""
    _seed_everything(tmp_path)
    full = sorted(V._collect_report_index_seed_ids(tmp_path))
    dropped = "INV-002"
    counters = {"H": 0}
    rows = []
    for fid in full:
        if fid == dropped:
            continue
        counters["H"] += 1
        rows.append(
            f"| H-{counters['H']:02d} | T | High | Foo.sol | VERIFIED | - | {fid} |"
        )
    _write_index(tmp_path, rows)
    issues = V._check_index_completeness(tmp_path, str(tmp_path), write_retry_hint=True)
    assert issues
    hint = list(tmp_path.glob("report_index*"))
    hint_texts = [
        p.read_text(encoding="utf-8") for p in hint
        if p.name != "report_index.md" and p.name != "report_index_coverage_seed.md"
        and not p.name.startswith("report_index_seed_")
    ]
    assert any(dropped in t for t in hint_texts), (
        f"retry hint must name dropped ID {dropped}"
    )


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
