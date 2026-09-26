import hashlib
import json

import pytest

import methodology_application as A


def _descriptor(path, steps=("1", "2")):
    return {
        "skill": "ORACLE_ANALYSIS",
        "path": path.as_posix(),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "top_level_checklist_step_ids": list(steps),
    }


def _dispatch(sp, descriptor, output="analysis_oracle.md"):
    entry = {
        "worker_id": "B1",
        "output": output,
        "prompt_sha256": "a" * 64,
        "prompt_snapshot_required": False,
        "methodologies": [descriptor],
    }
    entry["dispatch_contract_sha256"] = A.worker_dispatch_contract_sha256(
        "breadth", entry
    )
    return A.write_phase_dispatch(
        sp, phase="breadth", backend="claude-pty", entries=[entry]
    )


def _trace(sp, *rows, phase="breadth", worker="B1", output="analysis_oracle.md"):
    dispatch = json.loads((sp / "skill_dispatch.json").read_text())
    contract = dispatch["phases"][phase]["entries"][0][
        "dispatch_contract_sha256"
    ]
    payload = {
        "schema_version": 1,
        "rows": [dict(zip(A.TRACE_COLUMNS, row)) for row in rows],
    }
    return (
        f"<!-- PLAMEN_DISPATCH_PHASE: {phase} -->\n"
        f"<!-- PLAMEN_DISPATCH_WORKER: {worker} -->\n"
        f"<!-- PLAMEN_DISPATCH_OUTPUT: {output} -->\n"
        f"<!-- PLAMEN_DISPATCH_CONTRACT_SHA256: {contract} -->\n\n"
        "# Findings\n\n## Step Execution Trace\n\n"
        f"{A.TRACE_JSON_BEGIN}\n"
        + json.dumps(payload, ensure_ascii=False)
        + f"\n{A.TRACE_JSON_END}\n"
        + "\n<!-- PLAMEN_STATUS: COMPLETE -->\n"
    )


def _validate(sp, project, *, phase="breadth"):
    return A.validate_phase_application(
        sp,
        project,
        phase=phase,
        trusted_methodology_roots=[sp.parent.parent],
    )


def test_authoritative_json_trace_does_not_require_cosmetic_heading():
    payload = {
        "schema_version": 1,
        "rows": [
            {
                "skill": "ORACLE_ANALYSIS",
                "step": "1",
                "executed": "yes",
                "evidence": "src/Oracle.sol:L2",
                "result": "traced the concrete return-value branch",
            }
        ],
    }
    text = (
        "# Findings\n\n"
        f"{A.TRACE_JSON_BEGIN}\n"
        f"{json.dumps(payload)}\n"
        f"{A.TRACE_JSON_END}\n"
    )

    assert A._trace_rows(text) == payload["rows"]


def test_headerless_authoritative_trace_reconciles_with_full_contract(tmp_path):
    project = tmp_path / "project"
    sp = project / ".scratchpad"
    sp.mkdir(parents=True)
    (project / "Oracle.sol").write_text("function read() {}\n", encoding="utf-8")
    skill = tmp_path / "ORACLE_SKILL.md"
    skill.write_text("# immutable skill\n", encoding="utf-8")
    _dispatch(sp, _descriptor(skill, steps=("1",)))
    output = _trace(
        sp,
        (
            "ORACLE_ANALYSIS",
            "1",
            "yes",
            "Oracle.sol:L1",
            "traced the concrete return-value branch",
        ),
    ).replace("## Step Execution Trace\n\n", "")
    (sp / "analysis_oracle.md").write_text(output, encoding="utf-8")

    result = _validate(sp, project)

    assert result["status"] == "ATTESTED"
    assert result["closed_steps"] == 1
    assert result["rows"][0]["application_completeness"] == "APPLIED"


def test_duplicate_or_malformed_trace_sentinels_fail_closed():
    payload = json.dumps({"schema_version": 1, "rows": []})
    valid = f"{A.TRACE_JSON_BEGIN}\n{payload}\n{A.TRACE_JSON_END}"
    malformed = (
        f"{A.TRACE_JSON_BEGIN}\n{{not-json}}\n{A.TRACE_JSON_END}"
    )
    reversed_markers = (
        f"{A.TRACE_JSON_END}\n{payload}\n{A.TRACE_JSON_BEGIN}"
    )

    assert A._trace_rows(valid + "\n" + A.TRACE_JSON_BEGIN) == []
    assert A._trace_rows(valid + "\n" + A.TRACE_JSON_END) == []
    assert A._trace_rows(malformed) == []
    assert A._trace_rows(reversed_markers) == []


def _repair_trace_source_evidence(executed: str, evidence: str) -> bytes:
    payload = {
        "schema_version": 1,
        "rows": [{
            "skill": "RESCAN_METHOD",
            "step": "RS-X",
            "executed": executed,
            "evidence": evidence,
            "result": "MAO-0123456789ABCDEF: exact repair result",
        }],
    }
    return (
        f"{A.TRACE_JSON_BEGIN}\n{json.dumps(payload)}\n{A.TRACE_JSON_END}\n"
    ).encode()


@pytest.mark.parametrize(
    "evidence",
    (
        "analysis_cross_chain_message_flow.md:L28",
        "src/Oracle.sol:L3",
        "Missing.sol:L1",
    ),
)
def test_repair_positive_trace_requires_real_project_source_locus(
    tmp_path, evidence,
):
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    (project / "src").mkdir(parents=True)
    scratchpad.mkdir()
    (project / "src" / "Oracle.sol").write_text(
        "line one\nline two\n", encoding="utf-8"
    )
    (scratchpad / "analysis_cross_chain_message_flow.md").write_text(
        "\n" * 30, encoding="utf-8"
    )

    issues = A.staged_repair_source_evidence_issues(
        _repair_trace_source_evidence("yes", evidence),
        project_root=project,
        scratchpad=scratchpad,
    )

    assert issues == [
        "repair step trace RESCAN_METHOD/RS-X "
        + A.REPAIR_POSITIVE_EVIDENCE_REQUIREMENT
    ]


def test_repair_real_source_locus_or_explicit_debt_is_admitted(tmp_path):
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    (project / "src").mkdir(parents=True)
    scratchpad.mkdir()
    (project / "src" / "Oracle.sol").write_text("line\n", encoding="utf-8")

    assert A.staged_repair_source_evidence_issues(
        _repair_trace_source_evidence("partial", "src/Oracle.sol:L1"),
        project_root=project,
        scratchpad=scratchpad,
    ) == []
    assert A.staged_repair_source_evidence_issues(
        _repair_trace_source_evidence("unknown", "-"),
        project_root=project,
        scratchpad=scratchpad,
    ) == []
    fake_success = (
        b"## Finding [MAR-1]: unsupported\n\n"
        + _repair_trace_source_evidence("unknown", "-")
    )
    assert A.staged_repair_source_evidence_issues(
        fake_success, project_root=project, scratchpad=scratchpad
    ) == [
        "repair finding cannot be published when every assigned step remains "
        "Executed=no/unknown debt"
    ]
    contract = A.repair_source_evidence_prompt_contract()
    assert A.REPAIR_POSITIVE_EVIDENCE_REQUIREMENT in contract
    assert "Executed=no/unknown" in contract
    assert "visible methodology debt" in contract


def test_dispatch_merges_phases_and_binds_exact_methodology(tmp_path):
    skill = tmp_path / "SKILL.md"
    skill.write_text("# skill bytes\n", encoding="utf-8")
    breadth = _dispatch(tmp_path, _descriptor(skill))
    A.write_phase_dispatch(
        tmp_path, phase="depth", backend="claude-pty", entries=[]
    )
    payload = json.loads((tmp_path / "skill_dispatch.json").read_text())
    assert set(payload["phases"]) == {"breadth", "depth"}
    assert breadth["dispatch_sha256"] == payload["phases"]["breadth"]["dispatch_sha256"]
    assert A.phase_dispatch_sha256(payload["phases"]["breadth"]) == breadth[
        "dispatch_sha256"
    ]


def test_application_requires_every_expected_step_and_resolvable_evidence(tmp_path):
    project = tmp_path / "project"
    sp = project / ".scratchpad"
    sp.mkdir(parents=True)
    source = project / "src" / "Oracle.sol"
    source.parent.mkdir()
    source.write_text("line one\nline two\n", encoding="utf-8")
    skill = tmp_path / "ORACLE_SKILL.md"
    skill.write_text("# immutable skill\n", encoding="utf-8")
    _dispatch(sp, _descriptor(skill))
    (sp / "analysis_oracle.md").write_text(
        _trace(
            sp,
            (
                "ORACLE_ANALYSIS",
                "Step 1",
                "yes",
                "src/Oracle.sol:L2",
                "traced the concrete return-value branch",
            ),
        ),
        encoding="utf-8",
    )
    result = _validate(sp, project)
    assert result["status"] == "GAPS"
    assert result["closed_steps"] == 1
    assert result["gap_steps"] == 1


def test_safe_attestation_routes_to_independent_skeptic_not_closed(tmp_path):
    project = tmp_path / "project"
    sp = project / ".scratchpad"
    sp.mkdir(parents=True)
    (project / "Oracle.sol").write_text("function read() {}\n", encoding="utf-8")
    skill = tmp_path / "ORACLE_SKILL.md"
    skill.write_text("# immutable skill\n", encoding="utf-8")
    _dispatch(sp, _descriptor(skill, steps=("1",)))
    (sp / "analysis_oracle.md").write_text(
        _trace(
            sp,
            (
                "ORACLE_ANALYSIS",
                "1",
                "yes",
                "Oracle.sol:L1",
                "SAFE: caller validates the returned value at the cited locus",
            ),
        ),
        encoding="utf-8",
    )
    result = _validate(sp, project)
    assert result["status"] == "SKEPTIC_PENDING"
    assert result["rows"][0]["application_completeness"] == "APPLIED"
    assert result["rows"][0]["semantic_outcome"] == "NEGATIVE"
    assert result["rows"][0]["disposition"] == "ATTESTED"  # compatibility only
    assert result["rows"][0]["skeptic_required"] is True
    queue = json.loads((sp / "methodology_skeptic_queue_breadth.json").read_text())
    assert queue["row_count"] == 1
    repair = json.loads((sp / "methodology_repair_queue_breadth.json").read_text())
    assert repair["row_count"] == 0


def test_methodology_drift_reopens_even_with_affirmative_trace(tmp_path):
    project = tmp_path / "project"
    sp = project / ".scratchpad"
    sp.mkdir(parents=True)
    (project / "Oracle.sol").write_text("line\n", encoding="utf-8")
    skill = tmp_path / "ORACLE_SKILL.md"
    skill.write_text("# v1\n", encoding="utf-8")
    _dispatch(sp, _descriptor(skill, steps=("1",)))
    skill.write_text("# v2 changed after dispatch\n", encoding="utf-8")
    (sp / "analysis_oracle.md").write_text(
        _trace(
            sp,
            ("ORACLE_ANALYSIS", "1", "yes", "Oracle.sol:L1", "specific branch trace"),
        ),
        encoding="utf-8",
    )
    result = _validate(sp, project)
    assert result["status"] == "GAPS"
    assert "SHA-256 drifted" in result["rows"][0]["reason"]


def test_duplicate_or_unresolvable_affirmative_never_closes(tmp_path):
    project = tmp_path / "project"
    sp = project / ".scratchpad"
    sp.mkdir(parents=True)
    skill = tmp_path / "ORACLE_SKILL.md"
    skill.write_text("# immutable skill\n", encoding="utf-8")
    _dispatch(sp, _descriptor(skill, steps=("1", "2")))
    (sp / "analysis_oracle.md").write_text(
        _trace(
            sp,
            ("ORACLE_ANALYSIS", "1", "yes", "Missing.sol:L9", "specific trace"),
            ("ORACLE_ANALYSIS", "2", "yes", "Missing.sol:L9", "specific trace A"),
            ("ORACLE_ANALYSIS", "2", "no", "-", "not executed"),
        ),
        encoding="utf-8",
    )
    result = _validate(sp, project)
    by_step = {row["step"]: row for row in result["rows"]}
    assert "lacks resolvable" in by_step["1"]["reason"]
    assert "duplicate/conflicting" in by_step["2"]["reason"]


def test_unenumerated_methodology_becomes_whole_method_obligation(tmp_path):
    project = tmp_path / "project"
    sp = project / ".scratchpad"
    sp.mkdir(parents=True)
    skill = tmp_path / "ODD_SKILL.md"
    skill.write_text("# no numbered structure\n", encoding="utf-8")
    _dispatch(sp, _descriptor(skill, steps=()))
    (sp / "analysis_oracle.md").write_text("# analysis without trace\n", encoding="utf-8")
    result = _validate(sp, project)
    assert result["gap_steps"] == 1
    assert result["rows"][0]["step"] == "WHOLE_METHOD/UNENUMERATED"


def test_tampered_dispatch_digest_is_unmeasurable_and_durable(tmp_path):
    project = tmp_path / "project"
    sp = project / ".scratchpad"
    sp.mkdir(parents=True)
    skill = tmp_path / "ORACLE_SKILL.md"
    skill.write_text("# immutable skill\n", encoding="utf-8")
    _dispatch(sp, _descriptor(skill, steps=("1",)))
    payload = json.loads((sp / "skill_dispatch.json").read_text())
    payload["phases"]["breadth"]["entries"][0]["output"] = "tampered.md"
    (sp / "skill_dispatch.json").write_text(json.dumps(payload), encoding="utf-8")
    result = _validate(sp, project)
    assert result["status"] == "UNMEASURABLE"
    assert "dispatch SHA-256 mismatch" in result["rows"][0]["reason"]
    assert "dispatch SHA-256 mismatch" in (
        sp / "skill_execution_gaps_breadth.md"
    ).read_text(encoding="utf-8")


def test_empty_dispatch_never_yields_attested(tmp_path):
    project = tmp_path / "project"
    sp = project / ".scratchpad"
    sp.mkdir(parents=True)
    A.write_phase_dispatch(sp, phase="breadth", backend="codex", entries=[])
    result = _validate(sp, project)
    assert result["status"] == "UNMEASURABLE"
    assert result["gap_steps"] == 1


def test_output_must_echo_exact_dispatch_contract(tmp_path):
    project = tmp_path / "project"
    sp = project / ".scratchpad"
    sp.mkdir(parents=True)
    (project / "Oracle.sol").write_text("line\n", encoding="utf-8")
    skill = tmp_path / "ORACLE_SKILL.md"
    skill.write_text("# immutable skill\n", encoding="utf-8")
    _dispatch(sp, _descriptor(skill, steps=("1",)))
    text = _trace(
        sp,
        ("ORACLE_ANALYSIS", "1", "yes", "Oracle.sol:L1", "specific check"),
    ).replace("PLAMEN_DISPATCH_WORKER: B1", "PLAMEN_DISPATCH_WORKER: B9")
    (sp / "analysis_oracle.md").write_text(text, encoding="utf-8")
    result = _validate(sp, project)
    assert result["status"] == "GAPS"
    assert "output dispatch metadata" in result["rows"][0]["reason"]


def test_repeated_generic_self_attestation_is_not_application_proof(tmp_path):
    project = tmp_path / "project"
    sp = project / ".scratchpad"
    sp.mkdir(parents=True)
    (project / "Oracle.sol").write_text("line\n", encoding="utf-8")
    skill = tmp_path / "ORACLE_SKILL.md"
    skill.write_text("# immutable skill\n", encoding="utf-8")
    _dispatch(sp, _descriptor(skill, steps=("1", "2")))
    (sp / "analysis_oracle.md").write_text(
        _trace(
            sp,
            ("ORACLE_ANALYSIS", "1", "yes", "Oracle.sol:L1", "executed"),
            ("ORACLE_ANALYSIS", "2", "yes", "Oracle.sol:L1", "executed"),
        ),
        encoding="utf-8",
    )
    result = _validate(sp, project)
    assert result["status"] == "GAPS"
    assert result["gap_steps"] == 2
    assert all(
        "repeated generic producer attestation" in row["reason"]
        for row in result["rows"]
    )
    assert result["assurance"] == "PRODUCER_ATTESTATION_ONLY"


def test_typed_step_ids_do_not_collapse_decimal_hierarchy(tmp_path):
    project = tmp_path / "project"
    sp = project / ".scratchpad"
    sp.mkdir(parents=True)
    (project / "Oracle.sol").write_text("line\n", encoding="utf-8")
    skill = tmp_path / "ORACLE_SKILL.md"
    skill.write_text("# immutable skill\n", encoding="utf-8")
    _dispatch(sp, _descriptor(skill, steps=("1.1", "11")))
    (sp / "analysis_oracle.md").write_text(
        _trace(
            sp,
            ("ORACLE_ANALYSIS", "1.1", "yes", "Oracle.sol:L1", "checked branch alpha"),
            ("ORACLE_ANALYSIS", "11", "yes", "Oracle.sol:L1", "checked branch omega"),
        ),
        encoding="utf-8",
    )
    result = _validate(sp, project)
    assert result["status"] == "ATTESTED"
    assert {row["step"] for row in result["rows"]} == {"1.1", "11"}


def test_authoritative_json_preserves_pipe_characters(tmp_path):
    project = tmp_path / "project"
    sp = project / ".scratchpad"
    sp.mkdir(parents=True)
    (project / "Oracle.sol").write_text("line\n", encoding="utf-8")
    skill = tmp_path / "ORACLE_SKILL.md"
    skill.write_text("# immutable skill\n", encoding="utf-8")
    _dispatch(sp, _descriptor(skill, steps=("1",)))
    (sp / "analysis_oracle.md").write_text(
        _trace(
            sp,
            (
                "ORACLE_ANALYSIS",
                "1",
                "yes",
                "Oracle.sol:L1 | branch B",
                "compared branch A | branch B specifically",
            ),
        ),
        encoding="utf-8",
    )
    result = _validate(sp, project)
    assert result["status"] == "ATTESTED"
    assert result["rows"][0]["result"] == "compared branch A | branch B specifically"


def test_methodology_outside_trusted_root_is_gap(tmp_path):
    project = tmp_path / "project"
    sp = project / ".scratchpad"
    sp.mkdir(parents=True)
    (project / "Oracle.sol").write_text("line\n", encoding="utf-8")
    outside = tmp_path / "outside" / "SKILL.md"
    outside.parent.mkdir()
    outside.write_text("# method\n", encoding="utf-8")
    _dispatch(sp, _descriptor(outside, steps=("1",)))
    (sp / "analysis_oracle.md").write_text(
        _trace(
            sp,
            ("ORACLE_ANALYSIS", "1", "yes", "Oracle.sol:L1", "specific check"),
        ),
        encoding="utf-8",
    )
    result = A.validate_phase_application(
        sp,
        project,
        phase="breadth",
        trusted_methodology_roots=[tmp_path / "trusted"],
    )
    assert result["status"] == "GAPS"
    assert "outside trusted" in result["rows"][0]["reason"]


def test_absolute_or_parent_output_escape_is_malformed(tmp_path):
    project = tmp_path / "project"
    sp = project / ".scratchpad"
    sp.mkdir(parents=True)
    skill = tmp_path / "SKILL.md"
    skill.write_text("# method\n", encoding="utf-8")
    for output in ("../escape.md", (tmp_path / "absolute.md").as_posix()):
        entry = {
            "worker_id": "B1",
            "output": output,
            "prompt_sha256": "a" * 64,
            "prompt_snapshot_required": False,
            "methodologies": [_descriptor(skill, steps=("1",))],
        }
        entry["dispatch_contract_sha256"] = A.worker_dispatch_contract_sha256(
            "breadth", entry
        )
        A.write_phase_dispatch(sp, phase="breadth", backend="codex", entries=[entry])
        result = _validate(sp, project)
        assert result["status"] == "UNMEASURABLE"
        assert "scratchpad basename" in result["rows"][0]["reason"]
