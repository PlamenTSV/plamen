"""Deterministic offline low/info body child for same-run integration.

The proposed bytes are rendered only from the already committed typed P1-K
evidence shard.  This fixture exercises POSIX MODEL transport and PhaseIO
lineage; it is not a semantic model-quality or audit-proof claim.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping, Sequence
import json
import os
import stat
import sys

import pytest

import plamen_driver as D
from report_evidence_authority import (
    load_typed_report_evidence_shard,
    render_typed_report_evidence_shard,
    validate_typed_report_evidence_shard_markdown,
)
from test_verification_report_tail_same_run_integration import (
    _patch_compat_codex_lookup,
)


_SHARD = "report_low_info"
_EXPECTED_IDS = ("INV-1", "INV-2", "INV-3")
_ATTEMPT_PROMPTS = {
    1: "Render the already-bound deterministic low/info evidence fixture attempt 1.\n",
    2: "Render the already-bound deterministic low/info evidence fixture attempt 2.\n",
}


def _phase(phases: Sequence[Any], name: str) -> Any:
    return next(item for item in phases if item.name == name)


def _typed_body(root: Path) -> str:
    source_path = root / "body_manifests" / f"{_SHARD}.json"
    source = json.loads(source_path.read_text(encoding="utf-8"))
    findings = source.get("findings")
    if not isinstance(findings, list):
        raise AssertionError("low/info source manifest has no exact denominator")
    source_ids = tuple(sorted(str(row.get("finding_id") or "") for row in findings))
    if source_ids != _EXPECTED_IDS:
        raise AssertionError(f"unexpected low/info source denominator: {source_ids}")

    _bundle, records = load_typed_report_evidence_shard(root, _SHARD)
    report_ids = tuple(sorted(str(row.get("report_id") or "") for row in findings))
    typed_report_ids = tuple(sorted(str(row.get("report_id") or "") for row in records))
    if typed_report_ids != report_ids or len(records) != len(findings):
        raise AssertionError("typed low/info evidence denominator differs from routing")
    # The public renderer includes only normalized, digest-bound evidence,
    # locations, titles, states and limitations from the typed records.
    body = render_typed_report_evidence_shard(root, _SHARD)
    issues = validate_typed_report_evidence_shard_markdown(root, _SHARD, body)
    if issues:
        raise AssertionError(f"typed low/info rendering failed replay: {issues}")
    return body


def _body_child_source(
    *, model: str, body: str, retry_body: str,
) -> bytes:
    """Render one immutable executable for both exact report-body attempts."""

    outputs = {
        1: {"report_low_info.md": body},
        2: {"report_low_info.md": retry_body},
    }
    return (
        f"#!{sys.executable} -B\n"
        "import hashlib,json,os,re,stat,sys\n"
        "from pathlib import Path\n"
        "if sys.argv[1:] == ['--version']:\n"
        " print('codex-cli low-info-body-fixture'); raise SystemExit(0)\n"
        "prompt=sys.stdin.read()\n"
        f"sys.stderr.write('OpenAI Codex v0.test\\n--------\\nworkdir: /fixture\\nmodel: {model}\\nprovider: openai\\n--------\\nuser\\n')\n"
        "marker='\\n# PROVIDER-EFFECTIVE LOCAL PHASEIO ROUTING\\n'\n"
        "request,separator,_transport=prompt.partition(marker)\n"
        f"attempts={{{_ATTEMPT_PROMPTS[1]!r}:1,{_ATTEMPT_PROMPTS[2]!r}:2}}\n"
        "if not separator or request not in attempts:\n"
        " raise SystemExit('low-info fixture prompt has no exact attempt')\n"
        "attempt=attempts[request]\n"
        "blocks=[json.loads(b) for b in re.findall(r'```json\\s*(.*?)\\s*```',_transport,re.S)]\n"
        "routes=[b for b in blocks if b.get('schema')=='plamen.posix_v2_codex_local_phaseio.v1']\n"
        "if len(routes)!=1:\n"
        " raise SystemExit('low-info fixture requires one routing block')\n"
        "routing=routes[0]\n"
        "if set(routing)!={'schema','project_source_root','project_source_access','codex_working_directory','input_routes','output_routes'}:\n"
        " raise SystemExit('low-info fixture routing shape differs')\n"
        "inputs=routing['input_routes']\n"
        "if not isinstance(inputs,list) or not inputs:\n"
        " raise SystemExit('low-info fixture input roster is empty')\n"
        "seen=set()\n"
        "for route in inputs:\n"
        " if set(route)!={'identity','path','class','binding_status','sha256','size'}:\n"
        "  raise SystemExit('low-info fixture input route shape differs')\n"
        " identity=route['identity']\n"
        " if not isinstance(identity,str) or identity.casefold() in seen:\n"
        "  raise SystemExit('low-info fixture input route collides')\n"
        " seen.add(identity.casefold())\n"
        " path=Path(route['path']); observed=os.lstat(path)\n"
        " if not stat.S_ISREG(observed.st_mode) or observed.st_nlink!=1:\n"
        "  raise SystemExit('low-info fixture input route is unsafe')\n"
        " raw=path.read_bytes()\n"
        " if type(route['size']) is not int or len(raw)!=route['size']:\n"
        "  raise SystemExit('low-info fixture input size differs')\n"
        " if hashlib.sha256(raw).hexdigest()!=route['sha256']:\n"
        "  raise SystemExit('low-info fixture input digest differs')\n"
        "output_routes=routing['output_routes']\n"
        "if not isinstance(output_routes,list) or len(output_routes)!=1:\n"
        " raise SystemExit('low-info fixture output roster differs')\n"
        "route=output_routes[0]\n"
        "if set(route)!={'identity','path','canonical_path','write_mode','prestate_status','prestate_existed','prestate_sha256','prestate_size'}:\n"
        " raise SystemExit('low-info fixture output route shape differs')\n"
        "if route['identity']!='scratchpad:report_low_info.md':\n"
        " raise SystemExit('low-info fixture output identity differs')\n"
        "target=Path(route['path'])\n"
        "if target.name!='report_low_info.md' or target.is_symlink():\n"
        " raise SystemExit('low-info fixture output path differs')\n"
        f"outputs_by_attempt={outputs!r}\n"
        "target.write_text(outputs_by_attempt[attempt]['report_low_info.md'],encoding='utf-8')\n"
        "if '-o' not in sys.argv or sys.argv.count('-o')!=1:\n"
        " raise SystemExit('low-info fixture transcript route is absent')\n"
        "Path(sys.argv[sys.argv.index('-o')+1]).write_text('complete\\n',encoding='utf-8')\n"
        "print(json.dumps({'type':'turn.completed'}))\n"
    ).encode("utf-8")


def run_nonempty_low_info_body_child(
    *,
    root: Path,
    project: Path,
    config: Mapping[str, Any],
    checkpoint: Any,
    phases: Sequence[Any],
    monkeypatch,
    attempt: int = 1,
):
    """Route, publish P1-K evidence, then execute one real local child."""
    if os.name != "posix":
        pytest.skip("deterministic body child requires POSIX compatibility")
    run_id = config.get("_run_id")
    assert attempt in {1, 2}
    assert isinstance(run_id, str) and run_id
    assert getattr(checkpoint, "run_id", None) == run_id
    assert D._posix_v2_compat_session_for_launch() is not None

    manifests, routing_issues = D._run_report_index_routing_transaction(root, config)
    assert routing_issues == []
    assert _SHARD in manifests
    phase = _phase(phases, "report_body_writer_low_info")
    assert D._ensure_report_evidence_before_body_writer(phase, dict(config), root) == []
    body = _typed_body(root)
    retry_body = body.rstrip() + (
        "\n\n<!-- deterministic transport variant: report body attempt 0002 -->\n"
    )

    contract, launch = D._typed_model_phase_contract_and_launch(phase, root, config)
    assert contract is not None and contract.model_invoked
    assert tuple(spec.path for spec in contract.outputs) == ("report_low_info.md",)
    assert D._bind_typed_model_phase_inputs(phase, root, config) == []

    binary = project.parent / "fixture-codex-nonempty-low-info-body"
    binary_raw = _body_child_source(
        model=launch.model, body=body, retry_body=retry_body,
    )
    if attempt == 1:
        assert not binary.exists() and not binary.is_symlink()
        binary.write_bytes(binary_raw)
        binary.chmod(0o755)
    else:
        observed_binary = os.lstat(binary)
        assert stat.S_ISREG(observed_binary.st_mode)
        assert observed_binary.st_nlink == 1
        assert stat.S_IMODE(observed_binary.st_mode) == 0o755
        assert binary.read_bytes() == binary_raw
    _patch_compat_codex_lookup(monkeypatch, binary)
    import posix_v2_compat_runtime as compat
    monkeypatch.setattr(
        compat, "_load_ambient_codex_auth",
        lambda: ("PRIVATE_AUTH_JSON_COPY", b'{"tokens":{}}\n', "c" * 64),
    )
    assert D._run_one_codex_exec(
        prompt=_ATTEMPT_PROMPTS[attempt],
        phase=phase, config=config, scratchpad=root, attempt=attempt,
        label=phase.name, expected_outputs=[spec.path for spec in contract.outputs],
        timeout=float(launch.timeout_s), effective_model=launch.model,
        phase_io_contract=contract, phase_io_launch=launch,
    ) == 0
    assert validate_typed_report_evidence_shard_markdown(
        root, _SHARD, (root / "report_low_info.md").read_text(encoding="utf-8"),
    ) == []
    # This helper returns committed raw MODEL bytes. The caller exercises the
    # DRIVER evidence successor (including crash/recovery) before enforcing
    # the final tier fixed-point gate, matching production validator order.
    return phase, contract, launch


def commit_nonempty_low_info_body(
    *, root: Path, config: Mapping[str, Any], checkpoint: Any,
    phases: Sequence[Any], phase: Any,
) -> None:
    """Exact splice after the child; confirmation/merge remain caller-owned."""
    D._commit_phase_from_disk_debt(
        phase, checkpoint, root, config, phases, clean_transients=True,
    )
    confirmation = _phase(phases, "report_low_info")
    assert D._validate_tier_body_against_manifest(
        root, confirmation.name,
        project_root=Path(str(config["project_root"])), config=config,
    ) == []
    D._commit_accepted_phase_from_disk(
        confirmation, checkpoint, root, config, phases,
    )
    merge = _phase(phases, "report_low_info_merge")
    D.merge_report_tier_shards(root, "low_info")
    D._commit_accepted_phase_from_disk(merge, checkpoint, root, config, phases)
