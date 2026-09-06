from __future__ import annotations

import hashlib
import json
import threading
import time
from pathlib import Path

import codex_dependency_research as C
import plamen_driver as D
import rooted_path_io as rooted_io
from phase_io_contracts import resolve_phase_io_contract


URL = "https://docs.example.com/protocol"


def _report(url: str = URL) -> bytes:
    return (
        "| Obligation ID | Dependency | Integration Surface | Assumed Behavior | "
        "Real Behavior | Source | Conformance | Fetch Status |\n"
        "|---|---|---|---|---|---|---|---|\n"
        f"| DEP-1 | Example | Vault.sol:L1 | atomic | documented | {url} | "
        "CONFORMS | RESEARCHED |\n"
    ).encode()


def _provider_evidence(root: Path, *, event_url: str = URL) -> dict[str, str]:
    attempt_dir = root / ".worker_transactions" / "recon" / "dependency_research" / "attempts" / ("attempt-" + "a" * 24)
    provider_dir = root / ".worker_execution_receipts" / "wt-test"
    attempt_dir.mkdir(parents=True)
    (provider_dir / "blobs").mkdir(parents=True)
    stdout = (
        json.dumps({
            "type": "item.completed",
            "item": {
                "type": "web_search",
                "action": {"type": "open_page", "url": event_url},
            },
        }) + "\n"
    ).encode()
    stdout_sha = hashlib.sha256(stdout).hexdigest()
    (provider_dir / "blobs" / "stdout.bin").write_bytes(stdout)
    provider = {
        "stdout_blob": {
            "relative_path": "blobs/stdout.bin",
            "sha256": stdout_sha,
            "size": len(stdout),
        },
        "stream_observation": {"stdout_overflow": False},
    }
    (provider_dir / "completion.json").write_text(json.dumps(provider), encoding="utf-8")
    attempt = {
        "provider_completion_relative_path": (
            ".worker_execution_receipts/wt-test/completion.json"
        )
    }
    completion = attempt_dir / "completion.json"
    completion.write_text(json.dumps(attempt), encoding="utf-8")
    obligations = root / "external_dependency_obligations.json"
    obligations.write_text(
        json.dumps({"obligations": [{"obligation_id": "DEP-1"}]}),
        encoding="utf-8",
    )
    return {
        "schema": C.CONTEXT_SCHEMA,
        "scratchpad_root": str(root),
        "attempt_completion": str(completion),
        "obligations_path": str(obligations),
        "research_output": "recon_external_dependency_research.md",
    }


def test_staged_gate_joins_researched_url_to_typed_codex_event(tmp_path: Path):
    context = _provider_evidence(tmp_path)
    assert C.staged_codex_dependency_research_validator(
        {"scratchpad:recon_external_dependency_research.md": _report()},
        context,
    ) == []


def test_staged_gate_rejects_unreceipted_source(tmp_path: Path):
    context = _provider_evidence(
        tmp_path, event_url="https://docs.example.com/different"
    )
    issues = C.staged_codex_dependency_research_validator(
        {"recon_external_dependency_research.md": _report()}, context
    )
    assert issues and "absent from typed Codex web_search events" in issues[0]


def test_provider_receipt_allows_bounded_windows_visibility_delay(tmp_path: Path):
    context = _provider_evidence(tmp_path)
    completion = json.loads(Path(context["attempt_completion"]).read_text())
    provider = tmp_path / completion["provider_completion_relative_path"]
    raw = provider.read_bytes()
    provider.unlink()

    def publish() -> None:
        time.sleep(0.05)
        provider.write_bytes(raw)

    thread = threading.Thread(target=publish)
    thread.start()
    try:
        assert C._provider_stdout(context)
    finally:
        thread.join(timeout=1.0)


def test_provider_stdout_reads_extended_length_receipt_paths(tmp_path: Path):
    root = tmp_path / "scratch"
    rooted_io.ensure_directory(root)
    long_parts = [(letter * 80) for letter in ("a", "b", "c")]
    attempt_relative = Path(
        ".worker_transactions", *long_parts, "completion.json"
    )
    provider_relative = Path(
        ".worker_execution_receipts", *long_parts, "completion.json"
    )
    blob_relative = Path(
        ".worker_execution_receipts", *long_parts, "blobs", "stdout.bin"
    )
    attempt_path = root / attempt_relative
    provider_path = root / provider_relative
    blob_path = root / blob_relative
    rooted_io.ensure_directory(attempt_path.parent)
    rooted_io.ensure_directory(blob_path.parent)
    stdout = (
        json.dumps({
            "type": "item.completed",
            "item": {
                "type": "web_search",
                "action": {"type": "open_page", "url": URL},
            },
        }) + "\n"
    ).encode()
    rooted_io.durable_write_once_bytes(blob_path, stdout)
    rooted_io.durable_write_once_bytes(
        provider_path,
        json.dumps({
            "stdout_blob": {
                "relative_path": "blobs/stdout.bin",
                "sha256": hashlib.sha256(stdout).hexdigest(),
                "size": len(stdout),
            },
            "stream_observation": {"stdout_overflow": False},
        }).encode(),
    )
    rooted_io.durable_write_once_bytes(
        attempt_path,
        json.dumps({
            "provider_completion_relative_path": provider_relative.as_posix(),
        }).encode(),
    )
    assert len(str(provider_path)) > 260
    assert C._provider_stdout({
        "scratchpad_root": str(root),
        "attempt_completion": str(attempt_path),
    }) == stdout


def test_fetch_receipt_validation_is_exact_and_compare_only(tmp_path: Path):
    report = tmp_path / "recon_external_dependency_research.md"
    report.write_bytes(_report())
    payload = {
        "schema_version": C.FETCH_RECEIPT_SCHEMA,
        "observed_at": "2026-09-06T00:00:00+00:00",
        "report_sha256": hashlib.sha256(report.read_bytes()).hexdigest(),
        "entries": [{
            "status": "FETCHED",
            "requested_url": URL,
            "final_url": URL,
            "redirects": [],
            "resolved_addresses": ["93.184.216.34"],
            "http_status": 200,
            "content_type": "text/html",
            "content_sha256": "b" * 64,
            "content_size": 123,
            "error_code": "",
            "obligation_ids": ["DEP-1"],
        }],
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    payload["payload_digest"] = hashlib.sha256(canonical).hexdigest()
    receipt = tmp_path / C.FETCH_RECEIPT_FILE
    receipt.write_text(json.dumps(payload), encoding="utf-8")
    before = receipt.read_bytes()
    assert C.validate_fetch_receipt(report, receipt) == []
    assert receipt.read_bytes() == before


def test_codex_dependency_fetch_phaseio_and_search_flag_order():
    contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="codex",
        phase="recon",
        work_unit_id="codex_dependency_fetch",
        exact_inputs=("recon_external_dependency_research.md",),
        exact_outputs=(C.FETCH_RECEIPT_FILE,),
        exact_writer="DRIVER",
    )
    assert contract.model_invoked is False
    command = D._build_codex_cmd("test-model", live_search=True)
    assert command[1:3] == ["--search", "exec"]
    assert "--search" not in D._build_codex_cmd("test-model")
