"""Focused integration tests for authenticated MCP front transport behavior."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import time

import pytest


ROOT = Path(__file__).resolve().parent.parent
SANITIZER = ROOT / "mcp-packages" / "schema-sanitizer.js"


def _node() -> str:
    value = shutil.which("node")
    if not value:
        pytest.skip("Node is unavailable")
    return value


def _child(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "child.js"
    path.write_text(body, encoding="utf-8")
    return path


@pytest.mark.parametrize("backend", ["claude", "codex"])
def test_sanitizer_real_initialize_and_tools_roundtrip(tmp_path: Path, backend: str) -> None:
    node = _node()
    child = _child(tmp_path, """
const readline = require('readline');
const rl = readline.createInterface({input: process.stdin});
rl.on('line', line => {
  const request = JSON.parse(line);
  const result = request.method === 'tools/list' ? {tools: [{name:'x', inputSchema:{oneOf:[{type:'object',properties:{x:{type:'string'}}},{type:'null'}]}}]} : {protocolVersion:'2025-06-18',capabilities:{}};
  process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:request.id,result})+'\\n');
});
""")
    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    ]
    result = subprocess.run(
        [node, str(SANITIZER), f"--backend={backend}", node, str(child)],
        input="".join(json.dumps(item) + "\n" for item in messages),
        capture_output=True, text=True, timeout=15,
    )
    assert result.returncode == 0, result.stderr
    rows = [json.loads(line) for line in result.stdout.splitlines()]
    assert [row["id"] for row in rows] == [1, 2]
    schema = rows[1]["result"]["tools"][0]["inputSchema"]
    assert "oneOf" not in schema and schema["type"] == "object"


def test_sanitizer_rejects_oversized_unterminated_parent_message(tmp_path: Path) -> None:
    node = _node()
    child = _child(tmp_path, "process.stdin.resume();\n")
    result = subprocess.run(
        [node, str(SANITIZER), "--backend=codex", node, str(child)],
        input="x" * (4 * 1024 * 1024 + 1), capture_output=True, text=True, timeout=15,
    )
    assert result.returncode != 0
    assert "exceeds limit" in result.stderr


def test_sanitizer_parent_eof_closes_child_and_propagates_exit(tmp_path: Path) -> None:
    node = _node()
    child = _child(
        tmp_path,
        "process.stdin.resume(); process.stdin.on('end',()=>process.exit(7));\n",
    )
    result = subprocess.run(
        [node, str(SANITIZER), "--backend=claude", node, str(child)],
        input="", capture_output=True, text=True, timeout=15,
    )
    assert result.returncode == 7


def test_sanitizer_rejects_deep_schema_and_child_output(tmp_path: Path) -> None:
    node = _node()
    child = _child(tmp_path, """
let schema={type:'string'}; for(let i=0;i<40;i++) schema={type:'array',items:schema};
process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:1,result:{tools:[{name:'x',inputSchema:schema}]}})+'\\n');
setInterval(()=>{},1000);
""")
    result = subprocess.run(
        [node, str(SANITIZER), "--backend=codex", node, str(child)],
        input="{}\n", capture_output=True, text=True, timeout=15,
    )
    assert result.returncode != 0
    assert "schema nesting exceeds limit" in result.stderr


@pytest.mark.parametrize("shape", ["allOf", "properties"])
def test_sanitizer_rejects_global_schema_work_exhaustion_without_quadratic_wait(
    tmp_path: Path, shape: str,
) -> None:
    node = _node()
    if shape == "allOf":
        schema = "{allOf:Array.from({length:10000},(_,i)=>({type:'object',properties:{['p'+i]:{type:'string'}}}))}"
    else:
        schema = "{type:'object',properties:Object.fromEntries(Array.from({length:20000},(_,i)=>['p'+i,{type:'string'}]))}"
    child = _child(tmp_path, f"""
const schema={schema};
process.stdout.write(JSON.stringify({{jsonrpc:'2.0',id:1,result:{{tools:[{{name:'x',inputSchema:schema}}]}}}})+'\\n');
setInterval(()=>{{}},1000);
""")
    process = subprocess.Popen(
        [node, str(SANITIZER), "--backend=codex", node, str(child)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    started = time.monotonic()
    try:
        assert process.wait(timeout=6) != 0
        elapsed = time.monotonic() - started
        assert elapsed < 4.0
        assert process.stderr is not None
        denial = process.stderr.read()
        assert b"schema" in denial and b"work exceeds limit" in denial
    finally:
        if process.poll() is None:
            process.kill()
        if process.stdin is not None:
            process.stdin.close()


def test_sanitizer_parent_eof_terminates_child_that_ignores_eof_bounded(
    tmp_path: Path,
) -> None:
    node = _node()
    child = _child(
        tmp_path,
        "process.stdin.resume(); process.stdin.on('end',()=>{}); setInterval(()=>{},1000);\n",
    )
    started = time.monotonic()
    result = subprocess.run(
        [node, str(SANITIZER), "--backend=claude", node, str(child)],
        input=b"", capture_output=True, timeout=5,
    )
    assert result.returncode != 0
    assert time.monotonic() - started < 4.0
    assert b"child did not exit after parent EOF" in result.stderr


def test_sanitizer_rejects_oversized_unterminated_child_output(tmp_path: Path) -> None:
    node = _node()
    child = _child(
        tmp_path,
        "process.stdout.write('x'.repeat(4*1024*1024+1)); setInterval(()=>{},1000);\n",
    )
    result = subprocess.run(
        [node, str(SANITIZER), "--backend=codex", node, str(child)],
        input="{}\n", capture_output=True, text=True, timeout=15,
    )
    assert result.returncode != 0
    assert "unterminated child message exceeds limit" in result.stderr


def test_sanitizer_malformed_parent_with_held_open_stdin_exits_bounded(
    tmp_path: Path,
) -> None:
    node = _node()
    child = _child(tmp_path, "process.stdin.resume(); setInterval(()=>{},1000);\n")
    process = subprocess.Popen(
        [node, str(SANITIZER), "--backend=codex", node, str(child)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        assert process.stdin is not None
        process.stdin.write(b"{bad}\n")
        process.stdin.flush()
        # Do not close stdin: the denial path itself must release the client pipe.
        assert process.wait(timeout=4) != 0
        assert process.stderr is not None
        assert b"MCP sanitizer denied" in process.stderr.read()
    finally:
        if process.poll() is None:
            process.kill()
        if process.stdin is not None:
            process.stdin.close()


def test_sanitizer_rejects_truncated_parent_tail(tmp_path: Path) -> None:
    node = _node()
    child = _child(tmp_path, "process.stdin.resume();\n")
    result = subprocess.run(
        [node, str(SANITIZER), "--backend=claude", node, str(child)],
        input=b'{"jsonrpc":"2.0"', capture_output=True, timeout=5,
    )
    assert result.returncode != 0
    assert b"truncated parent message at EOF" in result.stderr


def test_sanitizer_rejects_truncated_child_tail(tmp_path: Path) -> None:
    node = _node()
    child = _child(
        tmp_path,
        'process.stdout.write(\'{"jsonrpc":"2.0"\');\n',
    )
    result = subprocess.run(
        [node, str(SANITIZER), "--backend=codex", node, str(child)],
        input=b"", capture_output=True, timeout=5,
    )
    assert result.returncode != 0
    assert b"truncated child message at EOF" in result.stderr


@pytest.mark.parametrize("direction", ["parent", "child"])
def test_sanitizer_rejects_invalid_utf8(tmp_path: Path, direction: str) -> None:
    node = _node()
    invalid_line = b'{"value":"\xff"}\n'
    if direction == "parent":
        child = _child(tmp_path, "process.stdin.resume(); setInterval(()=>{},1000);\n")
        command = [node, str(SANITIZER), "--backend=claude", node, str(child)]
        result = subprocess.run(command, input=invalid_line, capture_output=True, timeout=5)
    else:
        child = _child(
            tmp_path,
            "process.stdout.write(Buffer.from([123,34,118,97,108,117,101,34,58,34,255,34,125,10])); setInterval(()=>{},1000);\n",
        )
        command = [node, str(SANITIZER), "--backend=codex", node, str(child)]
        result = subprocess.run(command, input=b"{}\n", capture_output=True, timeout=5)
    assert result.returncode != 0
    assert f"invalid UTF-8 in {direction} message".encode() in result.stderr


def test_sanitizer_backpressures_child_when_parent_stdout_stalls(tmp_path: Path) -> None:
    node = _node()
    completed = tmp_path / "child-completed"
    child = _child(tmp_path, f"""
const fs = require('fs');
const payload = JSON.stringify({{jsonrpc:'2.0',method:'progress',params:{{blob:'x'.repeat(256*1024)}}}}) + '\\n';
let remaining = 128;
function pump() {{
  while (remaining > 0) {{
    remaining -= 1;
    if (!process.stdout.write(payload)) {{ process.stdout.once('drain', pump); return; }}
  }}
  fs.writeFileSync({json.dumps(str(completed))}, 'done');
  setInterval(()=>{{}}, 1000);
}}
pump();
""")
    process = subprocess.Popen(
        [node, str(SANITIZER), "--backend=codex", node, str(child)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        # Leave stdout unread. Correct propagation fills the sanitizer/client
        # pipe, pauses child.stdout, then fills the child/sanitizer pipe before
        # the producer can emit the complete 32 MiB sequence.
        time.sleep(1.5)
        assert not completed.exists(), "sanitizer drained child into unbounded stdout state"
        assert process.stdin is not None
        process.stdin.write(b"{bad}\n")
        process.stdin.flush()
        assert process.wait(timeout=4) != 0
    finally:
        if process.poll() is None:
            process.kill()
        if process.stdin is not None:
            process.stdin.close()


def test_sanitizer_propagates_child_exit_with_client_stdin_held_open(
    tmp_path: Path,
) -> None:
    node = _node()
    child = _child(tmp_path, "process.exit(7);\n")
    process = subprocess.Popen(
        [node, str(SANITIZER), "--backend=claude", node, str(child)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        assert process.wait(timeout=4) == 7
    finally:
        if process.poll() is None:
            process.kill()
        if process.stdin is not None:
            process.stdin.close()


@pytest.mark.skipif(os.name == "nt", reason="portable POSIX child-signal assertion")
def test_sanitizer_reports_signaled_child(tmp_path: Path) -> None:
    node = _node()
    child = _child(tmp_path, "process.kill(process.pid, 'SIGTERM');\n")
    result = subprocess.run(
        [node, str(SANITIZER), "--backend=codex", node, str(child)],
        input=b"", capture_output=True, timeout=5,
    )
    assert result.returncode != 0
    assert b"MCP child terminated by SIGTERM" in result.stderr


@pytest.mark.skipif(os.name == "nt", reason="portable POSIX signal assertion")
def test_sanitizer_forwards_sigterm_and_exits(tmp_path: Path) -> None:
    node = _node()
    child = _child(tmp_path, "process.stdin.resume(); setInterval(()=>{},1000);\n")
    process = subprocess.Popen(
        [node, str(SANITIZER), "--backend=claude", node, str(child)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    process.terminate()
    process.wait(timeout=10)
    assert process.returncode != 0


@pytest.mark.skipif(os.name == "nt", reason="stock Node exposes owned process groups only on POSIX")
def test_sanitizer_signal_kills_owned_posix_child_process_group(tmp_path: Path) -> None:
    node = _node()
    ready = tmp_path / "child-ready"
    descendant_marker = tmp_path / "descendant-survived"
    grandchild = (
        "const fs=require('fs');"
        f"setTimeout(()=>{{fs.writeFileSync({json.dumps(str(descendant_marker))},'survived');process.exit(0)}},2000);"
    )
    child = _child(tmp_path, f"""
const fs=require('fs'), {{spawn}}=require('child_process');
spawn(process.execPath,['-e',{json.dumps(grandchild)}],{{stdio:'ignore'}});
fs.writeFileSync({json.dumps(str(ready))},'ready');
setInterval(()=>{{}},1000);
""")
    process = subprocess.Popen(
        [node, str(SANITIZER), "--backend=claude", node, str(child)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        deadline = time.monotonic() + 5
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert ready.exists(), "child process group did not become ready"
        process.terminate()
        assert process.wait(timeout=4) != 0
        time.sleep(2.25)
        assert not descendant_marker.exists()
    finally:
        if process.poll() is None:
            process.kill()
        if process.stdin is not None:
            process.stdin.close()


def test_front_source_has_no_executable_fixed_node_modules_route() -> None:
    source = (ROOT / "plamen.py").read_text(encoding="utf-8")
    locked_region = source[source.index("def _locked_claude_cli"):source.index("def _windows_plamen_command_bytes")]
    assert "mcp-packages" not in locked_region
    assert "node_modules" not in locked_region
    assert "backend-launch" in source and "mcp-launch" in source
