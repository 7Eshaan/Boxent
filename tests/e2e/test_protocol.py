"""Verification suite E: the MCP contract, seen from a real client over stdio."""

import asyncio
import base64
import json
import subprocess

import jsonschema
import pytest
from mcp.shared.exceptions import MCPError

from conftest import BOXENT, call, ok, open_session

TOOLS = {"run_bash", "run_python", "write_file", "read_file", "create_sandbox", "destroy_sandbox"}


async def test_e1_tools_have_strict_input_and_output_schemas():
    async with open_session() as session:
        await _test_e1_tools_have_strict_input_and_output_schemas(session)


async def _test_e1_tools_have_strict_input_and_output_schemas(session):
    tools = {t.name: t for t in (await session.list_tools()).tools}
    assert set(tools) == TOOLS
    for t in tools.values():
        assert t.description, t.name
        assert t.input_schema["type"] == "object"
        assert t.input_schema["additionalProperties"] is False, t.name
        assert t.output_schema and t.output_schema["type"] == "object", t.name
        jsonschema.Draft202012Validator.check_schema(t.output_schema)
    # Every result in this test validates against its declared output schema.
    out = await ok(session, "run_bash", command="echo hi")
    jsonschema.validate(out, tools["run_bash"].output_schema)
    out = await ok(session, "write_file", path="a.txt", content="x")
    jsonschema.validate(out, tools["write_file"].output_schema)
    out = await ok(session, "read_file", path="a.txt")
    jsonschema.validate(out, tools["read_file"].output_schema)


def test_e2_stdout_carries_only_json_rpc():
    """Raw stdio: every line on stdout is a JSON-RPC message; diagnostics go to stderr."""
    msgs = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "e2", "version": "0"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
            "name": "run_bash", "arguments": {"command": "echo out; echo err >&2; printf '\\x00\\xff'"}}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
            "name": "run_bash", "arguments": {"command": "exit 3"}}},
    ]
    proc = subprocess.Popen([BOXENT, "mcp"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    for m in msgs:
        proc.stdin.write((json.dumps(m) + "\n").encode())
    proc.stdin.flush()
    seen = {}
    while len(seen) < 3:
        line = proc.stdout.readline()
        assert line, "stdout closed early"
        msg = json.loads(line)  # raises if anything else was printed
        assert msg["jsonrpc"] == "2.0"
        seen[msg["id"]] = msg
    proc.stdin.close()
    proc.wait(timeout=10)
    assert seen[2]["result"]["structuredContent"]["stdout"] == "out\n\x00�"
    assert seen[3]["result"]["structuredContent"]["exit_code"] == 3


async def test_e3_errors_are_structured():
    async with open_session() as session:
        await _test_e3_errors_are_structured(session)


async def _test_e3_errors_are_structured(session):
    # Schema violations come back as tool errors (MCP 2025-11-25+), so the model can correct them.
    err, is_err = await call(session, "run_bash", comand="typo")
    assert is_err and "unknown field `comand`" in err["message"]
    err, is_err = await call(session, "run_bash")
    assert is_err and "command" in err["message"]
    with pytest.raises(MCPError):  # unknown tool: JSON-RPC error
        await session.call_tool("no_such_tool", {})
    err, is_err = await call(session, "run_bash", command="true", sandbox_id="sb-does-not-exist")
    assert is_err and err["code"] == "sandbox_not_found"
    err, is_err = await call(session, "run_bash", command="true", timeout_sec=0)
    assert is_err and err["code"] == "invalid_argument"
    err, is_err = await call(session, "write_file", path="/etc/passwd", content="x")
    assert is_err and err["code"] == "invalid_path"
    err, is_err = await call(session, "write_file", path="b.bin", content="%%%", encoding="base64")
    assert is_err and err["code"] == "invalid_argument"
    err, is_err = await call(session, "read_file", path="nope.txt")
    assert is_err and err["code"] == "not_found"
    err, is_err = await call(session, "create_sandbox", profile="gpu")
    assert is_err and err["code"] == "invalid_argument"


async def test_e4_huge_and_binary_output_is_capped_and_valid():
    async with open_session() as session:
        await _test_e4_huge_and_binary_output_is_capped_and_valid(session)


async def _test_e4_huge_and_binary_output_is_capped_and_valid(session):
    out = await ok(session, "run_bash", command="head -c 10000000 /dev/urandom | base64 -w0")
    assert out["stdout_truncated"] and out["stdout_total_bytes"] == 13333336
    assert len(out["stdout"].encode()) <= 64 * 1024 + 64
    assert "bytes omitted" in out["stdout"]
    out = await ok(session, "run_bash", command="head -c 4096 /dev/urandom")
    assert out["stdout_total_bytes"] == 4096 and not out["stdout_truncated"]
    out["stdout"].encode("utf-8")  # always valid UTF-8 (invalid bytes replaced)


async def test_e5_parallel_calls_across_and_within_sandboxes():
    async with open_session() as session:
        await _test_e5_parallel_calls_across_and_within_sandboxes(session)


async def _test_e5_parallel_calls_across_and_within_sandboxes(session):
    created = [await ok(session, "create_sandbox") for _ in range(3)]
    ids = [c["sandbox_id"] for c in created]
    jobs = [call(session, "run_bash", command=f"sleep 0.3; echo {i}", sandbox_id=ids[i % 3])
            for i in range(9)]
    jobs += [call(session, "run_bash", command=f"sleep 0.3; echo d{i}") for i in range(3)]
    loop = asyncio.get_running_loop()
    t = loop.time()
    results = await asyncio.gather(*jobs)
    took = loop.time() - t
    assert all(not err for _, err in results)
    assert sorted(r["stdout"].strip() for r, _ in results) == sorted(
        [str(i) for i in range(9)] + [f"d{i}" for i in range(3)])
    assert took < 2.0, f"parallel calls took {took:.2f}s"
    for i in ids:
        await ok(session, "destroy_sandbox", sandbox_id=i)


async def test_session_routing_and_sandbox_lifecycle():
    async with open_session() as session:
        await _test_session_routing_and_sandbox_lifecycle(session)


async def _test_session_routing_and_sandbox_lifecycle(session):
    a = await ok(session, "run_bash", command="echo 1 > state.txt")
    b = await ok(session, "run_bash", command="cat state.txt")
    assert a["sandbox_id"] == b["sandbox_id"] and b["stdout"] == "1\n"

    other = (await ok(session, "create_sandbox"))["sandbox_id"]
    assert other != a["sandbox_id"]
    r = await ok(session, "run_bash", command="ls -A", sandbox_id=other)
    assert r["stdout"] == "" and r["sandbox_id"] == other

    payload = bytes(range(256))
    await ok(session, "write_file", path="bin/data", content=base64.b64encode(payload).decode(),
             encoding="base64", mode="600", sandbox_id=other)
    got = await ok(session, "read_file", path="bin/data", sandbox_id=other)
    assert got["encoding"] == "base64" and base64.b64decode(got["content"]) == payload
    assert (await ok(session, "run_bash", command="stat -c %a bin/data", sandbox_id=other))["stdout"] == "600\n"

    py = await ok(session, "run_python", code="import os\nprint(os.getcwd(), os.getuid())")
    assert py["stdout"] == "/workspace 1000\n" and py["sandbox_id"] == a["sandbox_id"]

    await ok(session, "destroy_sandbox", sandbox_id=other)
    err, is_err = await call(session, "run_bash", command="true", sandbox_id=other)
    assert is_err and err["code"] == "sandbox_reaped"

    # Destroying the default makes the next call start a fresh one.
    await ok(session, "destroy_sandbox")
    fresh = await ok(session, "run_bash", command="ls -A | wc -l")
    assert fresh["sandbox_id"] != a["sandbox_id"] and fresh["stdout"] == "0\n"


async def test_sandbox_ids_work_across_sessions():
    """sandbox_id is a capability: a second connection can use it (stateless clients)."""
    async with open_session() as s1:
        sid = (await ok(s1, "create_sandbox"))["sandbox_id"]
        await ok(s1, "write_file", path="shared.txt", content="hello", sandbox_id=sid)
        async with open_session() as s2:
            out = await ok(s2, "run_bash", command="cat shared.txt", sandbox_id=sid)
            assert out["stdout"] == "hello"
        await ok(s1, "destroy_sandbox", sandbox_id=sid)
