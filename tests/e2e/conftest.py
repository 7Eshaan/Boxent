"""Shared helpers: open MCP sessions to Boxent through `boxent mcp`, as an IDE would."""

import contextlib
import json
import os
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parents[2]
BOXENT = os.environ.get("BOXENT_BIN", str(ROOT / "target" / "debug" / "boxent"))


def server_params() -> StdioServerParameters:
    return StdioServerParameters(command=BOXENT, args=["mcp"])


@contextlib.asynccontextmanager
async def open_session():
    async with stdio_client(server_params()) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield session


async def call(session: ClientSession, tool: str, **args):
    """Calls a tool; returns (structured result or error object, is_error)."""
    r = await session.call_tool(tool, args)
    if r.is_error:
        text = "".join(c.text for c in r.content if getattr(c, "type", "") == "text")
        try:
            return json.loads(text)["error"], True
        except (ValueError, KeyError):
            # Argument validation errors come from the MCP SDK as plain text.
            return {"code": "invalid_params", "message": text}, True
    return r.structured_content, False


async def ok(session: ClientSession, tool: str, **args) -> dict:
    out, err = await call(session, tool, **args)
    assert not err, f"{tool} failed: {out}"
    return out
