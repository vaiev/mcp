"""Control MCP server (stdio): exposes the allow-listed actions of control.toml as three tools.

    CONTROL_CONFIG=/path/to/control.toml python3 server.py

Tools: list_actions(), run_read(action, params), run_change(action, params, approved).
Register it in your agent CLI as a stdio MCP server; the CLI starts it outside its own shell sandbox, so the
server is the only place that runs the wrapped commands.
"""
from __future__ import annotations

import os
from pathlib import Path

import control_core as cc

try:  # MCP Python SDK 2.x
    from mcp.server.mcpserver import MCPServer as _Server
except ImportError:  # SDK 1.x
    from mcp.server.fastmcp import FastMCP as _Server

CONFIG = cc.load(os.environ.get("CONTROL_CONFIG", Path(__file__).with_name("control.toml")))

server = _Server(
    "control",
    instructions="Run only the allow-listed actions from list_actions. Read actions are free; change actions need "
                 "approved='<who> <YYYY-MM-DD>: <what>' from the owner and are written to the audit log. Deletions "
                 "and destroys are refused: a human runs them.",
)


@server.tool()
def list_actions() -> list[dict]:
    """List the allowed actions with their kind (read/change), description and parameter names."""
    return cc.list_actions(CONFIG)


@server.tool()
def run_read(action: str, params: dict[str, str] | None = None) -> dict:
    """Run a read action. Change actions are refused here; use run_change with the owner's approval."""
    if action in CONFIG.actions and CONFIG.actions[action].kind != "read":
        return {"status": "refused", "reason": f"{action} changes something: use run_change"}
    return cc.run(CONFIG, action, params or {})


@server.tool()
def run_change(action: str, approved: str, params: dict[str, str] | None = None) -> dict:
    """Run a change action with the owner's approval '<who> <YYYY-MM-DD>: <what>' (audited before and after)."""
    return cc.run(CONFIG, action, params or {}, approved=approved)


if __name__ == "__main__":
    server.run("stdio")
