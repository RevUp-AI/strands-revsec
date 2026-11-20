"""A small MCP server for the tests (stdio): one read tool and one tool that
writes a marker file when it runs, so a test can tell it never ran."""
import os

try:                                            # mcp 2.x
    from mcp.server.mcpserver import MCPServer as Server
except ImportError:                             # mcp 1.x
    from mcp.server.fastmcp import FastMCP as Server

srv = Server("notes")


@srv.tool()
def read_note(name: str) -> str:
    """Read a note."""
    return f"note {name}: buy milk"


@srv.tool()
def delete_note(name: str) -> str:
    """Delete a note."""
    with open(os.environ["NOTES_MARKER"], "w") as f:
        f.write(name)
    return "deleted"


@srv.tool()
def archive_note(name: str) -> str:
    """Archive a note."""
    raise ValueError(f"no note called {name}")


if __name__ == "__main__":
    srv.run()
