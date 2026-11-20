"""strands-revsec: RevSec for Strands agents.

Add one hook provider to the Agent: RevSec checks each tool call before it
runs (an MCP server's tool against that MCP server, the agent's own tools as
the agent's), what the user asks before it reaches the model, and what each
tool hands back before the model reads it; records what happened, and lists
the agent in your RevSec console with its model and tools.

    from strands import Agent
    from strands_revsec import RevSecHooks, revsec_mcp_client

    notes = revsec_mcp_client("notes", command="npx", args=["-y", "@acme/notes-mcp"])
    agent = Agent(tools=[notes, lookup_order], hooks=[RevSecHooks(agent_name="orders-agent")])

No AI gateway is needed. A team whose model calls go through the RevSec AI
gateway turns the prompt check here off: ``revsec.mcp.configure(check_prompts=False)``.

Set REVSEC_API_KEY and REVSEC_BASE_URL first (Settings → SDK in the console).
"""
from strands_revsec._version import __version__
from strands_revsec.hooks import RevSecHooks
from strands_revsec.mcp import note_mcp_server, revsec_mcp_client, revsec_mcp_servers

__all__ = ["RevSecHooks", "revsec_mcp_client", "revsec_mcp_servers", "note_mcp_server", "__version__"]
