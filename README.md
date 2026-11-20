# strands-revsec

RevSec for [Strands Agents](https://strandsagents.com). Add `RevSecHooks` to
your agent and RevSec checks each tool call before it runs: a call to an MCP
server's tool against that MCP server, a call to one of the agent's own tools
against the agent's own rules. A blocked call never runs, and the model is told
why. What the user asks is checked before it reaches the model, and what each
tool hands back before the model reads it. What happened is recorded, and the
agent is listed in your RevSec console with its model and tools.

Your rules live in RevSec, not in your code. If you ship agents to customers,
each customer account gets its own rules, approvals and evidence.

## Get a key

- **Shipping agents to your customers?** [Start a free trial](https://app.revsec.app/start?from=strands)
  and choose "AI we ship to our customers". Your Sandbox key is shown once, when you sign up.
- **Building agents for your own company?** [Book a demo](mailto:sales@revupai.com?subject=Book%20a%20RevSec%20demo).

```bash
pip install strands-revsec
export REVSEC_API_KEY="<your key>"
export REVSEC_BASE_URL="https://app.revsec.app/fcc"
```

## Add it to your agent

Build your MCP clients with `revsec_mcp_client` (in place of `MCPClient`) and
add `RevSecHooks`:

```python
from strands import Agent, tool
from strands_revsec import RevSecHooks, revsec_mcp_client

github = revsec_mcp_client("github", url="https://api.githubcopilot.com/mcp/")
notes = revsec_mcp_client("notes", command="npx", args=["-y", "@acme/notes-mcp"])

@tool
def lookup_order(order_id: str) -> str:
    """Look up an order."""
    ...

agent = Agent(
    tools=[github, notes, lookup_order],
    hooks=[RevSecHooks(agent_name="orders-agent")],
)
agent("Where is order A1?")
```

That's all. Block a tool in RevSec and run the agent: the call doesn't run,
and the model gets a tool result saying `Blocked by RevSec: <the reason>`, so
it can tell the user or try something else.

- **MCP tools** are checked against their MCP server: the server's approval,
  your MCP policies and its known vulnerabilities.
- **The agent's own tools** (functions in your code, like `lookup_order`) are
  checked as the agent's: its status (a quarantined agent is stopped) and its
  tool-call policies, such as "block `refund_order`". They are recorded with
  the agent's tool calls, never as an MCP server.
- **What a tool sends out** (secrets, personal data) is scanned by your data
  protection policies when you turn it on: `revsec.mcp.configure(..., dlp=True)`.
- **What a tool hands back** (a web page, a file, an MCP server's reply) is
  checked before the model reads it: instructions hidden in it, secrets,
  personal data. A result RevSec stops is replaced with one saying
  `Withheld by RevSec: ...`; the call itself ran.
- **Calls RevSec stops, holds or flags** reach your SIEM, if one is connected
  in the RevSec console.

## MCP servers

RevSec files each MCP server under the name you give it, and is told its
address, or for a local server the package it runs; never the rest of its
launch command (which can carry tokens).

- `revsec_mcp_client(name, url=...)` for a remote server, or
  `revsec_mcp_client(name, command=..., args=..., env=...)` for a local one.
  Other keyword arguments go to `MCPClient` (`prefix=`, `startup_timeout=`, ...).
- `revsec_mcp_servers("mcp.json")` in place of `MCPClient.load_servers(...)`:
  each server is filed under its key in the `mcpServers` config.
- An `MCPClient` you build yourself: `note_mcp_server(client, "github", url=...)`.

Calls to an MCP client RevSec can't name are still checked as MCP calls, under
`unnamed-mcp-server`, and a warning says how to name it.

Strands' MCP router tool reaches servers through one tool of the agent's
(`mcp_router`), so RevSec checks those calls as that one tool. Give the agent
the MCP clients themselves to check each server's calls.

## Prompts

What the user asks is checked before it reaches the model, with the same Model
Security check RevSec runs for coding tools on a laptop: your prompt rules and
the built-in checks (prompt injection, secrets, personal data). A prompt
RevSec stops never reaches the model and isn't kept in the conversation; the
agent answers `Blocked by RevSec: <the reason>` instead, and the conversation
carries on. Each check is kept on the agent in RevSec, in the same
conversation as its tool calls, and the model it was about to call is listed
on the agent. No AI gateway is needed.

If your model calls go through the RevSec AI gateway (Settings → AI gateway in
the console), it checks prompts there; turn the check here off so each prompt
is checked once:

```python
from revsec import mcp
mcp.configure(api_key=os.environ["REVSEC_API_KEY"], check_prompts=False)
```

`check_tool_results=False` turns off the tool-result check.

## Options

| Option | Default | What it does |
|---|---|---|
| `agent_name` | required | The agent's name in RevSec. Registering again updates the same agent. |
| `api_key` | `REVSEC_API_KEY` | Your RevSec key. |
| `base_url` | `REVSEC_BASE_URL` | Your RevSec address, ending in `/fcc`. |
| `register` | `True` | List the agent in RevSec on its first request, with its model and tools. |
| `description`, `owner_email`, `environment` | none | Shown on the agent in RevSec. |
| `customer_facing` | none | `True` when the agent talks to your customers; shown on the agent and used in its setup rating. |
| `on_block` | `"message"` | `"raise"` raises instead of telling the model or the user: `revsec.RevsecBlocked` for a stopped prompt, and Strands' `EventLoopException` for a blocked tool call (the `RevsecBlocked` is its `original_exception`). A tool result RevSec stops is always withheld, since Strands doesn't pass on an error raised after a tool has run. |

A customer account key, such as the Sandbox key you get when you sign up,
checks the agent's tool calls and registers the agent in that customer account.

Calls and checks in one conversation (one `Agent`, or one session when you use
a Strands session manager) are grouped into one chain in RevSec's Activity
Explorer.

## When RevSec can't be reached

By default a call is allowed when RevSec can't be reached, so an outage never
stops your agent. To block instead:

```python
from revsec import mcp
mcp.configure(api_key=os.environ["REVSEC_API_KEY"], failure_mode="fail_closed")
```

`mcp.configure(api_key=..., enabled=False)` turns the checks off. This package
is built on [revsec-sdk](https://pypi.org/project/revsec-sdk/); its README
covers these settings.

Works with strands-agents 1.54 and later.

## License

Apache License 2.0; see [LICENSE](LICENSE). This package calls the RevSec
service through [revsec-sdk](https://pypi.org/project/revsec-sdk/); use of the
service is subject to the RevSec terms of service.
