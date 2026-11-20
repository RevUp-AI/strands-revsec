"""MCP servers that RevSec recognises.

Strands keeps an MCP server's tools on an ``MCPClient`` and tells them apart
from the agent's own tools, but it does not keep how the server is reached
(its address, or the package a local server runs), and that is what RevSec
files the server under. Build the client with ``revsec_mcp_client`` or
``revsec_mcp_servers`` and the server's identity is noted on it, so each call
is checked against that MCP server (its approval, its policies, its known
vulnerabilities) and attaches to the record RevSec already has for it.

    from strands import Agent
    from strands_revsec import RevSecHooks, revsec_mcp_client

    github = revsec_mcp_client("github", url="https://api.githubcopilot.com/mcp/")
    notes = revsec_mcp_client("notes", command="npx", args=["-y", "@acme/notes-mcp"])
    agent = Agent(tools=[github, notes, lookup_order], hooks=[RevSecHooks(agent_name="orders-agent")])

An ``MCPClient`` you build yourself works too: note it with
``note_mcp_server(client, "github", url=...)``. Without a note, RevSec uses
the client's name and what Strands keeps of its connection.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Mapping, Optional, Sequence

from revsec._launch import package_from_launch

logger = logging.getLogger("strands_revsec")

# Where the server's identity is noted on an MCPClient.
IDENTITY_ATTR = "_revsec_mcp_server"
UNNAMED = "unnamed-mcp-server"


def server_identity(name: Optional[str], *, url: Optional[str] = None, command: Optional[str] = None,
                    args: Optional[Sequence[str]] = None) -> Dict[str, Any]:
    """How RevSec recognises a server: its name, and its address when remote or the package a runner starts when
    local (never the launch's other arguments, which can carry tokens)."""
    ident: Dict[str, Any] = {"server": name or UNNAMED}
    if url:
        ident.update(server_url=str(url), transport="remote")
    elif command:
        ident["transport"] = "stdio"
        package = package_from_launch(str(command), [str(a) for a in (args or [])])
        if package:
            ident["package"] = package
    return ident


def note_mcp_server(client: Any, name: str, *, url: Optional[str] = None, command: Optional[str] = None,
                    args: Optional[Sequence[str]] = None) -> Any:
    """Note on an ``MCPClient`` you built yourself which server it reaches. Returns the client."""
    setattr(client, IDENTITY_ATTR, server_identity(name, url=url, command=command, args=args))
    return client


def revsec_mcp_client(name: str, *, url: Optional[str] = None, command: Optional[str] = None,
                      args: Optional[Sequence[str]] = None, env: Optional[Mapping[str, str]] = None,
                      cwd: Optional[str] = None, **client_kwargs: Any) -> Any:
    """A Strands ``MCPClient`` for one server, with its identity noted: ``url=`` for a remote server (streamable
    HTTP), ``command=`` and ``args=`` for a local one (stdio). Other keyword arguments go to ``MCPClient``."""
    from strands.tools.mcp import MCPClient
    if bool(url) == bool(command):
        raise ValueError("give url= for a remote MCP server or command= for a local one")
    client_kwargs.setdefault("application_name", name)
    if url:
        client = MCPClient(url=url, **client_kwargs)
    else:
        from mcp import StdioServerParameters
        from mcp.client.stdio import stdio_client
        params = StdioServerParameters(command=str(command), args=[str(a) for a in (args or [])],
                                       env=dict(env) if env is not None else None, cwd=cwd)
        client = MCPClient(lambda: stdio_client(params), **client_kwargs)
    return note_mcp_server(client, name, url=url, command=command, args=args)


def _servers_mapping(config: Any) -> Dict[str, Dict[str, Any]]:
    if isinstance(config, (str, os.PathLike)):
        path = os.fspath(config)
        path = path[len("file://"):] if path.startswith("file://") else path
        with open(os.path.expanduser(path), encoding="utf-8") as f:
            config = json.load(f)
    if not isinstance(config, Mapping):
        raise ValueError("an mcpServers config is a JSON object of server name to its settings")
    inner = config.get("mcpServers", config)
    return {str(k): v for k, v in inner.items()}


def revsec_mcp_servers(config: Any, **load_kwargs: Any) -> List[Any]:
    """``MCPClient.load_servers(config)`` (an ``mcpServers`` JSON file or mapping), with each server's identity
    noted under its config key. Each server is loaded on its own, so its name is known for certain. Other keyword
    arguments go to ``load_servers``."""
    from strands.tools.mcp import MCPClient
    clients: List[Any] = []
    for name, cfg in _servers_mapping(config).items():
        loaded = MCPClient.load_servers({name: cfg}, **load_kwargs)
        settings = cfg if isinstance(cfg, Mapping) else {}
        for client in loaded:
            note_mcp_server(client, name, url=settings.get("url"), command=settings.get("command"),
                            args=settings.get("args"))
            clients.append(client)
    return clients


def _from_connection(client: Any) -> Dict[str, Any]:
    """What Strands keeps of a client's connection: the address or launch parameters its transport closes over (an
    ``MCPClient(url=...)`` or a ``load_servers`` client). Strands keeps these privately, so this is best effort and
    finds nothing for a transport the caller built inside a lambda."""
    found: Dict[str, Any] = {}
    fn = getattr(client, "_transport_callable", None)
    for cell in getattr(fn, "__closure__", None) or ():
        try:
            v = cell.cell_contents
        except ValueError:
            continue
        if isinstance(v, str) and v.startswith(("http://", "https://")):
            found["url"] = v
        elif hasattr(v, "command") and hasattr(v, "args"):
            found["command"], found["args"] = getattr(v, "command"), list(getattr(v, "args") or [])
    return found


_warned: set = set()


def identity_of(client: Any) -> Dict[str, Any]:
    """The server an MCP tool's client reaches, for RevSec: the noted identity, else the client's name and what
    Strands keeps of its connection, else an unnamed server (warned once per client)."""
    noted = getattr(client, IDENTITY_ATTR, None)
    if isinstance(noted, dict) and noted.get("server"):
        return noted
    # The name it reports to the server: ``client_name`` (Strands 1.6x), kept as ``_application_name`` before.
    name = getattr(client, "client_name", None) or getattr(client, "_application_name", None)
    try:
        conn = _from_connection(client)
    except Exception:  # noqa: BLE001 — Strands' private layout changed: name only
        conn = {}
    if not name and id(client) not in _warned:
        _warned.add(id(client))
        logger.warning("An MCP server's tools were used with no name for RevSec: build the client with "
                       "revsec_mcp_client(name, ...) so its calls are filed under that server.")
    return server_identity(name, url=conn.get("url"), command=conn.get("command"), args=conn.get("args"))
