"""RevSecHooks: RevSec checks for a Strands agent.

What it does, with nothing else to change in the agent:

  * each tool call is checked by RevSec before it runs. A call to an MCP
    server's tool is checked against that MCP server; a call to one of the
    agent's own tools is checked as the agent's, against its hold and its
    tool-call policies, and is never filed as an MCP server. A blocked call
    never runs; the model gets a tool result saying why;
  * what the user asks is checked before it reaches the model, and what each
    tool hands back is checked before the model reads it, with RevSec's Model
    Security check (instructions aimed at the model, secrets, personal data).
    A stopped prompt never reaches the model or the conversation; a stopped
    tool result is replaced with one saying it was withheld;
  * the agent is put in RevSec's agent registry on its first request, with
    the model and tools it was built with.

    from strands import Agent
    from strands_revsec import RevSecHooks

    agent = Agent(tools=[lookup_order], hooks=[RevSecHooks(agent_name="orders-agent")])

No AI gateway is needed. If your model calls go through the RevSec AI gateway,
turn the prompt check here off with ``revsec.mcp.configure(check_prompts=False)``.
"""
from __future__ import annotations

import json
import logging
import os
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from revsec import agent as _agent
from revsec import checks as _checks
from revsec import mcp as _mcp
from revsec import tools as _tools
from strands.hooks import (
    AfterToolCallEvent,
    BeforeInvocationEvent,
    BeforeModelCallEvent,
    BeforeToolCallEvent,
    HookProvider,
    HookRegistry,
)

from strands.tools.mcp import MCPAgentTool

from strands_revsec._version import __version__
from strands_revsec.mcp import identity_of

try:                                    # Strands' named hook orders (interventions and later)
    from strands.hooks import HookOrder
    _CHECK_ORDER: Optional[float] = HookOrder.INTERVENTION_INPUT - 1
except ImportError:                     # pragma: no cover - an older Strands: default order
    _CHECK_ORDER = None

logger = logging.getLogger("strands_revsec")

INTEGRATION = f"strands-revsec/{__version__}"
FRAMEWORK = "strands_agents"            # RevSec's name for Strands Agents in its framework registry
# A conversation's Strands session id becomes its RevSec session id (a UUID), so the calls in one conversation show
# as one chain in the Activity Explorer.
_SESSION_NAMESPACE = uuid.UUID("2b8e6f1a-7c4d-4e5f-9a8b-1c2d3e4f5a6b")
_BLOCKED_KEY = "revsec_prompt_blocked"
# What stays in the conversation in place of a prompt RevSec stopped (the prompt itself is never stored).
WITHHELD_PROMPT = "[Prompt withheld by RevSec]"


def _text_of(content: Any) -> str:
    """The text in a list of Strands content blocks: the text blocks, else the JSON ones as text (a server that sends
    structured content sends it as text too, so it is read once). Tool uses and images are left out."""
    texts = [b["text"] for b in content or () if isinstance(b, dict) and isinstance(b.get("text"), str)]
    if not any(t.strip() for t in texts):
        texts = []
        for block in content or ():
            if isinstance(block, dict) and "json" in block:
                try:
                    texts.append(json.dumps(block["json"], ensure_ascii=False, default=str))
                except (TypeError, ValueError):
                    pass
    return "\n".join(t for t in texts if t.strip())


def _user_text(messages: Any) -> str:
    """What the user sent in this request: the text of its user messages (never tool results)."""
    return "\n".join(t for t in (_text_of(m.get("content")) for m in (messages or ())
                                 if isinstance(m, dict) and m.get("role") == "user") if t)


def _model_id(agent: Any) -> Optional[str]:
    try:
        cfg = agent.model.get_config()
        mid = cfg.get("model_id") if isinstance(cfg, dict) else None
        return str(mid) if mid else None
    except Exception:  # noqa: BLE001
        return None


class RevSecHooks(HookProvider):
    """Checks each request, tool call and tool result with RevSec and registers the agent.

    Args:
        agent_name: the agent's name in RevSec (one per agent; registering again updates the same agent).
        api_key: a RevSec SDK key. Default: the REVSEC_API_KEY environment variable.
        base_url: your RevSec address ending in /fcc. Default: REVSEC_BASE_URL. Leave both out if you already
            called ``revsec.mcp.configure()``.
        register: put the agent in RevSec's registry on its first request.
        description, owner_email, environment, customer_facing: shown on the agent in RevSec (customer_facing
            also feeds its setup rating).
        on_block: "message" (default) tells the model, or the user for a stopped request, why; "raise" raises
            ``revsec.RevsecBlocked`` for a stopped request, and Strands' ``EventLoopException`` (with the
            ``RevsecBlocked`` as ``original_exception``) for a stopped tool call. A tool result RevSec stops is
            always withheld (Strands does not let a raise after a tool through).
    """

    def __init__(
        self,
        *,
        agent_name: str,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        register: bool = True,
        description: Optional[str] = None,
        owner_email: Optional[str] = None,
        environment: Optional[str] = None,
        customer_facing: Optional[bool] = None,
        on_block: str = "message",
    ) -> None:
        if not agent_name or not agent_name.strip():
            raise ValueError("agent_name is required: the agent's name in RevSec")
        if on_block not in ("message", "raise"):
            raise ValueError("on_block must be 'message' or 'raise'")
        key = api_key or (None if _mcp._config.api_key else os.environ.get("REVSEC_API_KEY"))
        if key or base_url:
            if not (key or _mcp._config.api_key):
                raise ValueError("RevSec key not set: pass api_key= or set REVSEC_API_KEY")
            _mcp.configure(api_key=key or _mcp._config.api_key, base_url=base_url)
        elif not _mcp._config.api_key:
            raise ValueError("RevSec key not set: pass api_key= or set REVSEC_API_KEY "
                             "(Settings → SDK in the RevSec console issues one)")
        self.agent_name = agent_name.strip()
        self.on_block = on_block
        self._registered = not register
        self._profile = {"description": description, "owner_email": owner_email, "environment": environment}
        self._customer_facing = customer_facing
        self.agent_id: Optional[str] = None
        self.agent_status: Optional[str] = None
        # What a checked call needs after it runs, by its toolUseId (tool calls of one turn run concurrently)
        self._pending: Dict[str, Tuple[Optional[int], float, bool]] = {}

    # ── wiring ────────────────────────────────────────────────────────────

    def register_hooks(self, registry: HookRegistry, **kwargs: Any) -> None:
        order = {} if _CHECK_ORDER is None else {"order": _CHECK_ORDER}
        registry.add_callback(BeforeInvocationEvent, self._before_request, **order)
        registry.add_callback(BeforeModelCallEvent, self._before_model)
        registry.add_callback(BeforeToolCallEvent, self._before_tool, **order)
        registry.add_callback(AfterToolCallEvent, self._after_tool)

    # ── registration ──────────────────────────────────────────────────────

    async def aregister_agent(self, *, models: Optional[List[str]] = None,
                              tools: Optional[List[str]] = None) -> Optional[str]:
        """Put the agent in RevSec's registry now (the hooks otherwise do it on the first request). Returns its id,
        or None when RevSec refused or could not be reached: that is logged as an error and its calls are still
        checked, without the agent."""
        self._registered = True
        try:
            me = await _agent.aregister(
                name=self.agent_name, framework=FRAMEWORK, models=[m for m in models or [] if m],
                tools=[t for t in tools or [] if t], tags={"integration": INTEGRATION},
                customer_facing=self._customer_facing, **{k: v for k, v in self._profile.items() if v})
        except _agent.RegistrationFailed as e:
            logger.error("RevSec did not register agent %r: %s. Its calls are still checked, but agent-level "
                         "rules can't apply to it.", self.agent_name, e)
            return None
        self.agent_id, self.agent_status = me.agent_id, me.status
        return self.agent_id

    def register_agent(self, **kwargs: Any) -> Optional[str]:
        """Sync form of ``aregister_agent``."""
        return _mcp._run_async(self.aregister_agent(**kwargs))

    @staticmethod
    def _session_of(agent: Any) -> Optional[str]:
        sid = getattr(agent, "session_id", None)
        return str(uuid.uuid5(_SESSION_NAMESPACE, str(sid))) if sid else None

    # ── the request, before the model ─────────────────────────────────────

    async def _before_request(self, event: BeforeInvocationEvent) -> None:
        agent = event.agent
        if not self._registered:
            await self.aregister_agent(models=[_model_id(agent)] if _model_id(agent) else [],
                                       tools=list(getattr(agent, "tool_names", None) or []))
        if not (_mcp._config.enabled and _mcp._config.check_prompts):
            return
        prompt = _user_text(event.messages)
        if not prompt.strip():
            return
        verdict = await _checks.check_prompt(prompt, agent_id=self.agent_id, model=_model_id(agent),
                                             session_id=self._session_of(agent))
        if verdict.allowed:
            return
        if self.on_block == "raise":
            raise _mcp.RevsecBlocked(verdict.as_decision())
        why = (verdict.reason or verdict.rule_name or "a RevSec policy").rstrip(". ")
        # The prompt never reaches the model or the conversation: a placeholder stands in its place, and the model
        # call is cancelled with the reply (``_before_model``), so the turns still alternate.
        event.messages = [{"role": "user", "content": [{"text": WITHHELD_PROMPT}]}]
        event.invocation_state[_BLOCKED_KEY] = (f"Blocked by RevSec: {why}. "
                                                "This request was not sent to the model.")

    async def _before_model(self, event: BeforeModelCallEvent) -> None:
        reply = event.invocation_state.pop(_BLOCKED_KEY, None)
        if reply:
            event.cancel = reply

    # ── tool calls ────────────────────────────────────────────────────────

    def _blocked(self, event: BeforeToolCallEvent, decision: Any) -> None:
        if self.on_block == "raise":
            raise _mcp.RevsecBlocked(decision)
        reason = decision.reason or f"policy '{decision.policy_name or 'unnamed'}'"
        event.cancel_tool = f"Blocked by RevSec: {reason}"

    async def _before_tool(self, event: BeforeToolCallEvent) -> None:
        tool, use = event.selected_tool, event.tool_use
        if tool is None:
            return                               # an unknown tool: Strands answers it, nothing runs
        name = str(use.get("name") or "")
        args = dict(use.get("input") or {}) if isinstance(use.get("input"), dict) else {}
        session = self._session_of(event.agent)
        if not isinstance(tool, MCPAgentTool):
            # One of the agent's own tools: checked as the agent's, never as an MCP server's.
            decision = await _tools.evaluate(tool=name, args=args, agent_id=self.agent_id, session_id=session)
            if not decision.allowed and not decision.soft_launch_only:
                return self._blocked(event, decision)
            data = await _tools.scan_args(tool=name, args=args, agent_id=self.agent_id)
            if data is not None:
                return self._blocked(event, data)
            self._pending[str(use.get("toolUseId"))] = (None, time.perf_counter(), False)
            return
        ident = identity_of(tool.mcp_client)
        server, mcp_tool = ident["server"], getattr(getattr(tool, "mcp_tool", None), "name", None) or name
        extra = {k: ident[k] for k in ("server_url", "package", "transport") if ident.get(k)}
        decision = await _mcp.evaluate(server=server, tool=mcp_tool, args=args, agent_id=self.agent_id,
                                       tool_input_redacted=_mcp._redact_payload(args), session_id=session, **extra)
        if not decision.allowed and not decision.soft_launch_only:
            await _mcp.record_outcome(event_id=decision.event_id, outcome="blocked", response_latency_ms=0)
            return self._blocked(event, decision)
        try:            # what the tool sends out, with revsec.mcp.configure(dlp=True)
            await _mcp._egress_dlp_gate(kwargs=args, server=server, tool=mcp_tool, agent_id=self.agent_id,
                                        api_key=None, event_id=decision.event_id)
        except _mcp.RevsecBlocked as blocked:
            return self._blocked(event, blocked.decision)
        self._pending[str(use.get("toolUseId"))] = (decision.event_id, time.perf_counter(), True)

    async def _after_tool(self, event: AfterToolCallEvent) -> None:
        use_id = str(event.tool_use.get("toolUseId"))
        pending = self._pending.pop(use_id, None)
        if event.cancel_message is not None or pending is None:
            return                               # never ran (stopped here or by another hook)
        event_id, started, is_mcp = pending
        result = event.result or {}
        failed = event.exception is not None or result.get("status") == "error"
        if is_mcp:
            content = result.get("content")
            took = getattr(event, "duration", None)
            await _mcp.record_outcome(
                event_id=event_id, outcome="error" if failed else "success",
                response_latency_ms=int((took if took is not None else time.perf_counter() - started) * 1000),
                response_size_bytes=len(json.dumps(content, default=str).encode("utf-8")) if content else None)
        if failed or not (_mcp._config.enabled and _mcp._config.check_tool_results):
            return
        text = _text_of(result.get("content"))
        if not text.strip() and result.get("structuredContent") is not None:
            text = json.dumps(result["structuredContent"], ensure_ascii=False, default=str)
        if not text.strip():
            return
        verdict = await _checks.check_tool_result(text, tool=str(event.tool_use.get("name") or ""),
                                                  agent_id=self.agent_id, session_id=self._session_of(event.agent))
        if not verdict.allowed:
            event.result = {"toolUseId": result.get("toolUseId", use_id), "status": "error",
                            "content": [{"text": verdict.withheld_text("tool result")}]}
