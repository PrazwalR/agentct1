"""LangChain-compatible payment-tool middleware.

Routes payment-tool calls through the agentctl guard before they execute. Kept
framework-light — it does not import LangChain, so it also works with CrewAI,
AutoGen, or any agent loop that offers a `wrap_tool_call` seam.

LangChain's middleware protocol is **async**: `wrap_tool_call` is awaited and so is
the handler it receives. This exposes `awrap_tool_call` for that, and keeps a
synchronous `wrap_tool_call` for plain agent loops. The async path uses a real async
subprocess so evaluating a payment never stalls the event loop.
"""

from __future__ import annotations

import inspect
from typing import Any, Awaitable, Callable, Iterable, Union

from .guard import AgentGuard, PaymentDecisionError, PaymentRequest

Handler = Callable[[str, dict], Union[Any, Awaitable[Any]]]


class AgentctlPaymentMiddleware:
    """Gate a named set of payment tools behind the guard.

    Args:
        guard: the configured AgentGuard.
        payment_tool_names: tools to intercept. Anything else passes straight through.
        on_escalate: optional async/sync callback for an escalated payment, returning
            True to approve. Without it an escalation is refused, which is the safe
            default — an agent must not be able to self-approve.
    """

    def __init__(
        self,
        guard: AgentGuard,
        payment_tool_names: Iterable[str],
        on_escalate: Callable[[PaymentRequest, Any], Union[bool, Awaitable[bool]]] | None = None,
    ):
        self.guard = guard
        self.payment_tools = set(payment_tool_names)
        self.on_escalate = on_escalate

    # ── request construction ────────────────────────────────────────────────

    def _to_request(self, tool_name: str, tool_args: dict) -> PaymentRequest:
        missing = [k for k in ("amount", "token", "recipient") if k not in tool_args]
        if missing:
            raise PaymentDecisionError(
                f"{tool_name} is registered as a payment tool but its call is missing "
                f"{', '.join(missing)} — the guard cannot evaluate it, so it is refused."
            )
        return PaymentRequest(
            intent=tool_args.get("reason") or tool_args.get("intent") or f"{tool_name} payment",
            amount=int(tool_args["amount"]),
            token=tool_args["token"],
            recipient=tool_args["recipient"],
            chain=tool_args.get("chain", "eip155:84532"),
            agent_id=self.guard.agent_id,
            resource_url=tool_args.get("resource_url"),
        )

    @staticmethod
    def _refusal(decision) -> str:
        # Returned as the tool result so the agent can reason about it and pick another
        # action, rather than raising and derailing the run.
        if decision.verdict == "block":
            return f"Payment blocked by policy: {decision.reason}"
        return f"Payment requires human approval and was not approved: {decision.reason}"

    # ── async: LangChain's protocol ─────────────────────────────────────────

    async def awrap_tool_call(self, tool_name: str, tool_args: dict, next_handler: Handler):
        if tool_name not in self.payment_tools:
            return await _maybe_await(next_handler(tool_name, tool_args))

        decision = await self.guard.aevaluate(self._to_request(tool_name, tool_args))

        if decision.verdict == "block":
            return self._refusal(decision)
        if decision.verdict == "escalate":
            if self.on_escalate is None:
                return self._refusal(decision)
            approved = await _maybe_await(
                self.on_escalate(self._to_request(tool_name, tool_args), decision)
            )
            if not approved:
                return self._refusal(decision)

        return await _maybe_await(next_handler(tool_name, tool_args))

    # ── sync: plain agent loops ─────────────────────────────────────────────

    def wrap_tool_call(self, tool_name: str, tool_args: dict, next_handler: Handler):
        if tool_name not in self.payment_tools:
            return next_handler(tool_name, tool_args)

        decision = self.guard.evaluate(self._to_request(tool_name, tool_args))

        if decision.verdict == "block":
            return self._refusal(decision)
        if decision.verdict == "escalate":
            if self.on_escalate is None:
                return self._refusal(decision)
            approved = self.on_escalate(self._to_request(tool_name, tool_args), decision)
            if inspect.isawaitable(approved):
                raise PaymentDecisionError(
                    "on_escalate is async — use awrap_tool_call, not wrap_tool_call"
                )
            if not approved:
                return self._refusal(decision)

        return next_handler(tool_name, tool_args)


async def _maybe_await(value):
    """Accept a handler that is either sync or async."""
    return await value if inspect.isawaitable(value) else value
