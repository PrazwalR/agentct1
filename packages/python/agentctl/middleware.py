"""LangChain payment-tool middleware (see guide Part 8.1).

Routes payment-tool calls through the agentctl guard before they execute. Kept
framework-light — it does not import LangChain, so it works with LangChain's
middleware protocol (or any agent loop with a wrap_tool_call seam).
"""

from __future__ import annotations

from typing import Callable, Iterable

from .guard import AgentGuard, PaymentRequest


class AgentctlPaymentMiddleware:
    def __init__(self, guard: AgentGuard, payment_tool_names: Iterable[str]):
        self.guard = guard
        self.payment_tools = set(payment_tool_names)

    def wrap_tool_call(self, tool_name: str, tool_args: dict, next_handler: Callable):
        if tool_name not in self.payment_tools:
            return next_handler(tool_name, tool_args)

        req = PaymentRequest(
            intent=tool_args.get("reason") or tool_args.get("intent", f"{tool_name} payment"),
            amount=int(tool_args["amount"]),
            token=tool_args["token"],
            recipient=tool_args["recipient"],
            chain=tool_args.get("chain", "eip155:84532"),
            agent_id=self.guard.agent_id,
        )
        decision = self.guard.evaluate(req)
        if decision.verdict == "block":
            return f"Payment blocked by policy: {decision.reason}"
        if decision.verdict == "escalate":
            return f"Payment requires human approval (escalated): {decision.reason}"
        return next_handler(tool_name, tool_args)
