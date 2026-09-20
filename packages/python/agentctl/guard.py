"""Python-facing guard API. Thin wrapper over the TS engine bridge."""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from ._bridge import evaluate_via_bridge, evaluate_via_bridge_async


class PaymentDecisionError(RuntimeError):
    """The guard could not reach a decision, so the payment is refused."""


@dataclass
class PaymentRequest:
    intent: str
    amount: int  # token units (e.g. USDC 6 decimals: 100000 == $0.10)
    token: str
    recipient: str
    chain: str = "eip155:84532"
    agent_id: str = "python-agent"
    resource_url: Optional[str] = None


@dataclass
class PolicyCheck:
    id: str
    passed: bool
    severity: str
    message: str


@dataclass
class PolicyDecision:
    verdict: str  # "allow" | "block" | "escalate"
    risk_score: float
    reason: str
    checks: List[PolicyCheck]


class AgentGuard:
    """Evaluates payments against a policy via the TS engine.

    `policy` is the compiler-output shape (USD amounts), e.g.::

        {
          "rules": [
            {"type": "spend-cap", "window": "day", "maxAmount": 20, "escalateAbove": 2},
            {"type": "allowlist", "mode": "recipients", "entries": ["0x.."], "enforce": True},
          ],
          "anomalyThreshold": 0.8,
          "anomalyAction": "escalate",
        }
    """

    def __init__(self, policy: dict, agent_id: str = "python-agent"):
        self.policy = policy
        self.agent_id = agent_id

    def _request(self, req: PaymentRequest) -> dict:
        return {
            "intent": req.intent,
            "amount": str(req.amount),
            "token": req.token,
            "recipient": req.recipient,
            "chain": req.chain,
            "agentId": req.agent_id or self.agent_id,
            "resourceUrl": req.resource_url,
        }

    @staticmethod
    def _decision(out: dict) -> PolicyDecision:
        return PolicyDecision(
            verdict=out["verdict"],
            risk_score=out["riskScore"],
            reason=out["reason"],
            checks=[PolicyCheck(**c) for c in out.get("checks", [])],
        )

    def evaluate(self, req: PaymentRequest) -> PolicyDecision:
        """Evaluate one payment. Blocking — use `aevaluate` inside an async agent."""
        return self._decision(evaluate_via_bridge(self.policy, self._request(req)))

    async def aevaluate(self, req: PaymentRequest) -> PolicyDecision:
        """Async evaluate, for async agent frameworks (LangChain, CrewAI, AutoGen)."""
        return self._decision(await evaluate_via_bridge_async(self.policy, self._request(req)))
