"""Bridges to the built TS CLI (packages/cli/dist/cli.js) — requires Node + a core/cli build."""

from agentctl import AgentGuard, AgentctlPaymentMiddleware, PaymentRequest

USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
KNOWN = "0x1111111111111111111111111111111111111111"
ATTACKER = "0x9999999999999999999999999999999999999999"

POLICY = {
    "rules": [
        {"type": "spend-cap", "window": "day", "maxAmount": 20, "escalateAbove": 2},
        {"type": "allowlist", "mode": "recipients", "entries": [KNOWN], "enforce": True},
    ],
    "anomalyThreshold": 0.8,
    "anomalyAction": "escalate",
}


def test_allow_small_known_payment():
    guard = AgentGuard(POLICY)
    decision = guard.evaluate(
        PaymentRequest(intent="weather data", amount=500_000, token=USDC, recipient=KNOWN)
    )
    assert decision.verdict == "allow"


def test_escalate_large_known_payment():
    guard = AgentGuard(POLICY)
    decision = guard.evaluate(
        PaymentRequest(intent="bulk compute", amount=15_000_000, token=USDC, recipient=KNOWN)
    )
    assert decision.verdict == "escalate"


def test_block_fresh_attacker_address():
    guard = AgentGuard(POLICY)
    decision = guard.evaluate(
        PaymentRequest(intent="weather data", amount=15_000_000, token=USDC, recipient=ATTACKER)
    )
    assert decision.verdict == "block"
    assert "allowlist" in decision.reason.lower()


def test_middleware_blocks_payment_tool():
    guard = AgentGuard(POLICY)
    mw = AgentctlPaymentMiddleware(guard, ["pay_for_api"])
    called = {"v": False}

    def next_handler(name, args):
        called["v"] = True
        return "tool ran"

    out = mw.wrap_tool_call(
        "pay_for_api",
        {"reason": "x", "amount": 15_000_000, "token": USDC, "recipient": ATTACKER},
        next_handler,
    )
    assert "blocked" in out.lower()
    assert called["v"] is False  # the real tool never ran
