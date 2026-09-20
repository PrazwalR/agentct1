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


# ── async middleware (LangChain's protocol is async) ────────────────────────

import asyncio

import pytest

from agentctl import PaymentDecisionError


def test_async_evaluate_matches_sync():
    guard = AgentGuard(POLICY)
    req = PaymentRequest(intent="weather data", amount=500_000, token=USDC, recipient=KNOWN)
    assert asyncio.run(guard.aevaluate(req)).verdict == guard.evaluate(req).verdict


def test_async_middleware_blocks_and_never_runs_the_tool():
    guard = AgentGuard(POLICY)
    mw = AgentctlPaymentMiddleware(guard, ["pay_for_api"])
    called = {"v": False}

    async def next_handler(name, args):
        called["v"] = True
        return "tool ran"

    out = asyncio.run(
        mw.awrap_tool_call(
            "pay_for_api",
            {"reason": "x", "amount": 15_000_000, "token": USDC, "recipient": ATTACKER},
            next_handler,
        )
    )
    assert "blocked" in out.lower()
    assert called["v"] is False


def test_async_middleware_lets_an_allowed_payment_through():
    guard = AgentGuard(POLICY)
    mw = AgentctlPaymentMiddleware(guard, ["pay_for_api"])

    async def next_handler(name, args):
        return "tool ran"

    out = asyncio.run(
        mw.awrap_tool_call(
            "pay_for_api",
            {"reason": "weather", "amount": 500_000, "token": USDC, "recipient": KNOWN},
            next_handler,
        )
    )
    assert out == "tool ran"


def test_async_middleware_refuses_an_escalation_without_an_approver():
    # An agent must never be able to self-approve: no handler means refused.
    guard = AgentGuard(POLICY)
    mw = AgentctlPaymentMiddleware(guard, ["pay_for_api"])

    async def next_handler(name, args):
        return "tool ran"

    out = asyncio.run(
        mw.awrap_tool_call(
            "pay_for_api",
            {"reason": "bulk compute", "amount": 15_000_000, "token": USDC, "recipient": KNOWN},
            next_handler,
        )
    )
    assert "approval" in out.lower()


def test_async_middleware_honours_an_async_approver():
    guard = AgentGuard(POLICY)

    async def approve(req, decision):
        return True

    mw = AgentctlPaymentMiddleware(guard, ["pay_for_api"], on_escalate=approve)

    async def next_handler(name, args):
        return "tool ran"

    out = asyncio.run(
        mw.awrap_tool_call(
            "pay_for_api",
            {"reason": "bulk compute", "amount": 15_000_000, "token": USDC, "recipient": KNOWN},
            next_handler,
        )
    )
    assert out == "tool ran"


def test_non_payment_tools_pass_straight_through():
    guard = AgentGuard(POLICY)
    mw = AgentctlPaymentMiddleware(guard, ["pay_for_api"])

    async def next_handler(name, args):
        return "search ran"

    assert asyncio.run(mw.awrap_tool_call("search", {"q": "x"}, next_handler)) == "search ran"


def test_a_payment_tool_missing_fields_is_refused_not_guessed():
    guard = AgentGuard(POLICY)
    mw = AgentctlPaymentMiddleware(guard, ["pay_for_api"])

    async def next_handler(name, args):
        return "tool ran"

    with pytest.raises(PaymentDecisionError, match="recipient"):
        asyncio.run(mw.awrap_tool_call("pay_for_api", {"amount": 1, "token": USDC}, next_handler))
