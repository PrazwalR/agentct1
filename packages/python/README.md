# agentctl (Python)

Python bindings for [agentctl](../../README.md). A thin wrapper that bridges to the
TypeScript decision engine via the `agentctl eval` JSON command — one engine, no
policy/behavioral/intent logic duplicated in Python.

## Requirements

- Node.js, and the built CLI (`pnpm -r build` at the repo root). Override the CLI
  location with `AGENTCTL_CLI=/path/to/cli.js` and the node binary with `NODE_BIN`.

## Usage

```python
from agentctl import AgentGuard, PaymentRequest

guard = AgentGuard({
    "rules": [
        {"type": "spend-cap", "window": "day", "maxAmount": 20, "escalateAbove": 2},
        {"type": "allowlist", "mode": "recipients", "entries": ["0x1111…"], "enforce": True},
    ],
    "anomalyThreshold": 0.8,
    "anomalyAction": "escalate",
})

decision = guard.evaluate(PaymentRequest(
    intent="weather data for trip",
    amount=15_000_000,            # token units (USDC 6 decimals)
    token="0x036CbD…",
    recipient="0x9999…",
))
print(decision.verdict, decision.reason)   # -> "block" ...
```

### LangChain

```python
from agentctl import AgentctlPaymentMiddleware

mw = AgentctlPaymentMiddleware(guard, ["pay_for_api"])
# wrap_tool_call(tool_name, tool_args, next_handler) routes payment tools through
# the guard; blocked/escalated payments return a message instead of executing.
```

Policy uses the compiler-output shape (USD amounts); the TS engine converts to token
units. Amounts in `PaymentRequest` are in token units.
