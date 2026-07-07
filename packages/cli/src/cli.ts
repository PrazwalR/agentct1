import { readFileSync, writeFileSync } from "node:fs";
import { Command } from "commander";
import { type Address, formatUnits, parseUnits } from "viem";
import { generatePrivateKey } from "viem/accounts";
import { serveControlPlane } from "@agentctl/server";
import {
  ApprovalQueue,
  AuditAnchorClient,
  AuditLogger,
  type PaymentRequest,
  type Policy,
  type PolicyDecision,
  ViemAdapter,
  compilePolicy,
  compilePolicyObject,
  createGuard,
  getChain,
  policyFromJSON,
  policyToJSON,
  report,
  simulatePolicy,
} from "@agentctl/core";

const DEFAULT_CHAIN = "eip155:84532";
const DEFAULT_DB = "./agentctl.sqlite";

const program = new Command();
program
  .name("agentctl")
  .description("Policy & observability layer for autonomous AI agent payments")
  .version("0.1.0");

// ─── check ───────────────────────────────────────────────────────────────────
program
  .command("check")
  .description("Dry-run a payment against a policy (no execution)")
  .requiredOption("--amount <usd>", "amount in USD, e.g. 0.10")
  .requiredOption("--recipient <address>", "recipient address")
  .option("--intent <text>", "the agent's stated intent", "")
  .option("--token <symbol|address>", "token (USDC or an address)", "USDC")
  .option("--chain <caip2>", "CAIP-2 chain id", DEFAULT_CHAIN)
  .option("--policy <file>", "policy JSON file (default: built-in demo policy)")
  .option("--agent <id>", "agent id", "cli-agent")
  .option("--llm", "enable the LLM intent check (needs ANTHROPIC_API_KEY)")
  .action(async (opts) => {
    const chain: string = opts.chain;
    const cfg = getChain(chain);
    const policy: Policy = opts.policy
      ? policyFromJSON(readFileSync(opts.policy, "utf8"))
      : demoPolicy(opts.agent);

    const wallet = new ViemAdapter({ privateKey: generatePrivateKey(), chain });
    const guard = await createGuard({
      wallet,
      policy,
      llmApiKey: opts.llm ? process.env.ANTHROPIC_API_KEY : undefined,
    });

    const token =
      String(opts.token).toUpperCase() === "USDC" ? cfg.usdc : (opts.token as Address);
    const req: PaymentRequest = {
      intent: opts.intent,
      amount: parseUnits(String(opts.amount), 6),
      token,
      recipient: opts.recipient as Address,
      chain,
      agentId: policy.agentId,
    };

    renderDecision(req, await guard.evaluate(req));
  });

// ─── policy create ───────────────────────────────────────────────────────────
const policyCmd = program.command("policy").description("Manage policies");
policyCmd
  .command("create")
  .description("Compile a natural-language policy into JSON (uses Claude Haiku)")
  .requiredOption("--agent <id>", "agent id")
  .requiredOption("--text <nl>", "natural-language policy")
  .option("--out <file>", "output file (default: <agent>.policy.json)")
  .action(async (opts) => {
    const policy = await compilePolicy(opts.text, opts.agent, process.env.ANTHROPIC_API_KEY);
    const out: string = opts.out ?? `${opts.agent}.policy.json`;
    writeFileSync(out, policyToJSON(policy));
    console.log(`✓ wrote ${out} (${policy.rules.length} rules)`);
    for (const r of policy.rules) console.log(`  • ${r.type}`);
  });

// ─── audit ───────────────────────────────────────────────────────────────────
program
  .command("audit")
  .description("Show the audit trail (optionally verify against the on-chain anchor)")
  .option("--agent <id>", "filter by agent id")
  .option("--db <file>", "audit sqlite path", DEFAULT_DB)
  .option("--chain <caip2>", "CAIP-2 chain id", DEFAULT_CHAIN)
  .option("--verify", "verify each anchored entry against AuditAnchor.sol")
  .action(async (opts) => {
    const log = new AuditLogger(opts.db);
    const entries = await log.list({ agentId: opts.agent });
    if (entries.length === 0) {
      console.log("no audit entries");
      await log.close();
      return;
    }
    for (const e of entries) {
      const settle = !e.settlement
        ? "—"
        : e.settlement.txHash
          ? `tx ${e.settlement.txHash.slice(0, 12)}…`
          : e.settlement.success
            ? "settled"
            : "settle-failed";
      console.log(
        `${new Date(e.timestamp).toISOString()}  ${e.decision.verdict.toUpperCase().padEnd(8)} ` +
          `${formatUnits(e.request.amount, 6)} USDC → ${e.request.recipient.slice(0, 10)}…  ${settle}  [${e.id.slice(0, 8)}]`,
      );
    }
    if (opts.verify) await verifyEntries(log, opts.chain, opts.agent);
    await log.close();
  });

// ─── report (spending analytics) ─────────────────────────────────────────────
program
  .command("report")
  .description("Spending + risk analytics over the audit log")
  .option("--agent <id>", "filter by agent id")
  .option("--db <file>", "audit sqlite path", DEFAULT_DB)
  .option("--top <n>", "number of top counterparties", "5")
  .action(async (opts) => {
    const log = new AuditLogger(opts.db);
    const entries = await log.list({ agentId: opts.agent });
    const r = report(entries, { topN: Number(opts.top) });
    if (r.total === 0) {
      console.log("no audit entries");
      await log.close();
      return;
    }
    const pct = (n: number) => `${(n * 100).toFixed(1)}%`;
    console.log(`\n  ${r.total} payments — ${r.settled} settled`);
    console.log(
      `  allow ${r.verdicts.allow}  escalate ${r.verdicts.escalate} (${pct(r.escalateRate)})  ` +
        `block ${r.verdicts.block} (${pct(r.blockRate)})  anomalies ${r.anomalies}`,
    );
    console.log("  settled spend:");
    for (const [token, units] of Object.entries(r.totalSpendByToken)) {
      console.log(`    ${formatUnits(BigInt(units), 6)}  (${token.slice(0, 10)}…)`);
    }
    if (r.topCounterparties.length > 0) {
      console.log("  top counterparties:");
      for (const c of r.topCounterparties) {
        console.log(
          `    ${c.recipient.slice(0, 12)}…  ${c.count} payments  ${formatUnits(BigInt(c.totalSpend), 6)} USDC`,
        );
      }
    }
    console.log("");
    await log.close();
  });

// ─── watch ───────────────────────────────────────────────────────────────────
program
  .command("watch")
  .description("Tail an agent's live audit log")
  .option("--agent <id>", "filter by agent id")
  .option("--db <file>", "audit sqlite path", DEFAULT_DB)
  .action((opts) => {
    const log = new AuditLogger(opts.db);
    const seen = new Set<string>();
    console.log(`watching ${opts.agent ?? "all agents"}… (ctrl-C to stop)`);
    setInterval(async () => {
      for (const e of await log.list({ agentId: opts.agent })) {
        if (seen.has(e.id)) continue;
        seen.add(e.id);
        console.log(
          `${new Date(e.timestamp).toISOString()} ${e.decision.verdict} ` +
            `${formatUnits(e.request.amount, 6)} USDC → ${e.request.recipient.slice(0, 10)}…`,
        );
      }
    }, 2000);
  });

// ─── demo ────────────────────────────────────────────────────────────────────
program
  .command("demo")
  .description("Run the killer-demo scenario: allow → escalate → block, recorded to the audit log")
  .option("--db <file>", "audit sqlite path", DEFAULT_DB)
  .action(async (opts) => {
    const known = "0x000000000000000000000000000000000000beef" as Address;
    const attacker = "0x00000000000000000000000000000000deAddEad" as Address;
    const usdc = getChain(DEFAULT_CHAIN).usdc;
    const policy: Policy = {
      agentId: "research-agent-1",
      anomalyThreshold: 0.8,
      anomalyAction: "escalate",
      sourceText: "max $20/day, escalate anything over $2, only pay services you've used before",
      rules: [
        {
          type: "spend-cap",
          window: "day",
          maxAmount: parseUnits("20", 6),
          escalateAbove: parseUnits("2", 6),
          token: usdc,
        },
        { type: "allowlist", mode: "recipients", entries: [known.toLowerCase()], enforce: true },
      ],
    };
    const guard = await createGuard({
      wallet: new ViemAdapter({ privateKey: generatePrivateKey() }),
      policy,
    });
    const log = new AuditLogger(opts.db);

    const scenarios: Array<[string, PaymentRequest]> = [
      ["normal — pay the known weather API $0.50", mkReq("0.50", known, "weather data for trip")],
      ["large — pay the known API $15 (over $2 approval line)", mkReq("15", known, "bulk compute")],
      ["prompt-injected — send $15 to a fresh attacker address", mkReq("15", attacker, "weather data")],
    ];
    for (const [label, req] of scenarios) {
      console.log(`\n── ${label} ──`);
      const decision = await guard.evaluate(req);
      await log.record(req, decision);
      renderDecision(req, decision);
    }
    log.close();
    console.log(`recorded to ${opts.db} — run \`agentctl audit\` to see the trail.\n`);
    process.exitCode = 0;
  });

// ─── simulate (backtest a candidate policy against history) ──────────────────
program
  .command("simulate")
  .description("Backtest a candidate policy against the recorded audit history")
  .requiredOption("--policy <file>", "candidate policy JSON")
  .option("--agent <id>", "filter by agent id")
  .option("--db <file>", "audit sqlite path", DEFAULT_DB)
  .action(async (opts) => {
    const log = new AuditLogger(opts.db);
    const history = await log.list({ agentId: opts.agent });
    if (history.length === 0) {
      console.log("no audit history to simulate against");
      await log.close();
      return;
    }
    const candidate = policyFromJSON(readFileSync(opts.policy, "utf8"));
    const result = await simulatePolicy(history, candidate);

    console.log(`\n  Backtest of ${opts.policy} over ${result.total} recorded payments:`);
    console.log(
      `  changed ${result.changed}  —  newly blocked ${result.newlyBlocked}, ` +
        `newly escalated ${result.newlyEscalated}, newly allowed ${result.newlyAllowed}\n`,
    );
    for (const e of result.entries.filter((x) => x.changed).slice(0, 15)) {
      console.log(
        `  ● ${formatUnits(e.request.amount, 6)} USDC → ${e.request.recipient.slice(0, 10)}…  ` +
          `${e.recordedVerdict.toUpperCase()} → ${e.simulatedVerdict.toUpperCase()}`,
      );
    }
    if (result.changed === 0) console.log("  (no verdicts would change)");
    await log.close();
  });

// ─── serve (HTTP control plane) ──────────────────────────────────────────────
program
  .command("serve")
  .description("Run the HTTP control plane (evaluate / approvals / breaker / report)")
  .requiredOption("--policy <file>", "policy JSON")
  .option("--port <n>", "port", "8787")
  .option("--token <token>", "require Authorization: Bearer <token>")
  .action(async (opts) => {
    const policy = policyFromJSON(readFileSync(opts.policy, "utf8"));
    const guard = await createGuard({
      wallet: new ViemAdapter({ privateKey: generatePrivateKey() }),
      policy,
      approvalQueue: new ApprovalQueue(),
      circuitBreaker: { windowSeconds: 3600, maxBlocks: 10, maxAnomalies: 5 },
    });
    const server = await serveControlPlane(guard, {
      port: Number(opts.port),
      token: opts.token,
    });
    const addr = server.address();
    const port = addr && typeof addr === "object" ? addr.port : opts.port;
    console.log(`agentctl control plane → http://127.0.0.1:${port}`);
    console.log(
      "  POST /evaluate · GET /approvals · POST /approvals/:id/(approve|deny) · " +
        "GET+POST /breaker · GET /report",
    );
    if (opts.token) console.log("  (auth: Authorization: Bearer <token>)");
  });

// ─── eval (machine bridge: JSON in → JSON out) ───────────────────────────────
program
  .command("eval")
  .description("Evaluate a JSON {policy, request} from stdin; write the decision as JSON")
  .action(async () => {
    const { policy: policyInput, request } = JSON.parse(await readStdin());
    const agentId: string = request.agentId ?? "bridge-agent";
    const policy = compilePolicyObject(policyInput, agentId);
    const guard = await createGuard({
      wallet: new ViemAdapter({ privateKey: generatePrivateKey(), chain: request.chain }),
      policy,
      llmApiKey: request.llm ? process.env.ANTHROPIC_API_KEY : undefined,
    });
    const req: PaymentRequest = {
      intent: request.intent ?? "",
      amount: BigInt(request.amount),
      token: request.token as Address,
      recipient: request.recipient as Address,
      chain: request.chain ?? DEFAULT_CHAIN,
      agentId,
      resourceUrl: request.resourceUrl,
    };
    const decision = await guard.evaluate(req);
    process.stdout.write(
      `${JSON.stringify({
        verdict: decision.verdict,
        riskScore: decision.riskScore,
        reason: decision.reason,
        checks: decision.checks,
      })}\n`,
    );
  });

program.parseAsync().catch((err) => {
  console.error(`error: ${err instanceof Error ? err.message : String(err)}`);
  process.exitCode = 1;
});

// ─── helpers ─────────────────────────────────────────────────────────────────
function readStdin(): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin
      .on("data", (chunk) => {
        data += chunk;
      })
      .on("end", () => resolve(data))
      .on("error", reject);
  });
}

function mkReq(amountUsd: string, recipient: Address, intent: string): PaymentRequest {
  return {
    intent,
    amount: parseUnits(amountUsd, 6),
    token: getChain(DEFAULT_CHAIN).usdc,
    recipient,
    chain: DEFAULT_CHAIN,
    agentId: "research-agent-1",
  };
}

function demoPolicy(agentId: string): Policy {
  const usdc = getChain(DEFAULT_CHAIN).usdc;
  return {
    agentId,
    anomalyThreshold: 0.8,
    anomalyAction: "escalate",
    rules: [
      {
        type: "spend-cap",
        window: "day",
        maxAmount: parseUnits("20", 6),
        escalateAbove: parseUnits("2", 6),
        token: usdc,
      },
      { type: "counterparty", flagNewRecipients: true, action: "escalate" },
    ],
  };
}

function renderDecision(req: PaymentRequest, decision: PolicyDecision): void {
  const tag =
    decision.verdict === "allow"
      ? "✓ ALLOW   "
      : decision.verdict === "escalate"
        ? "⚠ ESCALATE"
        : "✗ BLOCK   ";
  console.log(`\n  ${tag}  (risk score: ${decision.riskScore.toFixed(2)})`);
  console.log(
    `  Payment: ${formatUnits(req.amount, 6)} USDC → ${req.recipient.slice(0, 12)}…  on ${req.chain}`,
  );
  console.log(`  Intent:  "${req.intent}"`);
  console.log("  Checks:");
  if (decision.checks.length === 0) console.log("  ● (no rules fired)");
  for (const c of decision.checks) {
    const label = c.passed ? "PASS" : c.severity === "critical" ? "FAIL" : "WARN";
    console.log(`  ● ${c.id.padEnd(28)} ${label.padEnd(5)} ${c.message}`);
  }
  console.log(`  → ${decision.reason}\n`);
  if (decision.verdict === "block") process.exitCode = 2;
}

async function verifyEntries(
  log: AuditLogger,
  chain: string,
  agent: string | undefined,
): Promise<void> {
  const contractAddress = process.env.AUDIT_ANCHOR_ADDRESS;
  const committerKey = process.env.ANCHOR_COMMITTER_KEY as `0x${string}` | undefined;
  if (!contractAddress || !committerKey) {
    console.log("\n(--verify needs AUDIT_ANCHOR_ADDRESS + ANCHOR_COMMITTER_KEY in env)");
    return;
  }
  const anchor = new AuditAnchorClient({
    chain,
    contractAddress: contractAddress as Address,
    committerKey,
    rpcUrl: process.env.RPC_BASE_SEPOLIA,
  });
  const operator = anchor.operatorAddress();
  console.log("\nverification:");
  for (const e of await log.list({ agentId: agent })) {
    const proof = await log.proofFor(e.id);
    if (!proof) {
      console.log(`  ${e.id.slice(0, 8)}  not anchored yet`);
      continue;
    }
    const batch = await anchor.getBatch(operator, proof.batchIndex);
    const onchain = await anchor.verifyEntry(operator, proof.batchIndex, proof.leaf, proof.proof);
    const rootMatch = batch.root.toLowerCase() === proof.localRoot.toLowerCase();
    console.log(
      `  ${e.id.slice(0, 8)}  batch#${proof.batchIndex}  ${
        onchain && rootMatch ? "✓ verified on-chain" : "✗ MISMATCH"
      }`,
    );
  }
}
