import { readFileSync, writeFileSync } from "node:fs";
import { Command } from "commander";
import { type Address, formatUnits, parseUnits } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { serveControlPlane } from "@agentctl/server";
import {
  ApprovalQueue,
  AuditAnchorClient,
  AuditLogger,
  type LLMConfig,
  type LLMProvider,
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

/** Shared --provider/--ollama-url/--model flags -> LLMConfig (env auto-detect if unset). */
function resolveCliLLM(opts: { provider?: string; ollamaUrl?: string; model?: string }): LLMConfig {
  return {
    provider: opts.provider as LLMProvider | undefined,
    baseUrl: opts.ollamaUrl,
    model: opts.model,
  };
}

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
  .option("--db <file>", "audit sqlite path — history to evaluate against", DEFAULT_DB)
  .option("--no-history", "ignore recorded history (evaluate from a cold start)")
  .option("--llm", "enable the LLM intent check (Anthropic key or a local Ollama)")
  .option("--provider <name>", "llm provider: anthropic or ollama (default: auto-detect from env)")
  .option("--ollama-url <url>", "ollama server URL (default http://127.0.0.1:11434)")
  .option("--model <name>", "override the provider's default model")
  .action(async (opts) => {
    const chain: string = opts.chain;
    const cfg = getChain(chain);
    const policy: Policy = opts.policy
      ? policyFromJSON(readFileSync(opts.policy, "utf8"))
      : demoPolicy(opts.agent);

    const wallet = new ViemAdapter({ privateKey: generatePrivateKey(), chain });
    // Bind the audit db so the dry-run is evaluated against spend that actually
    // happened — without it a rolling cap like "max $20/day" always reads as unused.
    const guard = await createGuard({
      wallet,
      policy,
      llm: opts.llm ? resolveCliLLM(opts) : undefined,
      auditStore: opts.db,
      hydrate: opts.history !== false,
    });

    const token = String(opts.token).toUpperCase() === "USDC" ? cfg.usdc : (opts.token as Address);
    const req: PaymentRequest = {
      intent: opts.intent,
      amount: parseUnits(String(opts.amount), 6),
      token,
      recipient: opts.recipient as Address,
      chain,
      agentId: policy.agentId,
    };

    renderDecision(req, await guard.evaluate(req));
    await guard.auditLog.close();
  });

// ─── policy create ───────────────────────────────────────────────────────────
const policyCmd = program.command("policy").description("Manage policies");
policyCmd
  .command("create")
  .description("Compile a natural-language policy into JSON (Anthropic, or a local Ollama)")
  .requiredOption("--agent <id>", "agent id")
  .requiredOption("--text <nl>", "natural-language policy")
  .option("--out <file>", "output file (default: <agent>.policy.json)")
  .option("--provider <name>", "llm provider: anthropic or ollama (default: auto-detect from env)")
  .option("--ollama-url <url>", "ollama server URL (default http://127.0.0.1:11434)")
  .option("--model <name>", "override the provider's default model")
  .option("--chain <caip2>", "chain spend-cap rules are denominated in", DEFAULT_CHAIN)
  .action(async (opts) => {
    const policy = await compilePolicy(opts.text, opts.agent, resolveCliLLM(opts), opts.chain);
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
  .option(
    "--operator <address>",
    "operator whose batches to verify against (default: derived from ANCHOR_COMMITTER_KEY)",
  )
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
    if (opts.verify) await verifyEntries(log, opts.chain, opts.agent, opts.operator);
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
    const attacker = "0x00000000000000000000000000000000dEadDEaD" as Address;
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
      [
        "prompt-injected — send $15 to a fresh attacker address",
        mkReq("15", attacker, "weather data"),
      ],
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
  .option("--host <address>", "bind address", "127.0.0.1")
  .option("--token <token>", "require Authorization: Bearer <token>")
  .option("--rate-limit-max <n>", "max requests per window per client", "60")
  .option("--rate-limit-window-ms <ms>", "rate-limit window in ms", "60000")
  .option("--breaker-window <seconds>", "circuit-breaker window", "3600")
  .option("--breaker-max-blocks <n>", "freeze the agent after this many blocks in the window", "10")
  .option(
    "--breaker-max-anomalies <n>",
    "freeze the agent after this many anomalies in the window",
    "5",
  )
  .action(async (opts) => {
    if (!opts.token) {
      console.warn("warning: --token not set — the control plane is unauthenticated");
    }
    const policy = policyFromJSON(readFileSync(opts.policy, "utf8"));
    const guard = await createGuard({
      wallet: new ViemAdapter({ privateKey: generatePrivateKey() }),
      policy,
      approvalQueue: new ApprovalQueue(),
      circuitBreaker: {
        windowSeconds: Number(opts.breakerWindow),
        maxBlocks: Number(opts.breakerMaxBlocks),
        maxAnomalies: Number(opts.breakerMaxAnomalies),
      },
    });
    const server = await serveControlPlane(guard, {
      port: Number(opts.port),
      host: opts.host,
      token: opts.token,
      rateLimit: { windowMs: Number(opts.rateLimitWindowMs), max: Number(opts.rateLimitMax) },
    });
    const addr = server.address();
    const port = addr && typeof addr === "object" ? addr.port : opts.port;
    console.log(`agentctl control plane → http://${opts.host}:${port}`);
    console.log(
      "  POST /evaluate · GET /approvals · POST /approvals/:id/(approve|deny) · " +
        "GET+POST /breaker · GET /report",
    );
    if (opts.token) console.log("  (auth: Authorization: Bearer <token>)");

    // Graceful shutdown: stop accepting new connections and let in-flight ones
    // finish, rather than dropping them mid-request on SIGTERM/SIGINT.
    const shutdown = (signal: string) => {
      console.log(`\n${signal} received, closing control plane…`);
      server.close(() => process.exit(0));
    };
    process.on("SIGTERM", () => shutdown("SIGTERM"));
    process.on("SIGINT", () => shutdown("SIGINT"));
  });

// ─── eval (machine bridge: JSON in → JSON out) ───────────────────────────────
program
  .command("eval")
  .description("Evaluate a JSON {policy, request} from stdin; write the decision as JSON")
  .action(async () => {
    const { policy: policyInput, request } = JSON.parse(await readStdin());
    const agentId: string = request.agentId ?? "bridge-agent";
    const policy = compilePolicyObject(policyInput, agentId, undefined, request.chain);
    // request.llm may be `true` (env auto-detect — Anthropic or Ollama, whichever is
    // configured) or an explicit { provider, baseUrl, model } object, e.g. from the
    // Python bridge choosing Ollama without any API key.
    const llm: LLMConfig | undefined =
      request.llm && typeof request.llm === "object"
        ? (request.llm as LLMConfig)
        : request.llm
          ? {}
          : undefined;
    const guard = await createGuard({
      wallet: new ViemAdapter({ privateKey: generatePrivateKey(), chain: request.chain }),
      policy,
      llm,
      // `db` opts the bridge into shared, persistent state: each `eval` runs in its
      // own process, so without a store every call would evaluate from a cold start.
      ...(request.db ? { auditStore: request.db as string } : { hydrate: false }),
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
    await guard.auditLog.close();
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

/** Pick the singular or plural form for a count. */
function plural(n: number, one: string, many: string): string {
  return n === 1 ? one : many;
}

/**
 * Select the RPC for a chain.
 *
 * Previously this always used RPC_BASE_SEPOLIA regardless of --chain, so verifying
 * a mainnet anchor silently read Base Sepolia and reported success (viem does not
 * check chain id on plain reads). assertChainId() below is the backstop.
 */
function rpcUrlFor(chain: string): string | undefined {
  const byChain: Record<string, string | undefined> = {
    "eip155:8453": process.env.RPC_BASE,
    "eip155:84532": process.env.RPC_BASE_SEPOLIA,
  };
  // Undefined falls through to the chain's built-in default RPC in makePublicClient.
  return byChain[chain];
}

/**
 * Verify the audit log against the on-chain anchor.
 *
 * Checks four distinct things, because inclusion alone is a weak guarantee:
 *   1. the RPC really is the configured chain;
 *   2. every anchored entry is provably in its batch (the contract recomputes the
 *      leaf from the entry's fields — no pre-hashed leaf is accepted);
 *   3. each batch's local membership matches the count committed on chain, and the
 *      operator's total committed count matches what is stored locally — this is
 *      what catches a *deleted* entry, which inclusion proofs can never reveal;
 *   4. no entry claims a timestamp after the batch that anchored it.
 */
async function verifyEntries(
  log: AuditLogger,
  chain: string,
  agent: string | undefined,
  operatorOverride?: string,
): Promise<void> {
  const contractAddress = process.env.AUDIT_ANCHOR_ADDRESS;
  if (!contractAddress) {
    console.log("\n(--verify needs AUDIT_ANCHOR_ADDRESS in env)");
    return;
  }
  // Verification needs only the operator's PUBLIC address. Requiring the committer
  // key meant only the party being audited could check the log.
  const committerKey = process.env.ANCHOR_COMMITTER_KEY as `0x${string}` | undefined;
  const operator = (operatorOverride ??
    (committerKey ? privateKeyToAccount(committerKey).address : undefined)) as Address | undefined;
  if (!operator) {
    console.log("\n(--verify needs --operator <address>, or ANCHOR_COMMITTER_KEY in env)");
    return;
  }

  const anchor = new AuditAnchorClient({
    chain,
    contractAddress: contractAddress as Address,
    rpcUrl: rpcUrlFor(chain),
  });

  try {
    await anchor.assertChainId();
  } catch (err) {
    console.log(`\n✗ ${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = 2;
    return;
  }

  const ctx = anchor.leafContext(operator);
  const entries = await log.list({ agentId: agent });
  console.log(`\nverification (operator ${operator} on ${chain}):`);

  // Group by batch so each batch's tree is built once, not once per entry.
  const byBatch = new Map<number, typeof entries>();
  let unanchored = 0;
  for (const e of entries) {
    const stored = await log.getById(e.id);
    const idx = stored?.batchIndex ?? null;
    if (idx === null) {
      unanchored++;
      continue;
    }
    const group = byBatch.get(idx) ?? [];
    group.push(e);
    byBatch.set(idx, group);
  }

  let verified = 0;
  let failed = 0;
  let errored = 0;
  const problems: string[] = [];

  for (const [batchIndex, group] of [...byBatch.entries()].sort((a, b) => a[0] - b[0])) {
    try {
      const onChain = await anchor.getBatch(operator, batchIndex);
      if (!onChain.found) {
        problems.push(`batch#${batchIndex} is not on chain (${group.length} entries affected)`);
        failed += group.length;
        console.log(`  batch#${batchIndex}  ✗ NOT ON CHAIN`);
        continue;
      }

      const proofs = await log.proofsForBatch(batchIndex, ctx);
      const localRoot = [...proofs.values()][0]?.localRoot;
      if (localRoot && localRoot.toLowerCase() !== onChain.root.toLowerCase()) {
        problems.push(`batch#${batchIndex} local root does not match the committed root`);
      }
      // Inclusion proofs cannot reveal a removed entry; only the count can.
      if (proofs.size !== onChain.entryCount) {
        const missing = onChain.entryCount - proofs.size;
        problems.push(
          `batch#${batchIndex} holds ${proofs.size} ${plural(proofs.size, "entry", "entries")} ` +
            `locally but ${onChain.entryCount} ${onChain.entryCount === 1 ? "was" : "were"} ` +
            `committed — ${Math.abs(missing)} ` +
            `${plural(Math.abs(missing), "entry is", "entries are")} ` +
            `${missing > 0 ? "missing from the local log" : "present locally but never committed"}`,
        );
      }

      for (const e of group) {
        const proof = proofs.get(e.id);
        if (!proof) {
          errored++;
          console.log(`  ${e.id.slice(0, 8)}  ⚠ not present in its own batch`);
          continue;
        }
        const ok = await anchor.verifyEntry(operator, batchIndex, proof.fields, proof.proof);
        // An entry cannot legitimately postdate the batch that anchored it.
        const withinTime = e.timestamp <= onChain.timestamp * 1000;
        if (!withinTime) {
          problems.push(`${e.id.slice(0, 8)} claims a timestamp after batch#${batchIndex}`);
        }
        // A stored hash that disagrees with the row's contents means the row was
        // edited after it was written — report that specifically, because it is a
        // different failure from a bad index or a reorg.
        if (!proof.storedHashMatches) {
          problems.push(
            `${e.id.slice(0, 8)} was EDITED after it was recorded — its contents no longer ` +
              `match the hash committed on-chain`,
          );
        }
        const good = ok && withinTime && proof.storedHashMatches;
        if (good) verified++;
        else failed++;
        console.log(
          `  ${e.id.slice(0, 8)}  batch#${batchIndex}  ${
            good ? "✓ verified on-chain" : proof.storedHashMatches ? "✗ MISMATCH" : "✗ EDITED"
          }`,
        );
      }
    } catch (err) {
      // One bad batch must not discard every already-confirmed result.
      errored += group.length;
      console.log(
        `  batch#${batchIndex}  ⚠ could not verify: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }

  // Completeness across the whole chain: the operator cannot hide a dropped batch.
  // Only meaningful over the whole log — under --agent the local set is a subset of
  // what was committed, so the counts are expected to differ.
  if (agent === undefined) {
    try {
      const committedTotal = (await anchor.getAllBatches(operator)).reduce(
        (sum, b) => sum + b.entryCount,
        0,
      );
      const anchoredLocally = entries.length - unanchored;
      if (committedTotal !== anchoredLocally) {
        problems.push(
          `operator committed ${committedTotal} entries on chain but the local log holds ` +
            `${anchoredLocally} anchored entries`,
        );
      }
    } catch {
      problems.push("could not read the operator's full batch list for a completeness check");
    }
  } else {
    console.log("  (completeness check skipped — it needs the full log, not --agent)");
  }

  console.log(
    `\n  ${verified} verified, ${failed} mismatched, ${unanchored} not yet anchored, ${errored} errored`,
  );
  for (const p of problems) console.log(`  ⚠ ${p}`);

  // A mismatch or a completeness gap is a real integrity failure; an error is
  // inconclusive. Distinguish them so a config mistake is not read as tampering.
  if (failed > 0 || problems.length > 0) process.exitCode = 2;
  else if (errored > 0) process.exitCode = 1;
}
