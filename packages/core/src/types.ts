import type { Address, Hex, LocalAccount } from "viem";

// ─── What the agent declares before paying ──────────────────────────────────
export interface PaymentRequest {
  /** Natural-language reason the agent states for this payment */
  intent: string;
  /** Token amount in smallest units (USDC 6 decimals: 100000n = $0.10) */
  amount: bigint;
  /** Token contract address */
  token: Address;
  /** Recipient address (the merchant/API) */
  recipient: Address;
  /** Chain in CAIP-2 format, e.g. "eip155:84532" for Base Sepolia */
  chain: string;
  /** Which agent is making this request (for per-agent baselines) */
  agentId: string;
  /** Optional: the resource URL being paid for (from the x402 402 response) */
  resourceUrl?: string;
}

// ─── The decision agentctl returns ──────────────────────────────────────────
export type Verdict = "allow" | "block" | "escalate";

export interface PolicyDecision {
  verdict: Verdict;
  /** Aggregate risk score 0-1 from the behavioral model */
  riskScore: number;
  /** Every check that fired, with detail */
  checks: PolicyCheck[];
  /** Human-readable explanation */
  reason: string;
  /** If escalate: how the human is notified */
  escalation?: EscalationTarget;
}

export type Severity = "info" | "warning" | "critical";

export interface PolicyCheck {
  id: string; // "spend-cap-daily", "counterparty-unknown", etc.
  passed: boolean;
  severity: Severity;
  message: string;
}

// ─── Policy definition ──────────────────────────────────────────────────────
export interface Policy {
  agentId: string;
  rules: PolicyRule[];
  /** Behavioral anomaly score above which anomalyAction fires */
  anomalyThreshold: number; // e.g. 0.8
  anomalyAction: "block" | "escalate";
  /** Source NL policy, kept for audit */
  sourceText?: string;
}

export type PolicyRule =
  | SpendCapRule
  | AllowlistRule
  | RateLimitRule
  | CounterpartyRule
  | TimeWindowRule;

export type SpendWindow = "transaction" | "session" | "hour" | "day";

export interface SpendCapRule {
  type: "spend-cap";
  window: SpendWindow;
  maxAmount: bigint;
  token: Address;
  /** Over this amount → escalate instead of block */
  escalateAbove?: bigint;
}

export interface AllowlistRule {
  type: "allowlist";
  mode: "recipients" | "resources";
  /** Allowed addresses (lowercased) or URL substrings */
  entries: string[];
  /** Block (true) or just warn (false) on non-allowlisted */
  enforce: boolean;
}

export interface RateLimitRule {
  type: "rate-limit";
  maxPayments: number;
  windowSeconds: number;
}

export interface CounterpartyRule {
  type: "counterparty";
  /** Flag the first payment to a never-seen-before address */
  flagNewRecipients: boolean;
  action: "block" | "escalate" | "warn";
}

export interface TimeWindowRule {
  type: "time-window";
  /** Allowed hours in UTC, e.g. [9, 17] = 9am-5pm */
  allowedHours: [number, number];
  action: "block" | "escalate" | "warn";
}

export interface EscalationTarget {
  method: "webhook" | "push" | "email";
  destination: string;
  /** Payment proceeds only if approved within this window */
  timeoutSeconds: number;
}

// ─── Audit ──────────────────────────────────────────────────────────────────
export interface Settlement {
  txHash: Hex;
  /** EIP-3009 nonce (when known) */
  nonce?: Hex;
  facilitator?: string;
  success: boolean;
}

export interface AuditEntry {
  id: string;
  timestamp: number;
  agentId: string;
  request: PaymentRequest;
  decision: PolicyDecision;
  settlement?: Settlement;
  /** Hash of (request + decision) for Merkle inclusion */
  entryHash: Hex;
}

// ─── Wallet adapter interface ───────────────────────────────────────────────
export interface IWalletAdapter {
  readonly provider: string;
  /** CAIP-2 chain this adapter signs on, e.g. "eip155:84532" */
  readonly chain: string;
  /** The agent's wallet address */
  getAddress(): Promise<Address>;
  /** Current token balance in smallest units */
  getBalance(token: Address): Promise<bigint>;
  /**
   * A viem-compatible account usable directly as an @x402/evm ClientEvmSigner.
   * This is the choke point the x402 client signs through.
   */
  getSigner(): Promise<LocalAccount>;
  /** Build + sign an EIP-3009 authorization WITHOUT settling (manual path + verification) */
  authorizePayment(req: PaymentRequest): Promise<SignedAuthorization>;
  /** Build + sign a Permit2 witness authorization (any ERC-20, incl. USDT). Optional. */
  authorizePaymentPermit2?(req: PaymentRequest): Promise<SignedPermit2Authorization>;
}

export interface SignedAuthorization {
  signature: Hex;
  authorization: {
    from: Address;
    to: Address;
    value: bigint;
    validAfter: bigint;
    validBefore: bigint;
    nonce: Hex;
  };
  method: "eip3009" | "permit2";
}

// ─── Permit2 (any ERC-20, incl. USDT which lacks EIP-3009) ───────────────────
export interface Permit2Authorization {
  permitted: { token: Address; amount: bigint };
  /** The x402 Permit2 proxy authorized to pull funds. */
  spender: Address;
  /** Unordered uint256 nonce (word + bitmap) — allows cancelling one of many. */
  nonce: bigint;
  deadline: bigint;
  /** Witness binds the authorization to the recipient. */
  witness: { to: Address; validAfter: bigint };
}

export interface SignedPermit2Authorization {
  signature: Hex;
  permit: Permit2Authorization;
  method: "permit2";
}

export type AuthMethod = "eip3009" | "permit2";
