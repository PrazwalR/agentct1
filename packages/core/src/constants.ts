import { type Address, type Chain, parseUnits } from "viem";
import { base, baseSepolia } from "viem/chains";

export const USDC_DECIMALS = 6;

export interface Eip712Domain {
  name: string;
  version: string;
  chainId: number;
  verifyingContract: Address;
}

export interface ChainConfig {
  /** CAIP-2 identifier, e.g. "eip155:84532" */
  caip2: string;
  viemChain: Chain;
  /** Canonical USDC address on this chain */
  usdc: Address;
  /** EIP-712 domain for USDC's EIP-3009 / EIP-2612 signing */
  usdcDomain: Eip712Domain;
  defaultRpcUrl: string;
}

/**
 * Supported settlement chains. Base Sepolia is the MVP testnet target.
 * USDC EIP-712 domains differ by chain: mainnet name is "USD Coin",
 * Base Sepolia testnet name is "USDC" — both version "2".
 */
export const CHAINS: Record<string, ChainConfig> = {
  "eip155:84532": {
    caip2: "eip155:84532",
    viemChain: baseSepolia,
    usdc: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
    usdcDomain: {
      name: "USDC",
      version: "2",
      chainId: 84532,
      verifyingContract: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
    },
    defaultRpcUrl: "https://sepolia.base.org",
  },
  "eip155:8453": {
    caip2: "eip155:8453",
    viemChain: base,
    usdc: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    usdcDomain: {
      name: "USD Coin",
      version: "2",
      chainId: 8453,
      verifyingContract: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    },
    defaultRpcUrl: "https://mainnet.base.org",
  },
};

export function getChain(caip2: string): ChainConfig {
  const c = CHAINS[caip2];
  if (!c) {
    throw new Error(
      `Unsupported chain "${caip2}". Supported: ${Object.keys(CHAINS).join(", ")}`,
    );
  }
  return c;
}

/** Default Base Sepolia testnet facilitator (mainnet uses the CDP facilitator). */
export const DEFAULT_TESTNET_FACILITATOR = "https://x402.org/facilitator";

import type { AuthMethod } from "./types.js";

/**
 * Tokens that natively implement EIP-3009 (gasless, recipient-bound). Everything
 * else — notably USDT, which has stated it never will — must use Permit2.
 */
export const EIP3009_TOKENS: ReadonlySet<string> = new Set(
  [
    "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", // USDC Base mainnet
    "0x036CbD53842c5426634e7929541eC2318f3dCF7e", // USDC Base Sepolia
    "0x60a3E35Cc302bFA44Cb288Bc5a4F316Fdb1adb42", // EURC Base mainnet
  ].map((a) => a.toLowerCase()),
);

/** Pick the authorization method for a token: EIP-3009 if supported, else Permit2. */
export function recommendedAuthMethod(token: Address): AuthMethod {
  return EIP3009_TOKENS.has(token.toLowerCase()) ? "eip3009" : "permit2";
}

/**
 * Convert a USD amount to 6-decimal token units. Formats via Intl (which never
 * uses scientific notation, unlike String()/toFixed for very small or >=1e21
 * numbers) so viem's parseUnits — which rejects "1e-7"/"1e+21" — never throws.
 */
export function usdToTokenUnits(usd: number | string): bigint {
  const n = typeof usd === "string" ? Number(usd) : usd;
  const decimal = n.toLocaleString("en-US", {
    useGrouping: false,
    minimumFractionDigits: 0,
    maximumFractionDigits: 6,
  });
  return parseUnits(decimal, 6);
}
