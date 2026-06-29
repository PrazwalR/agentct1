import {
  SOLANA_DEVNET_CAIP2,
  SOLANA_MAINNET_CAIP2,
  SOLANA_TESTNET_CAIP2,
  USDC_DEVNET_ADDRESS,
  USDC_MAINNET_ADDRESS,
  getUsdcAddress,
  validateSvmAddress,
} from "@x402/svm";
import type { Network } from "@x402/fetch";

export {
  SOLANA_DEVNET_CAIP2,
  SOLANA_MAINNET_CAIP2,
  SOLANA_TESTNET_CAIP2,
  USDC_DEVNET_ADDRESS as SOLANA_USDC_DEVNET,
  USDC_MAINNET_ADDRESS as SOLANA_USDC_MAINNET,
  validateSvmAddress,
};

/** CAIP-2 ids for the supported Solana clusters. */
export const SOLANA_NETWORKS: readonly string[] = [
  SOLANA_MAINNET_CAIP2,
  SOLANA_DEVNET_CAIP2,
  SOLANA_TESTNET_CAIP2,
];

/** True for any Solana CAIP-2 network (e.g. "solana:5eykt4..."). */
export function isSolanaNetwork(caip2: string): boolean {
  return caip2.startsWith("solana:");
}

/** Canonical USDC mint (base58) for a Solana CAIP-2 network. */
export function getSolanaUsdc(network: string): string {
  return getUsdcAddress(network as Network);
}
