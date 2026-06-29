import { ExactSvmScheme, type ClientSvmSigner, toClientSvmSigner } from "@x402/svm";
import type { x402Client } from "@x402/fetch";

export type { ClientSvmSigner };

/**
 * Register the x402 Solana (SVM) "exact" scheme on a client for a Solana network.
 * The signer is a @solana/kit TransactionSigner the consumer builds from their
 * Solana keypair — agentctl never holds it. The guard's policy/behavioral/intent/
 * audit layers are chain-agnostic and apply to Solana payments unchanged.
 */
export function registerSvmScheme(
  client: x402Client,
  signer: ClientSvmSigner,
  network: string,
): x402Client {
  return client.register(
    network as `${string}:${string}`,
    new ExactSvmScheme(toClientSvmSigner(signer)),
  );
}
