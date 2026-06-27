import type { Address, PublicClient } from "viem";
import { createPublicClient, erc20Abi, http } from "viem";
import { getChain } from "../constants.js";

/** Build a viem PublicClient for a CAIP-2 chain (balance reads, anchor commits). */
export function makePublicClient(caip2: string, rpcUrl?: string): PublicClient {
  const chain = getChain(caip2);
  return createPublicClient({
    chain: chain.viemChain,
    transport: http(rpcUrl ?? chain.defaultRpcUrl),
  });
}

/** Read an ERC-20 balance in smallest units. */
export function erc20Balance(
  client: PublicClient,
  token: Address,
  owner: Address,
): Promise<bigint> {
  return client.readContract({
    address: token,
    abi: erc20Abi,
    functionName: "balanceOf",
    args: [owner],
  });
}
