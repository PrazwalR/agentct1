import { type Address, type Hex, createWalletClient, http } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { getChain } from "../constants.js";
import { makePublicClient } from "../adapters/base.js";

export const AUDIT_ANCHOR_ABI = [
  {
    type: "function",
    name: "commitBatch",
    stateMutability: "nonpayable",
    inputs: [
      { name: "merkleRoot", type: "bytes32" },
      { name: "entryCount", type: "uint256" },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "verifyEntry",
    stateMutability: "view",
    inputs: [
      { name: "operator", type: "address" },
      { name: "batchIndex", type: "uint256" },
      { name: "leaf", type: "bytes32" },
      { name: "proof", type: "bytes32[]" },
    ],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    type: "function",
    name: "getBatchCount",
    stateMutability: "view",
    inputs: [{ name: "operator", type: "address" }],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    type: "function",
    name: "batches",
    stateMutability: "view",
    inputs: [
      { name: "operator", type: "address" },
      { name: "index", type: "uint256" },
    ],
    outputs: [
      { name: "merkleRoot", type: "bytes32" },
      { name: "timestamp", type: "uint256" },
      { name: "entryCount", type: "uint256" },
    ],
  },
] as const;

export interface AnchorClientConfig {
  chain: string;
  contractAddress: Address;
  /** Key that pays gas for root commits (testnet key only). */
  committerKey?: Hex;
  rpcUrl?: string;
}

/** Commits Merkle roots to AuditAnchor.sol and verifies inclusion against it. */
export class AuditAnchorClient {
  constructor(private readonly cfg: AnchorClientConfig) {}

  /** Commit a batch root on-chain. Returns the commit tx hash. */
  async commit(root: Hex, entryCount: number): Promise<Hex> {
    if (!this.cfg.committerKey) {
      throw new Error("committerKey required to commit a Merkle root on-chain");
    }
    const chain = getChain(this.cfg.chain);
    const account = privateKeyToAccount(this.cfg.committerKey);
    const wallet = createWalletClient({
      account,
      chain: chain.viemChain,
      transport: http(this.cfg.rpcUrl ?? chain.defaultRpcUrl),
    });
    const txHash = await wallet.writeContract({
      address: this.cfg.contractAddress,
      abi: AUDIT_ANCHOR_ABI,
      functionName: "commitBatch",
      args: [root, BigInt(entryCount)],
    });
    // Wait for the batch to actually mine, so a subsequent getBatchCount()
    // reflects it. Without this, writeContract returns on broadcast and the
    // batch index derived from getBatchCount() is off by one (first batch → -1).
    await makePublicClient(this.cfg.chain, this.cfg.rpcUrl).waitForTransactionReceipt({
      hash: txHash,
    });
    return txHash;
  }

  /** The committer's own address (the operator key in AuditAnchor). */
  operatorAddress(): Address {
    if (!this.cfg.committerKey) throw new Error("committerKey required");
    return privateKeyToAccount(this.cfg.committerKey).address;
  }

  /** Verify an audit entry is in a committed batch, on-chain. */
  async verifyEntry(
    operator: Address,
    batchIndex: number,
    leaf: Hex,
    proof: Hex[],
  ): Promise<boolean> {
    const pub = makePublicClient(this.cfg.chain, this.cfg.rpcUrl);
    return pub.readContract({
      address: this.cfg.contractAddress,
      abi: AUDIT_ANCHOR_ABI,
      functionName: "verifyEntry",
      args: [operator, BigInt(batchIndex), leaf, proof],
    });
  }

  /** Number of batches committed by an operator. */
  async getBatchCount(operator: Address): Promise<number> {
    const pub = makePublicClient(this.cfg.chain, this.cfg.rpcUrl);
    const n = await pub.readContract({
      address: this.cfg.contractAddress,
      abi: AUDIT_ANCHOR_ABI,
      functionName: "getBatchCount",
      args: [operator],
    });
    return Number(n);
  }

  /** Read a committed batch's stored root + metadata. */
  async getBatch(
    operator: Address,
    batchIndex: number,
  ): Promise<{ root: Hex; timestamp: number; entryCount: number }> {
    const pub = makePublicClient(this.cfg.chain, this.cfg.rpcUrl);
    const [root, timestamp, entryCount] = await pub.readContract({
      address: this.cfg.contractAddress,
      abi: AUDIT_ANCHOR_ABI,
      functionName: "batches",
      args: [operator, BigInt(batchIndex)],
    });
    return { root, timestamp: Number(timestamp), entryCount: Number(entryCount) };
  }
}
