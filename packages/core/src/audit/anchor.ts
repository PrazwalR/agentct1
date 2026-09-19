import { type Address, type Hex, createWalletClient, http, parseEventLogs } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { getChain } from "../constants.js";
import { makePublicClient } from "../adapters/base.js";
import type { LeafContext } from "./merkle.js";

export const AUDIT_ANCHOR_ABI = [
  {
    type: "event",
    name: "BatchCommitted",
    anonymous: false,
    inputs: [
      { name: "operator", type: "address", indexed: true },
      { name: "batchIndex", type: "uint256", indexed: true },
      { name: "merkleRoot", type: "bytes32", indexed: false },
      { name: "prevRoot", type: "bytes32", indexed: false },
      { name: "entryCount", type: "uint64", indexed: false },
      { name: "timestamp", type: "uint64", indexed: false },
    ],
  },
  {
    type: "function",
    name: "commitBatch",
    stateMutability: "nonpayable",
    inputs: [
      { name: "prevRoot", type: "bytes32" },
      { name: "merkleRoot", type: "bytes32" },
      { name: "entryCount", type: "uint64" },
    ],
    outputs: [{ name: "batchIndex", type: "uint256" }],
  },
  {
    type: "function",
    name: "verifyEntry",
    stateMutability: "view",
    inputs: [
      { name: "operator", type: "address" },
      { name: "batchIndex", type: "uint256" },
      { name: "agentId", type: "string" },
      { name: "timestamp", type: "uint256" },
      { name: "recipient", type: "address" },
      { name: "verdict", type: "uint8" },
      { name: "entryHash", type: "bytes32" },
      { name: "proof", type: "bytes32[]" },
    ],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    type: "function",
    name: "leafHash",
    stateMutability: "view",
    inputs: [
      { name: "operator", type: "address" },
      { name: "agentId", type: "string" },
      { name: "timestamp", type: "uint256" },
      { name: "recipient", type: "address" },
      { name: "verdict", type: "uint8" },
      { name: "entryHash", type: "bytes32" },
    ],
    outputs: [{ name: "", type: "bytes32" }],
  },
  {
    type: "function",
    name: "head",
    stateMutability: "view",
    inputs: [{ name: "operator", type: "address" }],
    outputs: [{ name: "", type: "bytes32" }],
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
    name: "getBatch",
    stateMutability: "view",
    inputs: [
      { name: "operator", type: "address" },
      { name: "batchIndex", type: "uint256" },
    ],
    outputs: [
      { name: "found", type: "bool" },
      { name: "merkleRoot", type: "bytes32" },
      { name: "timestamp", type: "uint64" },
      { name: "entryCount", type: "uint64" },
    ],
  },
] as const;

export const ZERO_ROOT = `0x${"0".repeat(64)}` as Hex;

export interface AnchorClientConfig {
  chain: string;
  contractAddress: Address;
  /** Key that pays gas for root commits (testnet key only). */
  committerKey?: Hex;
  rpcUrl?: string;
  /**
   * Block tag a commit must reach before it is treated as durable. Default "safe":
   * on an OP Stack chain (Base) the default `confirmations: 1` returns at the
   * *unsafe* head, which can reorg — and once rows are tagged as anchored, nothing
   * ever re-anchors them, so the loss is silent and permanent.
   */
  confirmationTag?: "latest" | "safe" | "finalized";
  /** How long to wait for the confirmation tag before giving up (default 15 min). */
  confirmationTimeoutMs?: number;
}

export interface CommitResult {
  txHash: Hex;
  /**
   * The batch's index, read from the BatchCommitted event in the commit receipt.
   *
   * Authoritative, never inferred. Deriving it from `getBatchCount() - 1` is a
   * read-after-write race: a concurrent commit under the same operator key, or a
   * lagging RPC replica, yields a wrong index — and because proofs are rebuilt
   * from locally-tagged rows, a wrong index makes those entries permanently
   * unprovable against an append-only contract with no repair path.
   */
  batchIndex: number;
  /** The root that was committed — recorded locally so a reorg can be detected. */
  root: Hex;
}

/** An entry's leaf fields, as the contract's verifyEntry/leafHash expect them. */
export interface LeafFields {
  agentId: string;
  timestamp: bigint;
  recipient: Address;
  verdict: number;
  entryHash: Hex;
}

/** On-chain batch record. `found` distinguishes "absent" from "zeroed". */
export interface OnChainBatch {
  found: boolean;
  root: Hex;
  timestamp: number;
  entryCount: number;
}

/** Commits Merkle roots to AuditAnchor.sol and verifies inclusion against it. */
export class AuditAnchorClient {
  constructor(private readonly cfg: AnchorClientConfig) {}

  private pub() {
    return makePublicClient(this.cfg.chain, this.cfg.rpcUrl);
  }

  /** The leaf context this deployment defines — chain id, anchor address, operator. */
  leafContext(operator: Address): LeafContext {
    return {
      chainId: BigInt(getChain(this.cfg.chain).viemChain.id),
      anchor: this.cfg.contractAddress,
      operator,
    };
  }

  /**
   * Guard against verifying against the wrong network: viem does not check the
   * chain id on plain reads, so a mismatched RPC would silently return another
   * chain's data (or none) and read as a verification result.
   */
  async assertChainId(): Promise<void> {
    const expected = getChain(this.cfg.chain).viemChain.id;
    const actual = await this.pub().getChainId();
    if (actual !== expected) {
      throw new Error(
        `RPC chain mismatch: configured chain ${this.cfg.chain} expects chain id ${expected}, ` +
          `but the RPC reports ${actual}. Check the RPC URL for this chain.`,
      );
    }
  }

  /** The operator's current chain head (ZERO_ROOT before their first commit). */
  async head(operator: Address): Promise<Hex> {
    return this.pub().readContract({
      address: this.cfg.contractAddress,
      abi: AUDIT_ANCHOR_ABI,
      functionName: "head",
      args: [operator],
    });
  }

  /**
   * Append a batch to the operator's chain and wait for it to become durable.
   *
   * `prevRoot` must be the operator's current head; the contract rejects anything
   * else, which is what makes each operator's history unforkable.
   */
  async commit(prevRoot: Hex, root: Hex, entryCount: number): Promise<CommitResult> {
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
      args: [prevRoot, root, BigInt(entryCount)],
    });

    const receipt = await this.pub().waitForTransactionReceipt({
      hash: txHash,
      timeout: this.cfg.confirmationTimeoutMs ?? 900_000,
    });
    await this.awaitDurable(receipt.blockNumber);

    // Take the index straight from our own BatchCommitted log rather than
    // re-reading the count afterwards (see CommitResult.batchIndex).
    const events = parseEventLogs({
      abi: AUDIT_ANCHOR_ABI,
      eventName: "BatchCommitted",
      logs: receipt.logs,
    });
    const mine = events.find(
      (e) => e.address.toLowerCase() === this.cfg.contractAddress.toLowerCase(),
    );
    if (!mine) {
      throw new Error(
        `commitBatch tx ${txHash} mined without a BatchCommitted event from ` +
          `${this.cfg.contractAddress} — refusing to guess the batch index`,
      );
    }
    return { txHash, batchIndex: Number(mine.args.batchIndex), root };
  }

  /**
   * Block until the commit's block is at or below the configured durability tag.
   * On OP Stack only `safe`/`finalized` are irreversible; returning at the unsafe
   * head is what lets a reorg silently un-anchor already-tagged entries.
   */
  private async awaitDurable(blockNumber: bigint): Promise<void> {
    const tag = this.cfg.confirmationTag ?? "safe";
    if (tag === "latest") return;
    const pub = this.pub();
    const deadline = Date.now() + (this.cfg.confirmationTimeoutMs ?? 900_000);
    for (;;) {
      try {
        const block = await pub.getBlock({ blockTag: tag });
        if (block.number !== null && block.number >= blockNumber) return;
      } catch {
        // A chain without the tag (e.g. a local devnet) can't offer this guarantee;
        // don't hang forever waiting for something that will never advance.
        return;
      }
      if (Date.now() > deadline) {
        throw new Error(
          `commit block ${blockNumber} did not reach "${tag}" within the confirmation timeout`,
        );
      }
      await new Promise((r) => setTimeout(r, 2_000));
    }
  }

  /** The committer's own address (the operator key in AuditAnchor). */
  operatorAddress(): Address {
    if (!this.cfg.committerKey) throw new Error("committerKey required");
    return privateKeyToAccount(this.cfg.committerKey).address;
  }

  /** Verify an audit entry is in a committed batch, on-chain. Never reverts. */
  async verifyEntry(
    operator: Address,
    batchIndex: number,
    fields: LeafFields,
    proof: Hex[],
  ): Promise<boolean> {
    return this.pub().readContract({
      address: this.cfg.contractAddress,
      abi: AUDIT_ANCHOR_ABI,
      functionName: "verifyEntry",
      args: [
        operator,
        BigInt(batchIndex),
        fields.agentId,
        fields.timestamp,
        fields.recipient,
        fields.verdict,
        fields.entryHash,
        proof,
      ],
    });
  }

  /** Number of batches committed by an operator. */
  async getBatchCount(operator: Address): Promise<number> {
    const n = await this.pub().readContract({
      address: this.cfg.contractAddress,
      abi: AUDIT_ANCHOR_ABI,
      functionName: "getBatchCount",
      args: [operator],
    });
    return Number(n);
  }

  /** Read a committed batch. Returns `found: false` rather than reverting. */
  async getBatch(operator: Address, batchIndex: number): Promise<OnChainBatch> {
    const [found, root, timestamp, entryCount] = await this.pub().readContract({
      address: this.cfg.contractAddress,
      abi: AUDIT_ANCHOR_ABI,
      functionName: "getBatch",
      args: [operator, BigInt(batchIndex)],
    });
    return { found, root, timestamp: Number(timestamp), entryCount: Number(entryCount) };
  }

  /** Every batch an operator has committed, in order. */
  async getAllBatches(operator: Address): Promise<OnChainBatch[]> {
    const count = await this.getBatchCount(operator);
    const out: OnChainBatch[] = [];
    for (let i = 0; i < count; i++) out.push(await this.getBatch(operator, i));
    return out;
  }
}
