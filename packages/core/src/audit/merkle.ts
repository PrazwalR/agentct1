import { StandardMerkleTree } from "@openzeppelin/merkle-tree";
import type { Address, Hex } from "viem";
import type { AuditEntry, Verdict } from "../types.js";

/**
 * Leaf encoding. Uses @openzeppelin/merkle-tree (StandardMerkleTree) so the root,
 * leaf hashing (double-keccak of abi.encode), and sorted-pair proofs match
 * AuditAnchor.sol's `leafHash`/`verifyEntry` exactly.
 *
 * The first three fields are domain separation, not audit data: binding the chain
 * id, the anchor deployment, and the operator into every leaf means a root
 * committed on Sepolia cannot be verified against mainnet, and a published root
 * cannot be replayed under someone else's operator address to claim authorship.
 * The contract recomputes all three from `block.chainid`, `address(this)`, and its
 * `operator` argument, so a client cannot lie about them.
 */
export const LEAF_TYPES = [
  "uint256", // chainId
  "address", // anchor contract
  "address", // operator
  "string", // agentId
  "uint256", // entry timestamp
  "address", // recipient
  "uint8", // verdict
  "bytes32", // entryHash
] as const;

export type LeafTuple = [bigint, Address, Address, string, bigint, Address, number, Hex];

/** Identifies which anchor deployment, on which chain, under which operator. */
export interface LeafContext {
  chainId: bigint;
  anchor: Address;
  operator: Address;
}

const ZERO_ROOT = `0x${"0".repeat(64)}` as Hex;

function verdictToNum(v: Verdict): number {
  return { allow: 0, escalate: 1, block: 2 }[v];
}

export function entryToLeaf(e: AuditEntry, ctx: LeafContext): LeafTuple {
  return [
    ctx.chainId,
    ctx.anchor,
    ctx.operator,
    e.agentId,
    BigInt(e.timestamp),
    e.request.recipient,
    verdictToNum(e.decision.verdict),
    e.entryHash,
  ];
}

/**
 * Batches audit entries into a Merkle tree whose root is committed on-chain.
 * The context is required because it is part of every leaf — a batch built for one
 * anchor/chain/operator is deliberately not reusable against another.
 */
export class MerkleAuditBatch {
  private readonly values: LeafTuple[] = [];
  private tree?: StandardMerkleTree<LeafTuple>;

  constructor(private readonly ctx: LeafContext) {}

  addEntry(entry: AuditEntry): void {
    this.values.push(entryToLeaf(entry, this.ctx));
    this.tree = undefined; // invalidate cache
  }

  size(): number {
    return this.values.length;
  }

  private build(): StandardMerkleTree<LeafTuple> {
    if (!this.tree) {
      this.tree = StandardMerkleTree.of(this.values, [...LEAF_TYPES]);
    }
    return this.tree;
  }

  /** Merkle root of the batch (zero hash if empty). */
  root(): Hex {
    if (this.values.length === 0) return ZERO_ROOT;
    return this.build().root as Hex;
  }

  /** The leaf hash for entry `index`, as the contract expects it. */
  leafAt(index: number): Hex {
    const value = this.values[index];
    if (!value) throw new Error(`no entry at index ${index}`);
    return this.build().leafHash(value) as Hex;
  }

  /** Sorted-pair Merkle proof for entry `index`. */
  proofAt(index: number): Hex[] {
    return this.build().getProof(index) as Hex[];
  }

  /** Verify a leaf against this batch locally (no chain call). */
  verify(index: number): boolean {
    const value = this.values[index];
    if (!value) return false;
    return this.build().verify(value, this.proofAt(index));
  }
}
