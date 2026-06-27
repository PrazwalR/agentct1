import { StandardMerkleTree } from "@openzeppelin/merkle-tree";
import type { Hex } from "viem";
import type { AuditEntry, Verdict } from "../types.js";

/**
 * Leaf encoding. Uses @openzeppelin/merkle-tree (StandardMerkleTree) so the
 * root, leaf hashing (double-keccak of abi.encode), and sorted-pair proofs
 * match AuditAnchor.sol's verifyEntry exactly. The earlier hand-rolled tree in
 * the v0.1 guide used index-ordered pairs and would NOT verify against the
 * contract — this is the corrected path.
 */
export const LEAF_TYPES = ["string", "uint256", "address", "uint8", "bytes32"] as const;

export type LeafTuple = [string, bigint, string, number, Hex];

const ZERO_ROOT = `0x${"0".repeat(64)}` as Hex;

function verdictToNum(v: Verdict): number {
  return { allow: 0, escalate: 1, block: 2 }[v];
}

export function entryToLeaf(e: AuditEntry): LeafTuple {
  return [
    e.agentId,
    BigInt(e.timestamp),
    e.request.recipient,
    verdictToNum(e.decision.verdict),
    e.entryHash,
  ];
}

/** Batches audit entries into a Merkle tree whose root is committed on-chain. */
export class MerkleAuditBatch {
  private readonly values: LeafTuple[] = [];
  private tree?: StandardMerkleTree<LeafTuple>;

  addEntry(entry: AuditEntry): void {
    this.values.push(entryToLeaf(entry));
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
