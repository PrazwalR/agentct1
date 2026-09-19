// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/**
 * @title AuditAnchor
 * @notice Stores a per-operator hash-chain of Merkle roots committing to batches of
 *         agentctl audit-log entries, so a third party can verify that a given entry
 *         was recorded, unaltered, at a known point in an unforkable history.
 *
 * @dev Design notes, each closing a specific finding from the 2026-09-18 audit:
 *
 *      - **Batches are chained.** `commitBatch` requires the caller to name the current
 *        head, so each operator has exactly one linear history. An operator cannot
 *        publish two conflicting versions of the past: a fork is impossible, not merely
 *        detectable. (H-3)
 *
 *      - **The contract computes the leaf itself** from the entry's fields, using the
 *        OpenZeppelin StandardMerkleTree encoding — `keccak256(keccak256(abi.encode(..)))`.
 *        Accepting a caller-supplied pre-hashed leaf allowed an internal node, or the root
 *        itself, to verify as an entry; the double hash is what separates leaves from
 *        nodes, and it must be enforced here rather than trusted from one client. (M-1)
 *
 *      - **The leaf binds chain id, this contract, and the operator.** A root committed on
 *        Sepolia is therefore not verifiable on mainnet, and a published root cannot be
 *        replayed under another operator's address to claim authorship. (M-5)
 *
 *      - **Reads never revert on bad input.** An unknown operator or out-of-range index
 *        returns false, so a configuration mistake is distinguishable from tampering and
 *        cannot abort a verifier's whole run. (M-10)
 *
 *      - `commitBatch` returns the index it wrote and emits it, so a committer never has
 *        to infer it from a separate `getBatchCount()` read. (H-1)
 *
 *      Proof hashing is sorted-pair (commutative) keccak256, matching OpenZeppelin's
 *      `MerkleProof` and the OpenZeppelin merkle-tree JS library.
 */
contract AuditAnchor {
    /// Packed into two slots: root, then timestamp+entryCount+prevRoot pointer-free.
    struct Batch {
        bytes32 merkleRoot;
        uint64 timestamp;
        uint64 entryCount;
    }

    /// Longest accepted proof. 2**64 leaves is far beyond any real batch; this only
    /// exists so the verification loop can never be handed an unbounded array.
    uint256 internal constant MAX_PROOF_LENGTH = 64;

    /// operator => committed batches, in order
    mapping(address => Batch[]) public batches;

    /// operator => root of the most recent batch (bytes32(0) before the first commit)
    mapping(address => bytes32) public head;

    event BatchCommitted(
        address indexed operator,
        uint256 indexed batchIndex,
        bytes32 merkleRoot,
        bytes32 prevRoot,
        uint64 entryCount,
        uint64 timestamp
    );

    error EmptyRoot();
    error EmptyBatch();
    /// The caller's view of the chain head disagrees with this contract's.
    error WrongPrevRoot(bytes32 expected, bytes32 supplied);

    /**
     * @notice Append a batch to the caller's chain.
     * @param prevRoot The caller's current head — `bytes32(0)` for a first commit.
     *                 Guarantees the new batch extends the history the caller last saw,
     *                 rather than silently forking it.
     * @param merkleRoot StandardMerkleTree root over this batch's entries.
     * @param entryCount Number of entries in the batch. Bound into the chain via the
     *                   event and stored so a verifier can check completeness.
     * @return batchIndex The index this batch was written at.
     */
    function commitBatch(bytes32 prevRoot, bytes32 merkleRoot, uint64 entryCount)
        external
        returns (uint256 batchIndex)
    {
        if (merkleRoot == bytes32(0)) revert EmptyRoot();
        if (entryCount == 0) revert EmptyBatch();

        bytes32 expected = head[msg.sender];
        if (prevRoot != expected) revert WrongPrevRoot(expected, prevRoot);

        batches[msg.sender].push(
            Batch({
                merkleRoot: merkleRoot,
                timestamp: uint64(block.timestamp),
                entryCount: entryCount
            })
        );
        head[msg.sender] = merkleRoot;
        batchIndex = batches[msg.sender].length - 1;

        emit BatchCommitted(
            msg.sender, batchIndex, merkleRoot, prevRoot, entryCount, uint64(block.timestamp)
        );
    }

    /**
     * @notice Verify that an audit entry is in a committed batch.
     * @dev Computes the StandardMerkleTree leaf from the entry's fields — callers cannot
     *      supply a pre-hashed leaf, so an internal node cannot masquerade as an entry.
     *      The leaf is bound to `block.chainid`, this contract, and `operator`.
     * @return True only if the entry is provably in that operator's batch at that index.
     */
    function verifyEntry(
        address operator,
        uint256 batchIndex,
        string calldata agentId,
        uint256 timestamp,
        address recipient,
        uint8 verdict,
        bytes32 entryHash,
        bytes32[] calldata proof
    ) external view returns (bool) {
        if (batchIndex >= batches[operator].length) return false;
        if (proof.length > MAX_PROOF_LENGTH) return false;

        bytes32 computed =
            leafHash(operator, agentId, timestamp, recipient, verdict, entryHash);
        for (uint256 i = 0; i < proof.length; i++) {
            computed = computed < proof[i]
                ? keccak256(abi.encodePacked(computed, proof[i]))
                : keccak256(abi.encodePacked(proof[i], computed));
        }
        return computed == batches[operator][batchIndex].merkleRoot;
    }

    /**
     * @notice The StandardMerkleTree leaf hash for an entry under this anchor.
     * @dev Exposed so an off-chain client can derive the identical leaf without
     *      reimplementing the encoding. Double keccak of `abi.encode` is what makes a
     *      leaf unforgeable as an internal node.
     */
    function leafHash(
        address operator,
        string calldata agentId,
        uint256 timestamp,
        address recipient,
        uint8 verdict,
        bytes32 entryHash
    ) public view returns (bytes32) {
        return keccak256(
            bytes.concat(
                keccak256(
                    abi.encode(
                        block.chainid,
                        address(this),
                        operator,
                        agentId,
                        timestamp,
                        recipient,
                        verdict,
                        entryHash
                    )
                )
            )
        );
    }

    function getBatchCount(address operator) external view returns (uint256) {
        return batches[operator].length;
    }

    /// Read a batch without reverting on an out-of-range index (`found` says which).
    function getBatch(address operator, uint256 batchIndex)
        external
        view
        returns (bool found, bytes32 merkleRoot, uint64 timestamp, uint64 entryCount)
    {
        if (batchIndex >= batches[operator].length) return (false, bytes32(0), 0, 0);
        Batch storage b = batches[operator][batchIndex];
        return (true, b.merkleRoot, b.timestamp, b.entryCount);
    }
}
