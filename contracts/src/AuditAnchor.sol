// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title AuditAnchor
 * @notice Stores periodic Merkle roots of agentctl audit logs. Each root commits
 *         to a batch of payment decisions. Anyone can later verify a specific
 *         audit entry was included and unaltered by providing a Merkle proof
 *         against the stored root.
 *
 * @dev verifyEntry uses sorted-pair (commutative) hashing, matching
 *      OpenZeppelin's MerkleProof.verify and the StandardMerkleTree from the
 *      openzeppelin merkle-tree library used on the agentctl side. Leaves are
 *      supplied pre-hashed (the StandardMerkleTree leaf hash).
 */
contract AuditAnchor {
    struct Batch {
        bytes32 merkleRoot;
        uint256 timestamp;
        uint256 entryCount;
    }

    /// operator address => list of committed batches
    mapping(address => Batch[]) public batches;

    event BatchCommitted(
        address indexed operator,
        uint256 indexed batchIndex,
        bytes32 merkleRoot,
        uint256 entryCount
    );

    /// Commit a new batch root for the calling operator.
    function commitBatch(bytes32 merkleRoot, uint256 entryCount) external {
        batches[msg.sender].push(
            Batch({merkleRoot: merkleRoot, timestamp: block.timestamp, entryCount: entryCount})
        );
        emit BatchCommitted(msg.sender, batches[msg.sender].length - 1, merkleRoot, entryCount);
    }

    /// Verify an entry is in a committed batch.
    function verifyEntry(
        address operator,
        uint256 batchIndex,
        bytes32 leaf,
        bytes32[] calldata proof
    ) external view returns (bool) {
        bytes32 root = batches[operator][batchIndex].merkleRoot;
        bytes32 computed = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            computed = computed < proof[i]
                ? keccak256(abi.encodePacked(computed, proof[i]))
                : keccak256(abi.encodePacked(proof[i], computed));
        }
        return computed == root;
    }

    function getBatchCount(address operator) external view returns (uint256) {
        return batches[operator].length;
    }
}
