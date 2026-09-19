// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {AuditAnchor} from "../src/AuditAnchor.sol";

contract AuditAnchorTest is Test {
    AuditAnchor internal anchor;

    bytes32 internal constant R1 = bytes32(uint256(0x1111));
    bytes32 internal constant R2 = bytes32(uint256(0x2222));
    bytes32 internal constant ZERO = bytes32(0);

    function setUp() public {
        anchor = new AuditAnchor();
    }

    // ─── commit + chaining (H-3) ────────────────────────────────────────────

    function testFirstCommitRequiresZeroPrevRoot() public {
        uint256 idx = anchor.commitBatch(ZERO, R1, 3);
        assertEq(idx, 0);
        assertEq(anchor.getBatchCount(address(this)), 1);
        assertEq(anchor.head(address(this)), R1);
    }

    function testCommitReturnsAndEmitsItsOwnIndex() public {
        assertEq(anchor.commitBatch(ZERO, R1, 1), 0);
        assertEq(anchor.commitBatch(R1, R2, 2), 1);
    }

    function testChainRejectsAForkOffAnOlderHead() public {
        anchor.commitBatch(ZERO, R1, 1);
        anchor.commitBatch(R1, R2, 1);
        // Trying to re-extend from R1 would create a second, conflicting history.
        bytes32 fork = bytes32(uint256(0x3333));
        vm.expectRevert(abi.encodeWithSelector(AuditAnchor.WrongPrevRoot.selector, R2, R1));
        anchor.commitBatch(R1, fork, 1);
    }

    function testChainRejectsASkippedPrevRoot() public {
        vm.expectRevert(abi.encodeWithSelector(AuditAnchor.WrongPrevRoot.selector, ZERO, R1));
        anchor.commitBatch(R1, R2, 1); // no first commit yet, head is still zero
    }

    function testHeadsAreIndependentPerOperator() public {
        anchor.commitBatch(ZERO, R1, 1);
        address other = address(0xBEEF);
        vm.prank(other);
        anchor.commitBatch(ZERO, R2, 1); // other operator starts its own chain at zero

        assertEq(anchor.head(address(this)), R1);
        assertEq(anchor.head(other), R2);
        assertEq(anchor.getBatchCount(other), 1);
    }

    function testCommitsAreOperatorScoped() public {
        anchor.commitBatch(ZERO, R1, 1);
        assertEq(anchor.getBatchCount(address(0xBEEF)), 0);
        assertEq(anchor.getBatchCount(address(this)), 1);
    }

    // ─── input validation (M-7) ─────────────────────────────────────────────

    function testRejectsZeroRoot() public {
        vm.expectRevert(AuditAnchor.EmptyRoot.selector);
        anchor.commitBatch(ZERO, ZERO, 1);
    }

    function testRejectsZeroEntryCount() public {
        vm.expectRevert(AuditAnchor.EmptyBatch.selector);
        anchor.commitBatch(ZERO, R1, 0);
    }

    // ─── reads never revert (M-10) ──────────────────────────────────────────

    function testGetBatchReportsNotFoundInsteadOfReverting() public {
        (bool found,,,) = anchor.getBatch(address(0xDEAD), 0);
        assertFalse(found);

        anchor.commitBatch(ZERO, R1, 1);
        (bool f2, bytes32 root, uint64 ts, uint64 count) = anchor.getBatch(address(this), 0);
        assertTrue(f2);
        assertEq(root, R1);
        assertEq(count, 1);
        assertGt(ts, 0);

        (bool f3,,,) = anchor.getBatch(address(this), 1); // one past the end
        assertFalse(f3);
    }

    function testVerifyReturnsFalseForUnknownOperatorOrIndex() public view {
        bytes32[] memory proof = new bytes32[](0);
        assertFalse(anchor.verifyEntry(address(0xDEAD), 0, "a", 1, address(1), 0, R1, proof));
        assertFalse(anchor.verifyEntry(address(this), 99, "a", 1, address(1), 0, R1, proof));
    }

    function testVerifyRejectsAnOverlongProof() public {
        bytes32 leaf = anchor.leafHash(address(this), "a", 1, address(1), 0, R1);
        anchor.commitBatch(ZERO, leaf, 1);
        bytes32[] memory proof = new bytes32[](65); // MAX_PROOF_LENGTH is 64
        assertFalse(anchor.verifyEntry(address(this), 0, "a", 1, address(1), 0, R1, proof));
    }

    // ─── leaf/node domain separation (M-1) ──────────────────────────────────

    function testVerifiesASingleLeafBatch() public {
        bytes32 leaf = anchor.leafHash(address(this), "agent", 1700, address(0xA11CE), 2, R1);
        anchor.commitBatch(ZERO, leaf, 1); // 1-leaf tree: root == leaf
        bytes32[] memory proof = new bytes32[](0);

        assertTrue(anchor.verifyEntry(address(this), 0, "agent", 1700, address(0xA11CE), 2, R1, proof));
        // Any changed field must fail.
        assertFalse(anchor.verifyEntry(address(this), 0, "other", 1700, address(0xA11CE), 2, R1, proof));
        assertFalse(anchor.verifyEntry(address(this), 0, "agent", 1701, address(0xA11CE), 2, R1, proof));
        assertFalse(anchor.verifyEntry(address(this), 0, "agent", 1700, address(0xB0B), 2, R1, proof));
        assertFalse(anchor.verifyEntry(address(this), 0, "agent", 1700, address(0xA11CE), 1, R1, proof));
        assertFalse(anchor.verifyEntry(address(this), 0, "agent", 1700, address(0xA11CE), 2, R2, proof));
    }

    function testAnInternalNodeCannotMasqueradeAsAnEntry() public {
        // Two real leaves, one real root.
        bytes32 l0 = anchor.leafHash(address(this), "a", 1, address(1), 0, R1);
        bytes32 l1 = anchor.leafHash(address(this), "b", 2, address(2), 0, R2);
        bytes32 root = l0 < l1 ? keccak256(abi.encodePacked(l0, l1)) : keccak256(abi.encodePacked(l1, l0));
        anchor.commitBatch(ZERO, root, 2);

        // Both genuine leaves verify.
        bytes32[] memory p0 = new bytes32[](1);
        p0[0] = l1;
        assertTrue(anchor.verifyEntry(address(this), 0, "a", 1, address(1), 0, R1, p0));

        // Under the old raw-leaf API, passing `root` with an empty proof verified.
        // There is now no way to express that: every input is re-hashed as a leaf.
        bytes32[] memory empty = new bytes32[](0);
        assertFalse(anchor.verifyEntry(address(this), 0, "a", 1, address(1), 0, root, empty));
    }

    // ─── domain separation (M-5) ────────────────────────────────────────────

    function testLeafIsBoundToChainIdContractAndOperator() public {
        bytes32 base = anchor.leafHash(address(this), "a", 1, address(1), 0, R1);

        // Different operator → different leaf.
        assertTrue(base != anchor.leafHash(address(0xBEEF), "a", 1, address(1), 0, R1));

        // Different anchor deployment → different leaf.
        AuditAnchor other = new AuditAnchor();
        assertTrue(base != other.leafHash(address(this), "a", 1, address(1), 0, R1));

        // Different chain → different leaf.
        vm.chainId(999);
        assertTrue(base != anchor.leafHash(address(this), "a", 1, address(1), 0, R1));
    }

    function testARootIsNotVerifiableUnderADifferentOperator() public {
        bytes32 leaf = anchor.leafHash(address(this), "a", 1, address(1), 0, R1);
        anchor.commitBatch(ZERO, leaf, 1);

        // Someone republishes the same root under their own address...
        address thief = address(0xBAD);
        vm.prank(thief);
        anchor.commitBatch(ZERO, leaf, 1);

        bytes32[] memory empty = new bytes32[](0);
        assertTrue(anchor.verifyEntry(address(this), 0, "a", 1, address(1), 0, R1, empty));
        // ...but the entry does not verify under theirs, because operator is in the leaf.
        assertFalse(anchor.verifyEntry(thief, 0, "a", 1, address(1), 0, R1, empty));
    }

    // ─── events ─────────────────────────────────────────────────────────────

    event BatchCommitted(
        address indexed operator,
        uint256 indexed batchIndex,
        bytes32 merkleRoot,
        bytes32 prevRoot,
        uint64 entryCount,
        uint64 timestamp
    );

    function testEmitsBatchCommittedWithTheChainLink() public {
        // The client reads batchIndex off this event rather than inferring it from a
        // separate getBatchCount() read, so every field here is load-bearing.
        vm.expectEmit(true, true, true, true);
        emit BatchCommitted(address(this), 0, R1, ZERO, 3, uint64(block.timestamp));
        anchor.commitBatch(ZERO, R1, 3);

        vm.expectEmit(true, true, true, true);
        emit BatchCommitted(address(this), 1, R2, R1, 7, uint64(block.timestamp));
        anchor.commitBatch(R1, R2, 7);
    }

    function testEmitsUnderTheCallingOperatorNotTheDeployer() public {
        address op = address(0xA11CE);
        vm.expectEmit(true, true, true, true);
        emit BatchCommitted(op, 0, R1, ZERO, 1, uint64(block.timestamp));
        vm.prank(op);
        anchor.commitBatch(ZERO, R1, 1);
    }

    // ─── storage packing (Batch was packed to two slots) ────────────────────

    function testFuzzBatchFieldsRoundTripThroughPackedStorage(uint64 count, uint64 warpTo) public {
        count = uint64(bound(count, 1, type(uint64).max));
        warpTo = uint64(bound(warpTo, 1, type(uint64).max));
        vm.warp(warpTo);

        anchor.commitBatch(ZERO, R1, count);
        (bool found, bytes32 root, uint64 ts, uint64 storedCount) = anchor.getBatch(address(this), 0);

        assertTrue(found);
        assertEq(root, R1);
        assertEq(storedCount, count, "entryCount truncated by packing");
        assertEq(ts, warpTo, "timestamp truncated by packing");
    }

    // ─── fuzz ───────────────────────────────────────────────────────────────

    /** Any change to any field must produce a different leaf — no field is ignored. */
    function testFuzzLeafHashIsInjectiveOverEveryField(
        address operator,
        uint256 timestamp,
        address recipient,
        uint8 verdict,
        bytes32 entryHash
    ) public view {
        vm.assume(operator != address(0) && recipient != address(0));
        timestamp = bound(timestamp, 0, type(uint64).max);
        verdict = uint8(bound(verdict, 0, 2));

        bytes32 base = anchor.leafHash(operator, "a", timestamp, recipient, verdict, entryHash);

        assertTrue(base != anchor.leafHash(address(uint160(operator) ^ 1), "a", timestamp, recipient, verdict, entryHash));
        assertTrue(base != anchor.leafHash(operator, "b", timestamp, recipient, verdict, entryHash));
        assertTrue(base != anchor.leafHash(operator, "a", timestamp ^ 1, recipient, verdict, entryHash));
        assertTrue(base != anchor.leafHash(operator, "a", timestamp, address(uint160(recipient) ^ 1), verdict, entryHash));
        assertTrue(base != anchor.leafHash(operator, "a", timestamp, recipient, verdict ^ 1, entryHash));
        assertTrue(base != anchor.leafHash(operator, "a", timestamp, recipient, verdict, entryHash ^ bytes32(uint256(1))));
    }

    /** A genuine entry verifies; the same entry with any one field altered does not. */
    function testFuzzVerifyRejectsAnyTamperedField(
        uint256 timestamp,
        address recipient,
        uint8 verdict,
        bytes32 entryHash
    ) public {
        vm.assume(recipient != address(0));
        timestamp = bound(timestamp, 1, type(uint64).max);
        verdict = uint8(bound(verdict, 0, 2));

        bytes32 leaf = anchor.leafHash(address(this), "agent", timestamp, recipient, verdict, entryHash);
        anchor.commitBatch(ZERO, leaf, 1);
        bytes32[] memory empty = new bytes32[](0);
        address op = address(this);

        assertTrue(anchor.verifyEntry(op, 0, "agent", timestamp, recipient, verdict, entryHash, empty));
        assertFalse(anchor.verifyEntry(op, 0, "other", timestamp, recipient, verdict, entryHash, empty));
        assertFalse(anchor.verifyEntry(op, 0, "agent", timestamp ^ 1, recipient, verdict, entryHash, empty));
        assertFalse(anchor.verifyEntry(op, 0, "agent", timestamp, address(uint160(recipient) ^ 1), verdict, entryHash, empty));
        assertFalse(anchor.verifyEntry(op, 0, "agent", timestamp, recipient, verdict ^ 1, entryHash, empty));
        assertFalse(anchor.verifyEntry(op, 0, "agent", timestamp, recipient, verdict, entryHash ^ bytes32(uint256(1)), empty));
    }

    /**
     * Every leaf in a multi-level tree verifies against the committed root, at any size.
     * The single-leaf tests exercise none of the proof walk; this does.
     */
    function testFuzzEveryLeafInATreeVerifies(uint8 sizeSeed, bytes32 salt) public {
        uint256 n = bound(sizeSeed, 2, 24);
        bytes32[] memory leaves = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            leaves[i] = anchor.leafHash(
                address(this), "agent", i + 1, address(uint160(i + 1)), uint8(i % 3),
                keccak256(abi.encode(salt, i))
            );
        }
        (bytes32 root, bytes32[][] memory levels) = _buildTree(leaves);
        anchor.commitBatch(ZERO, root, uint64(n));

        for (uint256 i = 0; i < n; i++) {
            assertTrue(
                anchor.verifyEntry(
                    address(this), 0, "agent", i + 1, address(uint160(i + 1)), uint8(i % 3),
                    keccak256(abi.encode(salt, i)), _proof(levels, i)
                ),
                "a genuine leaf failed to verify"
            );
        }
    }

    /** A proof belonging to one leaf must not validate a different leaf. */
    function testFuzzAProofDoesNotTransferBetweenLeaves(uint8 sizeSeed, bytes32 salt) public {
        uint256 n = bound(sizeSeed, 4, 16);
        bytes32[] memory leaves = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            leaves[i] = anchor.leafHash(
                address(this), "agent", i + 1, address(uint160(i + 1)), 0, keccak256(abi.encode(salt, i))
            );
        }
        (bytes32 root, bytes32[][] memory levels) = _buildTree(leaves);
        anchor.commitBatch(ZERO, root, uint64(n));

        // leaf 0's proof, presented for leaf 1's data
        assertFalse(
            anchor.verifyEntry(
                address(this), 0, "agent", 2, address(uint160(2)), 0,
                keccak256(abi.encode(salt, uint256(1))), _proof(levels, 0)
            ),
            "a proof verified a leaf it does not belong to"
        );
    }

    // ─── tree helpers (sorted-pair, promote-odd — matches the contract's walk) ──

    function _buildTree(bytes32[] memory leaves)
        internal
        pure
        returns (bytes32 root, bytes32[][] memory levels)
    {
        bytes32[][] memory acc = new bytes32[][](32);
        uint256 depth = 0;
        acc[depth] = leaves;
        while (acc[depth].length > 1) {
            bytes32[] memory cur = acc[depth];
            bytes32[] memory next = new bytes32[]((cur.length + 1) / 2);
            for (uint256 i = 0; i < cur.length; i += 2) {
                next[i / 2] = i + 1 < cur.length ? _hashPair(cur[i], cur[i + 1]) : cur[i];
            }
            depth++;
            acc[depth] = next;
        }
        levels = new bytes32[][](depth + 1);
        for (uint256 i = 0; i <= depth; i++) levels[i] = acc[i];
        root = acc[depth][0];
    }

    function _proof(bytes32[][] memory levels, uint256 index)
        internal
        pure
        returns (bytes32[] memory)
    {
        bytes32[] memory tmp = new bytes32[](levels.length);
        uint256 count = 0;
        uint256 idx = index;
        for (uint256 l = 0; l + 1 < levels.length; l++) {
            uint256 sib = idx % 2 == 0 ? idx + 1 : idx - 1;
            if (sib < levels[l].length) tmp[count++] = levels[l][sib];
            idx /= 2;
        }
        bytes32[] memory out = new bytes32[](count);
        for (uint256 i = 0; i < count; i++) out[i] = tmp[i];
        return out;
    }

    function _hashPair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a < b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
    }


    function testFuzzChainIsAlwaysLinear(bytes32 a, bytes32 b) public {
        vm.assume(a != bytes32(0) && b != bytes32(0));
        anchor.commitBatch(ZERO, a, 1);
        anchor.commitBatch(a, b, 1);
        assertEq(anchor.head(address(this)), b);
        assertEq(anchor.getBatchCount(address(this)), 2);
    }

    function testFuzzWrongPrevRootAlwaysReverts(bytes32 wrong) public {
        anchor.commitBatch(ZERO, R1, 1);
        vm.assume(wrong != R1);
        vm.expectRevert(abi.encodeWithSelector(AuditAnchor.WrongPrevRoot.selector, R1, wrong));
        anchor.commitBatch(wrong, R2, 1);
    }
}
