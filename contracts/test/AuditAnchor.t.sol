// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {AuditAnchor} from "../src/AuditAnchor.sol";

contract AuditAnchorTest is Test {
    AuditAnchor internal anchor;

    function setUp() public {
        anchor = new AuditAnchor();
    }

    function testCommitIncrementsCount() public {
        assertEq(anchor.getBatchCount(address(this)), 0);
        anchor.commitBatch(bytes32(uint256(1)), 3);
        assertEq(anchor.getBatchCount(address(this)), 1);
        (bytes32 root, uint256 ts, uint256 count) = anchor.batches(address(this), 0);
        assertEq(root, bytes32(uint256(1)));
        assertEq(count, 3);
        assertGt(ts, 0);
    }

    function testVerifySingleLeaf() public {
        // A single-leaf StandardMerkleTree has root == leaf and an empty proof.
        bytes32 leaf = keccak256("leaf");
        anchor.commitBatch(leaf, 1);
        bytes32[] memory proof = new bytes32[](0);
        assertTrue(anchor.verifyEntry(address(this), 0, leaf, proof));
        assertFalse(anchor.verifyEntry(address(this), 0, keccak256("other"), proof));
    }

    function testVerifyTwoLeavesSortedPairs() public {
        bytes32 a = keccak256("a");
        bytes32 b = keccak256("b");
        bytes32 root =
            a < b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
        anchor.commitBatch(root, 2);

        bytes32[] memory proofForA = new bytes32[](1);
        proofForA[0] = b;
        assertTrue(anchor.verifyEntry(address(this), 0, a, proofForA));

        bytes32[] memory proofForB = new bytes32[](1);
        proofForB[0] = a;
        assertTrue(anchor.verifyEntry(address(this), 0, b, proofForB));
    }

    function testCommitsAreOperatorScoped() public {
        anchor.commitBatch(bytes32(uint256(1)), 1);
        address other = address(0xBEEF);
        assertEq(anchor.getBatchCount(other), 0);
        assertEq(anchor.getBatchCount(address(this)), 1);
    }
}
