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

    // ─── fuzz ───────────────────────────────────────────────────────────────

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
