// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {AuditAnchor} from "../src/AuditAnchor.sol";
import {AuditAnchorHandler} from "./AuditAnchorHandler.sol";

/**
 * Invariants for AuditAnchor.
 *
 * Unit tests check one path at a time; these check that the guarantees the product
 * sells survive thousands of random call sequences across three competing operators.
 * The load-bearing one is invariant_AnchoredEntriesVerifyForever: if a proof can ever
 * stop verifying, the audit trail is not evidence.
 */
contract AuditAnchorInvariantTest is Test {
    AuditAnchor internal anchor;
    AuditAnchorHandler internal handler;
    address internal stranger;

    bytes32 internal constant ZERO = bytes32(0);

    function setUp() public {
        anchor = new AuditAnchor();
        handler = new AuditAnchorHandler(anchor);
        stranger = makeAddr("never-commits");
        targetContract(address(handler));
    }

    /**
     * Anchoring is append-only, so a proof that verified at commit time must keep
     * verifying no matter what anyone commits afterwards — including other operators
     * writing to the same contract. This is the whole guarantee.
     */
    function invariant_AnchoredEntriesVerifyForever() public view {
        uint256 n = handler.anchoredCount();
        bytes32[] memory emptyProof = new bytes32[](0);
        for (uint256 i = 0; i < n; i++) {
            AuditAnchorHandler.Anchored memory e = handler.entryAt(i);
            assertTrue(
                anchor.verifyEntry(
                    e.operator, e.batchIndex, e.agentId, e.timestamp,
                    e.recipient, e.verdict, e.entryHash, emptyProof
                ),
                "an entry that was anchored no longer verifies"
            );
        }
    }

    /** head is always the most recent batch's root — never drifts from the array. */
    function invariant_HeadMatchesLastBatch() public view {
        for (uint256 i = 0; i < 3; i++) {
            address op = handler.operatorAt(i);
            uint256 count = anchor.getBatchCount(op);
            if (count == 0) {
                assertEq(anchor.head(op), ZERO, "untouched operator must have a zero head");
            } else {
                (bool found, bytes32 root,,) = anchor.getBatch(op, count - 1);
                assertTrue(found);
                assertEq(anchor.head(op), root, "head does not match the last committed batch");
            }
        }
    }

    /** The contract's own count must match what commitBatch reported to callers. */
    function invariant_CountMatchesAcceptedCommits() public view {
        for (uint256 i = 0; i < 3; i++) {
            address op = handler.operatorAt(i);
            assertEq(
                anchor.getBatchCount(op),
                handler.ghostCount(op),
                "on-chain batch count disagrees with the indices commitBatch returned"
            );
            assertEq(anchor.head(op), handler.ghostHead(op), "head disagrees with ghost state");
        }
    }

    /** Validation is never bypassed: nothing invalid is ever persisted. */
    function invariant_NoStoredBatchIsDegenerate() public view {
        for (uint256 i = 0; i < 3; i++) {
            address op = handler.operatorAt(i);
            uint256 count = anchor.getBatchCount(op);
            for (uint256 j = 0; j < count; j++) {
                (bool found, bytes32 root,, uint64 entryCount) = anchor.getBatch(op, j);
                assertTrue(found, "a batch inside the count must be readable");
                assertTrue(root != ZERO, "a zero root was stored");
                assertTrue(entryCount > 0, "an empty batch was stored");
            }
        }
    }

    /** A fork off a stale head must never be accepted, however many are attempted. */
    function invariant_ForksAreAlwaysRejected() public view {
        // Every accepted commit produced exactly one recorded entry; forks and invalid
        // commits produce none. If a fork had slipped through, the counts would diverge.
        assertEq(
            handler.commitsAccepted(),
            handler.anchoredCount(),
            "a commit was accepted that was not a well-formed chain extension"
        );
    }

    /** One operator's activity can never disturb another's chain. */
    function invariant_OperatorsAreIsolated() public view {
        assertEq(anchor.getBatchCount(stranger), 0, "a stranger acquired batches");
        assertEq(anchor.head(stranger), ZERO, "a stranger acquired a head");
    }

    /** Reads never revert, whatever the input — a config mistake must not look like tampering. */
    function invariant_ViewsNeverRevert() public view {
        bytes32[] memory long = new bytes32[](70); // over MAX_PROOF_LENGTH
        for (uint256 i = 0; i < 3; i++) {
            address op = handler.operatorAt(i);
            anchor.getBatch(op, type(uint256).max);
            assertFalse(
                anchor.verifyEntry(op, type(uint256).max, "x", 1, address(1), 0, ZERO, long),
                "an out-of-range verify should be false, not true"
            );
        }
    }
}
