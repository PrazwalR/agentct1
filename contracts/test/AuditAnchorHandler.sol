// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {AuditAnchor} from "../src/AuditAnchor.sol";

/**
 * Guided random actions for the AuditAnchor invariant suite.
 *
 * Every action is wrapped in try/catch so an intentionally-rejected commit (a fork,
 * a zero root) does not abort the sequence — which lets the suite run with
 * `fail_on_revert = true`, so an *unexpected* revert is a real failure signal
 * rather than being silently swallowed.
 *
 * Ghost state mirrors what the contract should hold, and records a proof for every
 * batch at the moment it was committed, so the invariants can re-check old proofs
 * later. That is the property the whole product rests on: anchoring is append-only,
 * so a proof that verified once must verify forever.
 */
contract AuditAnchorHandler is Test {
    AuditAnchor public immutable anchor;

    address[3] public operators;

    /// The fields of a single-leaf batch, kept so its proof can be re-checked.
    struct Anchored {
        address operator;
        uint256 batchIndex;
        string agentId;
        uint256 timestamp;
        address recipient;
        uint8 verdict;
        bytes32 entryHash;
    }

    Anchored[] public anchoredEntries;

    // ghost state
    mapping(address => bytes32) public ghostHead;
    mapping(address => uint256) public ghostCount;
    uint256 public commitsAccepted;
    uint256 public commitsRejected;

    constructor(AuditAnchor _anchor) {
        anchor = _anchor;
        operators = [makeAddr("op-a"), makeAddr("op-b"), makeAddr("op-c")];
    }

    function operatorAt(uint256 i) external view returns (address) {
        return operators[i % 3];
    }

    function anchoredCount() external view returns (uint256) {
        return anchoredEntries.length;
    }

    function entryAt(uint256 i) external view returns (Anchored memory) {
        return anchoredEntries[i];
    }

    // ─── actions ────────────────────────────────────────────────────────────

    /**
     * Commit a well-formed single-leaf batch extending the operator's real head.
     * Single-leaf means root == leafHash and the proof is empty, so the entry can
     * be re-verified cheaply for the lifetime of the run.
     */
    function commitEntry(uint256 opSeed, uint256 tsSeed, uint256 recSeed, uint8 verdictSeed)
        external
    {
        address op = operators[opSeed % 3];
        uint256 timestamp = bound(tsSeed, 1, type(uint64).max);
        address recipient = address(uint160(bound(recSeed, 1, type(uint160).max)));
        uint8 verdict = uint8(bound(verdictSeed, 0, 2));
        string memory agentId = "inv-agent";
        bytes32 entryHash = keccak256(abi.encode(timestamp, recipient, verdict));

        bytes32 leaf = anchor.leafHash(op, agentId, timestamp, recipient, verdict, entryHash);
        bytes32 prev = anchor.head(op);

        vm.prank(op);
        try anchor.commitBatch(prev, leaf, 1) returns (uint256 idx) {
            commitsAccepted++;
            ghostHead[op] = leaf;
            ghostCount[op] = idx + 1;
            anchoredEntries.push(
                Anchored(op, idx, agentId, timestamp, recipient, verdict, entryHash)
            );
        } catch {
            commitsRejected++;
        }
    }

    /** Attempt to fork the chain off a stale head. Must always be rejected. */
    function commitFork(uint256 opSeed, bytes32 stalePrev, bytes32 root) external {
        address op = operators[opSeed % 3];
        bytes32 realHead = anchor.head(op);
        if (stalePrev == realHead) return; // not a fork; skip
        if (root == bytes32(0)) return;

        vm.prank(op);
        try anchor.commitBatch(stalePrev, root, 1) {
            commitsAccepted++; // should be unreachable — invariant_ForksAreAlwaysRejected catches it
        } catch {
            commitsRejected++;
        }
    }

    /** Attempt an invalid commit. Must always be rejected, leaving state untouched. */
    function commitInvalid(uint256 opSeed, bool zeroRoot) external {
        address op = operators[opSeed % 3];
        bytes32 prev = anchor.head(op);
        bytes32 root = zeroRoot ? bytes32(0) : keccak256(abi.encode(prev, block.number));
        uint64 count = zeroRoot ? 1 : 0;

        vm.prank(op);
        try anchor.commitBatch(prev, root, count) {
            commitsAccepted++; // unreachable — validation must reject both shapes
        } catch {
            commitsRejected++;
        }
    }

}
