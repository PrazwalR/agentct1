// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {AuditAnchor} from "../src/AuditAnchor.sol";

/**
 * Deploy AuditAnchor to Base Sepolia:
 *   forge script script/Deploy.s.sol --rpc-url base_sepolia --broadcast
 *
 * Requires ANCHOR_DEPLOYER_KEY (falls back to ANCHOR_COMMITTER_KEY).
 *
 * The anchor has no owner and no privileged role, so the deployer holds no special
 * power over it — any address can start its own batch chain. Deploying with the
 * committer key is therefore convenient, not required, and separating them is
 * preferable: the committer key is hot (it signs on every flush) while the deployer
 * key is used once.
 */
contract Deploy is Script {
    function run() external returns (AuditAnchor anchor) {
        uint256 pk = vm.envOr("ANCHOR_DEPLOYER_KEY", vm.envUint("ANCHOR_COMMITTER_KEY"));
        vm.startBroadcast(pk);
        anchor = new AuditAnchor();
        vm.stopBroadcast();

        console.log("AuditAnchor deployed at:", address(anchor));
        console.log("Deployer (no privileges):", vm.addr(pk));
        console.log("Set AUDIT_ANCHOR_ADDRESS to the address above.");
        console.log("Verify with: agentctl audit --verify --operator <committer address>");
    }
}
