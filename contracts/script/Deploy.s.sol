// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {AuditAnchor} from "../src/AuditAnchor.sol";

/**
 * Deploy AuditAnchor to Base Sepolia:
 *   forge script script/Deploy.s.sol --rpc-url base_sepolia --broadcast
 * Requires ANCHOR_COMMITTER_KEY in the environment.
 */
contract Deploy is Script {
    function run() external returns (AuditAnchor anchor) {
        uint256 pk = vm.envUint("ANCHOR_COMMITTER_KEY");
        vm.startBroadcast(pk);
        anchor = new AuditAnchor();
        vm.stopBroadcast();
        console.log("AuditAnchor deployed at:", address(anchor));
    }
}
