// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import "../AccountFactory.sol";

contract DeployAccountFactory is Script {
    address entrypoint = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789; //entry point v0.6

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);
        AccountFactory af = new AccountFactory(IEntryPoint(entrypoint));
        vm.stopBroadcast();
    }
}