// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import "../src/AccountFactory.sol";

contract DeployAccountFactory is Script {
    address entrypoint = 0x0576a174D229E3cFA37253523E645A78A0C91B57;

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);
        AccountFactory af = new AccountFactory(IEntryPoint(entrypoint));
        vm.stopBroadcast();
    }
}
