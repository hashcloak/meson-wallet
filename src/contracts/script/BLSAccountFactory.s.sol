// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import "../bls/BLSAccountFactory.sol";

contract DeployAccountFactory is Script {
    //address entrypoint = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789; //entry point v0.6
    address entrypoint = 0x3cD5A8Ddd0EFb5804978a4Da74D3Fb6d074829F3; //local entry point
    address aggregator = address(0); //do not support aggregator for now

    //deploy bls account factory and bls account (when calling new BLSAccountFactory)
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);
        BLSAccountFactory af = new BLSAccountFactory(
            IEntryPoint(entrypoint),
            aggregator
        );
        vm.stopBroadcast();
    }
}
