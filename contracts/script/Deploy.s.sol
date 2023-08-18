pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import "../AccountFactory.sol";
import "../SmartWalletLogic.sol";
import "../core/EntryPoint.sol";

//Deploy entrypoint, logic, factory
contract Deploy is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);
        EntryPoint ep = new EntryPoint();
        AccountFactory af = new AccountFactory(IEntryPoint(ep));
        vm.stopBroadcast();
    }
}
