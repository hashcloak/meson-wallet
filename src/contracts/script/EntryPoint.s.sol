pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import "../SmartWalletLogic.sol";
import "../core/EntryPoint.sol";

contract DeployEntryPoint is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        _deployEntryPoint(deployerPrivateKey);
    }

    function _deployEntryPoint(uint256 deployerPK) internal {
        vm.startBroadcast(deployerPK);
        EntryPoint ep = new EntryPoint();
        vm.stopBroadcast();
    }
}