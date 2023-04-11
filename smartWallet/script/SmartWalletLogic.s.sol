pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import "../src/SmartWalletLogic.sol";

contract DeploySmartWalletLogic is Script {
    address entrypoint = 0x0576a174D229E3cFA37253523E645A78A0C91B57;

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);
        SmartWalletLogic impl = new SmartWalletLogic(IEntryPoint(entrypoint));
        vm.stopBroadcast();
    }
}
