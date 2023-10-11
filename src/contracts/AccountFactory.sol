// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "openzeppelin-contracts/contracts/utils/Create2.sol";
import "openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "./SmartWalletProxy.sol";
import "./SmartWalletLogic.sol";

/**
 * A UserOperations "initCode" holds the address of the factory, and a method call (to createAccount, in this sample factory).
 * The factory's createAccount returns the target account address even if it is already installed.
 * This way, the entryPoint.getSenderAddress() can be called either before or after the account is created.
 */
contract AccountFactory {
    SmartWalletLogic public immutable accountImplementation;

    constructor(IEntryPoint _entryPoint) {
        accountImplementation = new SmartWalletLogic(_entryPoint);
    }

    /**
     * create an account, and return its address.
     * returns the address even if the account is already deployed.
     * Note that during UserOperation execution, this method is called only if the account is not deployed.
     * This method returns an existing account address so that entryPoint.getSenderAddress() would work even after account creation
     */
    function createAccount(
        address owner,
        uint salt
    ) public returns (SmartWalletLogic ret) {
        address addr = getAddress(owner, salt);
        uint codeSize = addr.code.length;
        if (codeSize > 0) {
            return SmartWalletLogic(payable(addr));
        }
        ret = SmartWalletLogic(
            payable(
                new SmartWalletProxy{salt: bytes32(salt)}(
                    address(accountImplementation),
                    abi.encodeCall(SmartWalletLogic.initialize, (owner))
                )
            )
        );
    }

    /**
     * calculate the counterfactual address of this account as it would be returned by createAccount()
     */
    function getAddress(
        address owner,
        uint salt
    ) public view returns (address) {
        return
            Create2.computeAddress(
                bytes32(salt),
                keccak256(
                    abi.encodePacked(
                        type(SmartWalletProxy).creationCode,
                        abi.encode(
                            address(accountImplementation),
                            abi.encodeCall(SmartWalletLogic.initialize, (owner))
                        )
                    )
                )
            );
    }
}