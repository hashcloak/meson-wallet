// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "openzeppelin-contracts/contracts/utils/Create2.sol";
import "openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import "../interfaces/IEntryPoint.sol";
import "./BLSWallet.sol";

/**
 * Based n SimpleAccountFactory
 * can't be a subclass, since both constructor and createAccount depend on the
 * actual wallet contract constructor and initializer
 */
contract BLSAccountFactory {
    BLSWallet public immutable accountImplementation;

    constructor(IEntryPoint entryPoint, address aggregator) {
        accountImplementation = new BLSWallet(entryPoint, aggregator);
    }

    /**
     * create an account, and return its address.
     * returns the address even if the account is already deployed.
     * Note that during UserOperation execution, this method is called only if the account is not deployed.
     * This method returns an existing account address so that entryPoint.getSenderAddress() would work even after account creation
     * Also note that out BLSSignatureAggregator requires that the public-key is the last parameter
     */
    function createAccount(
        address owner,
        uint salt,
        uint256[4] memory aPublicKey
    ) public returns (BLSWallet) {
        address addr = getAddress(owner, salt, aPublicKey);
        uint codeSize = addr.code.length;
        if (codeSize > 0) {
            return BLSWallet(payable(addr));
        }
        return
            BLSWallet(
                payable(
                    new ERC1967Proxy{salt: bytes32(salt)}(
                        address(accountImplementation),
                        abi.encodeCall(
                            BLSWallet.initialize,
                            (aPublicKey, owner)
                        )
                    )
                )
            );
    }

    /**
     * calculate the counterfactual address of this account as it would be returned by createAccount()
     */
    function getAddress(
        address owner,
        uint salt,
        uint256[4] memory aPublicKey
    ) public view returns (address) {
        return
            Create2.computeAddress(
                bytes32(salt),
                keccak256(
                    abi.encodePacked(
                        type(ERC1967Proxy).creationCode,
                        abi.encode(
                            address(accountImplementation),
                            abi.encodeCall(
                                BLSWallet.initialize,
                                (aPublicKey, owner)
                            )
                        )
                    )
                )
            );
    }
}
