// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "../SmartWalletLogic.sol";

/**
 * Minimal BLS-based account that uses an aggregated signature.
 * The account must maintain its own BLS public-key, and expose its trusted signature aggregator.
 * Note that unlike the "standard" SimpleAccount, this account can't be called directly
 * (normal SimpleAccount uses its "signer" address as both the ecrecover signer, and as a legitimate
 * Ethereum sender address. Obviously, a BLS public is not a valid Ethereum sender address.)
 */
contract BLSWallet is SmartWalletLogic {
    address public immutable aggregator;
    uint256[4] private publicKey;

    // The constructor is used only for the "implementation" and only sets immutable values.
    // Mutable values slots for proxy accounts are set by the 'initialize' function.
    constructor(
        IEntryPoint anEntryPoint,
        address anAggregator
    ) SmartWalletLogic(anEntryPoint) {
        aggregator = anAggregator;
    }

    function initialize(
        uint256[4] memory aPublicKey,
        address _owner
    ) public virtual initializer {
        super._initialize(_owner);
        publicKey = aPublicKey;
    }

    function _validateSignature(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        address userOpAggregator
    ) internal view override returns (uint256 sigTimeRange) {
        (userOp, userOpHash);
        require(userOpAggregator == aggregator, "BLSAccount: wrong aggregator");
        return 0;
    }

    event PublicKeyChanged(uint256[4] oldPublicKey, uint256[4] newPublicKey);

    function setBlsPublicKey(
        uint256[4] memory newPublicKey
    ) external onlyOwner {
        emit PublicKeyChanged(publicKey, newPublicKey);
        publicKey = newPublicKey;
    }

    function getAggregator() external view returns (address) {
        return aggregator;
    }

    function getBlsPublicKey() external view returns (uint256[4] memory) {
        return publicKey;
    }
}
