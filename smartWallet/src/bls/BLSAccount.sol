// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "../SmartWalletLogic.sol";
import "./lib/BLSOpen.sol";
import "./IBLSAccount.sol";
bytes32 constant BLS_DOMAIN = keccak256("eip4337.bls.domain");

/**
 * Minimal BLS-based account that uses an aggregated signature.
 * The account must maintain its own BLS public key, and expose its trusted signature aggregator.
 * Note that unlike the "standard" SimpleAccount, this account can't be called directly
 * (normal SimpleAccount uses its "signer" address as both the ecrecover signer, and as a legitimate
 * Ethereum sender address. Obviously, a BLS public key is not a valid Ethereum sender address.)
 */
contract BLSAccount is SmartWalletLogic, IBLSAccount {
    address public immutable aggregator;
    uint256[4] private publicKey;

    // The constructor is used only for the "implementation" and only sets immutable values.
    // Mutable value slots for proxy accounts are set by the 'initialize' function.
    constructor(
        IEntryPoint anEntryPoint,
        address anAggregator
    ) SmartWalletLogic(anEntryPoint) {
        aggregator = anAggregator;
    }

    /**
     * The initializer for the BLSAccount instance.
     * @param aPublicKey public key from a BLS keypair that will have a full ownership and control of this account.
     */
    function initialize(
        uint256[4] memory aPublicKey
    ) public virtual initializer {
        super._initialize(address(0));
        _setBlsPublicKey(aPublicKey);
    }

    function _validateSignature(
        UserOperation calldata userOp,
        bytes32 userOpHash
    ) internal view override returns (uint256 validationData) {
        (userOp, userOpHash);
        if (userOp.initCode.length != 0) {
            // BLSSignatureAggregator.getUserOpPublicKey() assumes that during account creation, the public key is
            // the suffix of the initCode.
            // The account MUST validate it
            bytes32 pubKeyHash = keccak256(abi.encode(getBlsPublicKey()));
            require(
                keccak256(userOp.initCode[userOp.initCode.length - 128:]) ==
                    pubKeyHash,
                "wrong pubkey"
            );
        }
        if (aggregator == address(0)) {
            uint256[2] memory blsSignature = abi.decode(
                userOp.signature,
                (uint256[2])
            );
            uint256[2] memory message = BLSOpen.hashToPoint(
                BLS_DOMAIN,
                abi.encodePacked(userOpHash)
            );

            if (!BLSOpen.verifySingle(blsSignature, publicKey, message)) {
                return SIG_VALIDATION_FAILED;
            }
            return 0;
        }
        return _packValidationData(ValidationData(aggregator, 0, 0));
    }

    /**
     * Allows the owner to set or change the BLS key.
     * @param newPublicKey public key from a BLS keypair that will have a full ownership and control of this account.
     */
    function setBlsPublicKey(uint256[4] memory newPublicKey) public onlyOwner {
        _setBlsPublicKey(newPublicKey);
    }

    function _setBlsPublicKey(uint256[4] memory newPublicKey) internal {
        emit PublicKeyChanged(publicKey, newPublicKey);
        publicKey = newPublicKey;
    }

    /// @inheritdoc IBLSAccount
    function getBlsPublicKey()
        public
        view
        override
        returns (uint256[4] memory)
    {
        return publicKey;
    }
}
