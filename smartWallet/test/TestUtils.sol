// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "forge-std/Test.sol";
import "../src/AccountFactory.sol";
import "../src/interfaces/UserOperation.sol";

contract TestUtils is Test {
    using ECDSA for bytes32;
    using UserOperationLib for UserOperation;
    struct UserOperationNoSig {
        address sender;
        uint256 nonce;
        bytes initCode;
        bytes callData;
        uint256 callGasLimit;
        uint256 verificationGasLimit;
        uint256 preVerificationGas;
        uint256 maxFeePerGas;
        uint256 maxPriorityFeePerGas;
        bytes paymasterAndData;
    }

    function createInitCode(
        AccountFactory af,
        address owner,
        uint salt
    ) public pure returns (bytes memory) {
        bytes memory call = abi.encodeCall(
            AccountFactory.createAccount,
            (owner, salt)
        );
        bytes memory initCode = abi.encodePacked(address(af), call);
        return initCode;
    }

    function signUserOp(
        UserOperation calldata userOp,
        address entryPoint,
        uint256 key
    ) public view returns (UserOperation memory, bytes32) {
        bytes32 opHash = keccak256(
            abi.encode(userOp.hash(), entryPoint, block.chainid)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            key,
            opHash.toEthSignedMessageHash()
        );
        bytes memory signature = abi.encodePacked(r, s, v);
        UserOperation memory mUserOp = userOp;
        mUserOp.signature = signature;
        return (mUserOp, opHash);
    }
}
