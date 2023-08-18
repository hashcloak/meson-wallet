// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "forge-std/Test.sol";
import "openzeppelin-contracts/contracts/utils/Create2.sol";
import "../AccountFactory.sol";
import "../interfaces/UserOperation.sol";
import "../SmartWalletLogic.sol";

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

    function testEncode() public view {
        bytes memory enc = type(SmartWalletProxy).creationCode;
        console.logBytes(enc);
    }

    function testCreat2() public view {
        uint salt = 100;
        address owner = 0x5B38Da6a701c568545dCfcB03FcB875f56beddC4;
        address accountImplementation = 0xc0ffee254729296a45a3885639AC7E10F9d54979;
        address fac = 0xd9145CCE52D386f254917e481eB44e9943F39138;
        address addr = Create2.computeAddress(
            bytes32(salt),
            keccak256(
                abi.encodePacked(
                    type(SmartWalletProxy).creationCode,
                    abi.encode(
                        accountImplementation,
                        abi.encodeCall(SmartWalletLogic.initialize, (owner))
                    )
                )
            ),
            fac
        );
        console.logAddress(addr);
    }
}
