// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "forge-std/Test.sol";
import "../src/SmartWalletLogic.sol";
import "../src/AccountFactory.sol";
import "../src/core/EntryPoint.sol";
import "./TestUtils.sol";
import "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";

contract WalletTest is Test {
    SmartWalletLogic impl;
    TestUtils tu;
    uint256 ownerKey = 1;
    using UserOperationLib for UserOperation;
    using ECDSA for bytes32;

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

    event SmartWalletInitialized(
        IEntryPoint indexed entryPoint,
        address indexed owner
    );

    function setUp() public {
        address owner = vm.addr(ownerKey);
        //fake entrypoint
        //impl without proxy
        impl = new SmartWalletLogic(IEntryPoint(address(this)));
        impl.initialize(owner);

        tu = new TestUtils();
    }

    function testNotReInitialize() public {
        vm.expectRevert("Initializable: contract is already initialized");
        impl.initialize(address(this));
    }

    function testValidateOp() public {
        address owner = vm.addr(ownerKey);
        EntryPoint ep = new EntryPoint();
        impl = new SmartWalletLogic(IEntryPoint(address(ep)));
        impl.initialize(owner);
        UserOperation memory userOp;
        uint256 preNonce = impl.getNonce();
        bytes32 opHash;
        (userOp, opHash) = tu.signUserOp(userOp, address(this), ownerKey);
        vm.prank(address(ep));
        uint256 result = impl.validateUserOp(userOp, opHash, 0);
        assertEq(result, 0);
        assertEq(preNonce, 0);
        //nonce is now validated in entrypoint
        //assertEq(impl.getNonce(), preNonce + 1);
    }

    function testCreate2Account() public {
        AccountFactory af = new AccountFactory(IEntryPoint(address(this)));
        address owner = vm.addr(1);
        uint salt = 123;
        address target = af.getAddress(owner, salt);
        assertEq(target.code.length == 0, true);

        SmartWalletLogic wallet = af.createAccount(owner, salt);
        assertEq(address(wallet) == target, true);
        assertEq(address(wallet).code.length > 0, true);
    }

    function testProxyValidateOp() public {
        EntryPoint ep = new EntryPoint();
        AccountFactory af = new AccountFactory(IEntryPoint(address(ep)));
        address owner = vm.addr(1);
        uint salt = 123;
        vm.prank(address(ep));
        SmartWalletLogic wallet = af.createAccount(owner, salt);
        UserOperation memory userOp;

        uint256 preNonce = wallet.getNonce();
        bytes32 opHash = signUserOp(userOp, ownerKey);
        vm.prank(address(ep));
        uint256 result = wallet.validateUserOp(userOp, opHash, 0);
        assertEq(result, 0);
        assertEq(preNonce, 0);
        //nonce is now validated in entrypoint
        //assertEq(wallet.getNonce(), preNonce + 1);
    }

    function signUserOp(
        UserOperation memory userOp,
        uint256 key
    ) public view returns (bytes32 opHash) {
        UserOperationNoSig memory userOpNoSig = UserOperationNoSig(
            userOp.sender,
            userOp.nonce,
            userOp.initCode,
            userOp.callData,
            userOp.callGasLimit,
            userOp.verificationGasLimit,
            userOp.preVerificationGas,
            userOp.maxFeePerGas,
            userOp.maxPriorityFeePerGas,
            userOp.paymasterAndData
        );
        opHash = keccak256(
            abi.encode(
                keccak256(abi.encode(userOpNoSig)),
                address(this),
                block.chainid
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            key,
            opHash.toEthSignedMessageHash()
        );
        bytes memory signature = abi.encodePacked(r, s, v);
        userOp.signature = signature;
    }

    // function fillAndSignOp() public returns (UserOperation memory) {
    //     UserOperationNoSig memory userOpNoSig;
    //     UserOperation memory userOp;
    //     bytes32 opHash = keccak256(abi.encode(keccak256(abi.encode(userOpNoSig)), address(this), block.chainid));
    //     (uint8 v, bytes32 r, bytes32 s) = vm.sign(1, opHash);
    //     bytes memory signature = abi.encodePacked(r,s,v);
    //     userOp.signature = signature;
    //     return userOp;
    // }
}
