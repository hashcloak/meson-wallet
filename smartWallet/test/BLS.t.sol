// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/bls/BLSSignatureAggregator.sol";
import "../src/core/EntryPoint.sol";
import "../src/interfaces/IEntryPoint.sol";
import "../src/SmartWalletLogic.sol";
import "../src/bls/BLSAccount.sol";
import "../src/bls/IBLSAccount.sol";
import "../src/bls/lib/BLSOpen.sol";
import "../src/bls/BLSAccountFactory.sol";
import "../src/interfaces/UserOperation.sol";
import "./BLSUtil.t.sol";
import "../src/core/SenderCreator.sol";

contract BlsTest is Test {
    BLSSignatureAggregator agg;
    EntryPoint entry;
    BLSAccount acc;
    BLSUtil bu;
    BLSAccountFactory bf;
    SenderCreator sc;

    function setUp() public {
        agg = new BLSSignatureAggregator();
        entry = new EntryPoint();
        bu = new BLSUtil();
        acc = new BLSAccount(IEntryPoint(entry), address(agg));
        bf = new BLSAccountFactory(IEntryPoint(entry), address(agg));
        sc = new SenderCreator();
        uint256[4] memory publicKey = [
            0x1fadb75252c5c536009f3bd72bfb398dae0bdfc82493826ffc38a264a7d47376,
            0x045115ebc7f7b978c02cd23e609077b1d8c6e73e51159e7bf98ec69fb0bebba7,
            0x128f731a6a0c284bbead710fa8059746ce3effdc7e59257fc5ade51b9e60b622,
            0x27bae2c16607c1428f8fc8eec7925fb0d7b6cc0e806c857b9cfb54aba0b9e026
        ];
        acc.initialize(publicKey);
    }

    //direct call to agreegator without entrypoint
    function testAgrregatorVerify() public view {
        uint256 key = 0xc9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721;
        UserOperation memory userOp = UserOperation(
            address(acc),
            0,
            "",
            "",
            999999,
            999999,
            999999,
            999999,
            999999,
            "",
            ""
        );
        (UserOperation memory userOp1, bytes memory signature) = bu.signUserOp(
            userOp,
            key,
            address(agg)
        );
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = userOp1;
        agg.validateSignatures(ops, signature); //revert when failed
    }

    //test generating account with SenderCreator.sol using createBLSInitCode function
    function testBLSInitcode() public {
        uint salt = 0x809a6715072c495964f0a9a06bd8ae66;
        uint256[4] memory publicKey = [
            0x1fadb75252c5c536009f3bd72bfb398dae0bdfc82493826ffc38a264a7d47376,
            0x045115ebc7f7b978c02cd23e609077b1d8c6e73e51159e7bf98ec69fb0bebba7,
            0x128f731a6a0c284bbead710fa8059746ce3effdc7e59257fc5ade51b9e60b622,
            0x27bae2c16607c1428f8fc8eec7925fb0d7b6cc0e806c857b9cfb54aba0b9e026
        ];
        address sender1 = bf.getAddress(salt, publicKey);
        //assert sender1 hasn't been created
        assertEq(sender1.code.length == 0, true);
        bytes memory initCode = this.createBLSInitCode(salt, publicKey);
        address sender = sc.createSender(initCode);
        assertEq(sender, sender1);
        assertEq(sender1.code.length > 0, true);

        uint256[4] memory pk = IBLSAccount(sender).getBlsPublicKey();
        assertEq(pk[0], publicKey[0]);
        assertEq(pk[1], publicKey[1]);
        assertEq(pk[2], publicKey[2]);
        assertEq(pk[3], publicKey[3]);
    }

    function createBLSInitCode(
        uint256 salt,
        uint256[4] calldata aPublicKey
    ) public view returns (bytes memory) {
        bytes memory call = abi.encodeCall(
            BLSAccountFactory.createAccount,
            (salt, aPublicKey)
        );
        bytes memory initCode = abi.encodePacked(address(bf), call);
        return initCode;
    }

    //test send ether through entrypoint with aggregator
    function testUserOpWithAggregator() public {
        uint256 key = 0xc9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721;
        vm.deal(address(this), 1 ether);
        vm.deal(address(acc), 1 ether);
        agg.addStake{value: 100000000000000}(IEntryPoint(entry), 100);
        address dest = 0x85ef6db74c13B3bfa12A784702418e5aAfad73EB;
        bytes memory callData = abi.encodeWithSelector(
            SmartWalletLogic.execute.selector,
            dest,
            10,
            ""
        );
        UserOperation memory userOp = UserOperation(
            address(acc),
            0,
            "",
            callData,
            999999,
            999999,
            999999,
            999999,
            999999,
            "",
            ""
        );
        (UserOperation memory userOp1, bytes memory signature) = bu.signUserOp(
            userOp,
            key,
            address(agg)
        );
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = userOp1;
        IEntryPoint.UserOpsPerAggregator[]
            memory opas = new IEntryPoint.UserOpsPerAggregator[](1);
        IEntryPoint.UserOpsPerAggregator memory opa = IEntryPoint
            .UserOpsPerAggregator(ops, IAggregator(agg), signature);
        opas[0] = opa;
        entry.handleAggregatedOps(opas, payable(acc));
        assertEq(dest.balance, 10);
    }

    function testHashtoPoint() public {
        bytes memory ms = "0x73616d706c65";
        uint256[2] memory message = BLSOpen.hashToPoint(BLS_DOMAIN, ms);
    }
}
