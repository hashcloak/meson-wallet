// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "forge-std/Test.sol";
import "../src/core/EntryPoint.sol";
import "../src/SmartWalletLogic.sol";
import "../src/AccountFactory.sol";
import "./TestUtils.sol";
import "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";

contract EnrtyPointTest is Test {
    using UserOperationLib for UserOperation;
    using ECDSA for bytes32;
    EntryPoint ep;
    AccountFactory af;
    TestUtils tu;
    uint256 ownerkey1 = 1;

    function setUp() public {
        ep = new EntryPoint();
        vm.deal(vm.addr(ownerkey1), 1 ether);
        af = new AccountFactory(ep);
        tu = new TestUtils();
    }

    function testStake() public {
        address addr1 = vm.addr(ownerkey1);
        address addrTest = vm.addr(2);
        uint256 preFund = ep.balanceOf(addrTest);
        vm.prank(addr1);
        ep.depositTo{value: 1 wei}(addrTest);
        assertEq(ep.balanceOf(addrTest) - preFund, 1 wei);
    }

    function testHandleOp() public {
        address owner1 = vm.addr(ownerkey1);
        uint256 salt = 123;
        //calculate wallet address
        address sender = af.getAddress(owner1, 123);
        assertEq(sender.code.length == 0, true);
        //prefund wallet
        vm.prank(owner1);
        ep.depositTo{value: 0.1 ether}(sender);

        bytes memory initCode = tu.createInitCode(af, owner1, salt);
        bytes memory callData = abi.encodeCall(
            SmartWalletLogic.increase_num,
            ()
        );
        UserOperation memory userOp = UserOperation(
            sender,
            0,
            initCode,
            callData,
            999999,
            999999,
            999999,
            999999,
            999999,
            "",
            ""
        );
        (userOp, ) = tu.signUserOp(userOp, address(ep), ownerkey1);
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = userOp;
        ep.handleOps(ops, payable(owner1));

        //check sender created
        assertEq(sender.code.length > 0, true);
        //check sender's testnum updated
        assertEq(SmartWalletLogic(payable(sender)).testingNum(), 1);
        //nonce won't update when initcode != ""
    }
}
