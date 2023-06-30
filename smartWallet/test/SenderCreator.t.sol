// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "forge-std/Test.sol";
import "../src/AccountFactory.sol";
import "../src/core/EntryPoint.sol";
import "../src/core/SenderCreator.sol";

contract SenderCreatorTest is Test {
    AccountFactory af;
    EntryPoint ep;

    // function setUp() public {
    //     ep = new EntryPoint();
    //     af = new AccountFactory(ep);
    // }

    function testCreatSender() public {
        ep = new EntryPoint();
        af = new AccountFactory(ep);
        SenderCreator sc = new SenderCreator();
        // address owner = vm.addr(1);
        // uint salt = 123;
        address owner = 0x8447f61c8D1AE66259329848c328E127A453fb52;
        uint salt = 0x26d430811a98b42981566c60913bb98c;
        address sender1 = af.getAddress(owner, salt);
        //assert sender1 hasn't been created
        assertEq(sender1.code.length == 0, true);
        bytes memory initCode = createInitCode(owner, salt);
        address sender = sc.createSender(initCode);
        assertEq(sender, sender1);
        assertEq(sender1.code.length > 0, true);
    }

    function createInitCode(
        address owner,
        uint salt
    ) public view returns (bytes memory) {
        bytes memory call = abi.encodeCall(
            AccountFactory.createAccount,
            (owner, salt)
        );
        bytes memory initCode = abi.encodePacked(address(af), call);
        return initCode;
    }
}
