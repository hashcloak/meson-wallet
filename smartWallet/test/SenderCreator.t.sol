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
        address owner = 0x1F0BDb0533b9aB79c891E65aC3ad3df4cd164B50;
        uint salt = 0x809a6715072c495964f0a9a06bd8ae66;
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
