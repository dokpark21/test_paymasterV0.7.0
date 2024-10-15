// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import "account-abstraction-v6/samples/TokenPaymaster.sol";

import {IEntryPoint} from "account-abstraction-v6/interfaces/IEntryPoint.sol";

import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

abstract contract PaymasterFactoryV06 is Ownable, TokenPaymaster {
    event DeployedPaymasterV06(
        bytes32 salt,
        bytes version,
        address entryPoint,
        address paymaster
    );

    function deployPaymasterV06(
        address accountFactory,
        string memory _symbol,
        IEntryPoint _entryPoint,
        bytes32 salt
    ) public onlyOwner returns (address paymaster) {
        bytes memory bytecode = type(TokenPaymaster).creationCode;

        bytes memory constructorArgs = abi.encode(
            accountFactory,
            _symbol,
            _entryPoint
        );

        paymaster = Create2.deploy(
            0,
            salt,
            abi.encodePacked(bytecode, constructorArgs)
        );

        emit DeployedPaymasterV06(salt, "V06", address(_entryPoint), paymaster);
    }
}
