// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import "account-abstraction-v7/samples/TokenPaymaster.sol";
import {IEntryPoint} from "account-abstraction-v7/interfaces/IEntryPoint.sol";

import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import {TestOracle2} from "account-abstraction-v7/test/TestOracle2.sol";
import {Test, console} from "forge-std/Test.sol";

struct OracleHelperConfig {
    uint32 cacheTimeToLive;
    uint32 maxOracleRoundAge;
    IOracle tokenOracle;
    IOracle nativeOracle;
    bool tokenToNativeOracle;
    bool tokenOracleReverse;
    bool nativeOracleReverse;
    uint32 priceUpdateThreshold;
}

struct TokenPaymasterConfig {
    uint256 priceMarkup;
    uint128 minEntryPointBalance;
    uint48 refundPostopCost;
    uint48 priceMaxAge;
}

struct UniswapHelperConfig {
    uint256 minSwapAmount;
    uint32 slippage;
    uint32 uniswapPoolFee;
}

contract PaymasterFactoryV07 is Ownable {
    event DeployedPaymasterV07(
        bytes32 salt,
        bytes version,
        address token,
        address tokenOracle,
        address nativeOracle,
        address entryPoint,
        address paymaster
    );

    OracleHelperConfig public _oracleHelperConfig;
    TokenPaymasterConfig public _tokenPaymasterConfig;
    UniswapHelperConfig public _uniswapHelperConfig;

    constructor(
        IOracle _tokenOracle,
        IOracle _nativeOracle,
        address _owner
    ) Ownable(_owner) {
        _oracleHelperConfig = OracleHelperConfig({
            cacheTimeToLive: 0,
            maxOracleRoundAge: 0,
            tokenOracle: _tokenOracle,
            nativeOracle: _nativeOracle,
            tokenToNativeOracle: false,
            tokenOracleReverse: false,
            nativeOracleReverse: false,
            priceUpdateThreshold: 0
        });

        _tokenPaymasterConfig = TokenPaymasterConfig({
            priceMaxAge: 86400,
            refundPostopCost: 80000,
            minEntryPointBalance: 0,
            priceMarkup: 1e26
        });

        _uniswapHelperConfig = UniswapHelperConfig({
            minSwapAmount: 1,
            slippage: 5,
            uniswapPoolFee: 3
        });
    }

    function deployPaymasterV07(
        bytes32 salt,
        IERC20Metadata _token,
        IEntryPoint _entryPoint,
        IERC20 _wrappedNative,
        ISwapRouter _uniswap,
        address _owner
    ) public onlyOwner returns (address payable paymaster) {
        bytes memory bytecode = type(TokenPaymaster).creationCode;
        bytes memory constructorArgs = abi.encode(
            _token,
            _entryPoint,
            _wrappedNative,
            _uniswap,
            _tokenPaymasterConfig,
            _oracleHelperConfig,
            _uniswapHelperConfig,
            _owner
        );

        paymaster = payable(
            Create2.deploy(0, salt, abi.encodePacked(bytecode, constructorArgs))
        );

        emit DeployedPaymasterV07(
            salt,
            "V07",
            address(_token),
            address(_oracleHelperConfig.tokenOracle),
            address(_oracleHelperConfig.nativeOracle),
            address(_entryPoint),
            paymaster
        );
    }
}
