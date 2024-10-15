// SPDX-License-Identifier:MIT
pragma solidity ^0.8.23;

import {Test, console} from "forge-std/Test.sol";
import "account-abstraction-v7/samples/SimpleAccountFactory.sol";
import "account-abstraction-v7/core/EntryPoint.sol";
import "account-abstraction-v7/samples/SimpleAccount.sol";
import "account-abstraction-v7/interfaces/PackedUserOperation.sol";
import "../../utils/TestERC20.sol";
import "../../utils/TestWrappedNativeToken.sol";
import "../../utils/TestUniswap.sol";
import "../../utils/paymasterFactory/PaymasterFactoryV07.sol";
import {OracleHelperConfig, TokenPaymasterConfig, UniswapHelperConfig} from "../../utils/paymasterFactory/PaymasterFactoryV07.sol";

contract TestTokenPaymasterV07 is Test {
    TokenPaymaster paymaster;
    SimpleAccountFactory accountfactory;
    EntryPoint entryPoint;
    SimpleAccount account;
    TestERC20 token;
    TestWrappedNativeToken wrappedNative;
    TestUniswap uniswap;
    TestOracle2 tokenOracle;
    TestOracle2 nativeOracle;
    PaymasterFactoryV07 paymasterFactory;

    address payable beneficiary;
    address paymasterOwner;
    address user;
    uint256 userKey;

    function setUp() external {
        beneficiary = payable(makeAddr("beneficiary"));
        paymasterOwner = makeAddr("paymasterOwner");
        (user, userKey) = makeAddrAndKey("user");

        entryPoint = new EntryPoint();
        accountfactory = new SimpleAccountFactory(entryPoint);
        account = accountfactory.createAccount(user, 0);

        token = new TestERC20(18);
        wrappedNative = new TestWrappedNativeToken();
        uniswap = new TestUniswap(wrappedNative);
        tokenOracle = new TestOracle2(1, 18);
        nativeOracle = new TestOracle2(1, 18);

        paymasterFactory = new PaymasterFactoryV07(
            IOracle(address(tokenOracle)),
            IOracle(address(nativeOracle)),
            paymasterOwner
        );

        vm.startPrank(paymasterOwner);
        address payable _paymaster = paymasterFactory.deployPaymasterV07(
            "0x00",
            IERC20Metadata(address(token)),
            IEntryPoint(address(entryPoint)),
            IERC20(address(wrappedNative)),
            ISwapRouter(address(uniswap)),
            paymasterOwner
        );
        paymaster = TokenPaymaster(_paymaster);

        vm.stopPrank();
    }
    // priceMarkUp 검사(O)
    // refundPostOpCost 검사
    // validation 단계에서 transferFrom을 통해 가져오나
    // postOp 단계에서 transfer를 통해 돌려주나
    // withDrawTo가 있냐

    function testPriceMarkUpisValid() external {
        // pricePriceMarkUp
        // if PRICE_DENOMINATOR is different, please change it
        uint256 PRICE_DENOMINATOR = 1e26;
        TokenPaymaster.TokenPaymasterConfig
            memory tokenPaymasterConfig = TokenPaymaster.TokenPaymasterConfig({
                priceMarkup: PRICE_DENOMINATOR / 2,
                minEntryPointBalance: 0,
                refundPostopCost: 0,
                priceMaxAge: 0
            });

        vm.startPrank(paymasterOwner);

        vm.expectRevert("TPM: price markup too low");
        paymaster.setTokenPaymasterConfig(tokenPaymasterConfig);

        vm.stopPrank();
    }

    // 고도화 필요
    /**
        paymasterAndData 생성
        user의 key로 sign
        handleOps 호출
     */
    function testGetFundInValidation() external {
        uint256 amount = 100;
        token.sudoMint(user, amount);
        vm.startPrank(user);
        token.approve(address(paymaster), amount);
        vm.stopPrank();

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: user,
            nonce: 0,
            initCode: "0x",
            callData: "0x",
            accountGasLimits: 0,
            preVerificationGas: 0,
            gasFees: bytes32(amount),
            paymasterAndData: "0x00000000000000000000000000000000000000000000000000",
            signature: "0x"
        });
        console.log(userOp.paymasterAndData.length);

        vm.startPrank(address(entryPoint));
        bytes memory context;
        uint256 validationData;
        (context, validationData) = paymaster.validatePaymasterUserOp(
            userOp,
            keccak256(abi.encode(userOp)),
            0
        );
        vm.stopPrank();

        uint256 balance = token.balanceOf(address(paymaster));
        vm.expectRevert("Test Failed");
        assertEq(balance, amount);
    }
}
