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
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

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
    address payable bundler;
    address payable receiver;

    function setUp() external {
        beneficiary = payable(makeAddr("beneficiary"));
        paymasterOwner = makeAddr("paymasterOwner");
        (user, userKey) = makeAddrAndKey("user");
        bundler = payable(makeAddr("bundler"));
        receiver = payable(makeAddr("receiver"));

        entryPoint = new EntryPoint();
        accountfactory = new SimpleAccountFactory(entryPoint);
        account = accountfactory.createAccount(user, 0);

        token = new TestERC20(18);
        wrappedNative = new TestWrappedNativeToken();
        uniswap = new TestUniswap(wrappedNative);
        tokenOracle = new TestOracle2(1, 18);
        nativeOracle = new TestOracle2(1, 18);
        accountfactory = new SimpleAccountFactory(entryPoint);

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

    // refundPostOpCost 검사
    // postOp 단계에서 transfer를 통해 정확히 돌려주나
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

    function testGetFundInValidation() external {
        uint256 initBalance = 1e18;
        token.sudoMint(user, initBalance);
        vm.startPrank(user);
        token.approve(address(paymaster), type(uint256).max);
        vm.stopPrank();

        (, , uint48 _refundPostopCost, ) = paymaster.tokenPaymasterConfig();

        bytes memory paymasterAndDataStatic = abi.encodePacked(
            address(paymaster),
            uint128(150),
            uint128(_refundPostopCost + 1), // bigger than refundPostOpCost
            uint256(1e24)
        );

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: user,
            nonce: 0,
            initCode: "0x",
            callData: "0x",
            accountGasLimits: bytes32(uint256(1e8)),
            preVerificationGas: 1e8,
            gasFees: bytes32(uint256(500000)),
            paymasterAndData: paymasterAndDataStatic,
            signature: "0x"
        });

        paymaster.updateCachedPrice(false);

        vm.startPrank(address(entryPoint));
        bytes memory context;
        uint256 validationData;
        (context, validationData) = paymaster.validatePaymasterUserOp(
            userOp,
            keccak256(abi.encode(userOp)),
            1e8
        );
        vm.stopPrank();

        uint256 balance = token.balanceOf(address(user));
        vm.expectRevert();
        assertEq(balance, initBalance);
    }

    function testAfterBalances() external {
        // first userOp cost is expensive than second and third userOp, because of cold storage access is expensive than warm storage access
        vm.deal(paymasterOwner, 10e18);
        vm.startPrank(paymasterOwner);
        entryPoint.depositTo{value: 10e18}(address(paymaster));
        vm.stopPrank();

        vm.deal(user, 1e18);
        vm.startPrank(user);
        SimpleAccount userAccount = accountfactory.createAccount(user, 0);
        vm.stopPrank();

        vm.deal(address(userAccount), 3e18);

        uint256 amount = 10000e18;
        token.sudoMint(address(userAccount), amount);
        token.sudoApprove(address(userAccount), address(paymaster), amount);

        (, , uint48 _refundPostopCost, ) = paymaster.tokenPaymasterConfig();

        bytes memory paymasterAndDataStatic = abi.encodePacked(
            address(paymaster),
            uint128(5000000),
            uint128(_refundPostopCost + 100000), // bigger than refundPostOpCost
            uint256(1e24)
        );

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(userAccount),
            nonce: 0,
            initCode: "",
            callData: abi.encodeWithSelector(
                SimpleAccount.execute.selector,
                receiver,
                uint256(1e18),
                hex""
            ),
            accountGasLimits: bytes32(
                abi.encodePacked(uint128(10000000), uint128(1000000))
            ),
            preVerificationGas: 1e5,
            gasFees: bytes32(abi.encodePacked(uint128(300000), uint128(30000))),
            paymasterAndData: paymasterAndDataStatic,
            signature: ""
        });

        userOp.signature = signUserOp(userOp, userKey);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.startPrank(bundler);
        entryPoint.handleOps(ops, beneficiary);
        vm.stopPrank();

        uint256 balance = token.balanceOf(address(userAccount));

        uint gasCost1 = amount - balance;
        amount = balance;

        console.log("beneficiary balance:", beneficiary.balance);
        console.log("gas cost1:", gasCost1);

        userOp.nonce = 1;
        userOp.signature = signUserOp(userOp, userKey);

        ops[0] = userOp;

        vm.startPrank(bundler);
        entryPoint.handleOps(ops, beneficiary);
        vm.stopPrank();

        balance = token.balanceOf(address(userAccount));
        uint gasCost2 = amount - balance;
        amount = balance;

        console.log("beneficiary balance:", beneficiary.balance);
        console.log("gas cost2:", gasCost2);

        paymasterAndDataStatic = abi.encodePacked(
            address(paymaster),
            uint128(500000000), // *= 100
            uint128(_refundPostopCost + 100000), // bigger than refundPostOpCost
            uint256(1e24)
        );
        userOp.paymasterAndData = paymasterAndDataStatic;
        userOp.nonce = 2;
        userOp.signature = signUserOp(userOp, userKey);

        ops[0] = userOp;

        vm.startPrank(bundler);
        entryPoint.handleOps(ops, beneficiary);
        vm.stopPrank();

        balance = token.balanceOf(address(userAccount));
        uint gasCost3 = amount - balance;

        console.log("beneficiary balance:", beneficiary.balance);
        console.log("gas cost3:", gasCost3);

        vm.assertEq(gasCost2, gasCost3);
    }

    function signUserOp(
        PackedUserOperation memory op,
        uint256 _key
    ) public view returns (bytes memory signature) {
        bytes32 hash = entryPoint.getUserOpHash(op);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            _key,
            MessageHashUtils.toEthSignedMessageHash(hash)
        );
        signature = abi.encodePacked(r, s, v);
    }

    function submitUserOp(PackedUserOperation memory op) public {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, beneficiary);
    }

    function check(address userAccount) public {
        console.log("bundler balance :", bundler.balance);
        console.log("paymaster balance :", address(paymaster).balance);
        console.log("user balance :", user.balance);
        console.log(
            "paymaster's deposit to EP :",
            entryPoint.balanceOf(address(paymaster))
        );
        console.log(
            "userAccount token :",
            token.balanceOf(address(userAccount))
        );
        console.log("");
    }
}
