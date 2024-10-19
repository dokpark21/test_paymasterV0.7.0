// SPDX-License-Identifier:MIT
pragma solidity ^0.8.23;

import {Test, console} from "forge-std/Test.sol";
import "account-abstraction-v7/samples/SimpleAccountFactory.sol";
import "account-abstraction-v7/core/EntryPoint.sol";
import "account-abstraction-v7/samples/SimpleAccount.sol";
import "account-abstraction-v7/interfaces/PackedUserOperation.sol";
import "account-abstraction-v7/test/TestERC20.sol";
import "account-abstraction-v7/test/TestWrappedNativeToken.sol";
import "account-abstraction-v7/test/TestUniswap.sol";
import "../utils/PaymasterFactoryV07.sol";
import {OracleHelperConfig, TokenPaymasterConfig, UniswapHelperConfig} from "../utils/PaymasterFactoryV07.sol";
// import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
// import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "account-abstraction-v7/core/UserOperationLib.sol";

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
    address payable bundler;
    address paymasterOwner;
    address user;
    uint256 userKey;
    address payable receiver;

    function setUp() external {
        beneficiary = payable(makeAddr("beneficiary"));
        bundler = payable(makeAddr("bundler"));
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
        tokenOracle = new TestOracle2(1e18, 18);
        nativeOracle = new TestOracle2(1e18, 18);

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

    // cold access가 warm access보다 gas가 많이 들기 때문에 제대로된 gas 비교를 위해서는 처음에 dummy userOp을 cold access로 보내줘야 함, 이를 증명하기 위한 test case
    function testColdAccessAndWarmAccess() external {
        vm.deal(paymasterOwner, 10e18);
        vm.startPrank(paymasterOwner);
        entryPoint.depositTo{value: 10e18}(address(paymaster));
        vm.stopPrank();

        uint256 initialBalance = 10e18;

        vm.deal(user, 1e18);
        SimpleAccount userAccount = accountfactory.createAccount(user, 0);
        vm.stopPrank();

        token.sudoMint(address(userAccount), initialBalance);
        token.sudoApprove(address(userAccount), address(paymaster), initialBalance);

        vm.deal(bundler, 10e18);
        uint256 gas1 = token.balanceOf(address(userAccount));
        (,,uint48 refundPostopCost,) = paymaster.tokenPaymasterConfig();
        // 처음 cold access를 통과하기 위해서는 postOpGasLimit를 refundPostopCost의 대략 1.5배로 설정해줘야함
        PackedUserOperation memory userOp = fillUserOp(address(userAccount), userKey, address(0), 0, "", address(paymaster), 50000, (refundPostopCost * 3) / 2);

        vm.startPrank(bundler);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        entryPoint.handleOps(ops, beneficiary); // cold access
        uint256 gas2 = token.balanceOf(address(userAccount));

        PackedUserOperation memory userOp2 = fillUserOp(address(userAccount), userKey, address(0), 0, "", address(paymaster), 50000, refundPostopCost + 1);
        ops[0] = userOp2;
        entryPoint.handleOps(ops, beneficiary); // warm access 1
        uint256 gas3 = token.balanceOf(address(userAccount));

        PackedUserOperation memory userOp3 = fillUserOp(address(userAccount), userKey, address(0), 0, "", address(paymaster), 50000, refundPostopCost + 1);
        ops[0] = userOp3;
        entryPoint.handleOps(ops, beneficiary); // warm access 2
        uint256 gas4 = token.balanceOf(address(userAccount));

        vm.stopPrank();

        uint256 cold = gas1 - gas2;
        uint256 warm1 = gas2 - gas3;
        uint256 warm2 = gas3 - gas4;
        
        console.log("Cold Access   :", cold);
        console.log("Warm Access 1 :", warm1);
        console.log("Warm Access 2 :", warm2);

        assert((cold > warm1) && warm1 == warm2);
    }

    // malicious user가 1st validation은 통과하고 2nd validation의 postOp에서 revert를 내도록 postOpGasLimit를 설정할 수 있음
    // 이 case의 경우, paymaster의 opsSeen이 1 증가하고 opsIncluded는 변하지 않아서 평판 공격이 가능
    function testPassValidationButRevertIn2ndValidation() external {
        vm.deal(paymasterOwner, 10e18);
        vm.startPrank(paymasterOwner);
        entryPoint.depositTo{value: 10e18}(address(paymaster));
        vm.stopPrank();

        uint256 initialBalance = 10e18;

        vm.deal(user, 1e18);
        SimpleAccount userAccount = accountfactory.createAccount(user, 0);
        vm.stopPrank();

        token.sudoMint(address(userAccount), initialBalance);
        token.sudoApprove(address(userAccount), address(paymaster), initialBalance);

        uint256 gas1 = token.balanceOf(address(userAccount));
        (, , uint48 refundPostopCost, ) = paymaster.tokenPaymasterConfig();
        PackedUserOperation memory userOp = fillUserOp(address(userAccount), userKey, address(0), 0, "", address(paymaster), 50000, refundPostopCost + 1);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.deal(bundler, 10e18);

        vm.startPrank(bundler);
        entryPoint.handleOps(ops, beneficiary);
        vm.stopPrank();

        uint256 gas2 = token.balanceOf(address(userAccount));

        console.log("attack cost :", gas1 - gas2);
    }

    // malicious paymaster가 refundPostopCost를 조작하여 user의 자금을 부당하게 더 되돌려 받는 공격
    // forge test --match-test testIfMaliciousPaymasterCanDrainUser -vvvvv --via-ir
    function testIfMaliciousPaymasterCanDrainUser() external {
        vm.deal(paymasterOwner, 10e18);
        vm.startPrank(paymasterOwner);
        entryPoint.depositTo{value: 10e18}(address(paymaster));
        vm.stopPrank();

        uint256 initialBalance = 10e18;

        vm.deal(user, 2e18);
        SimpleAccount userAccount = accountfactory.createAccount(user, 0);
        vm.stopPrank();

        token.sudoMint(address(userAccount), initialBalance);
        token.sudoApprove(address(userAccount), address(paymaster), initialBalance);

        (, , uint48 refundPostopCost, ) = paymaster.tokenPaymasterConfig();
        PackedUserOperation memory userOp = fillUserOp(address(userAccount), userKey, address(0), 0, "", address(paymaster), 50000, (refundPostopCost * 3) / 2);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.deal(bundler, 10e18);

        vm.startPrank(bundler);
        // 1. dummy userOp for cold access
        entryPoint.handleOps(ops, beneficiary);

        // user는 postOpGasLimit를 refundPostopCost의 1.5배로 설정
        PackedUserOperation memory userOp2 = fillUserOp(address(userAccount), userKey, address(0), 0, "", address(paymaster), 50000, (refundPostopCost * 3) / 2);
        ops[0] = userOp2;
        // 2. userOp이 정상적인 경우(warm access), 얼마나 cost가 드는지 확인
        uint256 gas1 = token.balanceOf(address(userAccount));
        entryPoint.handleOps(ops, beneficiary);
        uint256 gas2 = token.balanceOf(address(userAccount));

        console.log("userOp cost before changing refundPostopCost:", gas1 - gas2);
        vm.stopPrank();

        // userOp2와 같은 userOp3 생성
        PackedUserOperation memory userOp3 = fillUserOp(address(userAccount), userKey, address(0), 0, "", address(paymaster), 50000, (refundPostopCost * 3) / 2);
        ops[0] = userOp3;

        // 3. userOp이 first validation 통과 후 mempool에서 대기 중일 때, paymaster가 refuncPostopCost를 높였다고 가정
        TokenPaymaster.TokenPaymasterConfig memory malicioustokenPaymasterConfig = TokenPaymaster.TokenPaymasterConfig({
            priceMaxAge: 86400,
            refundPostopCost: (refundPostopCost * 3) / 2 - 1, // malicious value (postOpGasLimit의 1.5배보다 1 작게 설정)
            minEntryPointBalance: 0,
            priceMarkup: 1e26
        });

        vm.startPrank(paymasterOwner);
        paymaster.setTokenPaymasterConfig(malicioustokenPaymasterConfig);
        // console.log("paymaster changed refundPostopCost to malicious value");
        vm.stopPrank();

        // 4. 같은 userOp을 다시 보냈을 때의 cost 확인 (대기중이던 userOp이 실행됐을 때)
        vm.startPrank(bundler);
        entryPoint.handleOps(ops, beneficiary);
        vm.stopPrank();

        uint256 gas3 = token.balanceOf(address(userAccount));

        console.log("userOp cost after changing refundPostopCost:", gas2 - gas3);

        assert(gas2 - gas3 > gas1 - gas2); // user는 원래 내야 하는 cost보다 높은 cost를 내야 하게 됨
    }

    // ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- //

    // priceMarkup을 비정상적인 값으로 조작할 수 있는지 확인
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

    // validation에서 user의 token이 빠져나갔는지 확인
    function testGetFundInValidation() external {
        setUser();
        uint256 initBalance = token.balanceOf(user);

        (, , uint48 refundPostopCost, ) = paymaster.tokenPaymasterConfig();
        PackedUserOperation memory userOp = fillUserOp(address(user), userKey, address(0), 0, "", address(paymaster), 50000, refundPostopCost + 1);

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
        console.log(balance, initBalance);
        assert(initBalance > balance);
    }

    // user의 자금을 넣고 빼는 동작이 가능한지 확인
    // 해당 test는 BasePaymaster에서의 위협에 대한 test이다.
    // 보류
    function testUserDepositAndWithdraw() external {
        setUser();

        uint256 initUserBalance = user.balance;
        uint256 initPaymasterBalance = address(paymaster).balance;
        
        vm.startPrank(user);
        paymaster.deposit{value: 1 ether}();
        vm.stopPrank();

        // paymaster의 deposit을 통해 EP에 자금을 deposit하는 것이므로 paymaster의 balance가 변하면 안됨
        assert(address(paymaster).balance == initPaymasterBalance);

        vm.startPrank(paymasterOwner);
        paymaster.withdrawTo(payable(user), 1 ether);
        assert(user.balance == initUserBalance);
        vm.stopPrank();
    }

    // VerifyingPaymaster과 같이 signature 검증을 하는 paymaster에만 해당하는 함수 -> test해보려면 VerifyingPaymaster의 validatePaymasterUserOp함수를 호출해야함
    // 보류
    function testUserSignatureFail() external {

    }

    function setUser() public {
        uint256 initBalance = 1e18;
        token.sudoMint(user, initBalance);
        vm.deal(user, 1e18);

        vm.startPrank(user);
        token.approve(address(paymaster), type(uint256).max);
        vm.stopPrank();
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

    function check(address userAccount) public view {
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
        console.log("beneficiary balance :", beneficiary.balance);
        console.log("");
    }

    function fillUserOp(
        address _sender,
        uint256 _key,
        address _to,
        uint256 _value,
        bytes memory _data,
        address _paymaster,
        uint256 _validationGas,
        uint256 _postOpGas
    ) public view returns (PackedUserOperation memory op) {
        op.sender = address(_sender);
        op.nonce = entryPoint.getNonce(address(_sender), 0);
        if (_to == address(0)) {
            op.callData = "";
        } else {
            op.callData = abi.encodeWithSelector(
                SimpleAccount.execute.selector,
                _to,
                _value,
                _data
            );
        }
        // verificationGasLimit, callGasLimit
        op.accountGasLimits = bytes32(
            abi.encodePacked(uint128(50000), uint128(10000))
        );
        op.preVerificationGas = 0;
        // maxPriorityFeePerGas, maxFeePerGas -> 이거 0으로 정하면 공격 비용이 0이지만 그렇게 되면 bundler가 mempool에 끼워주지 않음 (https://github.com/eth-infinitism/bundler/blob/master/packages/bundler/src/modules/BundleManager.ts#L236-L241)
        op.gasFees = bytes32(abi.encodePacked(uint128(1000), uint128(3000)));
        if (_paymaster == address(0)) {
            op.paymasterAndData = "";
        } else {
            op.paymasterAndData = fillpaymasterAndData(
                _paymaster,
                _validationGas,
                _postOpGas
            );
        }
        op.signature = signUserOp(op, _key);
        return op;
    }

    function fillpaymasterAndData(
        address _paymaster,
        uint256 _validationGas,
        uint256 _postOpGas
    ) public view returns (bytes memory paymasterAndDataStatic) {
        paymasterAndDataStatic = abi.encodePacked(
            address(_paymaster),
            uint128(_validationGas), // validation gas
            uint128(_postOpGas), // postOp gas
            uint256(1e26) // clientSuppliedPrice
        );
    }
}

// forge test --match-test testIfMaliciousPaymasterCanDrainUser -vvvvv
// forge test --match-test testAfterBalances -vvvvv
// forge test --match-test testPassValidationButRevertIn2ndValidation -vvvvv