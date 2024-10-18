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
import "account-abstraction-v7/core/UserOperationLib.sol";
import "../../utils/PaymasterProxy.sol";
import "../../utils/MaliciousPaymaster.sol";

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
    PaymasterProxy paymasterProxy;

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

    // 고도화 필요
    /**
        paymasterAndData 생성
        user의 key로 sign
        handleOps 호출
     */
    // validation에서 user의 token이 빠져나갔는지 확인
    function testGetFundInValidation() external {
        uint256 initBalance = 1e10;
        token.sudoMint(user, initBalance);
        vm.startPrank(user);
        token.approve(address(paymaster), type(uint256).max);
        vm.stopPrank();

        (, , uint48 refundPostopCost, ) = paymaster.tokenPaymasterConfig();
        PackedUserOperation memory userOp = fillUserOp(
            user,
            userKey,
            address(0),
            0,
            "",
            address(paymaster),
            50000,
            refundPostopCost + 1
        );

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

    function testAfterBalances() external {
        vm.deal(paymasterOwner, 10e18);
        vm.startPrank(paymasterOwner);
        entryPoint.depositTo{value: 10e18}(address(paymaster));
        vm.stopPrank();

        uint256 initialBalance = 10e18;

        vm.deal(user, 2e18);
        SimpleAccount userAccount = accountfactory.createAccount(user, 0);
        vm.stopPrank();

        token.sudoMint(address(userAccount), initialBalance);
        token.sudoApprove(
            address(userAccount),
            address(paymaster),
            initialBalance
        );

        // generate userOp, dummy userOp
        (, , uint48 refundPostopCost, ) = paymaster.tokenPaymasterConfig();
        PackedUserOperation memory userOp = fillUserOp(
            address(userAccount),
            userKey,
            address(0),
            0,
            "",
            address(paymaster),
            50000,
            refundPostopCost + 20000 // == 60000 is pass value
        );

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.deal(bundler, 10e18);

        vm.startPrank(bundler);
        entryPoint.handleOps(ops, beneficiary);

        PackedUserOperation memory userOp2 = fillUserOp(
            address(userAccount),
            userKey,
            receiver,
            1e18,
            "",
            address(paymaster),
            50000,
            refundPostopCost * 10
        );
        ops[0] = userOp2;
        uint256 gas1 = token.balanceOf(address(userAccount));
        entryPoint.handleOps(ops, beneficiary);
        uint256 gas2 = token.balanceOf(address(userAccount));

        uint256 useGas1 = gas1 - gas2;

        PackedUserOperation memory userOp3 = fillUserOp(
            address(userAccount),
            userKey,
            receiver,
            1e18,
            "",
            address(paymaster),
            5000000, // *= 100 from userOp 2
            refundPostopCost * 10
        );

        ops[0] = userOp3;
        entryPoint.handleOps(ops, beneficiary);
        uint256 gas3 = token.balanceOf(address(userAccount));

        uint256 useGas2 = gas2 - gas3;
        vm.stopPrank();

        uint256 balance = token.balanceOf(address(userAccount));
        assert(initialBalance > balance);

        assertEq(useGas1, useGas2);
    }

    /**
    이거 하나 dummy로 보내고
    일단 userOp보내고 gas소모 확인
    paymaster가 update
    같은거 또 보내기    
     */
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
        token.sudoApprove(
            address(userAccount),
            address(paymaster),
            initialBalance
        );
        // 유저의 userOp이 멤풀에 대기 중일 때 paymaster가 refundPostopCost를 변경(더 높은 값으로)
        // 멤풀에 대기 중인 상황은 여기서 구현할 수 없으니 상황을 가정하고 테스트 진행
        (, , uint48 refundPostopCost, ) = paymaster.tokenPaymasterConfig();

        TokenPaymaster.TokenPaymasterConfig
            memory maliciousTokenPaymasterConfig = TokenPaymaster
                .TokenPaymasterConfig({
                    priceMarkup: 1e26,
                    minEntryPointBalance: 0,
                    refundPostopCost: (refundPostopCost / 2) * 3 - 1, // mempool에 대기 중인 userOp의 refundPostopCost보다 1 작은 값으로 설정
                    priceMaxAge: 0
                });

        vm.startPrank(paymasterOwner);
        paymaster.setTokenPaymasterConfig(maliciousTokenPaymasterConfig);
        vm.stopPrank();

        bytes memory data = "";

        PackedUserOperation memory userOp = fillUserOp(
            address(userAccount),
            userKey,
            address(0),
            0,
            data,
            address(paymaster),
            50000,
            (refundPostopCost / 2) * 3 // if refundPostopCost is 0 or smaller than tokenCofig.refundPostopCost, it must revert
        );

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.startPrank(bundler);
        entryPoint.handleOps(ops, beneficiary); // 이렇게 mempool에 대기 중인 userOp이 있을 때 paymaster의 refundPostopCost를 유저가 설정한 limit 값에 거의 도달하게 설정해 더 많은 가스를 소모하도록 유도
        vm.stopPrank();
    }

    function testBundleRevert() external {
        address user1;
        uint256 userKey1;
        address user2;
        uint256 userKey2;
        (user1, userKey1) = makeAddrAndKey("user1");
        (user2, userKey2) = makeAddrAndKey("user2");
        vm.deal(paymasterOwner, 10e18);
        vm.startPrank(paymasterOwner);
        entryPoint.depositTo{value: 10e18}(address(paymaster));
        vm.stopPrank();

        vm.deal(user2, 2e18);
        vm.startPrank(user1);
        SimpleAccount userAccount1 = accountfactory.createAccount(user1, 0);
        vm.stopPrank();

        vm.deal(user2, 2e18);
        vm.startPrank(user2);
        SimpleAccount userAccount2 = accountfactory.createAccount(user2, 0);
        vm.stopPrank();

        uint256 initialBalance = 10e18;

        vm.deal(user, 2e18);
        SimpleAccount userAccount = accountfactory.createAccount(user, 0);
        vm.stopPrank();

        token.sudoMint(address(userAccount), initialBalance);
        token.sudoApprove(
            address(userAccount),
            address(paymaster),
            initialBalance
        );

        token.sudoMint(address(userAccount1), initialBalance);
        token.sudoApprove(
            address(userAccount1),
            address(paymaster),
            initialBalance
        );

        token.sudoMint(address(userAccount2), initialBalance);
        token.sudoApprove(
            address(userAccount2),
            address(paymaster),
            initialBalance
        );

        // generate userOp, dummy userOp
        (, , uint48 refundPostopCost, ) = paymaster.tokenPaymasterConfig();
        PackedUserOperation memory userOp = fillUserOp(
            address(userAccount),
            userKey,
            address(0),
            0,
            "",
            address(paymaster),
            50000,
            refundPostopCost + 10 // == 60000 is pass value
        );

        PackedUserOperation memory userOp1 = fillUserOp(
            address(userAccount1),
            userKey1,
            address(0),
            0,
            "",
            address(paymaster),
            50000,
            refundPostopCost + 10000 // == 60000 is pass value
        );

        PackedUserOperation memory userOp2 = fillUserOp(
            address(userAccount2),
            userKey2,
            address(0),
            0,
            "",
            address(paymaster),
            50000,
            refundPostopCost + 10000 // == 60000 is pass value
        );

        PackedUserOperation[] memory ops = new PackedUserOperation[](3);
        ops[0] = userOp;
        ops[1] = userOp1;
        ops[2] = userOp2;

        vm.deal(bundler, 10e18);

        vm.startPrank(bundler);
        entryPoint.handleOps(ops, beneficiary);
    }

    // 악의적인 페이마스터 공격 로직
    /**
        1. 업그레이드 가능한 페이마스터 생성
        2. 유저들이 페이마스터를 사용하게 되고 악의적인 페이마스터는 계속해서 정상적으로 작동
        3. 유저가 충분히 모이고 approve된 금액이 일정 수준 이상이 되었다 싶으면 악의적인 페이마스터로 업그레이드
        4. transferFrom 같은 함수를 심어 유저의 모든 토큰을 빼낸다.    
    */
    function testIfPaymasterIsUpgradealble() external {
        address user1 = makeAddr("user1");
        address user2 = makeAddr("user2");
        address user3 = makeAddr("user3");
        address user4 = makeAddr("user4");
        SimpleAccount userAccount1 = accountfactory.createAccount(user1, 0);
        SimpleAccount userAccount2 = accountfactory.createAccount(user2, 0);
        SimpleAccount userAccount3 = accountfactory.createAccount(user3, 0);
        SimpleAccount userAccount4 = accountfactory.createAccount(user4, 0);

        token.sudoMint(address(userAccount1), 1e18);
        token.sudoMint(address(userAccount2), 1e18);
        token.sudoMint(address(userAccount3), 1e18);
        token.sudoMint(address(userAccount4), 1e18);

        vm.deal(paymasterOwner, 10e18);
        vm.startPrank(paymasterOwner);
        console.log("deploy paymasterProxy");
        paymasterProxy = new PaymasterProxy(
            address(paymaster),
            paymasterOwner,
            ""
        );

        console.log("deploy paymasterProxy done");

        entryPoint.depositTo{value: 10e18}(address(paymasterProxy));
        vm.stopPrank();

        token.sudoApprove(
            address(userAccount1),
            address(paymasterProxy),
            type(uint256).max
        );
        token.sudoApprove(
            address(userAccount2),
            address(paymasterProxy),
            type(uint256).max
        );
        token.sudoApprove(
            address(userAccount3),
            address(paymasterProxy),
            type(uint256).max
        );
        token.sudoApprove(
            address(userAccount4),
            address(paymasterProxy),
            type(uint256).max
        );

        vm.startPrank(paymasterOwner);
        console.log(address(paymasterOwner));
        address newPaymaster = address(new MaliciousPaymaster());

        address[] memory targets = new address[](4);
        targets[0] = address(userAccount1);
        targets[1] = address(userAccount2);
        targets[2] = address(userAccount3);
        targets[3] = address(userAccount4);

        bytes memory data = abi.encodeWithSelector(
            MaliciousPaymaster.attack.selector,
            targets, // 배열을 직접 전달
            address(token),
            address(paymasterOwner)
        );

        // low-level call
        console.log("call upgradeToAndCall");
        address(paymasterProxy).call(
            abi.encodeWithSignature(
                "upgradeToAndCall(address,bytes)",
                newPaymaster,
                data
            )
        );

        vm.stopPrank();

        assertEq(
            token.balanceOf(address(userAccount1)),
            0,
            "user1's balance must be 0"
        );

        assertEq(
            token.balanceOf(address(userAccount2)),
            0,
            "user2's balance must be 0"
        );

        assertEq(
            token.balanceOf(address(userAccount3)),
            0,
            "user3's balance must be 0"
        );

        assertEq(
            token.balanceOf(address(userAccount4)),
            0,
            "user4's balance must be 0"
        );
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
        op.preVerificationGas = 10000;
        // maxPriorityFeePerGas, maxFeePerGas
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
    // 660000000
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
