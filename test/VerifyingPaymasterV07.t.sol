// SPDX-License-Identifier:MIT
pragma solidity ^0.8.23;

import "account-abstraction-v7/samples/VerifyingPaymaster.sol";
import {Test, console} from "forge-std/Test.sol";
import "account-abstraction-v7/interfaces/IEntryPoint.sol";
import "account-abstraction-v7/core/EntryPoint.sol";
import "account-abstraction-v7/interfaces/PackedUserOperation.sol";
import "account-abstraction-v7/samples/SimpleAccount.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract VerifyingPaymasterV07 is Test {
    VerifyingPaymaster paymaster;
    IEntryPoint entryPoint;

    address user;
    uint256 userKey;
    address paymasterOwner;
    uint256 paymasterOwnerKey;

    function setUp() external {
        (user, userKey) = makeAddrAndKey("user");
        (paymasterOwner, paymasterOwnerKey) = makeAddrAndKey("paymasterOwner");

        entryPoint = new EntryPoint();
        paymaster = new VerifyingPaymaster(entryPoint, paymasterOwner);
    }

    // paymasterOwner가 서명
    function testValdiatePaymasterUserOpRevert() external {
        PackedUserOperation memory op = fillUserOp(
            user,
            userKey,
            address(0),
            0,
            "",
            address(paymaster),
            0,
            0
        );

        vm.startPrank(address(entryPoint));
        (, uint256 validationData) = paymaster.validatePaymasterUserOp(
            op,
            "",
            0
        );
        vm.stopPrank();

        // Check if sigFailed is true and validatePaymasterUserOp is not reverted(validationData is odd)
        assertEq(validationData % 2, 1);
    }

    function signUserOp(
        PackedUserOperation memory op,
        uint48 validUntil,
        uint48 validAfter,
        uint256 _key
    ) public view returns (bytes memory signature) {
        bytes32 hash = paymaster.getHash(op, validUntil, validAfter);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            _key,
            MessageHashUtils.toEthSignedMessageHash(hash)
        );
        signature = abi.encodePacked(r, s, v);
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

        op.paymasterAndData = abi.encodePacked(bytes20(""), bytes32(""));
        bytes memory signature = signUserOp(op, 10, 20, _key);
        if (_paymaster == address(0)) {
            op.paymasterAndData = "";
        } else {
            op.paymasterAndData = fillpaymasterAndData(10, 20, signature);
        }
        op.signature = signature;

        return op;
    }

    function fillpaymasterAndData(
        uint48 validUntil,
        uint48 validAfter,
        bytes memory signature
    ) public view returns (bytes memory paymasterAndDataStatic) {
        paymasterAndDataStatic = abi.encodePacked(
            bytes20(""),
            bytes32(""),
            abi.encode(validUntil, validAfter),
            signature // wrong signature, because it is not signed by the paymaster
        );
    }
}
