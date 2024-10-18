// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.1.0) (proxy/transparent/TransparentUpgradeableProxy.sol)

pragma solidity ^0.8.20;

import {ERC1967Utils} from "openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Utils.sol";
import {ERC1967Proxy} from "openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC1967} from "openzeppelin-contracts/contracts/interfaces/IERC1967.sol";
import {ProxyAdmin} from "openzeppelin-contracts/contracts/proxy/transparent/ProxyAdmin.sol";
import {Test, console} from "forge-std/Test.sol";

interface ITransparentUpgradeableProxy is IERC1967 {
    /// @dev See {UUPSUpgradeable-upgradeToAndCall}
    function upgradeToAndCall(
        address newImplementation,
        bytes calldata data
    ) external payable;
}

contract PaymasterProxy is ERC1967Proxy {
    address private immutable _admin;

    /**
     * @dev The proxy caller is the current admin, and can't fallback to the proxy target.
     */
    error ProxyDeniedAdminAccess();

    /**
     * @dev Initializes an upgradeable proxy managed by an instance of a {ProxyAdmin} with an `initialOwner`,
     * backed by the implementation at `_logic`, and optionally initialized with `_data` as explained in
     * {ERC1967Proxy-constructor}.
     */
    constructor(
        address _logic,
        address initialOwner,
        bytes memory _data
    ) payable ERC1967Proxy(_logic, _data) {
        _admin = initialOwner;
        // Set the storage value and emit an event for ERC-1967 compatibility
        ERC1967Utils.changeAdmin(_proxyAdmin());
    }

    /**
     * @dev Returns the admin of this proxy.
     */
    function _proxyAdmin() public view virtual returns (address) {
        return _admin;
    }

    /**
     * @dev If caller is the admin process the call internally, otherwise transparently fallback to the proxy behavior.
     */
    function _fallback() internal virtual override {
        console.log("UpgradeToAndCall");
        console.log(_proxyAdmin());
        if (msg.sender == _proxyAdmin()) {
            if (
                msg.sig !=
                ITransparentUpgradeableProxy.upgradeToAndCall.selector
            ) {
                revert ProxyDeniedAdminAccess();
            } else {
                console.log("_dispatchUpgradeToAndCall");
                _dispatchUpgradeToAndCall();
            }
        } else {
            console.log("super._fallback");
            super._fallback();
        }
    }

    function _dispatchUpgradeToAndCall() private {
        (address newImplementation, bytes memory data) = abi.decode(
            msg.data[4:],
            (address, bytes)
        );
        console.log("newImplementation", newImplementation);
        // console.log("data", data);
        ERC1967Utils.upgradeToAndCall(newImplementation, data);
    }
}
