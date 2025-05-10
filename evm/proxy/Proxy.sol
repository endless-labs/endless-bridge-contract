// // SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

import "@openzeppelin/contracts@5.0.0/proxy/Proxy.sol";
import "@openzeppelin/contracts@5.0.0/utils/Address.sol";
import "@openzeppelin/contracts@5.0.0/utils/StorageSlot.sol";

contract ProxyMY is Proxy {
    /**
     * @dev Storage slot with the admin of the contract.
     * This is the keccak-256 hash of "eip1967.proxy.admin" subtracted by 1, and is
     * validated in the constructor.
     */
    bytes32 internal constant _ADMIN_SLOT =
        0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;
    /**
     * @dev Storage slot with the address of the current implementation.
     * This is the keccak-256 hash of "eip1967.proxy.implementation" subtracted by 1, and is
     * validated in the constructor.
     */
    bytes32 private constant _IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    /**
     * set the admin & create2 address
     */
    constructor(address _admin) {
        StorageSlot.getAddressSlot(_ADMIN_SLOT).value = _admin;
    }

    /**
     * @dev Perform implementation upgrade
     */
    function upgradeTo(address _logic) public {
        address oldImplementation = _implementation();
        if (oldImplementation == address(0)) {
            _setImplementation(_logic);
        } else {
            Address.functionStaticCall(
                StorageSlot.getAddressSlot(_ADMIN_SLOT).value,
                abi.encodeWithSignature("mustMuster(address)", msg.sender)
            );
            _setImplementation(_logic);
        }
    }

    /**
     * @dev Returns the current implementation address.
     */
    function _implementation() internal view override returns (address) {
        return StorageSlot.getAddressSlot(_IMPLEMENTATION_SLOT).value;
    }

    /**
     * @dev Stores a new address in the EIP1967 implementation slot.
     */
    function _setImplementation(address newImplementation) private {
        require(
            newImplementation.code.length > 0,
            "New implementation must a contract"
        );
        StorageSlot
            .getAddressSlot(_IMPLEMENTATION_SLOT)
            .value = newImplementation;
    }

    receive() external payable {}
}
