// SPDX-License-Identifier: GPL-3.0

pragma solidity ^0.8.0;

import "@openzeppelin/contracts@5.0.0/proxy/Proxy.sol";
import "@openzeppelin/contracts@5.0.0/utils/Address.sol";
import "@openzeppelin/contracts@5.0.0/utils/StorageSlot.sol";

contract ProxyAdmin is Proxy {
    /**
     * @dev Storage slot with the address of the current implementation.
     * This is the keccak-256 hash of "eip1967.proxy.implementation" subtracted by 1, and is
     * validated in the constructor.
     */
    bytes32 internal constant _IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    /**
     * @dev Perform implementation upgrade
     *
     */
    function upgradeTo(address _logic) public {
        address oldImplementation = _implementation();
        if (oldImplementation == address(0)) {
            _setImplementation(_logic);
            Address.functionDelegateCall(
                _logic,
                abi.encodeWithSignature("init(address)", tx.origin)
            );
        } else {
            bytes memory mustMaster = abi.encodeWithSignature(
                "mustMaster(address)",
                msg.sender
            );
            // run address logic
            Address.functionDelegateCall(oldImplementation, mustMaster);
            //  run new address logic
            Address.functionDelegateCall(_logic, mustMaster);
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
