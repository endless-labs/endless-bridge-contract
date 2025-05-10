// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import "./comn/IAdmin.sol";
import {StorageSlot} from "@openzeppelin/contracts@5.0.0/utils/StorageSlot.sol";

/**
 * @title BaseComn
 * @dev Contains the core constants and base functionality
 */
abstract contract BaseComn {
    bytes32 constant _ADMIN_SLOT =
        0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;

    /**
     * @dev Throws if called by any account other than the master.
     */
    modifier onlyMaster() {
        IAdmin(getAdminAddr()).mustMaster(msg.sender);
        _;
    }

    /**
     * @dev Throws if called by any account other than the admin.
     */
    modifier onlyAdmin() {
        IAdmin(getAdminAddr()).mustAdmin(msg.sender);
        _;
    }

    /**
     * @dev Throws if called by any account other than the financer.
     */
    modifier onlyFinancer() {
        IAdmin(getAdminAddr()).mustFinancer(msg.sender);
        _;
    }


    /**
     * @dev Returns the admin address from storage slot
     */
    function getAdminAddr() public view returns (address) {
        return StorageSlot.getAddressSlot(_ADMIN_SLOT).value;
    }
}
