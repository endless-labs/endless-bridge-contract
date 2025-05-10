// SPDX-License-Identifier: GPL-3.0

pragma solidity ^0.8.0;

/**
 * @dev Interface for Admin
 */
interface IAdmin {
    function mustMaster(address addr) external view;
    function mustAdmin(address addr) external view;
    function mustFinancer(address addr) external view;
    function isMaster(address addr) external view returns (bool);
    function isAdmin(address addr) external view returns (bool);
    function isFinancer(address addr) external view returns (bool);
}
