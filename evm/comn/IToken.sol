// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import "@openzeppelin/contracts@5.0.0/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts@5.0.0/token/ERC20/extensions/IERC20Metadata.sol";

interface IToken is IERC20, IERC20Metadata {
    function isMinter(address addr) external pure returns (bool);
    function mintFor(address account, uint256 amount) external;
    function burnFor(address account, uint256 amount) external;
}