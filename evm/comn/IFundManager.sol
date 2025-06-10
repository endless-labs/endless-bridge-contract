// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {Types} from "./Types.sol";

interface IFundManager {
    function setTokenMaxAmountInPool(address token, uint256 maxAmount) external;

    function collect(address wallet, address sender) external;

    function markWalletDeprecated(address wallet, address sender) external;

    function markPoolDeprecated(address token, address wallet) external  returns (uint256);

    function payoutToUser(address token, address user, uint256 amount) external;

    function walletStatus(address wallet) external view returns (uint8);

    function getAvailableDepositWallet(
        address token,
        address sender
    ) external returns (address wallet);

    function getAvailablePoolsForAmount(
        address token,
        uint256 amount
    )
        external
        returns (Types.TPool[] memory selectedPools, uint256[] memory amounts);

    function getTokenPools(
        address token
    ) external view returns (Types.TPool[] memory);

    function getTokenPool(
        address token
    ) external view returns (uint256 next_idx, uint256 used_idx);

    function tokenMaxAmountInPool(
        address token
    ) external view returns (uint256);
}
