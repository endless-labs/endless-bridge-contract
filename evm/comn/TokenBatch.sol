// SPDX-License-Identifier: GPL-3.0

pragma solidity ^0.8.0;

/**
 * @title Batch function for Token
 * at sepolia 0x97f4Adff5e4C3091b083a7F0450c6BDa230f85cc
 * at bnbtest 0xb64bf9eA000A482c4f3009396f8e87464fA55eBf
 */
contract TokenBatch {
    // The token metadata
    struct Metadata {
        string symbol;
        string name;
        uint8 decimals;
    }

    /**
     * @dev claim token from game, multi transfer
     */
    function transfer(
        address tokenAddr,
        address[] memory toAddrs,
        uint256[] memory amounts
    ) public payable {
        uint256 len = amounts.length;
        require(toAddrs.length == len, "addresses & amounts error");
        uint256 total = 0;
        for (uint256 i = 0; i < len; i++) {
            total += amounts[i];
        }
        if (tokenAddr == address(0)) {
            require(msg.value >= total, "Value less");
            for (uint256 i = 0; i < len; i++) {
                uint256 amount = amounts[i];
                address to = toAddrs[i];
                TransferHelper.safeTransferETH(to, amount);
            }
            uint256 refund = msg.value - total;
            if (refund > 0) {
                TransferHelper.safeTransferETH(msg.sender, refund);
            }
        } else {
            address fromAddr = msg.sender;
            require(
                IERC20(tokenAddr).allowance(fromAddr, address(this)) >= total,
                "Approve less"
            );
            for (uint256 i = 0; i < len; i++) {
                address to = toAddrs[i];
                uint256 amount = amounts[i];
                TransferHelper.safeTransferFrom(
                    tokenAddr,
                    fromAddr,
                    to,
                    amount
                );
            }
        }
    }

    /**
     * @dev Get many address's one token balance
     */
    function balanceOf(address tokenAddr, address[] memory accounts)
        public
        view
        returns (uint256[] memory)
    {
        uint256 len = accounts.length;
        uint256[] memory amounts = new uint256[](len);

        if (tokenAddr == address(0)) {
            for (uint256 i = 0; i < len; i++) {
                amounts[i] = accounts[i].balance;
            }
        } else {
            IERC20 token = IERC20(tokenAddr);
            for (uint256 i = 0; i < len; i++) {
                amounts[i] = token.balanceOf(accounts[i]);
            }
        }

        return amounts;
    }

    /**
     * @dev Get one address's many token balance
     */
    function balanceOf(address[] memory tokenAddrs, address account)
        public
        view
        returns (uint256[] memory)
    {
        uint256 len = tokenAddrs.length;
        uint256[] memory amounts = new uint256[](len);
        for (uint256 i = 0; i < len; i++) {
            if (tokenAddrs[i] == address(0)) {
                amounts[i] = account.balance;
            } else {
                amounts[i] = IERC20(tokenAddrs[i]).balanceOf(account);
            }
        }
        return amounts;
    }

    /**
     * @dev Get many address's one token allowance for this
     */
    function allowance(
        address tokenAddr,
        address toAddr,
        address[] memory accounts
    ) public view returns (uint256[] memory) {
        require(address(0) != tokenAddr);
        uint256 len = accounts.length;
        uint256[] memory amounts = new uint256[](len);
        IERC20 token = IERC20(tokenAddr);
        for (uint256 i = 0; i < len; i++) {
            amounts[i] = token.allowance(accounts[i], toAddr);
        }
        return amounts;
    }

    /**
     * @dev Get many token's name
     */
    function name(address[] memory tokenAddrs)
        public
        view
        returns (string[] memory)
    {
        uint256 len = tokenAddrs.length;
        string[] memory names = new string[](len);

        for (uint256 i = 0; i < len; i++) {
            IERC20 token = IERC20(tokenAddrs[i]);
            names[i] = token.name();
        }
        return names;
    }

    /**
     * @dev Get many token's symbol
     */
    function symbol(address[] memory tokenAddrs)
        public
        view
        returns (string[] memory)
    {
        uint256 len = tokenAddrs.length;
        string[] memory symbols = new string[](len);

        for (uint256 i = 0; i < len; i++) {
            IERC20 token = IERC20(tokenAddrs[i]);
            symbols[i] = token.symbol();
        }
        return symbols;
    }

    /**
     * @dev Get many token's decimals
     */
    function decimals(address[] memory tokenAddrs)
        public
        view
        returns (uint8[] memory)
    {
        uint256 len = tokenAddrs.length;
        uint8[] memory arrs = new uint8[](len);

        for (uint256 i = 0; i < len; i++) {
            IERC20 token = IERC20(tokenAddrs[i]);
            arrs[i] = token.decimals();
        }
        return arrs;
    }

    /**
     * @dev Get many token's name
     */
    function metadata(address[] memory tokenAddrs)
        public
        view
        returns (Metadata[] memory)
    {
        uint256 len = tokenAddrs.length;
        Metadata[] memory metas = new Metadata[](len);

        for (uint256 i = 0; i < len; i++) {
            IERC20 token = IERC20(tokenAddrs[i]);
            metas[i] = Metadata(token.symbol(), token.name(), token.decimals());
        }
        return metas;
    }

    fallback() external payable {}

    receive() external payable {}
}

/**
 * @dev Interface of the ERC20 standard as defined in the EIP.
 */
interface IERC20 {
    function totalSupply() external view returns (uint256);

    function balanceOf(address account) external view returns (uint256);

    function transfer(address recipient, uint256 amount)
        external
        returns (bool);

    function allowance(address owner, address spender)
        external
        view
        returns (uint256);

    function approve(address spender, uint256 amount) external returns (bool);

    function transferFrom(
        address sender,
        address recipient,
        uint256 amount
    ) external returns (bool);

    function name() external view returns (string memory);

    function symbol() external view returns (string memory);

    function decimals() external view returns (uint8);
}

library TransferHelper {
    // mainnet:0xa614f803B6FD780986A42c78Ec9c7f77e6DeD13C
    address constant TronUSDTAddr = 0xa614f803B6FD780986A42c78Ec9c7f77e6DeD13C;

    /// @notice Transfers tokens from the targeted address to the given destination
    /// @notice Errors with 'STF' if transfer fails
    /// @param token The contract address of the token to be transferred
    /// @param from The originating address from which the tokens will be transferred
    /// @param to The destination address of the transfer
    /// @param value The amount to be transferred
    function safeTransferFrom(
        address token,
        address from,
        address to,
        uint256 value
    ) internal {
        (bool success, bytes memory data) = token.call(
            abi.encodeWithSelector(
                IERC20.transferFrom.selector,
                from,
                to,
                value
            )
        );
        require(
            success && (data.length == 0 || abi.decode(data, (bool))),
            "STF"
        );
    }

    /// @notice Transfers tokens from msg.sender to a recipient
    /// @dev Errors with ST if transfer fails
    /// @param token The contract address of the token which will be transferred
    /// @param to The recipient of the transfer
    /// @param value The value of the transfer
    function safeTransfer(
        address token,
        address to,
        uint256 value
    ) internal {
        (bool success, bytes memory data) = token.call(
            abi.encodeWithSelector(IERC20.transfer.selector, to, value)
        );
        if (token == TronUSDTAddr && success) {
            return;
        }
        require(
            success && (data.length == 0 || abi.decode(data, (bool))),
            "ST"
        );
    }

    /// @notice Approves the stipulated contract to spend the given allowance in the given token
    /// @dev Errors with 'SA' if transfer fails
    /// @param token The contract address of the token to be approved
    /// @param to The target of the approval
    /// @param value The amount of the given token the target will be allowed to spend
    function safeApprove(
        address token,
        address to,
        uint256 value
    ) internal {
        (bool success, bytes memory data) = token.call(
            abi.encodeWithSelector(IERC20.approve.selector, to, value)
        );
        require(
            success && (data.length == 0 || abi.decode(data, (bool))),
            "SA"
        );
    }

    /// @notice Transfers ETH to the recipient address
    /// @dev Fails with `STE`
    /// @param to The destination of the transfer
    /// @param value The value to be transferred
    function safeTransferETH(address to, uint256 value) internal {
        (bool success, ) = to.call{value: value}(new bytes(0));
        require(success, "STE");
    }
}
