// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts@5.0.0/proxy/Clones.sol";
import {IPool} from "../comn/IPool.sol";
import {IExecutor} from "../comn/IExecutor.sol";
import {IMessager} from "../comn/IMessager.sol";
import {IToken} from "../comn/IToken.sol";
import {SafeERC20} from "../comn/SafeERC20.sol";
import {Types} from "../comn/Types.sol";
import {Comn} from "./Comn.sol";

/// @title TempWallet
/// @notice Minimal proxy wallet for receiving and transferring ETH or ERC20 tokens.
///         Used for fund collection and later pooling.
contract TempWallet {
    address public manager; // The FundManager contract
    address public token;
    address public user;

    event Initialized(address indexed manager);
    event ETHWithdrawn(address indexed to, uint256 amount);
    event TokenWithdrawn(
        address indexed token,
        address indexed to,
        uint256 amount
    );

    /// @notice Initializes the wallet with its manager address
    function init(address _manager) external {
        require(manager == address(0), "Already initialized");
        manager = _manager;
        emit Initialized(_manager);
    }

    /// @notice Allows the manager to assign a user to withdraw funds if the wallet is deprecated
    function allocate(address _token, address _user) external {
        require(msg.sender == manager, "Not manager");
        token = _token;
        user = _user;
    }

    /// @notice Withdraw ETH from this wallet
    function withdrawETH(address payable to, uint256 amount) external {
        require(msg.sender == manager, "Not authorized");
        (bool success, ) = to.call{value: amount}("");
        require(success, "ETH transfer failed");
        emit ETHWithdrawn(to, amount);
    }

    /// @notice Withdraw ERC20 tokens from this wallet
    function withdrawToken(address to, uint256 amount) external {
        require(msg.sender == manager, "Not authorized");
        SafeERC20.safeTransfer(IToken(token), to, amount);
        emit TokenWithdrawn(token, to, amount);
    }

    /// @notice Allows wallet to receive ETH
    receive() external payable {}
}

/// @title FundManager
/// @notice Central manager contract to create, assign, collect, and manage proxy wallets and fund pools.
contract FundManager is Comn {
    using Clones for address;
    address public walletImplementation; // Wallet template for cloning

    mapping(address => Types.TokenPool) private tokenPools;
    mapping(address => uint256) public tokenMaxAmountInPool;

    struct WalletPools {
        address[] unusedWallets;
        address[] pendingWallets;
        address[] deprecatedWallets;
        mapping(address => uint) indexInUnused;
        mapping(address => uint) indexInPending;
        mapping(address => uint) indexInDeprecated;
    }
    WalletPools private pools;

    event WalletCreated(address indexed wallet);
    event PoolCreated(address indexed pool);
    event WalletMarkedPending(address indexed wallet);
    event WalletMarkedDeprecated(address indexed wallet);
    event FundsCollected(
        address indexed wallet,
        address indexed token,
        uint256 amount
    );
    event TokenPoolAdded(
        address indexed token,
        address indexed poolAddr,
        uint256 maxAmount
    );

    /**
     * @dev Modifier that restricts a function to be called only by the executor.
     * Throws an error if the caller is not the executor.
     */
    modifier onlyExecutor() {
        require(ExecutorAddr == msg.sender, "Must executor");
        _;
    }

    /**
     * @dev Modifier that restricts a function to be called only by the pool.
     * Throws an error if the caller is not the pool.
     */
    modifier onlyPool() {
        require(PoolAddr == msg.sender, "Must pool");
        _;
    }

    /// @notice Create multiple TempWallet clones and initialize them
    function createWallets(uint256 count) external onlyAdmin {
        _ensureWalletImpl();
        for (uint256 i = 0; i < count; i++) {
            address clone = walletImplementation.clone();
            TempWallet(payable(clone)).init(address(this));
            addToUnused(clone);
            emit WalletCreated(clone);
        }
    }

    /// @notice Set the max pool balance for a specific token
    function setTokenMaxAmountInPool(
        address token,
        uint256 maxAmount
    ) external onlyAdmin {
        require(maxAmount > 0, "Max amount must be > 0");
        tokenMaxAmountInPool[token] = maxAmount;
    }

    /// @notice Get an unused wallet and mark it as pending
    function getAvailableDepositWallet(
        address token,
        address sender
    ) public onlyExecutor returns (address wallet) {
        require(pools.unusedWallets.length > 0, "No wallet available");
        wallet = pools.unusedWallets[0];
        moveUnusedToPending(wallet);
        TempWallet(payable(wallet)).allocate(token, sender);

        emit WalletMarkedPending(wallet);
    }

    /// @notice Collect ETH and tokens from a pending wallet and deposit into the appropriate pool
    function collect(
        address wallet,
        address sender
    ) external onlyExecutor returns (address sourceToken, uint256 allAmount) {
        require(isInPending(wallet), "Not pending");

        //first transfer collectFee to signer
        uint collectFee = IExecutor(ExecutorAddr).collectFee();
        uint bridgeFee = IMessager(MessagerAddr).get_bridge_fee();
        uint256 totalBalance = wallet.balance;
        require(
            totalBalance >= collectFee + bridgeFee,
            "TempWallet insufficient balance"
        );
        TempWallet tempWallet = TempWallet(payable(wallet));
        tempWallet.withdrawETH(payable(sender), collectFee);
        tempWallet.withdrawETH(payable(msg.sender), bridgeFee);

        //then transfer remaining balance to pool
        uint256 ethBalance = wallet.balance;
        if (ethBalance > 0) {
            (
                Types.TPool[] memory _pools,
                uint256[] memory amounts
            ) = getAvailablePoolsForAmount(WTOKEN_ADDRESS, ethBalance);

            for (uint i = 0; i < _pools.length; i++) {
                tempWallet.withdrawETH(payable(_pools[i].addr), amounts[i]);
                IPool(PoolAddr).sendTokenFee(WTOKEN_ADDRESS, amounts[i]);
                emit FundsCollected(wallet, WTOKEN_ADDRESS, amounts[i]);
            }
        }

        movePendingToUnused(wallet);

        address token = tempWallet.token();
        if (!isWToken(token)) {
            uint256 tokenBalance = IToken(token).balanceOf(wallet);
            if (
                tokenBalance > 0 &&
                IPool(PoolAddr).getPoolInfo(token).token != address(0)
            ) {
                (
                    Types.TPool[] memory _pools,
                    uint256[] memory amounts
                ) = getAvailablePoolsForAmount(token, tokenBalance);

                for (uint i = 0; i < _pools.length; i++) {
                    tempWallet.withdrawToken(_pools[i].addr, amounts[i]);
                    IPool(PoolAddr).sendTokenFee(token, amounts[i]);
                    emit FundsCollected(wallet, token, amounts[i]);
                }
            } else {
                return (token, tokenBalance);
            }
        }

        return (token, 0);
    }

    /// @notice Mark a pending wallet as deprecated, allow user to withdraw, and replace it with a new one
    function markWalletDeprecated(
        address wallet,
        address sender
    ) external onlyExecutor {
        require(isInPending(wallet), "Only pending wallet");
        //first transfer collectFee to signer
        uint collectFee = IExecutor(ExecutorAddr).collectFee();
        uint bridgeFee = IMessager(MessagerAddr).get_bridge_fee();
        uint256 totalBalance = wallet.balance;
        require(
            totalBalance >= collectFee + bridgeFee,
            "TempWallet insufficient balance"
        );
        TempWallet tempWallet = TempWallet(payable(wallet));
        tempWallet.withdrawETH(payable(sender), collectFee);
        tempWallet.withdrawETH(payable(msg.sender), bridgeFee);

        //then transfer remaining balance to user
        uint256 ethBalance = wallet.balance;
        if (ethBalance > 0) {
            tempWallet.withdrawETH(payable(tempWallet.user()), ethBalance);
        }

        //transfer remaining token balance to user
        address token = tempWallet.token();
        if (!isWToken(token)) {
            uint256 tokenBalance = IToken(token).balanceOf(wallet);
            if (tokenBalance > 0) {
                tempWallet.withdrawToken(tempWallet.user(), tokenBalance);
            }
        }

        movePendingToDeprecated(wallet);
        emit WalletMarkedDeprecated(wallet);

        address newWallet = walletImplementation.clone();
        TempWallet(payable(newWallet)).init(address(this));
        addToUnused(newWallet);
        emit WalletCreated(newWallet);
    }

    /// @notice Refund token of temp wallet to user
    function refund(address wallet, address sender) external onlyExecutor {
        require(isInPending(wallet), "Only pending wallet");
        //first transfer collectFee to signer
        uint collectFee = IExecutor(ExecutorAddr).collectFee();
        uint bridgeFee = IMessager(MessagerAddr).get_bridge_fee();
        uint256 totalBalance = wallet.balance;
        require(
            totalBalance >= collectFee + bridgeFee,
            "TempWallet insufficient balance"
        );
        TempWallet tempWallet = TempWallet(payable(wallet));
        tempWallet.withdrawETH(payable(sender), collectFee);
        tempWallet.withdrawETH(payable(msg.sender), bridgeFee);

        //then transfer remaining balance to user
        uint256 ethBalance = wallet.balance;
        if (ethBalance > 0) {
            tempWallet.withdrawETH(payable(tempWallet.user()), ethBalance);
        }

        //transfer remaining token balance to user
        address token = tempWallet.token();
        if (!isWToken(token)) {
            uint256 tokenBalance = IToken(token).balanceOf(wallet);
            if (tokenBalance > 0) {
                tempWallet.withdrawToken(tempWallet.user(), tokenBalance);
            }
        }

        movePendingToUnused(wallet);
    }

    // @notice Refund token of temp wallet to user
    function withdrawTokenByDeprecated(address wallet) external onlyExecutor {
        require(isInDeprecated(wallet), "Only deprecated wallet");

        TempWallet tempWallet = TempWallet(payable(wallet));
        require(tempWallet.user() == msg.sender, "Only user");

        //transfer remaining balance to user
        uint256 ethBalance = wallet.balance;
        if (ethBalance > 0) {
            tempWallet.withdrawETH(payable(tempWallet.user()), ethBalance);
        }

        //transfer remaining token balance to user
        address token = tempWallet.token();
        if (!isWToken(token)) {
            uint256 tokenBalance = IToken(token).balanceOf(wallet);
            if (tokenBalance > 0) {
                tempWallet.withdrawToken(tempWallet.user(), tokenBalance);
            }
        }
    }

    /// @notice Pay user from available pool balances
    function payoutToUser(
        address token,
        address user,
        uint256 amount
    ) external onlyPool {
        require(user != address(0), "Invalid user");
        require(amount > 0, "Zero amount");

        Types.TokenPool storage tp = tokenPools[token];
        uint256 remaining = amount;

        uint256 used_idx = tp.used_idx;
        for (uint256 i = used_idx; i < tp.pools.length && remaining > 0; i++) {
            Types.TPool storage pool = tp.pools[i];
            if (pool.enabled == false) {
                used_idx++;
                continue;
            }

            uint256 available = 0;
            if (isWToken(token)) {
                available = address(pool.addr).balance;
            } else {
                available = IToken(token).balanceOf(pool.addr);
            }

            if (available == 0) {
                used_idx++;
                continue;
            }

            uint256 payout = available >= remaining ? remaining : available;
            if (available < remaining) {
                used_idx++;
            }

            if (isWToken(token)) {
                TempWallet(payable(pool.addr)).withdrawETH(
                    payable(user),
                    payout
                );
            } else {
                TempWallet(payable(pool.addr)).withdrawToken(user, payout);
            }

            remaining -= payout;
        }
        tp.used_idx = used_idx;

        require(remaining == 0, "Insufficient pool balance");
    }

    /// @notice Same as getPools, provided for naming flexibility
    function getTokenPools(
        address token
    ) external view returns (Types.TPool[] memory) {
        return tokenPools[token].pools;
    }

    function getTokenPool(
        address token
    ) external view returns (uint256 next_idx, uint256 used_idx) {
        Types.TokenPool storage tp = tokenPools[token];
        return (tp.next_idx, tp.used_idx);
    }

    /// @dev Get an available pool or create a new one if needed
    function getAvailablePoolsForAmount(
        address token,
        uint256 amount
    )
        public
        returns (Types.TPool[] memory selectedPools, uint256[] memory amounts)
    {
        uint256 maxAmount = tokenMaxAmountInPool[token];
        require(maxAmount > 0, "Token max amount per pool is not set");

        Types.TokenPool storage tp = tokenPools[token];
        if (tp.pools.length == 0) {
            createNewPool(token, tp);
        }

        uint256 maxNeededPools = 1 + (amount / maxAmount);
        selectedPools = new Types.TPool[](maxNeededPools);
        amounts = new uint256[](maxNeededPools);

        uint256 remaining = amount;
        uint256 idx = tp.next_idx;
        uint256 count = 0;
        while (remaining > 0) {
            if (idx >= tp.pools.length) {
                createNewPool(token, tp);
                continue;
            }

            Types.TPool storage pool = tp.pools[idx];
            if (pool.enabled == false) {
                idx++;
                continue;
            }

            uint256 currentBalance = 0;
            if (isWToken(token)) {
                currentBalance = address(pool.addr).balance;
            } else {
                currentBalance = IToken(token).balanceOf(pool.addr);
            }
            uint256 capacity = pool.maxAmount - currentBalance;
            if (capacity == 0) {
                idx++;
                continue;
            }

            uint256 assignAmount = remaining > capacity ? capacity : remaining;
            selectedPools[count] = pool;
            amounts[count] = assignAmount;

            remaining -= assignAmount;
            if (remaining > 0) {
                count++;
                idx++;
            }
        }
        tp.next_idx = idx;
    }

    /// @dev Create a new pool wallet for a token
    function createNewPool(
        address token,
        Types.TokenPool storage tokenPool
    ) internal returns (Types.TPool storage) {
        address clone = walletImplementation.clone();
        TempWallet(payable(clone)).init(address(this));
        TempWallet(payable(clone)).allocate(token, address(this));

        Types.TPool memory newPool = Types.TPool({
            addr: clone,
            maxAmount: tokenMaxAmountInPool[token],
            currentBalance: 0,
            enabled: true
        });

        tokenPool.pools.push(newPool);
        tokenPool.indexInPools[clone] = tokenPool.pools.length; // index + 1
        emit PoolCreated(clone);
        return tokenPool.pools[tokenPool.pools.length - 1];
    }

    /// @notice Mark a pool as deprecated, allow pool to withdraw
    function markPoolDeprecated(
        address token,
        address wallet
    ) public onlyPool returns (uint256 available)  {
        Types.TokenPool storage tp = tokenPools[token];

        uint index = tp.indexInPools[wallet];
        require(index > 0, "Not found");

        uint actualIndex = index - 1;
        Types.TPool storage pool = tp.pools[actualIndex];
        require(pool.addr == wallet, "Wallet not matched");
        pool.enabled = false;

        available = IToken(token).balanceOf(pool.addr);
        return available;
    }

    /// @notice withdraw a pool wallet by deprecated, allow financer to withdraw
    function withdrawPoolByDeprecated(
        address token,
        address wallet,
        uint256 amount
    ) external onlyFinancer {
        Types.TokenPool storage tp = tokenPools[token];

        uint index = tp.indexInPools[wallet];
        require(index > 0, "Not found");

        uint actualIndex = index - 1;
        Types.TPool storage pool = tp.pools[actualIndex];
        require(pool.addr == wallet, "Wallet not matched");
        require(pool.enabled = false, "Pool not deprecated");

        if (isWToken(token)) {
            TempWallet(payable(pool.addr)).withdrawETH(
                payable(msg.sender),
                amount
            );
        } else {
            TempWallet(payable(pool.addr)).withdrawToken(msg.sender, amount);
        }
    }

    /// @dev Ensure wallet implementation is initialized before cloning
    function _ensureWalletImpl() internal {
        if (walletImplementation == address(0)) {
            walletImplementation = address(new TempWallet());
        }
    }

    // --------- WalletPools Helper Methods ---------
    function getUnusedWallets() external view returns (address[] memory) {
        return pools.unusedWallets;
    }

    function getPendingWallets() external view returns (address[] memory) {
        return pools.pendingWallets;
    }

    function getDeprecatedWallets() external view returns (address[] memory) {
        return pools.deprecatedWallets;
    }

    function isInUnused(address wallet) public view returns (bool) {
        return pools.indexInUnused[wallet] > 0;
    }

    function isInPending(address wallet) public view returns (bool) {
        return pools.indexInPending[wallet] > 0;
    }

    function isInDeprecated(address wallet) public view returns (bool) {
        return pools.indexInDeprecated[wallet] > 0;
    }

    function addToUnused(address wallet) private {
        require(!isInUnused(wallet), "Already in unused");
        pools.unusedWallets.push(wallet);
        pools.indexInUnused[wallet] = pools.unusedWallets.length; // index + 1
    }

    function moveUnusedToPending(address wallet) private {
        require(isInUnused(wallet), "Not in unused");

        _removeFromArray(pools.unusedWallets, pools.indexInUnused, wallet);

        pools.pendingWallets.push(wallet);
        pools.indexInPending[wallet] = pools.pendingWallets.length;
    }

    function movePendingToUnused(address wallet) private {
        require(isInPending(wallet), "Not in pending");

        _removeFromArray(pools.pendingWallets, pools.indexInPending, wallet);

        pools.unusedWallets.push(wallet);
        pools.indexInUnused[wallet] = pools.unusedWallets.length;
    }

    function movePendingToDeprecated(address wallet) private {
        require(isInPending(wallet), "Not in pending");

        _removeFromArray(pools.pendingWallets, pools.indexInPending, wallet);

        pools.deprecatedWallets.push(wallet);
        pools.indexInDeprecated[wallet] = pools.deprecatedWallets.length;
    }

    function _removeFromArray(
        address[] storage array,
        mapping(address => uint) storage indexMap,
        address wallet
    ) internal {
        uint index = indexMap[wallet];
        require(index > 0, "Not found");
        uint actualIndex = index - 1;
        uint lastIndex = array.length - 1;

        if (actualIndex != lastIndex) {
            address lastWallet = array[lastIndex];
            array[actualIndex] = lastWallet;
            indexMap[lastWallet] = actualIndex + 1;
        }

        array.pop();
        delete indexMap[wallet];
    }
}