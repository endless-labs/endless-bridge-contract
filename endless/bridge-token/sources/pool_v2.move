module bridge_token::pool_v2 {
    use endless_framework::account::{Self};
    use endless_framework::timestamp;
    use endless_framework::endless_coin::{get_eds_token_address};
    use endless_std::simple_map::{Self, SimpleMap};
    use endless_std::table::{Self};
    use std::fixed_point64::{
        create_from_rational,
        create_from_u128,
        multiply_u128,
        get_raw_value,
        FixedPoint64
    };
    use std::error;
    use std::signer;
    use std::vector;
    use std::bcs::to_bytes;
    use bridge_token::token::{transfer};
    use bridge_token::config::{role_check, get_token_mint_type, islp};
    use bridge_token::fund_manage::{
        allocate_wallet,
        deposit_manage_pool,
        payout_to_user,
        refund_to_user,
        verify_collect_sender,
        withdraw_pool_by_deprecated,
        collect,
        mark_wallet,
        mark_pool
    };

    friend bridge_token::execute;

    /// The pool account has no other management pool beside admin.
    const EHAS_NO_POOL: u64 = 1;
    /// Token pool already exists
    const ETOKEN_ALREADY_EXISTS: u64 = 2;
    /// Token pool not fount
    const ETOKEN_NOT_FOUND: u64 = 3;
    /// Provider owner not fount
    const EOWNER_NOT_FOUND: u64 = 4;
    /// Insufficient balance to withdraw or transfer.
    const EINSUFFICIENT_BALANCE: u64 = 5;
    /// The amount has exceeded provided.
    const EMAX_AMOUNT_EXCEEDED: u64 = 6;
    const EAMOUNT_EXCEEDS_TOTAL: u64 = 7;
    const EAMOUNT_EXCEEDS_REWORD: u64 = 8;
    const EFEE_TOKEN_NOT_FOUND: u64 = 9;
    const EHAS_NO_STAKING_CONFIG: u64 = 10;
    const EAMOUNT_EXCEEDS_LIMIT: u64 = 11;
    const ETIME_NOT_YET_REACHED: u64 = 12;
    /// Function is deprecated.
    const EDEPRECATED_FUNCTION: u64 = 13;
    const EWITHDRAW_FEE_TYPE: u64 = 14;
    /// No longer supported.
    const ENO_LONGER_SUPPORTED: u64 = 15;

    const FEE_TYPE_PLATFORM: u8 = 1;
    const FEE_TYPE_COLLECT: u8 = 2;
    const FEE_TYPE_UPLOADGAS: u8 = 3;

    /// Define liquidity provider data struct
    struct LP has key, store {
        amount: u128,
        earns: u128,
        debt: u128,
        remaining: u128,
        last_deposit_time: u64
    }

    /// Define pool data struct
    struct Pool has key, store {
        liquidity_providers: SimpleMap<address, LP>,
        total_staked: u128,
        total_liquidity: u128,
        total_staked_liquidity: u128,
        total_earns: u128,
        acc_ratio: FixedPoint64,
        last_apy: FixedPoint64,
        last_receive_rewards_time: u64
    }

    struct StakingConfig has key, store {
        min_stake_amount: u128,
        max_stake_amount: u128,
        min_stake_time: u64
    }

    // Create a mapping to store the TokenPool corresponding to each token
    struct TokenPools has key {
        signer_cap: account::SignerCapability,
        financer: address,
        total_platform_fee: u128,
        total_collect_fee: u128,
        total_upload_gas_fee: u128,
        // address of token => Pool
        pool_mapping: SimpleMap<address, Pool>,
        // address of token => StakingConfig
        staking_mapping: SimpleMap<address, StakingConfig>
    }

    struct OwnerLinquidity {
        token: address,
        amount: u128,
        last_apy: u128,
        earns: u128,
        usage_rate: u128,
        withdrawal: u128
    }

    struct OrderStore has key {
        // to_chain_id => nonce => status
        order_status: simple_map::SimpleMap<u128, table::Table<u64, u8>>
    }

    fun init_module(account: &signer) {
        let (_resource_signer, signer_cap) =
            account::create_resource_account(account, b"pool");
        move_to(
            account,
            TokenPools {
                signer_cap: signer_cap,
                financer: @bridge_token,
                total_platform_fee: 0,
                total_collect_fee: 0,
                total_upload_gas_fee: 0,
                pool_mapping: simple_map::create<address, Pool>(),
                staking_mapping: simple_map::create<address, StakingConfig>()
            }
        );
    }

    public entry fun initialize_order_store(account: &signer) {
        if (signer::address_of(account) == @bridge_token
            && !exists<OrderStore>(@bridge_token)) {
            let order_status = simple_map::new();
            move_to(account, OrderStore { order_status });
        }
    }

    public entry fun set_financer(admin: &signer, new_financer: address) acquires TokenPools {
        let financer = &mut borrow_global_mut<TokenPools>(@bridge_token).financer;
        assert!(
            *financer == signer::address_of(admin)
                || signer::address_of(admin) == @bridge_token,
            0
        );

        *financer = new_financer;
    }

    public entry fun set_stake_amount(
        admin: &signer,
        token: address,
        new_min: u128,
        new_max: u128
    ) acquires TokenPools {
        role_check(admin);

        let staking_mapping =
            &mut borrow_global_mut<TokenPools>(@bridge_token).staking_mapping;

        if (simple_map::contains_key(staking_mapping, &token)) {
            let staking_config = simple_map::borrow_mut(staking_mapping, &token);
            staking_config.min_stake_amount = new_min;
            staking_config.max_stake_amount = new_max;
        } else {
            let staking_config = StakingConfig {
                min_stake_amount: new_min,
                max_stake_amount: new_max,
                min_stake_time: 24 * 60 * 60 // 1 day
            };
            simple_map::add(staking_mapping, token, staking_config);
        }
    }

    public entry fun set_stake_min_time(
        admin: &signer, token: address, new_time: u64
    ) acquires TokenPools {
        role_check(admin);

        let staking_mapping =
            &mut borrow_global_mut<TokenPools>(@bridge_token).staking_mapping;

        if (simple_map::contains_key(staking_mapping, &token)) {
            let staking_config = simple_map::borrow_mut(staking_mapping, &token);
            staking_config.min_stake_time = new_time;
        }
    }

    /// Initialize new pool
    public entry fun initialize_new_pool(admin: &signer, token: address) acquires TokenPools {
        // Only admin can initialize new pool
        role_check(admin);

        // Check if Token Pool exists
        assert!(
            exists<TokenPools>(@bridge_token),
            error::not_found(EHAS_NO_POOL)
        );

        let pool_mapping = &mut borrow_global_mut<TokenPools>(@bridge_token).pool_mapping;
        assert!(
            !simple_map::contains_key(pool_mapping, &token),
            error::already_exists(ETOKEN_ALREADY_EXISTS)
        );

        // Create a new pool for the token
        simple_map::add(
            pool_mapping,
            token,
            Pool {
                liquidity_providers: simple_map::create<address, LP>(),
                total_staked: 0,
                total_liquidity: 0,
                total_staked_liquidity: 0,
                total_earns: 0,
                acc_ratio: create_from_u128(0),
                last_apy: create_from_u128(0),
                last_receive_rewards_time: timestamp::now_seconds()
            }
        );
    }

    /// Add liquidity to token pool
    public entry fun add_liquidity(
        owner: &signer,
        token: address,
        amount: u128,
        timestamp: u64,
        signature: vector<u8>
    ) acquires TokenPools {
        let staking_mapping =
            &mut borrow_global_mut<TokenPools>(@bridge_token).staking_mapping;

        assert!(
            simple_map::contains_key(staking_mapping, &token), EHAS_NO_STAKING_CONFIG
        );
        let staking_config = simple_map::borrow(staking_mapping, &token);
        assert!(
            amount >= staking_config.min_stake_amount
                && amount <= staking_config.max_stake_amount,
            error::invalid_argument(EAMOUNT_EXCEEDS_LIMIT)
        );

        let msg = to_bytes(&signer::address_of(owner));
        let bytes = to_bytes(&timestamp);
        vector::reverse_slice(&mut bytes, 0, 8);
        vector::append(&mut msg, bytes);
        let message = endless_std::endless_hash::keccak256(msg);
        verify_collect_sender(message, signature);

        internal_add_liquidity(owner, token, amount);
    }

    fun internal_add_liquidity(
        owner: &signer, token: address, amount: u128
    ) acquires TokenPools {
        let pool_mapping = &mut borrow_global_mut<TokenPools>(@bridge_token).pool_mapping;
        assert!(
            simple_map::contains_key(pool_mapping, &token),
            error::not_found(ETOKEN_NOT_FOUND)
        );

        // Increase the liquidity volume of liquidity providers
        let pool = simple_map::borrow_mut(pool_mapping, &token);
        let liquidity_providers = &mut pool.liquidity_providers;
        if (simple_map::contains_key(liquidity_providers, &signer::address_of(owner))) {
            let lp =
                simple_map::borrow_mut(liquidity_providers, &signer::address_of(owner));
            lp.amount = lp.amount + amount;
            lp.debt = lp.debt + multiply_u128(amount, pool.acc_ratio);
            lp.last_deposit_time = timestamp::now_seconds();
        } else {
            let lp = LP {
                amount: amount,
                earns: 0,
                debt: multiply_u128(amount, pool.acc_ratio),
                remaining: 0,
                last_deposit_time: timestamp::now_seconds()
            };
            simple_map::add(liquidity_providers, signer::address_of(owner), lp);
        };

        let total_staked = &mut pool.total_staked;
        *total_staked = *total_staked + amount;

        let total_liquidity = &mut pool.total_liquidity;
        *total_liquidity = *total_liquidity + amount;

        let total_staked_liquidity = &mut pool.total_staked_liquidity;
        *total_staked_liquidity = *total_staked_liquidity + amount;

        // Transfer the token from the owner to the pool
        deposit_manage_pool(owner, token, amount);
    }

    /// Remove liquidity to token pool
    public entry fun remove_liquidity(
        owner: &signer, token: address, amount: u128
    ) acquires TokenPools {
        let staking_mapping = &borrow_global<TokenPools>(@bridge_token).staking_mapping;
        assert!(
            simple_map::contains_key(staking_mapping, &token), EHAS_NO_STAKING_CONFIG
        );
        let staking_config = simple_map::borrow(staking_mapping, &token);
        let min_stake_time = staking_config.min_stake_time;

        let pool_mapping = &mut borrow_global_mut<TokenPools>(@bridge_token).pool_mapping;
        assert!(
            simple_map::contains_key(pool_mapping, &token),
            error::not_found(ETOKEN_NOT_FOUND)
        );

        // Increase the liquidity volume of liquidity providers
        let pool = simple_map::borrow_mut(pool_mapping, &token);
        let liquidity_providers = &mut pool.liquidity_providers;
        assert!(
            simple_map::contains_key(liquidity_providers, &signer::address_of(owner)),
            error::not_found(EOWNER_NOT_FOUND)
        );

        let lp = simple_map::borrow_mut(
            liquidity_providers, &signer::address_of(owner)
        );
        assert!(lp.amount >= amount, error::invalid_argument(EMAX_AMOUNT_EXCEEDED));

        let now_seconds = timestamp::now_seconds();
        assert!(
            now_seconds >= lp.last_deposit_time + min_stake_time,
            error::invalid_argument(ETIME_NOT_YET_REACHED)
        );

        let old_amount = lp.amount;
        lp.amount = lp.amount - amount;
        lp.debt =
            lp.debt
                - multiply_u128(lp.debt, create_from_rational(lp.amount, old_amount));
        lp.remaining =
            lp.remaining
                + multiply_u128(
                    (multiply_u128(old_amount, pool.acc_ratio) - lp.debt),
                    create_from_rational(amount, old_amount)
                );

        let staked_decrease = amount * old_amount / pool.total_staked_liquidity;
        let total_staked = &mut pool.total_staked;
        *total_staked = *total_staked - staked_decrease;

        let total_liquidity = &mut pool.total_liquidity;
        *total_liquidity = *total_liquidity - amount;

        let total_staked_liquidity = &mut pool.total_staked_liquidity;
        *total_staked_liquidity = *total_staked_liquidity - amount;

        // Transfer the token from the pool to the owner
        payout_to_user(signer::address_of(owner), token, amount);
    }

    /// Transfer token to pool
    public(friend) fun transfer_to_pool(
        owner: &signer,
        source_token: address,
        tokens: vector<address>,
        amounts: vector<u128>,
        fee_types: vector<u8>
    ) acquires TokenPools {
        assert!(
            vector::length(&tokens) == vector::length(&amounts)
                && vector::length(&tokens) == vector::length(&fee_types),
            error::invalid_argument(0)
        );
        let token_pools = borrow_global_mut<TokenPools>(@bridge_token);
        let temp_wallet = allocate_wallet(source_token, signer::address_of(owner));
        let len = vector::length(&tokens);
        for (i in 0..len) {
            let token = *vector::borrow(&tokens, i);
            let amount = *vector::borrow(&amounts, i);
            let fee_type = *vector::borrow(&fee_types, i);

            transfer(owner, token, temp_wallet, amount);
            if (fee_type == FEE_TYPE_PLATFORM) {
                token_pools.total_platform_fee = token_pools.total_platform_fee
                    + amount;
            } else if (fee_type == FEE_TYPE_COLLECT) {
                token_pools.total_collect_fee = token_pools.total_collect_fee + amount;
            } else if (fee_type == FEE_TYPE_UPLOADGAS) {
                token_pools.total_upload_gas_fee =
                    token_pools.total_upload_gas_fee + amount;
            };
        };
    }

    /// Transfer token from pool
    public(friend) fun transfer_from_pool(
        owner: address,
        token: address,
        amount: u128,
        refund: u128,
        is_fee: bool
    ) acquires TokenPools {
        let pool_mapping = &mut borrow_global_mut<TokenPools>(@bridge_token).pool_mapping;
        assert!(
            simple_map::contains_key(pool_mapping, &token),
            error::not_found(ETOKEN_NOT_FOUND)
        );

        payout_to_user(owner, token, amount);
        let pool = simple_map::borrow_mut(pool_mapping, &token);

        // Only transferring funds to reduce liquidity. Otherwise, it will be calculated based on the share
        if (!is_fee) {
            let staked_decrease = amount * pool.total_staked / pool.total_liquidity;
            let total_staked = &mut pool.total_staked;
            *total_staked = *total_staked - staked_decrease;
        };

        let total_liquidity = &mut pool.total_liquidity;
        *total_liquidity = *total_liquidity - amount;
        *total_liquidity = *total_liquidity + refund;
    }

    /// Transfer token from pool
    public(friend) fun withdraw_bridge_fee(
        receiver: address, amount: u128
    ) acquires TokenPools {
        let eds_token_address = get_eds_token_address();
        let pool_mapping = &mut borrow_global_mut<TokenPools>(@bridge_token).pool_mapping;
        assert!(
            simple_map::contains_key(pool_mapping, &eds_token_address),
            error::not_found(ETOKEN_NOT_FOUND)
        );

        let pool = simple_map::borrow_mut(pool_mapping, &eds_token_address);
        let total_liquidity = &mut pool.total_liquidity;
        *total_liquidity = *total_liquidity - amount;

        payout_to_user(receiver, eds_token_address, amount);
    }

    /// acc calc reward
    public(friend) fun refresh_rewards(token: address, lp_fee: u128): u128 acquires TokenPools {
        if (lp_fee == 0) {
            return 0
        };
        // Check if Token Pool exists
        assert!(
            exists<TokenPools>(@bridge_token),
            error::not_found(EHAS_NO_POOL)
        );

        let pool_mapping = &mut borrow_global_mut<TokenPools>(@bridge_token).pool_mapping;
        assert!(
            simple_map::contains_key(pool_mapping, &token),
            error::not_found(ETOKEN_NOT_FOUND)
        );

        // Increase the liquidity volume of liquidity providers
        let pool = simple_map::borrow_mut(pool_mapping, &token);
        if (pool.total_liquidity == 0) {
            return 0
        };

        // Calculate the pool fee
        let pool_fee = lp_fee * pool.total_staked / pool.total_liquidity;
        pool.total_earns = pool.total_earns + pool_fee;

        let acc_ratio = create_from_rational(pool_fee, pool.total_liquidity);
        let result = std::fixed_point64::add(pool.acc_ratio, acc_ratio);
        pool.acc_ratio = result;

        // Calculate the APY
        let now_seconds = timestamp::now_seconds();
        let delta =
            if (now_seconds - pool.last_receive_rewards_time < 1) { 1 }
            else {
                now_seconds - pool.last_receive_rewards_time
            };

        pool.last_apy = std::fixed_point64::create_from_rational(
            (std::fixed_point64::multiply_u128(((365 * 24 * 60 * 60) as u128), acc_ratio)),
            (delta as u128)
        );
        pool.last_receive_rewards_time = now_seconds;

        return pool_fee
    }

    public entry fun batch_collect(
        _sender: &signer, _wallet_addrs: vector<address>
    ) {
        abort error::not_implemented(ENO_LONGER_SUPPORTED)
    }

    /// Collect funds from multiple wallets into pools
    public entry fun batch_collect_v2(
        sender: &signer,
        wallet_addrs: vector<address>,
        to_chains: vector<u128>,
        to_nonces: vector<u64>
    ) acquires TokenPools, OrderStore {
        let token_pools = borrow_global_mut<TokenPools>(@bridge_token);
        let eds_token_address = get_eds_token_address();

        let len = vector::length(&wallet_addrs);
        for (i in 0..len) {
            let wallet_addr = *vector::borrow(&wallet_addrs, i);

            let (token, token_amount, eds_amount) = collect(sender, wallet_addr);

            let to_chain = *vector::borrow(&to_chains, i);
            let to_nonce = *vector::borrow(&to_nonces, i);
            let order_store = borrow_global_mut<OrderStore>(@bridge_token);

            if (!simple_map::contains_key(&order_store.order_status, &to_chain)) {
                let inner_table = table::new();
                simple_map::add(&mut order_store.order_status, to_chain, inner_table);
            };
            let inner_table =
                simple_map::borrow_mut(&mut order_store.order_status, &to_chain);
            table::upsert(inner_table, to_nonce, 1); // 1 means collected

            if (token_amount > 0
                && simple_map::contains_key(&token_pools.pool_mapping, &token)) {
                let pool = simple_map::borrow_mut(&mut token_pools.pool_mapping, &token);
                let total_liquidity = &mut pool.total_liquidity;
                *total_liquidity = *total_liquidity + token_amount;
            };

            if (token != eds_token_address && eds_amount > 0) {
                let pool =
                    simple_map::borrow_mut(
                        &mut token_pools.pool_mapping, &eds_token_address
                    );
                let total_liquidity = &mut pool.total_liquidity;
                *total_liquidity = *total_liquidity + eds_amount;
            }
        }
    }

    /// mark wallet deprecated
    public entry fun mark_wallet_deprecated(
        _sender: &signer, _wallet_addr: address
    ) {
        abort error::not_implemented(ENO_LONGER_SUPPORTED)
    }

    /// mark wallet deprecated
    public entry fun mark_wallet_deprecated_v2(
        sender: &signer,
        wallet_addr: address,
        to_chain: u128,
        to_nonce: u64
    ) acquires OrderStore {
        mark_wallet(sender, wallet_addr);

        let order_store = borrow_global_mut<OrderStore>(@bridge_token);
        if (!simple_map::contains_key(&order_store.order_status, &to_chain)) {
            let inner_table = table::new();
            simple_map::add(&mut order_store.order_status, to_chain, inner_table);
        };
        let inner_table = simple_map::borrow_mut(
            &mut order_store.order_status, &to_chain
        );
        table::upsert(inner_table, to_nonce, 2); // 2 means deprecated
    }

    /// user wallet to refund
    public entry fun refund_wallet(
        _sender: &signer, _temp_wallet: address
    ) {
        abort error::not_implemented(ENO_LONGER_SUPPORTED)
    }

    /// user wallet to refund
    public entry fun refund_wallet_v2(
        sender: &signer,
        temp_wallet: address,
        to_chain: u128,
        to_nonce: u64
    ) acquires OrderStore {
        refund_to_user(signer::address_of(sender), temp_wallet);

        let order_store = borrow_global_mut<OrderStore>(@bridge_token);
        if (!simple_map::contains_key(&order_store.order_status, &to_chain)) {
            let inner_table = table::new();
            simple_map::add(&mut order_store.order_status, to_chain, inner_table);
        };
        let inner_table = simple_map::borrow_mut(
            &mut order_store.order_status, &to_chain
        );
        table::upsert(inner_table, to_nonce, 3); // 3 means refund
    }

    /// mark pool deprecated
    public entry fun mark_pool_deprecated(
        admin: &signer, token: address, pool_addr: address
    ) acquires TokenPools {
        let amount = mark_pool(admin, token, pool_addr);
        let token_pools = borrow_global_mut<TokenPools>(@bridge_token);
        let pool = simple_map::borrow_mut(&mut token_pools.pool_mapping, &token);
        let total_liquidity = &mut pool.total_liquidity;
        *total_liquidity = *total_liquidity - amount;
    }

    /// acc calc reward to withdrawal
    public entry fun withdrawal(
        owner: &signer, token: address, amount: u128
    ) acquires TokenPools {
        // Check if Token Pool exists
        assert!(
            exists<TokenPools>(@bridge_token),
            error::not_found(EHAS_NO_POOL)
        );

        let pool_mapping = &mut borrow_global_mut<TokenPools>(@bridge_token).pool_mapping;
        assert!(
            simple_map::contains_key(pool_mapping, &token),
            error::not_found(ETOKEN_NOT_FOUND)
        );

        let mint_type = get_token_mint_type(to_bytes(&token));
        if (islp(mint_type)) {
            // Increase the liquidity volume of liquidity providers
            let owner = signer::address_of(owner);
            let pool = simple_map::borrow_mut(pool_mapping, &token);
            let liquidity_providers = &mut pool.liquidity_providers;
            assert!(
                simple_map::contains_key(liquidity_providers, &owner),
                error::not_found(EOWNER_NOT_FOUND)
            );
            let lp = simple_map::borrow_mut(liquidity_providers, &owner);
            let reword = multiply_u128(lp.amount, pool.acc_ratio) - lp.debt
                + lp.remaining;
            assert!(reword >= amount, EAMOUNT_EXCEEDS_REWORD);

            // update the liquidity
            let total_liquidity = &mut pool.total_liquidity;
            *total_liquidity = *total_liquidity - amount;

            // update the remaining
            lp.earns = lp.earns + amount;
            lp.debt = multiply_u128(lp.amount, pool.acc_ratio);
            lp.remaining = reword - amount;

            payout_to_user(owner, token, amount);
        };
    }

    /// withdrawal fee
    public entry fun withdraw_uploadgas_fee(sender: &signer, amount: u128) acquires TokenPools {
        let token_pools = borrow_global_mut<TokenPools>(@bridge_token);
        assert!(
            token_pools.financer == signer::address_of(sender),
            error::invalid_argument(0)
        );

        let eds_token_address = get_eds_token_address();
        let pool_mapping = &mut token_pools.pool_mapping;
        assert!(
            simple_map::contains_key(pool_mapping, &eds_token_address),
            error::not_found(ETOKEN_NOT_FOUND)
        );

        token_pools.total_upload_gas_fee = token_pools.total_upload_gas_fee - amount;
        // update the liquidity
        let pool = simple_map::borrow_mut(pool_mapping, &eds_token_address);
        let total_liquidity = &mut pool.total_liquidity;
        *total_liquidity = *total_liquidity - amount;
        payout_to_user(signer::address_of(sender), eds_token_address, amount);
    }

    public entry fun withdraw_deprecated_pool(
        sender: &signer, token: address, pool_addr: address
    ) acquires TokenPools {
        let token_pools = borrow_global_mut<TokenPools>(@bridge_token);
        assert!(
            token_pools.financer == signer::address_of(sender),
            error::invalid_argument(0)
        );
        withdraw_pool_by_deprecated(signer::address_of(sender), token, pool_addr);
    }

    #[view]
    /// Get owner reward
    public fun get_reward(owner: address, token: address): u128 acquires TokenPools {
        // Check if Token Pool exists
        assert!(
            exists<TokenPools>(@bridge_token),
            error::not_found(EHAS_NO_POOL)
        );

        let pool_mapping = &borrow_global<TokenPools>(@bridge_token).pool_mapping;
        assert!(
            simple_map::contains_key(pool_mapping, &token),
            error::not_found(ETOKEN_NOT_FOUND)
        );

        let mint_type = get_token_mint_type(to_bytes(&token));
        let reword = 0;
        if (islp(mint_type)) {
            // Increase the liquidity volume of liquidity providers
            let pool = simple_map::borrow(pool_mapping, &token);
            let liquidity_providers = &pool.liquidity_providers;
            assert!(
                simple_map::contains_key(liquidity_providers, &owner),
                error::not_found(EOWNER_NOT_FOUND)
            );
            let lp = simple_map::borrow(liquidity_providers, &owner);
            let base_value = multiply_u128(lp.amount, pool.acc_ratio) + lp.remaining;
            if (base_value > lp.debt) {
                reword = base_value - lp.debt
            };
        };
        reword
    }

    #[view]
    /// Get the liquidity provider fee
    public fun get_lp_fee(token: address, amount: u128): u128 {
        let mint_type = get_token_mint_type(to_bytes(&token));
        let lp_fee = 0;
        if (islp(mint_type)) {
            lp_fee = (amount * 3) / 1000;
        };
        lp_fee
    }

    #[view]
    /// Query the liquidity information of Token Pool
    public fun get_liquidity(token: address): u128 acquires TokenPools {
        // Check if Token Pool exists
        assert!(
            exists<TokenPools>(@bridge_token),
            error::not_found(EHAS_NO_POOL)
        );

        let pool_mapping = &borrow_global<TokenPools>(@bridge_token).pool_mapping;
        assert!(
            simple_map::contains_key(pool_mapping, &token),
            error::not_found(ETOKEN_NOT_FOUND)
        );

        // Increase the liquidity volume of liquidity providers
        let pool = simple_map::borrow(pool_mapping, &token);
        pool.total_liquidity
    }

    #[view]
    /// Query the staked information of Token Pool
    public fun get_staked(token: address): u128 acquires TokenPools {
        // Check if Token Pool exists
        assert!(
            exists<TokenPools>(@bridge_token),
            error::not_found(EHAS_NO_POOL)
        );

        let pool_mapping = &borrow_global<TokenPools>(@bridge_token).pool_mapping;
        assert!(
            simple_map::contains_key(pool_mapping, &token),
            error::not_found(ETOKEN_NOT_FOUND)
        );

        // Increase the liquidity volume of liquidity providers
        let pool = simple_map::borrow(pool_mapping, &token);
        pool.total_staked
    }

    #[view]
    /// Query the liquidity information of Token Pool
    public fun get_liquiditys(): vector<OwnerLinquidity> acquires TokenPools {
        // Check if Token Pool exists
        assert!(
            exists<TokenPools>(@bridge_token),
            error::not_found(EHAS_NO_POOL)
        );
        let liquiditys = vector::empty<OwnerLinquidity>();
        let pool_mapping = &borrow_global<TokenPools>(@bridge_token).pool_mapping;
        let keys = simple_map::keys(pool_mapping);

        for (i in 0..vector::length(&keys)) {
            let key = vector::borrow(&keys, i);
            let pool = simple_map::borrow(pool_mapping, key);
            let bal = pool.total_staked_liquidity;
            let usage_rate =
                if (pool.total_staked == 0) { 0 }
                else {
                    get_raw_value(create_from_rational((bal as u128), pool.total_staked))
                };
            let ol = OwnerLinquidity {
                token: *key,
                amount: pool.total_staked,
                last_apy: get_raw_value(pool.last_apy),
                earns: pool.total_earns,
                usage_rate: usage_rate,
                withdrawal: 0
            };
            vector::push_back(&mut liquiditys, ol);
        };

        liquiditys
    }

    #[view]
    /// Query the liquidity information of Token Pool
    public fun get_owner_liquidity(owner: address, token: address): u128 acquires TokenPools {
        // Check if Token Pool exists
        assert!(
            exists<TokenPools>(@bridge_token),
            error::not_found(EHAS_NO_POOL)
        );

        let pool_mapping = &borrow_global<TokenPools>(@bridge_token).pool_mapping;
        assert!(
            simple_map::contains_key(pool_mapping, &token),
            error::not_found(ETOKEN_NOT_FOUND)
        );

        let mint_type = get_token_mint_type(to_bytes(&token));
        let liquidity = 0;
        if (islp(mint_type)) {
            // Increase the liquidity volume of liquidity providers
            let pool = simple_map::borrow(pool_mapping, &token);
            let liquidity_providers = &pool.liquidity_providers;
            assert!(
                simple_map::contains_key(liquidity_providers, &owner),
                error::not_found(EOWNER_NOT_FOUND)
            );
            let lp = simple_map::borrow(liquidity_providers, &owner);
            liquidity = lp.amount;
        };
        liquidity
    }

    #[view]
    /// Query the liquidity information of Token Pool
    public fun get_owner_liquiditys(owner: address): vector<OwnerLinquidity> acquires TokenPools {
        // Check if Token Pool exists
        assert!(
            exists<TokenPools>(@bridge_token),
            error::not_found(EHAS_NO_POOL)
        );

        let liquiditys = vector::empty<OwnerLinquidity>();
        let pool_mapping = &borrow_global<TokenPools>(@bridge_token).pool_mapping;
        let keys = simple_map::keys(pool_mapping);
        for (i in 0..vector::length(&keys)) {
            let key = vector::borrow(&keys, i);
            let pool = simple_map::borrow(pool_mapping, key);
            let liquidity_providers = &pool.liquidity_providers;
            if (simple_map::contains_key(liquidity_providers, &owner)) {
                let lp = simple_map::borrow(liquidity_providers, &owner);
                let base_value = multiply_u128(lp.amount, pool.acc_ratio) + lp.remaining;
                let withdrawal =
                    if (base_value > lp.debt) {
                        base_value - lp.debt
                    } else { 0 };
                let ol = OwnerLinquidity {
                    token: *key,
                    amount: lp.amount,
                    last_apy: 0,
                    earns: lp.earns,
                    usage_rate: 0,
                    withdrawal: withdrawal
                };
                vector::push_back(&mut liquiditys, ol);
            };
        };

        liquiditys
    }

    #[view]
    /// Get owner reward
    public fun get_pools(): vector<address> acquires TokenPools {
        // Check if Token Pool exists
        assert!(
            exists<TokenPools>(@bridge_token),
            error::not_found(EHAS_NO_POOL)
        );
        let pool_mapping = &borrow_global<TokenPools>(@bridge_token).pool_mapping;

        simple_map::keys(pool_mapping)
    }

    #[view]
    public fun get_financer(): address acquires TokenPools {
        let financer = borrow_global<TokenPools>(@bridge_token).financer;
        financer
    }

    #[view]
    public fun get_uploadgas_fee(): u128 acquires TokenPools {
        let token_pools = borrow_global_mut<TokenPools>(@bridge_token);
        token_pools.total_upload_gas_fee
    }

    #[view]
    public fun get_stake_info(token: address): (u128, u128, u64) acquires TokenPools {
        let staking_mapping = &borrow_global<TokenPools>(@bridge_token).staking_mapping;

        if (simple_map::contains_key(staking_mapping, &token)) {
            let staking_config = simple_map::borrow(staking_mapping, &token);
            let min_amount = staking_config.min_stake_amount;
            let max_amount = staking_config.max_stake_amount;
            let min_stake_time = staking_config.min_stake_time;
            return (min_amount, max_amount, min_stake_time)
        };

        return (0, 0, 0)
    }

    #[view]
    public fun get_order_status(to_chain: u128, to_nonce: u64): u8 acquires OrderStore {
        let order_store = borrow_global<OrderStore>(@bridge_token);
        if (!simple_map::contains_key(&order_store.order_status, &to_chain)) {
            return 0
        };

        let inner_table = simple_map::borrow(&order_store.order_status, &to_chain);
        if (!table::contains(inner_table, to_nonce)) {
            return 0
        };

        return *table::borrow(inner_table, to_nonce)
    }

    #[test_only]
    use endless_std::debug::print;
    #[test_only]
    use endless_framework::endless_coin::{Self, initialize_for_test, mint};
    #[test_only]
    use bridge_token::config::{test_init_module, test_set_mint_type};
    #[test_only]
    use bridge_token::fund_manage::{
        test_manage_init_module,
        test_create_wallets,
        set_token_max_amount
    };

    #[test(
        account = @bridge_token, alice = @0x123, box = @0x234, endless_framework = @0x1
    )]
    #[expected_failure(abort_code = 0x1000c, location = Self)]
    public fun test_basic_pool_flow(
        account: &signer,
        alice: &signer,
        box: &signer,
        endless_framework: &signer
    ) acquires TokenPools {
        test_init_module(account);
        test_manage_init_module(account);
        test_create_wallets(account, 1000);

        init_module(account);

        // set up global time for testing purpose
        timestamp::set_time_has_started_for_testing(endless_framework);
        initialize_for_test(endless_framework);
        mint(endless_framework, signer::address_of(alice), 200_000_000_000);
        mint(endless_framework, signer::address_of(box), 200_000_000_000);
        let bal = endless_coin::balance(signer::address_of(alice));
        assert!(bal == 200_000_000_000, 1);

        let token = @0xc69712057e634bebc9ab02745d2d69ee738e3eb4f5d30189a9acbf8e08fb823e;
        initialize_new_pool(account, token);
        set_stake_amount(account, token, 10, 1_000_000_000_000);
        set_token_max_amount(account, token, 500_000_000_000_000);

        add_liquidity(
            alice,
            token,
            100,
            1746515000,
            vector::empty<u8>()
        );
        let liquidity = get_liquidity(token);
        assert!(liquidity == 100, 1);

        add_liquidity(
            box,
            token,
            200,
            1746515000,
            vector::empty<u8>()
        );
        let liquidity = get_liquidity(token);
        assert!(liquidity == 300, 1);

        remove_liquidity(alice, token, 50);
        let liquidity = get_liquidity(token);
        assert!(liquidity == 250, 1);
    }

    #[test(
        account = @bridge_token, alice = @0x123, box = @0x234, endless_framework = @0x1
    )]
    public fun test_pool_reward_flow(
        account: &signer,
        alice: &signer,
        box: &signer,
        endless_framework: &signer
    ) acquires TokenPools {
        test_init_module(account);
        test_manage_init_module(account);
        test_create_wallets(account, 1000);

        init_module(account);

        // set up global time for testing purpose
        timestamp::set_time_has_started_for_testing(endless_framework);
        initialize_for_test(endless_framework);

        mint(endless_framework, signer::address_of(alice), 200_000_000_000);
        mint(endless_framework, signer::address_of(box), 200_000_000_000);
        let bal = endless_coin::balance(signer::address_of(alice));
        assert!(bal == 200_000_000_000, 1);

        let token = @0xc69712057e634bebc9ab02745d2d69ee738e3eb4f5d30189a9acbf8e08fb823e;
        initialize_new_pool(account, token);
        set_stake_amount(account, token, 10, 1_000_000_000_000);
        set_token_max_amount(account, token, 500_000_000_000_000);

        add_liquidity(
            alice,
            token,
            1_000_000_000,
            1746515000,
            vector::empty<u8>()
        );
        let liquidity = get_liquidity(token);
        assert!(liquidity == 1_000_000_000, 1);

        transfer_to_pool(
            box,
            token,
            vector[token],
            vector[200_000_000_000],
            vector[0]
        );
        let staked = get_staked(token);
        assert!(staked == 1_000_000_000, 1);
        let liquidity = get_liquidity(token);
        assert!(liquidity == 201_000_000_000, 1);

        test_set_mint_type(to_bytes(&token), 2);
        let lp_fee = get_lp_fee(token, 50_000_000_000);
        print(&lp_fee);

        refresh_rewards(token, lp_fee);
        let reward = get_reward(signer::address_of(alice), token);
        assert!(reward == 3712, 1);

        withdrawal(alice, token, reward);
        let staked = get_staked(token);
        assert!(staked == 1_000_000_000, 1);
        let liquidity = get_liquidity(token);
        assert!(liquidity == 201_000_000_000 - reward, 1);
    }

    #[test_only]
    public fun test_basic_pool_for_other_module(
        account: &signer,
        alice: &signer,
        box: &signer,
        endless_framework: &signer
    ) acquires TokenPools {
        test_init_module(account);
        test_manage_init_module(account);
        test_create_wallets(account, 1000);

        init_module(account);

        // set up global time for testing purpose
        timestamp::set_time_has_started_for_testing(endless_framework);
        initialize_for_test(endless_framework);
        mint(endless_framework, signer::address_of(alice), 200_000_000_000);
        mint(endless_framework, signer::address_of(box), 200_000_000_000);
        let bal = endless_coin::balance(signer::address_of(alice));
        assert!(bal == 200_000_000_000, 1);

        let token = @0xc69712057e634bebc9ab02745d2d69ee738e3eb4f5d30189a9acbf8e08fb823e;
        initialize_new_pool(account, token);
        set_stake_amount(account, token, 10, 1_000_000_000_000);
        set_token_max_amount(account, token, 500_000_000_000_000);

        add_liquidity(
            alice,
            token,
            100,
            1746515000,
            vector::empty<u8>()
        );
        let liquidity = get_liquidity(token);
        assert!(liquidity == 100, 1);

        add_liquidity(
            box,
            token,
            200,
            1746515000,
            vector::empty<u8>()
        );
        let liquidity = get_liquidity(token);
        assert!(liquidity == 300, 1);

        remove_liquidity(alice, token, 50);
        let liquidity = get_liquidity(token);
        assert!(liquidity == 250, 1);
    }
}
