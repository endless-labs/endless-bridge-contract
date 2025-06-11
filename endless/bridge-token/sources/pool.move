module bridge_token::pool {
    use endless_framework::account::{Self};
    use endless_framework::timestamp;
    use endless_std::simple_map::{Self, SimpleMap};
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
    use bridge_token::token::{transfer, balance};
    use bridge_token::config::{role_check, get_token_mint_type, islp};

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

    /// Define liquidity provider data struct
    struct LP has key, store {
        amount: u128,
        earns: u128,
        debt: u128,
        remaining: u128
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

    // Create a mapping to store the TokenPool corresponding to each token
    struct TokenPools has key {
        pool_mapping: SimpleMap<address, Pool>
    }

    struct PoolResource has key {
        signer_cap: account::SignerCapability
    }

    struct OwnerLinquidity {
        token: address,
        amount: u128,
        last_apy: u128,
        earns: u128,
        usage_rate: u128,
        withdrawal: u128
    }

    fun init_module(account: &signer) {
        move_to(
            account,
            TokenPools {
                pool_mapping: simple_map::create<address, Pool>()
            }
        );

        let (_resource_signer, signer_cap) =
            account::create_resource_account(account, b"pool");
        move_to(account, PoolResource { signer_cap });
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
        owner: &signer, token: address, amount: u128
    ) acquires TokenPools, PoolResource {
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
        let liquidity_providers = &mut pool.liquidity_providers;
        if (simple_map::contains_key(liquidity_providers, &signer::address_of(owner))) {
            let lp =
                simple_map::borrow_mut(liquidity_providers, &signer::address_of(owner));
            lp.amount = lp.amount + amount;
            lp.debt = lp.debt + multiply_u128(amount, pool.acc_ratio);
        } else {
            let lp = LP {
                amount: amount,
                earns: 0,
                debt: multiply_u128(amount, pool.acc_ratio),
                remaining: 0
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
        let pool_resource = borrow_global<PoolResource>(@bridge_token);
        let pool_signer =
            account::create_signer_with_capability(&pool_resource.signer_cap);
        transfer(
            owner,
            token,
            signer::address_of(&pool_signer),
            amount
        );
    }

    /// Remove liquidity to token pool
    public entry fun remove_liquidity(
        owner: &signer, token: address, amount: u128
    ) acquires TokenPools, PoolResource {
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
        let liquidity_providers = &mut pool.liquidity_providers;
        assert!(
            simple_map::contains_key(liquidity_providers, &signer::address_of(owner)),
            error::not_found(EOWNER_NOT_FOUND)
        );

        let lp = simple_map::borrow_mut(
            liquidity_providers, &signer::address_of(owner)
        );
        assert!(lp.amount >= amount, error::invalid_argument(EMAX_AMOUNT_EXCEEDED));
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
        let pool_resource = borrow_global<PoolResource>(@bridge_token);
        let pool_signer =
            account::create_signer_with_capability(&pool_resource.signer_cap);
        transfer(
            &pool_signer,
            token,
            signer::address_of(owner),
            amount
        );
    }

    /// Transfer token to pool
    public fun transfer_to_pool(
        owner: &signer, token: address, amount: u128
    ) acquires TokenPools, PoolResource {
        let pool_resource = borrow_global<PoolResource>(@bridge_token);
        let pool_signer =
            account::create_signer_with_capability(&pool_resource.signer_cap);
        transfer(
            owner,
            token,
            signer::address_of(&pool_signer),
            amount
        );

        let pool_mapping = &mut borrow_global_mut<TokenPools>(@bridge_token).pool_mapping;
        assert!(
            simple_map::contains_key(pool_mapping, &token),
            error::not_found(ETOKEN_NOT_FOUND)
        );
        let pool = simple_map::borrow_mut(pool_mapping, &token);
        let total_liquidity = &mut pool.total_liquidity;
        *total_liquidity = *total_liquidity + amount;
    }

    /// Transfer token from pool
    public(friend) fun transfer_from_pool(
        owner: address,
        token: address,
        amount: u128,
        is_fee: bool
    ) acquires TokenPools, PoolResource {
        let pool_resource = borrow_global<PoolResource>(@bridge_token);
        let pool_signer =
            account::create_signer_with_capability(&pool_resource.signer_cap);
        transfer(&pool_signer, token, owner, amount);

        let pool_mapping = &mut borrow_global_mut<TokenPools>(@bridge_token).pool_mapping;
        assert!(
            simple_map::contains_key(pool_mapping, &token),
            error::not_found(ETOKEN_NOT_FOUND)
        );
        let pool = simple_map::borrow_mut(pool_mapping, &token);

        // Only transferring funds to reduce liquidity. Otherwise, it will be calculated based on the share
        if (!is_fee) {
            let staked_decrease = amount * pool.total_staked / pool.total_liquidity;
            let total_staked = &mut pool.total_staked;
            *total_staked = *total_staked - staked_decrease;
        };

        let total_liquidity = &mut pool.total_liquidity;
        *total_liquidity = *total_liquidity - amount;
    }

    /// acc calc reward
    public(friend) fun refresh_rewards(token: address, lp_fee: u128) acquires TokenPools {
        if (lp_fee == 0) { return };
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
    }

    /// acc calc reward to withdrawal
    public entry fun withdrawal(
        owner: &signer, token: address, amount: u128
    ) acquires TokenPools, PoolResource {
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
            let pool_resource = borrow_global<PoolResource>(@bridge_token);
            let pool_signer =
                account::create_signer_with_capability(&pool_resource.signer_cap);
            let total_liquidity = &mut pool.total_liquidity;
            *total_liquidity = *total_liquidity - amount;

            // update the remaining
            lp.earns = lp.earns + amount;
            lp.debt = multiply_u128(lp.amount, pool.acc_ratio);
            lp.remaining = reword - amount;

            transfer(&pool_signer, token, owner, amount);
        };
    }

    /// acc calc reward to withdrawal
    public entry fun withdrawFee(
        admin: &signer, _token: address, _amount: u128
    ) {
        // Only admin can initialize new pool
        role_check(admin);
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
            // let total = get_liquidity(token);
            // assert!(amount <= total, EAMOUNT_EXCEEDS_TOTAL);

            // let ratio = amount * 1000 / total;
            // if (ratio < 3) {
            //     lp_fee = (amount * 3) / 1000;
            // } else {
            //     lp_fee = (amount * ratio) / 1000;
            // }
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
    public fun get_liquiditys(): vector<OwnerLinquidity> acquires TokenPools, PoolResource {
        // Check if Token Pool exists
        assert!(
            exists<TokenPools>(@bridge_token),
            error::not_found(EHAS_NO_POOL)
        );
        let pool_resource = borrow_global<PoolResource>(@bridge_token);
        let pool_signer =
            account::create_signer_with_capability(&pool_resource.signer_cap);

        let liquiditys = vector::empty<OwnerLinquidity>();
        let pool_mapping = &borrow_global<TokenPools>(@bridge_token).pool_mapping;
        let keys = simple_map::keys(pool_mapping);

        for (i in 0..vector::length(&keys)) {
            let key = vector::borrow(&keys, i);
            let bal = balance(signer::address_of(&pool_signer), *key);
            let pool = simple_map::borrow(pool_mapping, key);
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
}
