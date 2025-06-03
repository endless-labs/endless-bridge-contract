module bridge_token::fund_manage {
    use endless_framework::account::{Self};
    use endless_framework::endless_coin::{get_eds_token_address};
    use endless_framework::event;
    use std::error;
    use std::signer;
    use std::vector;
    use std::option::{Self, Option, some, none};
    use endless_std::simple_map::{Self, SimpleMap};
    use std::bcs::to_bytes;
    use endless_std::secp256k1::{
        ecdsa_recover,
        ecdsa_signature_from_bytes,
        ecdsa_raw_public_key_to_bytes
    };
    use endless_std::table::{Self};
    use bridge_token::token::{transfer, balance};
    use bridge_token::config::{role_check};

    friend bridge_token::pool_v2;

    /// The number of signers does not match the number of messages to be signed.
    const ENUM_SIGNERS_MUST_EQ_NUM_MESSAGES: u64 = 1;
    /// The length of the signature is invalid.
    const EINVALID_LENGTH: u64 = 2;
    const ENOT_FOUND: u64 = 3;
    const EOWNER_NOT_MATCH: u64 = 4;
    const EINVALID_RECOVERY_ID: u64 = 5;

    /// Struct representing a TempWallet equivalent (resource account)
    struct Wallet has key, store {
        signer_cap: account::SignerCapability,
        token: address,
        user: address
    }

    /// A pool address + limit info
    struct TPool has key, store {
        signer_cap: account::SignerCapability,
        addr: address,
        token: address,
        max_amount: u128,
        enabled: bool
    }

    /// Token Pool holding multiple TPools
    struct TokenPool has key, store {
        pools: vector<TPool>,
        // token address -> index in pools
        index_in_pools: table::Table<address, u64>,
        next_idx: u64,
        used_idx: u64
    }

    /// Global FundManager state
    struct FundManager has key {
        next_id: u64,
        signer_cap: account::SignerCapability,
        collect_sender: Option<vector<u8>>,
        collect_sender_address: Option<address>,
        collect_fee: u128,

        // wallet addresses
        unused_wallets: vector<address>,
        pending_wallets: vector<address>,
        deprecated_wallets: vector<address>,

        // address -> index + 1
        unused_wallets_index: table::Table<address, u64>,
        pending_wallets_index: table::Table<address, u64>,
        deprecated_wallets_index: table::Table<address, u64>,

        // wallet address -> Wallet
        temp_wallets: table::Table<address, Wallet>,
        // token address -> TokenPool
        token_pools: table::Table<address, TokenPool>,
        // token address -> max stored amount
        token_max_amount: SimpleMap<address, u128>
    }

    #[event]
    struct WalletMarkedPending has drop, store {
        wallet: address
    }

    #[event]
    struct WalletMarkedDeprecated has drop, store {
        wallet: address
    }

    /// Initialize FundManager under deployer's address
    fun init_module(account: &signer) {
        let (_resource_signer, signer_cap) =
            account::create_resource_account(account, b"manager");

        move_to(
            account,
            FundManager {
                next_id: 0,
                signer_cap: signer_cap,
                collect_sender: none<vector<u8>>(),
                collect_sender_address: none<address>(),
                collect_fee: 500000,
                unused_wallets: vector::empty<address>(),
                pending_wallets: vector::empty<address>(),
                deprecated_wallets: vector::empty<address>(),
                unused_wallets_index: table::new<address, u64>(),
                pending_wallets_index: table::new<address, u64>(),
                deprecated_wallets_index: table::new<address, u64>(),
                temp_wallets: table::new<address, Wallet>(),
                token_pools: table::new<address, TokenPool>(),
                token_max_amount: simple_map::create<address, u128>()
            }
        );
    }

    public entry fun set_collect_sender(
        admin: &signer, pk: vector<u8>, sender_address: address
    ) acquires FundManager {
        role_check(admin);

        let manager_resource = borrow_global_mut<FundManager>(@bridge_token);
        manager_resource.collect_sender = some(pk);
        manager_resource.collect_sender_address = some(sender_address);
    }

    public entry fun set_collect_fee(admin: &signer, collect_fee: u128) acquires FundManager {
        role_check(admin);

        let manager_resource = borrow_global_mut<FundManager>(@bridge_token);
        manager_resource.collect_fee = collect_fee;
    }

    public entry fun set_token_max_amount(
        admin: &signer, token: address, max_amount: u128
    ) acquires FundManager {
        role_check(admin);

        let manager_resource = borrow_global_mut<FundManager>(@bridge_token);
        simple_map::add(&mut manager_resource.token_max_amount, token, max_amount);
    }

    public(friend) fun verify_collect_sender(
        message: vector<u8>, signature_bytes: vector<u8>
    ): bool acquires FundManager {
        let manager_resource = borrow_global<FundManager>(@bridge_token);
        let sender_pk = manager_resource.collect_sender;

        if (option::is_none(&sender_pk)) {
            return true
        } else {
            assert!(
                vector::length(&signature_bytes) == 65,
                error::invalid_argument(EINVALID_LENGTH)
            );
            let signature = vector::slice(&signature_bytes, 0, 64);
            std::debug::print(&signature);
            let recovery_byte = *vector::borrow(&signature_bytes, 64);
            let recovery_id =
                if (recovery_byte == 27) { 0 }
                else {
                    assert!(recovery_byte == 28, EINVALID_RECOVERY_ID);
                    1
                };
            let ecdsa_signature = ecdsa_signature_from_bytes(signature);
            let recovered = ecdsa_recover(message, recovery_id, &ecdsa_signature);
            let pk = option::borrow(&recovered);
            let pk_bytes = ecdsa_raw_public_key_to_bytes(pk);

            assert!(
                option::borrow(&sender_pk) == &vector::slice(&pk_bytes, 0, 32),
                ENUM_SIGNERS_MUST_EQ_NUM_MESSAGES
            );
        };
        return true
    }

    public fun verify_collect_sender_address(sender: &signer): bool acquires FundManager {
        let manager_resource = borrow_global<FundManager>(@bridge_token);
        if (option::is_none(&manager_resource.collect_sender_address)) {
            return true
        } else {
            let collect_sender_address =
                *option::borrow(&manager_resource.collect_sender_address);
            return signer::address_of(sender) == collect_sender_address
        }
    }

    /// Create N new wallets (resource accounts)
    public entry fun create_wallets(admin: &signer, count: u64) acquires FundManager {
        role_check(admin);

        let manager_resource = borrow_global_mut<FundManager>(@bridge_token);
        let manager_signer =
            account::create_signer_with_capability(&manager_resource.signer_cap);

        let i = 0u64;
        while (i < count) {
            let seed = to_bytes(&manager_resource.next_id);
            manager_resource.next_id = manager_resource.next_id + 1;
            let (resource_signer, wallet_cap) =
                account::create_resource_account(&manager_signer, seed);
            let wallet_addr = signer::address_of(&resource_signer);
            let wallet = Wallet { signer_cap: wallet_cap, token: @0x0, user: @0x0 };
            table::add(&mut manager_resource.temp_wallets, wallet_addr, wallet);

            vector::push_back(&mut manager_resource.unused_wallets, wallet_addr);
            let idx = vector::length(&manager_resource.unused_wallets);
            table::add(&mut manager_resource.unused_wallets_index, wallet_addr, idx);
            i = i + 1;
        }
    }

    /// Allocate token and user to a wallet
    public(friend) fun allocate_wallet(token: address, user: address): address acquires FundManager {
        let manager_resource = borrow_global_mut<FundManager>(@bridge_token);

        let wallet_addr = vector::pop_back(&mut manager_resource.unused_wallets);
        table::remove(&mut manager_resource.unused_wallets_index, wallet_addr);

        vector::push_back(&mut manager_resource.pending_wallets, wallet_addr);
        let idx = vector::length(&manager_resource.pending_wallets);
        table::add(&mut manager_resource.pending_wallets_index, wallet_addr, idx);

        let wallet = table::borrow_mut(&mut manager_resource.temp_wallets, wallet_addr);
        wallet.token = token;
        wallet.user = user;

        event::emit(WalletMarkedPending { wallet: wallet_addr });
        wallet_addr
    }

    public(friend) fun deposit_manage_pool(
        owner: &signer, token: address, amount: u128
    ) acquires FundManager {
        let manager_resource = borrow_global_mut<FundManager>(@bridge_token);

        internal_deposit_pool(manager_resource, owner, token, amount);
    }

    // transfer token to user
    public(friend) fun payout_to_user(
        user: address, token: address, amount: u128
    ) acquires FundManager {
        let manager_resource = borrow_global_mut<FundManager>(@bridge_token);
        let remaining = amount;

        assert!(table::contains(&manager_resource.token_pools, token), 1003); // Token pool not found
        let token_pool = table::borrow_mut(&mut manager_resource.token_pools, token);

        let len = vector::length(&token_pool.pools);
        let i = token_pool.used_idx;
        while (i < len && remaining > 0) {
            let pool_ref = vector::borrow_mut(&mut token_pool.pools, i);
            if (!pool_ref.enabled) {
                i = i + 1;
                token_pool.used_idx = token_pool.used_idx + 1;
                continue
            };

            let pool_signer =
                account::create_signer_with_capability(&pool_ref.signer_cap);
            let pool_addr = signer::address_of(&pool_signer);

            let available = balance(pool_addr, token);
            if (available == 0) {
                i = i + 1;
                token_pool.used_idx = token_pool.used_idx + 1;
                continue
            };

            let payout =
                if (available >= remaining) {
                    remaining
                } else {
                    token_pool.used_idx = token_pool.used_idx + 1;
                    available
                };

            transfer(&pool_signer, token, user, payout);

            remaining = remaining - payout;
            i = i + 1;
        };

        assert!(remaining == 0, 1001); // Insufficient pool balance
    }

    // fefund token to user
    public(friend) fun refund_to_user(
        user: address, wallet_addr: address
    ) acquires FundManager {
        let manager_resource = borrow_global_mut<FundManager>(@bridge_token);
        assert!(
            table::contains(&manager_resource.deprecated_wallets_index, wallet_addr),
            ENOT_FOUND
        ); // Wallet not found

        let wallet_ref = table::borrow(&manager_resource.temp_wallets, wallet_addr);
        assert!(
            wallet_ref.user == user,
            EOWNER_NOT_MATCH // Wallet not owned by user
        ); // Wallet not owned by user
        let wallet_signer =
            account::create_signer_with_capability(&wallet_ref.signer_cap);

        let token = wallet_ref.token;
        transfer(
            &wallet_signer,
            token,
            user,
            balance(wallet_addr, token)
        );
        if (token != get_eds_token_address()) {
            transfer(
                &wallet_signer,
                token,
                user,
                balance(wallet_addr, get_eds_token_address())
            );
        };
    }

    /// Collect funds from wallet into pools
    public entry fun collect(sender: &signer, wallet_addr: address) acquires FundManager {
        assert!(verify_collect_sender_address(sender), 1002); // Invalid sender
        internal_collect(sender, wallet_addr);
    }

    /// Collect funds from multiple wallets into pools
    public entry fun batch_collect(
        sender: &signer, wallet_addrs: vector<address>
    ) acquires FundManager {
        assert!(verify_collect_sender_address(sender), 1002); // Invalid sender
        let len = vector::length(&wallet_addrs);
        for (i in 0..len) {
            internal_collect(sender, *vector::borrow(&wallet_addrs, i));
        }
    }

    /// Mark a wallet as deprecated
    public entry fun mark_wallet_deprecated(
        sender: &signer, wallet_addr: address
    ) acquires FundManager {
        assert!(verify_collect_sender_address(sender), 1002); // Invalid sender

        let manager_resource = borrow_global_mut<FundManager>(@bridge_token);
        let manager_signer =
            account::create_signer_with_capability(&manager_resource.signer_cap);

        // remove wallet from pending_wallets
        let idx_ref = table::borrow(
            &manager_resource.pending_wallets_index, wallet_addr
        );
        let real_idx = *idx_ref - 1;
        let len = vector::length(&manager_resource.pending_wallets);
        if (real_idx < len - 1) {
            let last_wallet = *vector::borrow(&manager_resource.pending_wallets, len
                - 1);
            *vector::borrow_mut(&mut manager_resource.pending_wallets, real_idx) =
                last_wallet;

            table::remove(&mut manager_resource.pending_wallets_index, last_wallet);
            table::add(
                &mut manager_resource.pending_wallets_index, last_wallet, real_idx + 1
            );
        };
        vector::pop_back(&mut manager_resource.pending_wallets);
        table::remove(&mut manager_resource.pending_wallets_index, wallet_addr);

        // add to deprecated_wallets
        vector::push_back(&mut manager_resource.deprecated_wallets, wallet_addr);
        let idx = vector::length(&manager_resource.deprecated_wallets);
        table::add(&mut manager_resource.deprecated_wallets_index, wallet_addr, idx);

        // add new
        let seed = to_bytes(&manager_resource.next_id);
        manager_resource.next_id = manager_resource.next_id + 1;
        let (resource_signer, wallet_cap) =
            account::create_resource_account(&manager_signer, seed);
        let wallet_addr = signer::address_of(&resource_signer);
        let wallet = Wallet { signer_cap: wallet_cap, token: @0x0, user: @0x0 };
        vector::push_back(&mut manager_resource.unused_wallets, wallet_addr);
        let idx = vector::length(&manager_resource.unused_wallets);
        table::add(&mut manager_resource.unused_wallets_index, wallet_addr, idx);
        table::add(&mut manager_resource.temp_wallets, wallet_addr, wallet);

        event::emit(WalletMarkedDeprecated { wallet: wallet_addr });
    }

    /// Mark a pool as deprecated
    public entry fun mark_pool_deprecated(
        admin: &signer, token: address, pool_addr: address
    ) acquires FundManager {
        role_check(admin);

        let manager_resource = borrow_global_mut<FundManager>(@bridge_token);
        // remove wallet from pending_wallets
        let token_pool = table::borrow_mut(&mut manager_resource.token_pools, token);

        // borrow pools
        let idx = table::borrow(&token_pool.index_in_pools, pool_addr);
        let pool_ref = vector::borrow_mut(&mut token_pool.pools, *idx - 1);
        assert!(pool_ref.addr == pool_addr, 1006); // pool not match
        pool_ref.enabled = false;
    }

    public(friend) entry fun withdraw_pool_by_deprecated(
        user: address, token: address, pool_addr: address
    ) acquires FundManager {
        let manager_resource = borrow_global_mut<FundManager>(@bridge_token);
        // remove wallet from pending_wallets
        let token_pool = table::borrow_mut(&mut manager_resource.token_pools, token);

        // borrow pools
        let idx = table::borrow(&token_pool.index_in_pools, pool_addr);
        let pool_ref = vector::borrow_mut(&mut token_pool.pools, *idx - 1);
        assert!(pool_ref.addr == pool_addr, 1006); // pool not match
        assert!(pool_ref.enabled == false, 1007); // pool not deprecated

        let pool_signer = account::create_signer_with_capability(&pool_ref.signer_cap);
        let pool_addr = signer::address_of(&pool_signer);
        transfer(
            &pool_signer,
            token,
            user,
            balance(pool_addr, token)
        );
    }

    /// Collect funds from wallet into pools
    fun internal_collect(sender: &signer, wallet_addr: address) acquires FundManager {
        let manager_resource = borrow_global_mut<FundManager>(@bridge_token);
        let wallet_ref = table::borrow(&manager_resource.temp_wallets, wallet_addr);
        let wallet_signer =
            account::create_signer_with_capability(&wallet_ref.signer_cap);
        let token = wallet_ref.token;

        // transfer funds to pool
        internal_deposit_pool(
            manager_resource,
            &wallet_signer,
            token,
            balance(wallet_addr, token)
        );

        // transfer eds funds to pool
        if (token != get_eds_token_address()) {
            internal_deposit_pool(
                manager_resource,
                &wallet_signer,
                get_eds_token_address(),
                balance(wallet_addr, get_eds_token_address())
            );
        };

        // remove wallet from pending_wallets
        let idx_ref = table::borrow(
            &manager_resource.pending_wallets_index, wallet_addr
        );
        let real_idx = *idx_ref - 1;
        let len = vector::length(&manager_resource.pending_wallets);
        if (real_idx < len - 1) {
            let last_wallet = *vector::borrow(&manager_resource.pending_wallets, len
                - 1);
            *vector::borrow_mut(&mut manager_resource.pending_wallets, real_idx) =
                last_wallet;

            table::remove(&mut manager_resource.pending_wallets_index, last_wallet);
            table::add(
                &mut manager_resource.pending_wallets_index, last_wallet, real_idx + 1
            );
        };
        vector::pop_back(&mut manager_resource.pending_wallets);
        table::remove(&mut manager_resource.pending_wallets_index, wallet_addr);

        // add to unused_wallets
        vector::push_back(&mut manager_resource.unused_wallets, wallet_addr);
        let idx = vector::length(&manager_resource.unused_wallets);
        table::add(&mut manager_resource.unused_wallets_index, wallet_addr, idx);
    }

    /// create or get a pool for a token
    fun internal_deposit_pool(
        manager_resource: &mut FundManager,
        owner: &signer,
        token: address,
        amount: u128
    ) {
        let token_max_amount =
            *simple_map::borrow(&manager_resource.token_max_amount, &token);
        let manager_signer =
            account::create_signer_with_capability(&manager_resource.signer_cap);

        // Create pool list for token if it doesn't exist
        if (!table::contains(&manager_resource.token_pools, token)) {
            let pool = create_new_pool(&manager_signer, token, token_max_amount, 0);
            let index_map = table::new<address, u64>();
            table::add(&mut index_map, pool.addr, 1);
            table::add(
                &mut manager_resource.token_pools,
                token,
                TokenPool {
                    pools: vector[pool],
                    next_idx: 0,
                    used_idx: 0,
                    index_in_pools: index_map
                }
            );
        };

        let token_pool = table::borrow_mut(&mut manager_resource.token_pools, token);

        // Keep depositing until all amount is distributed
        while (amount > 0) {
            if (token_pool.next_idx >= vector::length(&token_pool.pools)) {
                // No more pools available, create new
                let pool =
                    create_new_pool(
                        &manager_signer,
                        token,
                        token_max_amount,
                        token_pool.next_idx
                    );
                let idx = vector::length(&token_pool.pools);
                table::add(&mut token_pool.index_in_pools, pool.addr, idx);
                vector::push_back(&mut token_pool.pools, pool);
            };

            let pool_ref = vector::borrow_mut(&mut token_pool.pools, token_pool.next_idx);
            if (!pool_ref.enabled) {
                token_pool.next_idx = token_pool.next_idx + 1;
                continue
            };

            let current_balance = balance(pool_ref.addr, token);
            let available = pool_ref.max_amount - current_balance;

            if (available > 0) {
                let transfer_amount = if (amount <= available) { amount }
                else {
                    available
                };
                transfer(owner, token, pool_ref.addr, transfer_amount);
                amount = amount - transfer_amount;
            };

            if (amount > 0) {
                token_pool.next_idx = token_pool.next_idx + 1;
            };
        }
    }

    /// create a new pool for a token
    fun create_new_pool(
        manager_signer: &signer,
        token: address,
        max_amount: u128,
        idx: u64
    ): TPool {
        let seed = to_bytes(&idx);
        let (wallet_signer, wallet_cap) =
            account::create_resource_account(manager_signer, seed);
        let wallet_addr = signer::address_of(&wallet_signer);
        TPool {
            signer_cap: wallet_cap,
            addr: wallet_addr,
            token: token,
            max_amount: max_amount,
            enabled: true
        }
    }

    #[view]
    public fun get_collect_fee(): u128 acquires FundManager {
        let manager_resource = borrow_global_mut<FundManager>(@bridge_token);
        manager_resource.collect_fee
    }

    #[test_only]
    public fun test_create_wallets(account: &signer, number: u64) acquires FundManager {
        create_wallets(account, number);
    }

    #[test_only]
    use endless_framework::endless_coin::{initialize_for_test, mint};
    #[test_only]
    use bridge_token::config::{test_init_module};

    #[test(account = @bridge_token)]
    public fun test_manage_init_module(account: &signer) {
        init_module(account);
    }

    #[test(account = @bridge_token)]
    public fun test_ecdsa_recover() {
        let addr = @0x525fe10702f571ca2c41b551f2e62580b79a4de9f220bd33bd62184bc3ff01fe;
        let msg = to_bytes(&addr);
        let timestamp = 1746866776u64;
        let bytes = to_bytes(&timestamp);
        vector::reverse_slice(&mut bytes, 0, 8);
        vector::append(&mut msg, bytes);
        // let msg: vector<u8> = vector[
        //     82, 95, 225, 7, 2, 245, 113, 202, 44, 65, 181, 81, 242, 230, 37, 128, 183, 154,
        //     77, 233, 242, 32, 189, 51, 189, 98, 24, 75, 195, 255, 1, 254, 0, 0, 0, 0, 104,
        //     31, 18, 88
        // ];
        let message = endless_std::endless_hash::keccak256(msg);
        std::debug::print(&message);

        let signature_bytes: vector<u8> = vector[
            2, 249, 130, 124, 137, 223, 235, 155, 85, 155, 251, 7, 123, 145, 212, 220, 93,
            68, 174, 247, 60, 190, 15, 175, 104, 170, 100, 90, 157, 96, 220, 50, 21, 131,
            198, 175, 9, 239, 21, 92, 157, 72, 118, 69, 155, 138, 103, 235, 186, 199, 193,
            150, 76, 248, 117, 66, 228, 29, 122, 10, 14, 6, 21, 217
        ];
        let signature = ecdsa_signature_from_bytes(signature_bytes);
        let recovered = ecdsa_recover(message, 1, &signature);
        assert!(std::option::is_some(&recovered), 1);

        let pk = option::borrow(&recovered);
        let pk_bytes = ecdsa_raw_public_key_to_bytes(pk);
        std::debug::print(&pk_bytes);

        let hashed = endless_std::endless_hash::keccak256(pk_bytes);
        let len = vector::length(&hashed);
        std::debug::print(&vector::slice(&hashed, len - 20, len));
    }

    #[
        test(
            account = @bridge_token,
            alice = @0x123,
            box = @0x234,
            sender = @0x525fe10702f571ca2c41b551f2e62580b79a4de9f220bd33bd62184bc3ff01fe,
            endless_framework = @0x1
        )
    ]
    public fun test_base_flow(
        account: &signer,
        alice: &signer,
        box: &signer,
        sender: &signer,
        endless_framework: &signer
    ) acquires FundManager {
        test_init_module(account);

        init_module(account);

        // initialize eds token
        endless_framework::timestamp::set_time_has_started_for_testing(endless_framework);
        initialize_for_test(endless_framework);
        mint(endless_framework, signer::address_of(alice), 200_000_000_000);
        mint(endless_framework, signer::address_of(box), 200_000_000_000);

        // set sender and fee
        let sender_pk =
            x"e8c032e2803c561ba84452ffe0083adcbb75a76e91cc8631a07bcdf35b8be46d";
        let sender_address =
            @0x525fe10702f571ca2c41b551f2e62580b79a4de9f220bd33bd62184bc3ff01fe;
        set_collect_sender(account, sender_pk, sender_address);
        set_collect_fee(account, 10);

        // verify sender
        let msg =
            to_bytes(&@0x525fe10702f571ca2c41b551f2e62580b79a4de9f220bd33bd62184bc3ff01fe);
        let timestamp = 1746866776;
        let bytes = to_bytes(&timestamp);
        vector::reverse_slice(&mut bytes, 0, 8);
        vector::append(&mut msg, bytes);
        let message = endless_std::endless_hash::keccak256(msg);
        std::debug::print(&message);
        let signature_bytes: vector<u8> = vector[
            2, 249, 130, 124, 137, 223, 235, 155, 85, 155, 251, 7, 123, 145, 212, 220, 93,
            68, 174, 247, 60, 190, 15, 175, 104, 170, 100, 90, 157, 96, 220, 50, 21, 131,
            198, 175, 9, 239, 21, 92, 157, 72, 118, 69, 155, 138, 103, 235, 186, 199, 193,
            150, 76, 248, 117, 66, 228, 29, 122, 10, 14, 6, 21, 217, 28
        ];
        verify_collect_sender(message, signature_bytes);

        let token = get_eds_token_address();
        set_token_max_amount(account, token, 10_000);

        // create wallets
        create_wallets(account, 1000);

        // deposit to pool
        let temp_wallet = allocate_wallet(token, signer::address_of(alice));
        transfer(alice, token, temp_wallet, 5_000);
        assert!(balance(temp_wallet, token) == 5_000, 1); // check balance

        // collect
        collect(sender, temp_wallet);
        assert!(balance(temp_wallet, token) == 0, 2); // check balance

        // mark pool disabled
        {
            let manager_resource = borrow_global<FundManager>(@bridge_token);
            let token_pool = table::borrow(&manager_resource.token_pools, token);
            let pool_ref = vector::borrow(&token_pool.pools, 0);
            let pool_ref_addr = pool_ref.addr;
            mark_pool_deprecated(sender, token, pool_ref_addr);
        };

        // deposit to pool
        // assert the first pool is disabled
        // assert the last pool is balance = 5800
        {
            deposit_manage_pool(box, token, 55_800);
            let manager_resource = borrow_global<FundManager>(@bridge_token);
            let token_pool = table::borrow(&manager_resource.token_pools, token);
            assert!(token_pool.used_idx == 0, 3); // check used_idx
            assert!(token_pool.next_idx == 6, 4); // check next_idx
            let len = vector::length(&token_pool.pools);
            for (i in 0..len) {
                let pool_ref = vector::borrow(&token_pool.pools, i);
                let pool_signer =
                    account::create_signer_with_capability(&pool_ref.signer_cap);
                let pool_addr = signer::address_of(&pool_signer);
                std::debug::print(&pool_addr);
                std::debug::print(&balance(pool_addr, token));
            };
        };

        std::debug::print(&std::string::utf8(b"============================="));

        // payout to wallet
        // assert the first pool is disabled and this balance = 5_000
        // assert the second pool is balance = 0
        // assert the last pool is balance = 7_000
        {
            let alice_before_balance = balance(signer::address_of(alice), token);
            payout_to_user(signer::address_of(alice), token, 13_000);
            assert!(
                balance(signer::address_of(alice), token)
                    == alice_before_balance + 13_000,
                7
            ); // check balance
            let manager_resource = borrow_global<FundManager>(@bridge_token);
            let token_pool = table::borrow(&manager_resource.token_pools, token);
            let len = vector::length(&token_pool.pools);
            for (i in 0..len) {
                let pool_ref = vector::borrow(&token_pool.pools, i);
                let pool_signer =
                    account::create_signer_with_capability(&pool_ref.signer_cap);
                let pool_addr = signer::address_of(&pool_signer);
                std::debug::print(&pool_addr);
                std::debug::print(&balance(pool_addr, token));
            };
        }
    }
}
