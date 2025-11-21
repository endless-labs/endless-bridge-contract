module bridge_token::config {
    use std::error;
    use std::signer;
    use std::vector;
    use endless_std::simple_map::{Self, SimpleMap};
    use endless_framework::event;
    use bridge_core::message::{chain_from_bytes, Chain};

    /// The config account has no other management tokens beside admin.
    const EHAS_NO_TOKENS: u64 = 1;
    /// The config account has no such management tokens.
    const ETOKEN_NOT_FOUND: u64 = 2;

    const MINT_TYPE_MINT: u8 = 1;
    const MINT_TYPE_LP: u8 = 2;

    struct FromSource has key, store, copy, drop {
        from_chain: Chain,
        from_token: vector<u8>
    }

    struct TokenAccuracy has store, copy, drop {
        to_token: vector<u8>,
        to_decimals: u8,
        from_decimals: u8
    }

    struct Config has key {
        token_mapping: SimpleMap<FromSource, TokenAccuracy>,
        /// token mint type (1 mint | 2 lp)
        mint_type_mapping: SimpleMap<vector<u8>, u8>,
        /// <from_chain_id, contract_addr>
        from_chain_contract: SimpleMap<Chain, vector<u8>>,
        /// <from_chain_id, fee_token>
        from_chain_fee_token: SimpleMap<Chain, vector<u8>>
    }

    struct OwnerConf has key {
        admin: address
    }

    #[event]
    /// Event emitted when authority changed
    struct AuthorityChanged has drop, store {
        old_addr: address,
        new_addr: address,
        role: u8 // 2=admin
    }

    #[event]
    /// Event emitted when token relationship set
    struct TokenRelationshipSet has drop, store {
        source_chain: Chain,
        source_token: vector<u8>,
        source_token_decimals: u8,
        dest_token: vector<u8>,
        dest_token_type: u8
    }

    #[event]
    /// Event emitted when token relationship removed
    struct TokenRelationshipRemoved has drop, store {
        source_chain: Chain,
        source_token: vector<u8>
    }

    #[event]
    /// Event emitted when chain contract updated
    struct ChainContractUpdated has drop, store {
        source_chain: Chain,
        contract_addr: vector<u8>
    }

    #[event]
    /// Event emitted when chain fee token updated
    struct ChainFeeTokenUpdated has drop, store {
        source_chain: Chain,
        fee_token_addr: vector<u8>
    }

    fun init_module(account: &signer) {
        move_to(
            account,
            Config {
                token_mapping: simple_map::create<FromSource, TokenAccuracy>(),
                mint_type_mapping: simple_map::create<vector<u8>, u8>(),
                from_chain_contract: simple_map::create<Chain, vector<u8>>(),
                from_chain_fee_token: simple_map::create<Chain, vector<u8>>()
            }
        );

        move_to(account, OwnerConf { admin: @bridge_token });
    }

    public entry fun transfer_ownership(admin: &signer, new_admin: address) acquires OwnerConf {
        let owner_conf = borrow_global_mut<OwnerConf>(@bridge_token);
        verify_admin(admin, owner_conf);

        let old_admin = owner_conf.admin;
        owner_conf.admin = new_admin;

        event::emit(AuthorityChanged {
            old_addr: old_admin,
            new_addr: new_admin,
            role: 2 // admin role
        });
    }

    /// Set the token mapping
    public entry fun set_to_token(
        admin: &signer, // can transfer ownership
        from_chain: vector<u8>,
        from_token: vector<u8>,
        from_decimals: u8,
        to_token: vector<u8>,
        to_decimals: u8
    ) acquires OwnerConf, Config {
        let owner_conf = borrow_global<OwnerConf>(@bridge_token);
        verify_admin(admin, owner_conf);

        let from_chain = chain_from_bytes(from_chain);
        let from_source = FromSource { from_chain, from_token };
        let token_mapping = &mut borrow_global_mut<Config>(@bridge_token).token_mapping;
        if (!simple_map::contains_key(token_mapping, &from_source)) {
            simple_map::add(
                token_mapping,
                from_source,
                TokenAccuracy { from_decimals, to_token, to_decimals }
            );

            event::emit(TokenRelationshipSet {
                source_chain: from_chain,
                source_token: from_token,
                source_token_decimals: from_decimals,
                dest_token: to_token,
                dest_token_type: 1 // default mint type
            });
        }
    }

    /// delete the token of the mapping
    public entry fun remove_to_token(
        admin: &signer, // can transfer ownership
        from_token: vector<u8>,
        from_chain: vector<u8>
    ) acquires OwnerConf, Config {
        let owner_conf = borrow_global<OwnerConf>(@bridge_token);
        verify_admin(admin, owner_conf);

        let from_chain = chain_from_bytes(from_chain);
        let from_source = FromSource { from_chain, from_token };
        let token_mapping = &mut borrow_global_mut<Config>(@bridge_token).token_mapping;
        if (simple_map::contains_key(token_mapping, &from_source)) {
            simple_map::remove(token_mapping, &from_source);

            event::emit(TokenRelationshipRemoved {
                source_chain: from_chain,
                source_token: from_token
            });
        }
    }

    /// Set the token mint type
    public entry fun set_token_mint_type(token: vector<u8>, mint_type: u8) acquires Config {
        let mint_type_mapping =
            &mut borrow_global_mut<Config>(@bridge_token).mint_type_mapping;
        simple_map::upsert(mint_type_mapping, token, mint_type);
    }

    /// set the chain contract
    public entry fun set_chain_contract(
        admin: &signer, source_chain: vector<u8>, new_contract: vector<u8>
    ) acquires OwnerConf, Config {
        let owner_conf = borrow_global<OwnerConf>(@bridge_token);
        verify_admin(admin, owner_conf);

        let from_chain = chain_from_bytes(copy source_chain);
        let from_chain_contract =
            &mut borrow_global_mut<Config>(@bridge_token).from_chain_contract;
        if (simple_map::contains_key(from_chain_contract, &from_chain)) {
            let contract = simple_map::borrow_mut(from_chain_contract, &from_chain);
            *contract = new_contract
        } else {
            simple_map::add(from_chain_contract, from_chain, new_contract);
        };

        event::emit(ChainContractUpdated {
            source_chain: from_chain,
            contract_addr: new_contract
        });
    }

    /// set the chain fee token
    public entry fun set_chain_fee_token(
        admin: &signer, source_chain: vector<u8>, new_fee_token: vector<u8>
    ) acquires OwnerConf, Config {
        let owner_conf = borrow_global<OwnerConf>(@bridge_token);
        verify_admin(admin, owner_conf);

        let from_chain = chain_from_bytes(copy source_chain);
        let from_chain_fee_token =
            &mut borrow_global_mut<Config>(@bridge_token).from_chain_fee_token;
        if (simple_map::contains_key(from_chain_fee_token, &from_chain)) {
            let fee_token = simple_map::borrow_mut(from_chain_fee_token, &from_chain);
            *fee_token = new_fee_token
        } else {
            simple_map::add(from_chain_fee_token, from_chain, new_fee_token);
        };

        event::emit(ChainFeeTokenUpdated {
            source_chain: from_chain,
            fee_token_addr: new_fee_token
        });
    }

    inline fun verify_admin(admin: &signer, owner_conf: &OwnerConf) {
        assert!(
            owner_conf.admin == signer::address_of(admin)
                || signer::address_of(admin) == @bridge_token,
            0
        );
    }

    #[view]
    public fun role_check(admin: &signer): bool acquires OwnerConf {
        let owner_conf = borrow_global<OwnerConf>(@bridge_token);
        verify_admin(admin, owner_conf);
        true
    }

    #[view]
    public fun get_admin(): address acquires OwnerConf {
        let admin = borrow_global<OwnerConf>(@bridge_token).admin;
        admin
    }

    #[view]
    public fun islp(mint_type: u8): bool {
        mint_type == MINT_TYPE_LP
    }

    #[view]
    public fun ismint(mint_type: u8): bool {
        mint_type == MINT_TYPE_MINT
    }

    #[view]
    /// Get the token mapping and decimals
    public fun get_to_token(
        from_token: vector<u8>, from_chain: vector<u8>
    ): (vector<u8>, u8, u8) acquires Config {
        assert!(
            exists<Config>(@bridge_token),
            error::not_found(EHAS_NO_TOKENS)
        );

        let from_chain = chain_from_bytes(from_chain);
        let from_source = FromSource { from_chain, from_token };
        let token_mapping = &borrow_global<Config>(@bridge_token).token_mapping;
        assert!(
            simple_map::contains_key(token_mapping, &from_source),
            error::not_found(ETOKEN_NOT_FOUND)
        );

        let token_accuracy = simple_map::borrow(token_mapping, &from_source);
        (token_accuracy.to_token,
        token_accuracy.from_decimals,
        token_accuracy.to_decimals)
    }

    #[view]
    /// Set the token mint type
    /// @return mint type (1 mint | 2 lp)
    public fun get_token_mint_type(token: vector<u8>): u8 acquires Config {
        let mint_type_mapping = &borrow_global<Config>(@bridge_token).mint_type_mapping;
        assert!(
            simple_map::contains_key(mint_type_mapping, &token),
            error::not_found(ETOKEN_NOT_FOUND)
        );
        let mint_type = simple_map::borrow(mint_type_mapping, &token);
        *mint_type
    }

    #[view]
    /// All bridge token
    public fun get_tokens(): vector<vector<u8>> acquires Config {
        let mint_type_mapping = &borrow_global<Config>(@bridge_token).mint_type_mapping;
        let keys = simple_map::keys(mint_type_mapping);
        keys
    }

    #[view]
    /// All bridge token mapping
    public fun get_all_cross_relation(): SimpleMap<FromSource, TokenAccuracy> acquires Config {
        let token_mapping = &borrow_global<Config>(@bridge_token).token_mapping;
        *token_mapping
    }

    #[view]
    /// Get the chain contract
    public fun get_chain_contract(from_chain: vector<u8>): vector<u8> acquires Config {
        let from_chain_contract =
            borrow_global<Config>(@bridge_token).from_chain_contract;
        let from_chain = chain_from_bytes(from_chain);
        if (simple_map::contains_key(&from_chain_contract, &from_chain)) {
            let contract = simple_map::borrow(&from_chain_contract, &from_chain);
            return *contract
        };
        vector::empty<u8>()
    }

    #[view]
    /// Get the chain contract
    public fun get_chain_fee_token(from_chain: vector<u8>): vector<u8> acquires Config {
        let from_chain_fee_token =
            borrow_global<Config>(@bridge_token).from_chain_fee_token;
        let from_chain = chain_from_bytes(from_chain);
        if (simple_map::contains_key(&from_chain_fee_token, &from_chain)) {
            let fee_token = simple_map::borrow(&from_chain_fee_token, &from_chain);
            return *fee_token
        };
        vector::empty<u8>()
    }

    #[test_only]
    public fun test_set_mint_type(token: vector<u8>, mint_type: u8) acquires Config {
        set_token_mint_type(token, 2);
    }

    #[test_only]
    use endless_std::debug::print;
    #[test_only]
    use bridge_core::message::{generate_chain, chain_to_bytes};

    #[test(account = @bridge_token)]
    public fun test_basic_flow(account: &signer) acquires OwnerConf, Config {
        init_module(account);

        let eds = @0xc69712057e634bebc9ab02745d2d69ee738e3eb4f5d30189a9acbf8e08fb823e;
        set_token_mint_type(std::bcs::to_bytes(&eds), 2);

        let from_token = vector[1, 2, 3];
        let from_chain = generate_chain(1, 10);
        let to_token = vector[4, 5, 6];
        let to_chain = generate_chain(1, 2);
        let from_chain = chain_to_bytes(from_chain);
        // let i = 0;
        // while (i < vector::length(&from_chain)) {
        //     print(vector::borrow(&from_chain, i));
        //     i = i + 1;
        // };
        set_to_token(account, from_chain, from_token, 18, to_token, 6);

        let (to_token, from_decimals, to_decimals) = get_to_token(
            from_token, from_chain
        );
        print(&to_token);
        print(&from_decimals);
        print(&to_decimals);

        let relation = get_all_cross_relation();
        print(&relation);
    }

    #[test(account = @bridge_token)]
    public fun test_init_module(account: &signer) {
        init_module(account);
    }
}
