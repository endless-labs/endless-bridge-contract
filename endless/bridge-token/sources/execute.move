module bridge_token::execute {
    use endless_framework::account::{Self};
    use endless_framework::endless_coin::{get_eds_token_address};
    use endless_framework::event;
    use endless_std::math128;
    use endless_std::simple_map::{Self, SimpleMap};
    use std::error;
    use std::signer;
    use std::vector;
    use std::bcs::to_bytes;
    use endless_std::from_bcs;
    use std::option::{Self};

    use bridge_token::config::{
        role_check,
        get_chain_contract,
        get_chain_fee_token,
        get_to_token,
        get_token_mint_type,
        islp,
        ismint
    };
    use bridge_token::token::{mint, burn, transfer};
    use bridge_token::pool_v2::{
        transfer_to_pool,
        transfer_from_pool,
        get_lp_fee,
        refresh_rewards
    };
    use bridge_token::fund_manage::{get_collect_fee};
    use bridge_core::validator::get_pubkeys;
    use bridge_core::message::{
        send_message_v2,
        confirm_message,
        chain_from_bytes,
        get_platform_fee,
        get_execute_info_of_message,
        vec_reverse,
        Chain as ChainVM
    };

    /// Token pool already exists
    const EALLAMOUNT_MUST_GREATER_THAN_ALL_FEE: u64 = 1;
    /// `mint_type` does not exist.
    const ECODE_MINT_TYPE_DOES_NOT_EXIST: u64 = 2;
    const ESENDER_ADDR_NOT_MATCH: u64 = 3;
    const EEXECUTE_ADDR_NOT_MATCH: u64 = 4;
    const EREVERT_FOR_GAS_ESTIMATION: u64 = 5;
    const EAMOUNT_ZERO: u64 = 6;
    const EHAS_NO_BRIDGE_CONFIG: u64 = 7;
    /// The amount exceeds the limit
    const EAMOUNT_EXCEEDS_LIMIT: u64 = 8;
    const EMULTISIG_MUST_NOT_BE_EMPTY: u64 = 9;

    struct Chain has store, drop, copy {
        type: u8,
        id: u64
    }

    struct MsgBody has drop {
        source_token: address,
        all_amount: u128,
        from_who: address,
        to_who: address
    }

    struct MsgBodyV2 has drop {
        source_token: address,
        all_amount: u128,
        from_who: address,
        to_who: address,
        extra_data: vector<u8>
    }

    struct BridgeConfig has key, store {
        min_bridge_amount: u128,
        max_bridge_amount: u128
    }

    struct TokenBridges has key {
        // address of token => StakingConfig
        bridge_mapping: SimpleMap<address, BridgeConfig>
    }

    struct ExecuteResource has key {
        signer_cap: account::SignerCapability
    }

    #[event]
    /// Event emitted when bridge finished successfully
    struct PaymentInfo has drop, store {
        lp_fee: u128,
        final_amount: u128
    }

    #[event]
    /// Event emitted when a bridge finished
    struct BridgeFinish has drop, store {
        from_chain: ChainVM,
        from_who: address,
        from_token: address,
        from_amount: u128,
        to_who: address,
        to_token: address,
        to_amount: u128,
        extra_data: vector<u8>
    }

    fun init_module(account: &signer) {
        let (_resource_signer, signer_cap) =
            account::create_resource_account(account, b"execute");
        move_to(account, ExecuteResource { signer_cap });
    }

    public entry fun set_bridge_amount(
        admin: &signer,
        token: address,
        new_min: u128,
        new_max: u128
    ) acquires TokenBridges, ExecuteResource {
        role_check(admin);

        let execute_resource = borrow_global<ExecuteResource>(@bridge_token);
        let execute_signer =
            account::create_signer_with_capability(&execute_resource.signer_cap);
        let execute_signer_address = signer::address_of(&execute_signer);
        if (exists<TokenBridges>(execute_signer_address)) {
            let bridge_mapping =
                &mut borrow_global_mut<TokenBridges>(execute_signer_address).bridge_mapping;

            if (simple_map::contains_key(bridge_mapping, &token)) {
                let bridge_config = simple_map::borrow_mut(bridge_mapping, &token);
                bridge_config.min_bridge_amount = new_min;
                bridge_config.max_bridge_amount = new_max;
            } else {
                let bridge_config = BridgeConfig {
                    min_bridge_amount: new_min,
                    max_bridge_amount: new_max
                };
                simple_map::add(bridge_mapping, token, bridge_config);
            }
        } else {
            move_to(
                &execute_signer,
                TokenBridges {
                    bridge_mapping: simple_map::create<address, BridgeConfig>()
                }
            );
            let bridge_mapping =
                &mut borrow_global_mut<TokenBridges>(execute_signer_address).bridge_mapping;
            let bridge_config = BridgeConfig {
                min_bridge_amount: new_min,
                max_bridge_amount: new_max
            };
            simple_map::add(bridge_mapping, token, bridge_config);
        }
    }

    /// Send a message to another chain
    public entry fun bridge_proposal(
        sender: &signer,
        source_token: address,
        to_chain: vector<u8>,
        to_contract: vector<u8>,
        to_who: vector<u8>,
        all_amount: u128,
        upload_gas_fee: u128
    ) acquires ExecuteResource, TokenBridges {
        internal_bridge_proposal(
            sender,
            source_token,
            to_chain,
            to_contract,
            to_who,
            all_amount,
            upload_gas_fee,
            option::none()
        );
    }

    /// Send a message to another chain
    public entry fun bridge_proposal_with_extra_data(
        sender: &signer,
        source_token: address,
        to_chain: vector<u8>,
        to_contract: vector<u8>,
        to_who: vector<u8>,
        all_amount: u128,
        upload_gas_fee: u128,
        extra_data: vector<u8>
    ) acquires ExecuteResource, TokenBridges {
        internal_bridge_proposal(
            sender,
            source_token,
            to_chain,
            to_contract,
            to_who,
            all_amount,
            upload_gas_fee,
            option::some(extra_data)
        );
    }

    fun internal_bridge_proposal(
        sender: &signer,
        source_token: address,
        to_chain: vector<u8>,
        to_contract: vector<u8>,
        to_who: vector<u8>,
        all_amount: u128,
        upload_gas_fee: u128,
        extra_data_opt: option::Option<vector<u8>>
    ) acquires ExecuteResource, TokenBridges {
        let execute_resource = borrow_global<ExecuteResource>(@bridge_token);
        let execute_signer =
            account::create_signer_with_capability(&execute_resource.signer_cap);
        let execute_signer_address = signer::address_of(&execute_signer);
        assert!(
            exists<TokenBridges>(execute_signer_address),
            error::not_found(EHAS_NO_BRIDGE_CONFIG)
        );

        let token_bridges = borrow_global_mut<TokenBridges>(execute_signer_address);
        let bridge_mapping = &mut token_bridges.bridge_mapping;

        assert!(
            simple_map::contains_key(bridge_mapping, &source_token),
            EHAS_NO_BRIDGE_CONFIG
        );
        let bridge_config = simple_map::borrow(bridge_mapping, &source_token);
        assert!(
            all_amount >= bridge_config.min_bridge_amount
                && all_amount <= bridge_config.max_bridge_amount,
            error::invalid_argument(EAMOUNT_EXCEEDS_LIMIT)
        );

        let msg_body = MsgBody {
            source_token: source_token,
            all_amount: all_amount,
            from_who: signer::address_of(sender),
            to_who: from_bcs::to_address(to_who)
        };

        let payload =
            if (option::is_some(&extra_data_opt)) {
                let extra_data = option::borrow(&extra_data_opt);
                let body_v1 = decode_body(to_bytes(&msg_body));
                let body_v2 = MsgBodyV2 {
                    source_token: body_v1.source_token,
                    all_amount: body_v1.all_amount,
                    from_who: body_v1.from_who,
                    to_who: body_v1.to_who,
                    extra_data: *extra_data
                };
                to_bytes(&body_v2)
            } else {
                let body_v1 = decode_body(to_bytes(&msg_body));
                to_bytes(&body_v1)
            };

        // transfer the fee token to the pool
        let eds_token_address = get_eds_token_address();
        let tokens: vector<address> = vector::empty();
        let amounts: vector<u128> = vector::empty();
        let fee_types: vector<u8> = vector::empty();

        let platform_fee = get_platform_fee();
        transfer(
            sender,
            eds_token_address,
            execute_signer_address,
            platform_fee
        );

        let collect_fee = get_collect_fee();
        vector::push_back(&mut tokens, eds_token_address);
        vector::push_back(&mut amounts, collect_fee);
        vector::push_back(&mut fee_types, 2);

        vector::push_back(&mut tokens, eds_token_address);
        vector::push_back(&mut amounts, upload_gas_fee);
        vector::push_back(&mut fee_types, 3);

        let mint_type = get_token_mint_type(to_bytes(&msg_body.source_token));
        if (ismint(mint_type)) {
            transfer(
                sender,
                source_token,
                @bridge_token,
                all_amount
            );
            burn(source_token, all_amount);
            transfer_to_pool(
                sender,
                eds_token_address,
                tokens,
                amounts,
                fee_types
            );
        } else if (islp(mint_type)) {
            vector::push_back(&mut tokens, source_token);
            vector::push_back(&mut amounts, all_amount);
            vector::push_back(&mut fee_types, 0);
            transfer_to_pool(
                sender,
                source_token,
                tokens,
                amounts,
                fee_types
            );
        } else {
            assert!(false, error::not_found(ECODE_MINT_TYPE_DOES_NOT_EXIST));
        };

        send_message_v2(
            sender,
            &execute_signer,
            &@bridge_token,
            0,
            to_chain,
            to_contract,
            payload,
            upload_gas_fee
        );

    }

    /// Finish the bridge
    public entry fun bridge_finish(
        sender: &signer,
        msg_header: vector<u8>,
        msg_body: vector<u8>,
        multisig: vector<u8>,
        pks: vector<u64>
    ) acquires ExecuteResource {
        internal_bridge_finish(
            sender,
            msg_header,
            msg_body,
            multisig,
            pks,
            false
        );
    }

    /// Finish the bridge
    public entry fun bridge_finish_estimate_gas(
        sender: &signer,
        msg_header: vector<u8>,
        msg_body: vector<u8>,
        multisig: vector<u8>,
        pks: vector<u64>
    ) acquires ExecuteResource {
        internal_bridge_finish(
            sender,
            msg_header,
            msg_body,
            multisig,
            pks,
            true
        );
    }

    fun internal_bridge_finish(
        sender: &signer,
        msg_header: vector<u8>,
        msg_body: vector<u8>,
        multisig: vector<u8>,
        pks: vector<u64>,
        is_estimate: bool
    ) acquires ExecuteResource {
        if (is_estimate) {
            assert!(
                signer::address_of(sender) == @bridge_token, EREVERT_FOR_GAS_ESTIMATION
            );
        } else {
            assert!(!vector::is_empty(&multisig), EMULTISIG_MUST_NOT_BE_EMPTY);
        };

        let accum_pk = get_pubkeys(pks);
        let execute_resource = borrow_global<ExecuteResource>(@bridge_token);
        let execute_signer =
            account::create_signer_with_capability(&execute_resource.signer_cap);
        confirm_message(
            &execute_signer,
            multisig,
            accum_pk,
            msg_header,
            msg_body
        );

        let (_mtype, from_chain, from_addr, to_addr, upload_gas_fee) =
            get_execute_info_of_message(msg_header);
        assert!(from_bcs::to_address(to_addr) == @bridge_token, EEXECUTE_ADDR_NOT_MATCH);
        let from_sender = get_chain_contract(from_chain);
        assert!(from_addr == from_sender, ESENDER_ADDR_NOT_MATCH);

        let body = decode_body(msg_body);
        let (to_token, from_decimals, to_decimals) =
            get_to_token(to_bytes(&body.source_token), from_chain);
        let all_amount = body.all_amount;
        all_amount =
            all_amount * math128::pow(10, (to_decimals as u128))
                / math128::pow(10, (from_decimals as u128));
        assert!(all_amount > 0, EAMOUNT_ZERO);

        let mint_type = get_token_mint_type(to_token);
        if (ismint(mint_type)) {
            mint(from_bcs::to_address(to_token), body.to_who, all_amount);
            event::emit(PaymentInfo { lp_fee: 0, final_amount: all_amount });
        } else if (islp(mint_type)) {
            let lp_fee = get_lp_fee(from_bcs::to_address(to_token), all_amount);
            let (transfer_amount, refund_amount) =
                if (lp_fee > 0) {
                    let pool_fee = refresh_rewards(
                        from_bcs::to_address(to_token), lp_fee
                    );
                    (all_amount - lp_fee, lp_fee - pool_fee)
                } else {
                    (all_amount, 0)
                };
            transfer_from_pool(
                body.to_who,
                from_bcs::to_address(to_token),
                transfer_amount,
                refund_amount,
                false
            );
            event::emit(PaymentInfo { lp_fee, final_amount: transfer_amount });
        } else {
            assert!(false, error::not_found(ECODE_MINT_TYPE_DOES_NOT_EXIST));
        };

        {
            let gas_fee_token = get_chain_fee_token(from_chain);
            let (to_token, from_decimals, to_decimals) =
                get_to_token(gas_fee_token, from_chain);
            let gas_fee =
                upload_gas_fee * math128::pow(10, (to_decimals as u128))
                    / math128::pow(10, (from_decimals as u128));

            let mint_type = get_token_mint_type(to_token);
            if (ismint(mint_type)) {
                mint(
                    from_bcs::to_address(to_token),
                    signer::address_of(sender),
                    gas_fee
                );
            } else {
                transfer_from_pool(
                    signer::address_of(sender),
                    from_bcs::to_address(to_token),
                    gas_fee,
                    0,
                    true
                );
            }
        };

        event::emit(
            BridgeFinish {
                from_chain: chain_from_bytes(from_chain),
                from_who: body.from_who,
                from_token: body.source_token,
                from_amount: body.all_amount,
                to_who: body.to_who,
                to_token: from_bcs::to_address(to_token),
                to_amount: all_amount,
                extra_data: vector::slice(&msg_body, 112, vector::length(&msg_body))
            }
        );
    }

    /// Decode the body
    inline fun decode_body(body: vector<u8>): MsgBody {
        let source_token = from_bcs::to_address(vector::slice(&body, 0, 32));
        let all_amount = from_bcs::to_u128(vec_reverse(vector::slice(&body, 32, 48)));
        let from_who = from_bcs::to_address(vector::slice(&body, 48, 80));
        let to_who = from_bcs::to_address(vector::slice(&body, 80, 112));

        MsgBody {
            source_token: source_token,
            all_amount: all_amount,
            from_who: from_who,
            to_who: to_who
        }
    }

    #[view]
    public fun get_bridge_amount(token: address): (u128, u128) acquires TokenBridges, ExecuteResource {
        let execute_resource = borrow_global<ExecuteResource>(@bridge_token);
        let execute_signer =
            account::create_signer_with_capability(&execute_resource.signer_cap);
        let execute_signer_address = signer::address_of(&execute_signer);
        if (exists<TokenBridges>(execute_signer_address)) {
            let bridge_mapping =
                &borrow_global<TokenBridges>(execute_signer_address).bridge_mapping;

            if (simple_map::contains_key(bridge_mapping, &token)) {
                let bridge_config = simple_map::borrow(bridge_mapping, &token);
                let min_amount = bridge_config.min_bridge_amount;
                let max_amount = bridge_config.max_bridge_amount;
                return (min_amount, max_amount)
            }
        };

        return (0, 0)
    }

    #[test_only]
    use endless_std::debug::print;
    #[test_only]
    use endless_framework::endless_coin::{mint as edsmint};
    #[test_only]
    use bridge_token::pool_v2::{test_basic_pool_flow};

    #[
        test(
            account = @bridge_token,
            alice = @0x123,
            box = @0x234,
            carl = @0x567,
            msg_account = @bridge_core,
            endless_framework = @0x1,
            eth_executor = @0x11155111
        )
    ]
    public fun test_brige2tron_flow(
        account: &signer,
        msg_account: &signer,
        alice: &signer,
        box: &signer,
        carl: &signer,
        endless_framework: &signer,
        eth_executor: &signer
    ) {
        return;
        test_basic_pool_flow(account, alice, box, endless_framework);

        // initialize_for_test(endless_framework);
        edsmint(endless_framework, signer::address_of(carl), 100_000_000_000);

        let to_chain = to_bytes(&Chain { type: 2, id: 2494104990 });
        let to_contract = to_bytes(&@0x6143C0b81F69646064bbA7B4b5c9A856056de20b);
        print(&to_contract);
        let to_who = @0x6aCFFa96c7a090a28A08546a6364523aFd730e9d;
        let all_amount = 1_000_000_000;
        let upload_gas_fee = 5000000;
        let token = @0xc69712057e634bebc9ab02745d2d69ee738e3eb4f5d30189a9acbf8e08fb823e;

        let msg_body = MsgBody {
            source_token: token,
            all_amount: all_amount,
            from_who: signer::address_of(carl),
            to_who: to_who
        };
        let msg_bodybyte = to_bytes(&decode_body(to_bytes(&msg_body)));
        print(&msg_bodybyte);

        // bridge_proposal(carl, token, to_chain, to_contract, to_who, all_amount, upload_gas_fee);

        let msg: vector<u8> = vector[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 167, 54, 170, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 51, 152, 54, 78, 166, 184, 69, 163, 226, 18, 183, 40, 75, 143,
            112, 178, 15, 73, 246, 126, 0, 221, 0, 0, 0, 0, 0, 0, 0, 116, 209, 121, 188,
            63, 228, 11, 4, 185, 246, 33, 83, 129, 129, 40, 126, 59, 137, 176, 87, 248,
            105, 86, 172, 165, 107, 159, 139, 143, 185, 228, 48, 32, 216, 12, 15, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0
        ];
        let msg_body: vector<u8> = vector[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 249, 151, 103, 130, 212, 108, 192, 86,
            48, 209, 246, 235, 171, 24, 178, 50, 77, 107, 20, 0, 0, 0, 0, 0, 0, 0, 0, 152,
            167, 217, 184, 49, 76, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 79, 16, 157,
            56, 38, 189, 115, 4, 141, 85, 48, 125, 97, 57, 28, 239, 110, 113, 14, 133, 121,
            169, 92, 178, 102, 103, 240, 224, 255, 74, 127, 133, 76, 104, 96, 185, 230, 23,
            218, 247, 184, 197, 58, 138, 129, 51, 80, 210, 241, 154, 178, 156
        ];
        let multisig: vector<u8> = vector[];
        let pks: vector<u64> = vector[0];
        let (mtype, from_chain, from_addr, to_addr, upload_gas_fee) =
            get_execute_info_of_message(msg);
        print(&std::string::utf8(b"=================toaddr=================="));
        print(&from_bcs::to_address(to_addr));
        let body = decode_body(msg_body);
        print(&from_chain);
        let (to_token, from_decimals, to_decimals) =
            get_to_token(to_bytes(&body.source_token), from_chain);
        print(&std::string::utf8(b"=================totoken==================="));
        print(&from_bcs::to_address(to_token));
    }
}
