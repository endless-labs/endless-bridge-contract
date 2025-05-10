module bridge_core::message {
    use endless_framework::account::{Self};
    use endless_framework::endless_coin::{Self};
    use endless_framework::event;
    use endless_framework::chain_id;
    use std::error;
    use std::signer;
    use std::vector;
    use std::bcs::to_bytes;
    use endless_std::from_bcs;
    use endless_std::simple_map::{Self, SimpleMap};
    use endless_std::smart_table::{Self, SmartTable};
    use endless_std::bls12381::{
        aggregate_pubkeys,
        aggr_or_multi_signature_from_bytes,
        verify_multisignature,
        PublicKeyWithPoP
    };
    use endless_std::endless_hash;
    use bridge_core::validator::role_check;

    /// The enonce has already been confirmed.
    const ENONCE_ALREADY_CONFIRM: u64 = 1;
    /// The number of signers does not match the number of messages to be signed.
    const E_NUM_SIGNERS_MUST_EQ_NUM_MESSAGES: u64 = 2;
    /// The execute address does not match the message address.
    const EEXECUTE_ADDR_NOT_MATCH: u64 = 3;
    /// The enonce gap is too large.
    const ENONCE_GAP_TOO_LARGE: u64 = 4;
    /// No longer supported.
    const ENO_LONGER_SUPPORTED: u64 = 5;

    /// Chain types
    const ENDLESS: u8 = 0;
    const ETHEREUM: u8 = 1;
    const TRON: u8 = 2;
    const SOLANA: u8 = 3;
    /// Set a reasonable maximum nonce interval
    const MAX_NONCE_GAP: u64 = 1000;

    struct Chain has key, store, drop, copy {
        type: u8,
        id: u64
    }

    struct MsgHeader has drop, store {
        mtype: u8,
        nonce: u64,
        from_chain: Chain,
        from_addr: vector<u8>,
        to_chain: Chain,
        to_addr: vector<u8>,
        upload_gas_fee: u128
    }

    struct MissingNonce has key, store, drop, copy {
        from_chain: Chain,
        nonce: u64
    }

    // Create a mapping to store the message
    struct MessageInfo has key {
        // <to_chain_id, nonce>
        to_chain_nonce: SimpleMap<Chain, u64>,
        // <from_chain_id, max_nonce>
        from_chain_nonce: SimpleMap<Chain, u64>,
        // <from_chain_id, nonce>
        missing_chain_nonce: SmartTable<MissingNonce, bool>,
        // fee
        bridge_fee: u128
    }

    struct MessageResource has key {
        signer_cap: account::SignerCapability
    }

    #[event]
    /// Event emitted when a message is sent
    struct SendMessage has drop, store {
        header: MsgHeader,
        body: vector<u8>,
        fee: u128
    }

    #[event]
    /// Event emitted when a message is sent
    struct ConfirmMessage has drop, store {
        executor: vector<u8>,
        from_chain: vector<u8>,
        nonce: u64
    }

    #[event]
    /// Event emitted when a message is sent
    struct ConfirmMessageV2 has drop, store {
        executor: vector<u8>,
        from_chain: vector<u8>,
        nonce: u64,
        mbody: vector<u8>
    }

    fun init_module(account: &signer) {
        move_to(
            account,
            MessageInfo {
                to_chain_nonce: simple_map::create<Chain, u64>(),
                from_chain_nonce: simple_map::create<Chain, u64>(),
                missing_chain_nonce: smart_table::new<MissingNonce, bool>(),
                bridge_fee: 500000 // 0.005 EDS
            }
        );

        let (_resource_signer, signer_cap) =
            account::create_resource_account(account, b"message");
        move_to(account, MessageResource { signer_cap });
    }

    /// set the platform fee
    public entry fun set_platform_fee(admin: &signer, new_fee: u128) acquires MessageInfo {
        // Only admin can set the platform fee
        role_check(admin);

        let bridge_fee = &mut borrow_global_mut<MessageInfo>(@bridge_core).bridge_fee;
        *bridge_fee = new_fee;
    }

    /// Send a message to another chain
    public fun send_message(
        _sender: &signer,
        _executor: &signer,
        _mtype: u8,
        _to_chain: vector<u8>,
        _to_addr: vector<u8>,
        _mbody: vector<u8>,
        _fee: u128
    ) {
        abort error::not_implemented(ENO_LONGER_SUPPORTED)
    }

    /// Send a message to another chain
    public fun send_message_v2(
        _sender: &signer,
        executor: &signer,
        excutor_account: &address,
        mtype: u8,
        to_chain: vector<u8>,
        to_addr: vector<u8>,
        mbody: vector<u8>,
        fee: u128
    ) acquires MessageInfo, MessageResource {
        // Transfer the fee from the owner
        let message_resource = borrow_global<MessageResource>(@bridge_core);
        let message_signer =
            account::create_signer_with_capability(&message_resource.signer_cap);
        let message_info = borrow_global_mut<MessageInfo>(@bridge_core);

        let bridge_fee = message_info.bridge_fee;
        endless_coin::transfer(
            executor, signer::address_of(&message_signer), bridge_fee
        );

        // Send message
        let to_chain_nonce = &mut message_info.to_chain_nonce;
        let to_chain = chain_from_bytes(copy to_chain);
        let nonce =
            if (simple_map::contains_key(to_chain_nonce, &to_chain)) {
                let nonce = simple_map::borrow_mut(to_chain_nonce, &to_chain);
                *nonce = *nonce + 1;
                *nonce
            } else {
                simple_map::add(to_chain_nonce, copy to_chain, 1);
                1
            };

        // check if the executor account is valid
        assert!(
            signer::address_of(executor)
                == account::create_resource_address(excutor_account, b"execute"),
            EEXECUTE_ADDR_NOT_MATCH
        );

        let mheader = MsgHeader {
            mtype: mtype,
            nonce: nonce,
            from_chain: get_current_chain(),
            from_addr: to_bytes(excutor_account),
            to_chain: to_chain,
            to_addr: to_addr,
            upload_gas_fee: fee
        };

        // Emit the message
        event::emit(SendMessage { header: mheader, body: mbody, fee: fee });
    }

    /// Confirm the message
    public fun confirm_message(
        executor: &signer,
        multisig: vector<u8>,
        accum_pk: vector<PublicKeyWithPoP>,
        msg_header: vector<u8>,
        msg_body: vector<u8>
    ) acquires MessageInfo {
        // verify the message
        verify_message(multisig, accum_pk, msg_header, msg_body);

        let header = decode_header(msg_header);
        let from_chain = header.from_chain;
        let nonce = header.nonce;
        // Update the message info
        let message_info = borrow_global_mut<MessageInfo>(@bridge_core);
        let from_chain_nonce = &mut message_info.from_chain_nonce;
        let missing_chain_nonce = &mut message_info.missing_chain_nonce;

        // Check nonce must be greater than the max nonce of the chain or the nonce in missing_chain_nonce table
        if (simple_map::contains_key(from_chain_nonce, &from_chain)) {
            let max_nonce = simple_map::borrow_mut(from_chain_nonce, &from_chain);

            if (nonce <= *max_nonce) {
                let miss_nonce_key = MissingNonce { from_chain: from_chain, nonce: nonce };
                if (smart_table::contains(missing_chain_nonce, miss_nonce_key)) {
                    smart_table::remove(missing_chain_nonce, miss_nonce_key);
                } else {
                    assert!(false, error::already_exists(ENONCE_ALREADY_CONFIRM));
                }
            } else {
                assert!(
                    nonce - *max_nonce <= MAX_NONCE_GAP,
                    error::invalid_argument(ENONCE_GAP_TOO_LARGE)
                );

                let missing_nonces = vector::empty<u64>();
                let miss_nonce = *max_nonce + 1;
                while (miss_nonce < nonce) {
                    vector::push_back(&mut missing_nonces, miss_nonce);
                    miss_nonce = miss_nonce + 1;
                };

                batch_add_missing_nonces(
                    missing_chain_nonce, from_chain, missing_nonces
                );
                *max_nonce = nonce;
            }
        } else {
            assert!(
                nonce <= MAX_NONCE_GAP, error::invalid_argument(ENONCE_GAP_TOO_LARGE)
            );

            simple_map::add(from_chain_nonce, from_chain, nonce);
            let missing_nonces = vector::empty<u64>();
            let miss_nonce = 1;
            while (miss_nonce < nonce) {
                vector::push_back(&mut missing_nonces, miss_nonce);
                miss_nonce = miss_nonce + 1;
            };

            batch_add_missing_nonces(missing_chain_nonce, from_chain, missing_nonces);
        };

        // Emit the message
        event::emit(
            ConfirmMessageV2 {
                executor: to_bytes(&signer::address_of(executor)),
                from_chain: chain_to_bytes(from_chain),
                nonce,
                mbody: msg_body
            }
        );
    }

    /// Confirm the message
    public fun confirm_message_v2(
        executor: &signer,
        relay_sender: address,
        fee_token: address,
        multisig: vector<u8>,
        accum_pk: vector<PublicKeyWithPoP>,
        msg_header: vector<u8>,
        msg_body: vector<u8>
    ) acquires MessageInfo, MessageResource {
        // verify the message
        verify_message(multisig, accum_pk, msg_header, msg_body);

        let header = decode_header(msg_header);
        let from_chain = header.from_chain;
        let nonce = header.nonce;
        // Update the message info
        let message_info = borrow_global_mut<MessageInfo>(@bridge_core);
        let from_chain_nonce = &mut message_info.from_chain_nonce;
        let missing_chain_nonce = &mut message_info.missing_chain_nonce;

        // Check nonce must be greater than the max nonce of the chain or the nonce in missing_chain_nonce table
        if (simple_map::contains_key(from_chain_nonce, &from_chain)) {
            let max_nonce = simple_map::borrow_mut(from_chain_nonce, &from_chain);
            if (nonce > *max_nonce) {
                let miss_nonce = *max_nonce + 1;
                while (miss_nonce < nonce) {
                    let miss_nonce_key = MissingNonce {
                        from_chain: from_chain,
                        nonce: miss_nonce
                    };
                    smart_table::add(missing_chain_nonce, miss_nonce_key, true);
                    miss_nonce = miss_nonce + 1;
                };
                *max_nonce = nonce;
            } else {
                let miss_nonce_key = MissingNonce { from_chain: from_chain, nonce: nonce };
                if (smart_table::contains(missing_chain_nonce, miss_nonce_key)) {
                    smart_table::remove(missing_chain_nonce, miss_nonce_key);
                } else {
                    assert!(false, error::already_exists(ENONCE_ALREADY_CONFIRM));
                }
            }
        } else {
            simple_map::add(from_chain_nonce, from_chain, nonce);
            let miss_nonce = 1; // the first nonce of the chain
            while (miss_nonce < nonce) {
                let miss_nonce_key = MissingNonce {
                    from_chain: from_chain,
                    nonce: miss_nonce
                };
                smart_table::add(missing_chain_nonce, miss_nonce_key, true);
                miss_nonce = miss_nonce + 1;
            };
        };

        // transfer the fee from the executor to the relay_sender
        {
            let message_resource = borrow_global<MessageResource>(@bridge_core);
            let message_signer =
                account::create_signer_with_capability(&message_resource.signer_cap);
            endless_token::coin::transfer(
                &message_signer,
                fee_token,
                relay_sender,
                header.upload_gas_fee
            );
        };

        // Emit the message
        event::emit(
            ConfirmMessageV2 {
                executor: to_bytes(&signer::address_of(executor)),
                from_chain: chain_to_bytes(from_chain),
                nonce,
                mbody: msg_body
            }
        );
    }

    /// Verify the multi-signature
    public fun verify_message(
        multisig: vector<u8>,
        accum_pk: vector<PublicKeyWithPoP>,
        msg_header: vector<u8>,
        msg_body: vector<u8>
    ): bool {
        // Verify the multi-signature
        let message = reverse_header(msg_header);
        vector::append(&mut message, msg_body);
        let message = endless_hash::keccak256(message);

        if (!vector::is_empty(&multisig)) { // estimate_gas
            // Generate multi-signature.
            let aggr_pk = aggregate_pubkeys(accum_pk);
            let aggsigs = aggr_or_multi_signature_from_bytes(multisig);
            // Test signature verification.
            assert!(
                verify_multisignature(&aggsigs, &aggr_pk, message),
                E_NUM_SIGNERS_MUST_EQ_NUM_MESSAGES
            );
        };
        true
    }

    /// Get the execute info of the message
    public fun get_execute_info_of_message(
        msg_header: vector<u8>
    ): (u8, vector<u8>, vector<u8>, vector<u8>, u128) {
        let mtype = from_bcs::to_u8(vector::slice(&msg_header, 0, 1));
        let from_chain = vector::slice(&msg_header, 9, 18);
        let from_addr = vector::slice(&msg_header, 18, 50);
        let to_addr = vector::slice(&msg_header, 59, 91);
        let upload_gas_fee = from_bcs::to_u128(vector::slice(&msg_header, 91, 107));
        (mtype, from_chain, from_addr, to_addr, upload_gas_fee)
    }

    #[view]
    /// Generate a chain
    public fun generate_chain(chain_type: u8, chain_id: u64): Chain {
        Chain { type: chain_type, id: chain_id }
    }

    #[view]
    /// Convert bytes to a chain
    public fun chain_from_bytes(bytes: vector<u8>): Chain {
        let chain_type = from_bcs::to_u8(vector::slice(&bytes, 0, 1));
        let chain_id = from_bcs::to_u64(vector::slice(&bytes, 1, 9));
        Chain { type: chain_type, id: chain_id }
    }

    /// Convert a chain to bytes
    public fun chain_to_bytes(chain: Chain): vector<u8> {
        let bytes = to_bytes(&chain);
        vector::reverse_slice(&mut bytes, 1, 9);
        bytes
    }

    #[view]
    /// Get the nonce of the chain
    public fun get_current_chain(): Chain {
        Chain { type: ENDLESS, id: get_chain_id() }
    }

    #[view]
    /// Get the nonce of the chain
    public fun get_chain_id(): u64 {
        (chain_id::get() as u64)
    }

    #[view]
    public fun get_platform_fee(): u128 acquires MessageInfo {
        let message_info = borrow_global<MessageInfo>(@bridge_core);
        let bridge_fee = message_info.bridge_fee;
        bridge_fee
    }

    #[view]
    public fun get_tochain_nonce(to_chain: vector<u8>): u64 acquires MessageInfo {
        let message_info = borrow_global<MessageInfo>(@bridge_core);
        let to_chain_nonce = message_info.to_chain_nonce;
        let to_chain = chain_from_bytes(copy to_chain);
        let nonce =
            if (simple_map::contains_key(&to_chain_nonce, &to_chain)) {
                let nonce = simple_map::borrow(&to_chain_nonce, &to_chain);
                *nonce
            } else { 0 };
        nonce
    }

    public fun vec_reverse(be_bytes: vector<u8>): vector<u8> {
        vector::reverse(&mut be_bytes);
        be_bytes
    }

    /// Decode the header
    inline fun decode_header(header: vector<u8>): MsgHeader {
        let mtype = from_bcs::to_u8(vector::slice(&header, 0, 1));
        let nonce = from_bcs::to_u64(vector::slice(&header, 1, 9));
        let from_chain = chain_from_bytes(vector::slice(&header, 9, 18));
        let from_addr = vector::slice(&header, 18, 50);
        let to_chain = chain_from_bytes(vector::slice(&header, 50, 59));
        let to_addr = vector::slice(&header, 59, 91);
        let upload_gas_fee = from_bcs::to_u128(vector::slice(&header, 91, 107));

        MsgHeader {
            mtype: mtype,
            nonce: nonce,
            from_chain: from_chain,
            from_addr: from_addr,
            to_chain: to_chain,
            to_addr: to_addr,
            upload_gas_fee: upload_gas_fee
        }
    }

    /// Endpoint reverse of the chain
    inline fun reverse_chain(chain: vector<u8>): vector<u8> {
        let bytes = chain;
        vector::reverse_slice(&mut bytes, 1, 9);
        bytes
    }

    /// Endpoint reverse of the header
    inline fun reverse_header(header: vector<u8>): vector<u8> {
        let mtype = vector::slice(&header, 0, 1);
        let nonce = vec_reverse(vector::slice(&header, 1, 9));
        let from_chain = reverse_chain(vector::slice(&header, 9, 18));
        let from_addr = vector::slice(&header, 18, 50);
        let to_chain = reverse_chain(vector::slice(&header, 50, 59));
        let to_addr = vector::slice(&header, 59, 91);
        let upload_gas_fee = vec_reverse(vector::slice(&header, 91, 107));

        let msg_header = mtype;
        vector::append(&mut msg_header, nonce);
        vector::append(&mut msg_header, from_chain);
        vector::append(&mut msg_header, from_addr);
        vector::append(&mut msg_header, to_chain);
        vector::append(&mut msg_header, to_addr);
        vector::append(&mut msg_header, upload_gas_fee);
        msg_header
    }

    /// batch add missing nonces to the missing_chain_nonce table
    fun batch_add_missing_nonces(
        missing_chain_nonce: &mut SmartTable<MissingNonce, bool>,
        from_chain: Chain,
        missing_nonces: vector<u64>
    ) {
        vector::for_each(
            missing_nonces,
            |nonce| {
                let miss_nonce_key = MissingNonce { from_chain: from_chain, nonce: nonce };
                smart_table::add(missing_chain_nonce, miss_nonce_key, true);
            }
        );
    }

    #[test_only]
    use endless_std::debug::print;
    #[test_only]
    use endless_framework::chain_id::initialize_for_test;
    #[test_only]
    use bridge_core::validator::test_init_module;

    #[test(account = @bridge_core, alice = @0x123, endless_framework = @0x1)]
    public fun test_basic_message_flow(
        account: &signer, alice: &signer, endless_framework: &signer
    ) acquires MessageInfo {
        test_init_module(account);

        init_module(account);
        initialize_for_test(endless_framework, 221u8);

        let chain_id = get_chain_id();
        print(&std::string::utf8(b"=================current chain================="));
        print(&chain_id);

        let platform_fee = get_platform_fee();
        print(&std::string::utf8(b"=================platform fee================="));
        print(&platform_fee);

        // set platform fee
        set_platform_fee(account, 1000000000000000000u128);
        platform_fee = get_platform_fee();
        print(
            &std::string::utf8(
                b"=================new platform fee changed================="
            )
        );
        print(&platform_fee);
    }

    #[
        test(
            account = @bridge_core,
            from_addr = @0x7362aA2208a722472a78baefc79C77bDB36B999A,
            to_addr = @0x748bc1369f54ed4e649716583c93e9e8cead5e22da2326668239bb803cdeb7ba
        )
    ]
    public fun test_verify_message(
        account: &signer, from_addr: &address, to_addr: &address
    ) {
        init_module(account);

        let header = MsgHeader {
            mtype: 0,
            nonce: 14,
            from_chain: Chain { type: 1, id: 11155111 },
            from_addr: to_bytes(from_addr),
            to_chain: Chain { type: 0, id: 11 },
            to_addr: to_bytes(to_addr),
            upload_gas_fee: 317726602
        };

        let _ = to_bytes(&header);
        let mtype = to_bytes(&0u8);
        print(&mtype);
        let nonce = vec_reverse(to_bytes(&14u64));
        print(&nonce);
        let from_chain = reverse_chain(to_bytes(&Chain { type: 1, id: 11155111 }));
        print(&from_chain);
        let from_addr = to_bytes(from_addr);
        print(&from_addr);
        let to_chain = reverse_chain(to_bytes(&Chain { type: 0, id: 11 }));
        print(&to_chain);
        let to_addr = to_bytes(to_addr);
        print(&to_addr);
        let upload_gas_fee = vec_reverse(to_bytes(&317726602u128));
        print(&upload_gas_fee);

        let message1 = mtype;
        vector::append(&mut message1, nonce);
        vector::append(&mut message1, from_chain);
        vector::append(&mut message1, from_addr);
        vector::append(&mut message1, to_chain);
        vector::append(&mut message1, to_addr);
        vector::append(&mut message1, upload_gas_fee);

        print(&message1);
        // 00000000000000000e010000000000aa36a70000000000000000000000007362aa2208a722472a78baefc79c77bdb36b999a00000000000000000b748bc1369f54ed4e649716583c93e9e8cead5e22da2326668239bb803cdeb7ba00000000000000000000000012f01f8a";
        // 00000000000000000e010000000000aa36a70000000000000000000000007362aa2208a722472a78baefc79c77bdb36b999a00000000000000000b748bc1369f54ed4e649716583c93e9e8cead5e22da2326668239bb803cdeb7ba00000000000000000000000012f01f8a
        let msg_body1 =
            x"00000000000000000000000064e3fca27825107cebb4c97cce22310b279dcb3c0000000000000000000009184e72a000000000000000000000000000a14de8cb5f25e622525ffec68e8d285a26ba317e50cec40078e77752c753190429d7cc618e174d6ed68060b2eab030b81482441b";
        // let message1 = msg_header1;
        // let message1 = reverse_header(msg_header1);
        // print(&message1);
        vector::append(&mut message1, msg_body1);
        let message = endless_hash::keccak256(message1);
        print(&message);
    }

    #[test(account = @bridge_core)]
    public fun skip_nonce_check(account: &signer) acquires MessageInfo {
        init_module(account);

        print(&std::string::utf8(b"=================skip_nonce_check================="));
        let message_info = borrow_global_mut<MessageInfo>(@bridge_core);
        let from_chain_nonce = &mut message_info.from_chain_nonce;
        let missing_chain_nonce = &mut message_info.missing_chain_nonce;
        // first check
        let nonce = 2;
        let from_chain = Chain { type: 1, id: 11155111 };
        if (simple_map::contains_key(from_chain_nonce, &from_chain)) {
            let max_nonce = simple_map::borrow_mut(from_chain_nonce, &from_chain);
            print(max_nonce);
            if (nonce > *max_nonce) {
                let miss_nonce = *max_nonce + 1;
                while (miss_nonce < nonce) {
                    let miss_nonce_key = MissingNonce {
                        from_chain: from_chain,
                        nonce: miss_nonce
                    };
                    smart_table::add(missing_chain_nonce, miss_nonce_key, true);
                    print(&std::string::utf8(b"=========middle miss_nonce=========="));
                    print(&miss_nonce);
                    miss_nonce = miss_nonce + 1;
                };
                *max_nonce = nonce;
            } else {
                let miss_nonce_key = MissingNonce { from_chain: from_chain, nonce: nonce };
                if (smart_table::contains(missing_chain_nonce, miss_nonce_key)) {
                    smart_table::remove(missing_chain_nonce, miss_nonce_key);
                } else {
                    assert!(false, error::already_exists(ENONCE_ALREADY_CONFIRM));
                }
            }
        } else {
            simple_map::add(from_chain_nonce, from_chain, nonce);
            let miss_nonce = 1;
            while (miss_nonce < nonce) {
                let miss_nonce_key = MissingNonce {
                    from_chain: from_chain,
                    nonce: miss_nonce
                };
                smart_table::add(missing_chain_nonce, miss_nonce_key, true);
                print(&std::string::utf8(b"=========first miss_nonce=========="));
                print(&miss_nonce);
                miss_nonce = miss_nonce + 1;
            };
        };

        // middle check
        let nonce = 1;
        let from_chain = Chain { type: 1, id: 11155111 };
        if (simple_map::contains_key(from_chain_nonce, &from_chain)) {
            let max_nonce = simple_map::borrow_mut(from_chain_nonce, &from_chain);
            if (nonce > *max_nonce) {
                let miss_nonce = *max_nonce + 1;
                while (miss_nonce < nonce) {
                    let miss_nonce_key = MissingNonce {
                        from_chain: from_chain,
                        nonce: miss_nonce
                    };
                    smart_table::add(missing_chain_nonce, miss_nonce_key, true);
                    print(&std::string::utf8(b"=========middle miss_nonce=========="));
                    print(&miss_nonce);
                    miss_nonce = miss_nonce + 1;
                };
                *max_nonce = nonce;
            } else {
                let miss_nonce_key = MissingNonce { from_chain: from_chain, nonce: nonce };
                if (smart_table::contains(missing_chain_nonce, miss_nonce_key)) {
                    smart_table::remove(missing_chain_nonce, miss_nonce_key);
                    print(&std::string::utf8(b"nonce can be removed"));
                    print(&nonce);
                } else {
                    assert!(false, error::already_exists(ENONCE_ALREADY_CONFIRM));
                }
            }
        } else {
            simple_map::add(from_chain_nonce, from_chain, nonce);
            let miss_nonce = 1;
            while (miss_nonce < nonce) {
                let miss_nonce_key = MissingNonce {
                    from_chain: from_chain,
                    nonce: miss_nonce
                };
                smart_table::add(missing_chain_nonce, miss_nonce_key, true);
                print(&std::string::utf8(b"=========first miss_nonce=========="));
                print(&miss_nonce);
                miss_nonce = miss_nonce + 1;
            };
        };

        // end check
        let nonce = 3;
        let from_chain = Chain { type: 1, id: 11155111 };
        if (simple_map::contains_key(from_chain_nonce, &from_chain)) {
            let max_nonce = simple_map::borrow_mut(from_chain_nonce, &from_chain);
            if (nonce > *max_nonce) {
                let miss_nonce = *max_nonce + 1;
                while (miss_nonce < nonce) {
                    let miss_nonce_key = MissingNonce {
                        from_chain: from_chain,
                        nonce: miss_nonce
                    };
                    smart_table::add(missing_chain_nonce, miss_nonce_key, true);
                    print(&std::string::utf8(b"=========middle miss_nonce=========="));
                    print(&miss_nonce);
                    miss_nonce = miss_nonce + 1;
                };
                *max_nonce = nonce;
            } else {
                let miss_nonce_key = MissingNonce { from_chain: from_chain, nonce: nonce };
                if (smart_table::contains(missing_chain_nonce, miss_nonce_key)) {
                    smart_table::remove(missing_chain_nonce, miss_nonce_key);
                    print(&std::string::utf8(b"nonce can be removed"));
                    print(&nonce);
                } else {
                    assert!(false, error::already_exists(ENONCE_ALREADY_CONFIRM));
                }
            }
        } else {
            simple_map::add(from_chain_nonce, from_chain, nonce);
            let miss_nonce = 1;
            while (miss_nonce < nonce) {
                let miss_nonce_key = MissingNonce {
                    from_chain: from_chain,
                    nonce: miss_nonce
                };
                smart_table::add(missing_chain_nonce, miss_nonce_key, true);
                print(&std::string::utf8(b"=========first miss_nonce=========="));
                print(&miss_nonce);
                miss_nonce = miss_nonce + 1;
            };
        };
    }
}
