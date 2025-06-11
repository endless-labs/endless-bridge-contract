module bridge_core::message {
    use endless_framework::account::{Self};
    use endless_framework::chain_id;
    use std::error;
    use std::vector;
    use std::bcs::to_bytes;
    use endless_std::from_bcs;
    use endless_std::simple_map::{Self, SimpleMap};
    use endless_std::smart_table::{Self, SmartTable};
    use endless_std::bls12381::{PublicKeyWithPoP};
    use bridge_core::message_v2::{Self};

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
    const EINSUFFICIENT: u64 = 6;

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
    public entry fun set_platform_fee(_admin: &signer, _new_fee: u128) {
        abort error::not_implemented(ENO_LONGER_SUPPORTED)
    }

    /// withdraw the platform fee
    public entry fun witdraw_platform_fee(_admin: &signer, _amount: u128) {
        abort error::not_implemented(ENO_LONGER_SUPPORTED)
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
    ) {
        message_v2::send_message_v2(
            _sender,
            executor,
            excutor_account,
            mtype,
            to_chain,
            to_addr,
            mbody,
            fee
        );
    }

    /// Confirm the message
    public fun confirm_message(
        executor: &signer,
        multisig: vector<u8>,
        accum_pk: vector<PublicKeyWithPoP>,
        msg_header: vector<u8>,
        msg_body: vector<u8>
    ) {
        message_v2::confirm_message(
            executor,
            multisig,
            accum_pk,
            msg_header,
            msg_body
        )
    }

    /// Confirm the message
    public fun confirm_message_v2(
        _executor: &signer,
        _relay_sender: address,
        _fee_token: address,
        _multisig: vector<u8>,
        _accum_pk: vector<PublicKeyWithPoP>,
        _msg_header: vector<u8>,
        _msg_body: vector<u8>
    ) {
        abort error::not_implemented(ENO_LONGER_SUPPORTED)
    }

    /// Verify the multi-signature
    public fun verify_message(
        multisig: vector<u8>,
        accum_pk: vector<PublicKeyWithPoP>,
        msg_header: vector<u8>,
        msg_body: vector<u8>
    ): bool {
        message_v2::verify_message(multisig, accum_pk, msg_header, msg_body)
    }

    /// Get the execute info of the message
    public fun get_execute_info_of_message(
        msg_header: vector<u8>
    ): (u8, vector<u8>, vector<u8>, vector<u8>, u128) {
        message_v2::get_execute_info_of_message(msg_header)
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
    public fun get_platform_fee(): u128 {
        message_v2::get_platform_fee()
    }

    #[view]
    /// withdraw the platform fee
    public fun get_platform_fee_balance(): u128 {
        message_v2::get_platform_fee_balance()
    }

    #[view]
    public fun get_tochain_nonce(to_chain: vector<u8>): u64 {
        message_v2::get_tochain_nonce(to_chain)
    }

    public fun vec_reverse(be_bytes: vector<u8>): vector<u8> {
        message_v2::vec_reverse(be_bytes)
    }
}
