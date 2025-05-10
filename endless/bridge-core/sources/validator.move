module bridge_core::validator {
    use std::signer;
    use std::vector;
    use endless_std::math64::min;
    use endless_std::bls12381::{public_key_with_pop_from_bytes, PublicKeyWithPoP};

    /// The config account has no other management tokens beside admin.
    const HAS_NO_TOKENS: u64 = 1;
    /// The config account has no such management tokens.
    const ETOKEN_NOT_FOUND: u64 = 2;
    /// The config account has no such management chain.
    const ECHAIN_NOT_FOUND: u64 = 3;
    /// The caller was supposed to input one or more public keys.
    const EZERO_PUBKEYS: u64 = 4;
    const ETHRESHOLD: u64 = 5;
    const EMAX_NODES: u64 = 6;

    struct Validator has key, drop {
        validators: vector<PublicKeyWithPoP>,
        threshold: u8
    }

    struct OwnerConf has key {
        admin: address
    }

    fun init_module(account: &signer) {
        move_to(
            account,
            Validator {
                validators: vector::empty<PublicKeyWithPoP>(),
                threshold: 1
            }
        );

        move_to(account, OwnerConf { admin: @bridge_core });
    }

    public entry fun transfer_ownership(admin: &signer, new_admin: address) acquires OwnerConf {
        let owner_conf = borrow_global_mut<OwnerConf>(@bridge_core);
        verify_admin(admin, owner_conf);

        owner_conf.admin = new_admin;
    }

    /// add a validator to the validator list.
    public entry fun add_validator(
        admin: &signer, pk_with_pop: vector<u8>
    ) acquires OwnerConf, Validator {
        // check admin permission
        let owner_conf = borrow_global<OwnerConf>(@bridge_core);
        verify_admin(admin, owner_conf);

        let validators = &mut borrow_global_mut<Validator>(@bridge_core).validators;
        let pk_pop = public_key_with_pop_from_bytes(pk_with_pop);

        if (!vector::contains(validators, &pk_pop)) {
            vector::push_back(validators, pk_pop);
        };

        // u8::MAX is 255, so we can't have more than 255 validators.
        assert!(vector::length(validators) <= 255, EMAX_NODES);
    }

    /// batch add validators and set threshold.
    public entry fun add_validators(
        admin: &signer, pk_with_pops: vector<vector<u8>>, new_threshold: u8
    ) acquires OwnerConf, Validator {
        let owner_conf = borrow_global<OwnerConf>(@bridge_core);
        verify_admin(admin, owner_conf);

        let node = borrow_global_mut<Validator>(@bridge_core);
        let validators = &mut node.validators;
        for (i in 0..vector::length(&pk_with_pops)) {
            let pk_with_pop = vector::borrow(&pk_with_pops, i);
            let pk_pop = public_key_with_pop_from_bytes(*pk_with_pop);

            if (!vector::contains(validators, &pk_pop)) {
                vector::push_back(validators, pk_pop);
            }
        };
        // u8::MAX is 255, so we can't have more than 255 validators.
        assert!(vector::length(validators) <= 255, EMAX_NODES);

        assert!(
            new_threshold > 0 && (new_threshold as u64) <= vector::length(validators),
            ETHRESHOLD
        );
        node.threshold = new_threshold;
    }

    /// remove a validator from the validator list.
    public entry fun remove_validator(
        admin: &signer, pk_with_pop: vector<u8>
    ) acquires OwnerConf, Validator {
        // check admin permission
        let owner_conf = borrow_global<OwnerConf>(@bridge_core);
        verify_admin(admin, owner_conf);

        let node = borrow_global_mut<Validator>(@bridge_core);
        let validators = &mut node.validators;
        let pk_pop = public_key_with_pop_from_bytes(pk_with_pop);

        if (vector::contains(validators, &pk_pop)) {
            vector::remove_value(validators, &pk_pop);
        };
        node.threshold = (min((node.threshold as u64), vector::length(validators)) as u8);
    }

    /// change the threshold of the validator list.
    public entry fun threshold_change(admin: &signer, threshold: u8) acquires OwnerConf, Validator {
        let owner_conf = borrow_global<OwnerConf>(@bridge_core);
        verify_admin(admin, owner_conf);

        let node = borrow_global_mut<Validator>(@bridge_core);
        assert!(
            node.threshold > 0
                && (node.threshold as u64) <= vector::length(&node.validators),
            ETHRESHOLD
        );
        node.threshold = threshold;
    }

    inline fun verify_admin(admin: &signer, owner_conf: &OwnerConf) {
        assert!(
            owner_conf.admin == @bridge_core
                || owner_conf.admin == signer::address_of(admin)
                || signer::address_of(admin) == @bridge_core,
            0
        );
    }

    #[view]
    public fun role_check(admin: &signer): bool acquires OwnerConf {
        let owner_conf = borrow_global<OwnerConf>(@bridge_core);
        verify_admin(admin, owner_conf);
        true
    }

    #[view]
    /// Get the node status.
    public fun validators(): Validator acquires Validator {
        let node = borrow_global<Validator>(@bridge_core);
        Validator { validators: node.validators, threshold: node.threshold }
    }

    #[view]
    /// Get the node status.
    public fun threshold(): u8 acquires Validator {
        let node = borrow_global<Validator>(@bridge_core);
        node.threshold
    }

    #[view]
    /// get node pubkey by index
    public fun get_pubkeys(node_index: vector<u64>): vector<PublicKeyWithPoP> acquires Validator {
        let validators = borrow_global<Validator>(@bridge_core).validators;
        let pk_pops = vector::empty<PublicKeyWithPoP>();
        for (i in 0..vector::length(&node_index)) {
            let index = vector::borrow(&node_index, i);
            let pk_pop = vector::borrow(&validators, *index);
            vector::push_back(&mut pk_pops, *pk_pop);
        };

        pk_pops
    }

    #[view]
    public fun get_admin(): address acquires OwnerConf {
        let admin = borrow_global<OwnerConf>(@bridge_core).admin;
        admin
    }

    #[test_only]
    use endless_std::debug::print;
    #[test_only]
    use endless_std::bls12381::{public_key_to_bytes};
    #[test(account = @bridge_core, alice = @0x123)]
    public fun test_basic_relay_flow(account: &signer, alice: &signer) acquires OwnerConf, Validator {
        init_module(account);

        let pks = vector[
            x"b93d6aabb2b83e52f4b8bda43c24ea920bbced87a03ffc80f8f70c814a8b3f5d69fbb4e579ca76ee008d61365747dbc6",
            x"b45648ceae3a983bcb816a96db599b5aef3b688c5753fa20ce36ac7a4f2c9ed792ab20af6604e85e42dab746398bb82c",
            x"b3e4921277221e01ed71284be5e3045292b26c7f465a6fcdba53ee47edd39ec5160da3b229a73c75671024dcb36de091"
        ];

        let i = 0;
        while (i < std::vector::length(&pks)) {
            let pk = std::vector::borrow(&pks, i);
            add_validator(account, *pk);
            i = i + 1;
        };

        let pks = vector[
            x"8463b8671c9775a7dbd98bf76d3deba90b5a90535fc87dc8c13506bb5c7bbd99be4d257e60c548140e1e30b107ff5822",
            x"a79e3d0e9d04587a3b27d05efe5717da05fd93485dc47978c866dc70a01695c2efd247d1dd843a011a4b6b24079d7384"
        ];
        add_validators(account, pks, 4);

        let result = validators();
        print(&std::string::utf8(b"=================all validators================="));
        print(&result);

        let pks = vector[
            x"b93d6aabb2b83e52f4b8bda43c24ea920bbced87a03ffc80f8f70c814a8b3f5d69fbb4e579ca76ee008d61365747dbc6",
            x"b45648ceae3a983bcb816a96db599b5aef3b688c5753fa20ce36ac7a4f2c9ed792ab20af6604e85e42dab746398bb82c",
            x"a79e3d0e9d04587a3b27d05efe5717da05fd93485dc47978c866dc70a01695c2efd247d1dd843a011a4b6b24079d7384"
        ];
        let i = 0;
        while (i < std::vector::length(&pks)) {
            let pk = std::vector::borrow(&pks, i);
            remove_validator(account, *pk);
            i = i + 1;
        };

        let result = validators();
        print(
            &std::string::utf8(b"=================removed validators=================")
        );
        print(&result);

        // transfer ownership
        transfer_ownership(account, @0x123);
        let admin = get_admin();
        print(&std::string::utf8(b"=================admin changed================="));
        print(&admin);

        // threshold_change(account, 1); should fail
        threshold_change(alice, 1);
        let result = validators();
        print(
            &std::string::utf8(
                b"=================changed node threshold================="
            )
        );
        print(&result);
    }

    #[test(account = @bridge_core)]
    public fun test_init_module(account: &signer) {
        init_module(account);
    }
}
