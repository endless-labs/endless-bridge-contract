/// This module provides a managed fungible asset that allows the owner of the metadata object to
/// mint and burn fungible assets.
///
/// The functionalities offered by this module are:
/// 1. Mint fungible assets to fungible stores as the owner of metadata object.
/// 2. Burn fungible assets from fungible stores as the owner of metadata object.
module bridge_token::token {
    use endless_framework::fungible_asset::{Self, MintRef, BurnRef, Metadata};
    use endless_framework::object::{Self, Object};
    use endless_framework::primary_fungible_store;
    use endless_framework::event;
    use std::signer;
    use std::string::String;
    use std::option::{Self};
    use bridge_token::config::{role_check};

    friend bridge_token::execute;
    friend bridge_token::fund_manage;

    /// Only fungible asset metadata owner can make changes.
    const ERR_NOT_OWNER: u64 = 1;

    #[resource_group_member(group = endless_framework::object::ObjectGroup)]
    /// Hold refs to control the minting, transfer and burning of fungible assets.
    struct ManagingRefs has key {
        mint_ref: MintRef,
        burn_ref: BurnRef
    }
    
    #[event]
    /// Event emitted when create new token
    struct CreatToken has drop, store {
        token: address
    }

    #[event]
    /// Event emitted when token minted
    struct TokenMinted has drop, store {
        account: address,
        amount: u128
    }

    #[event]
    /// Event emitted when token burned
    struct TokenBurned has drop, store {
        account: address,
        amount: u128
    }

    public entry fun create(
        admin: &signer,
        coin_author: &auth,
        name: String,
        symbol: String,
        decimals: u8,
        icon_uri: String,
        project_uri: String
    ) {
        // Check if the caller is the admin of the bridge token.
        role_check(admin);

        // Create the metadata object.
        let constructor_ref = &object::create_specific_object(admin, coin_author);
        primary_fungible_store::create_primary_store_enabled_fungible_asset(
            constructor_ref,
            option::none(),
            name,
            symbol,
            decimals,
            icon_uri,
            project_uri
        );

        // Create mint/burn/transfer refs to allow creator to manage the fungible asset.
        let mint_ref = fungible_asset::generate_mint_ref(constructor_ref);
        let burn_ref = fungible_asset::generate_burn_ref(constructor_ref);
        let metadata_object_signer = object::generate_signer(constructor_ref);
        move_to(
            &metadata_object_signer,
            ManagingRefs { mint_ref, burn_ref }
        );
        event::emit(CreatToken { token: signer::address_of(&metadata_object_signer) });
    }

    /// Mint as the owner of metadata object to multiple fungible stores with amounts of FAs.
    public(friend) fun mint(asset: address, to: address, amount: u128) acquires ManagingRefs {
        let asset_obj = get_metadata(asset);
        let mint_ref = authorized_borrow_mint_ref(asset_obj);
        let to_wallet = primary_fungible_store::ensure_primary_store_exists(
            to, asset_obj
        );
        fungible_asset::mint_to(mint_ref, to_wallet, amount);
        event::emit(TokenMinted {
            account: to,
            amount
        });
    }

    /// Burn fungible assets as the owner of metadata object from fungible stores.
    public(friend) fun burn(asset: address, amount: u128) acquires ManagingRefs {
        let asset_obj = get_metadata(asset);
        let burn_ref = authorized_borrow_burn_ref(asset_obj);
        let from_wallet = primary_fungible_store::primary_store(
            @bridge_token, asset_obj
        );
        fungible_asset::burn_from(burn_ref, from_wallet, amount);
        event::emit(TokenBurned {
            account: @bridge_token,
            amount
        });
    }

    /// Transfer as the owner of metadata object.
    public entry fun transfer(
        sender: &signer,
        asset: address,
        to: address,
        amount: u128
    ) {
        let asset_obj = get_metadata(asset);
        let from_wallet =
            primary_fungible_store::primary_store(signer::address_of(sender), asset_obj);
        let to_wallet = primary_fungible_store::ensure_primary_store_exists(
            to, asset_obj
        );
        fungible_asset::transfer(sender, from_wallet, to_wallet, amount);
    }

    /// Check the existence and borrow `MintRef`.
    inline fun authorized_borrow_mint_ref(asset: Object<Metadata>): &MintRef acquires ManagingRefs {
        let refs = borrow_global<ManagingRefs>(object::object_address(&asset));
        &refs.mint_ref
    }

    /// Check the existence and borrow `BurnRef`.
    inline fun authorized_borrow_burn_ref(asset: Object<Metadata>): &BurnRef acquires ManagingRefs {
        let refs = borrow_global<ManagingRefs>(object::object_address(&asset));
        &refs.burn_ref
    }

    #[view]
    /// Return the address of the managed fungible asset that's created when this module is deployed.
    public fun get_metadata(asset_address: address): Object<Metadata> {
        object::address_to_object<Metadata>(asset_address)
    }

    #[view]
    /// Get the balance of a given store.
    public fun balance(owner: address, asset: address): u128 {
        let metadata = get_metadata(asset);
        primary_fungible_store::balance(owner, metadata)
    }

    #[test_only]
    use endless_std::debug::print;
    #[test_only]
    use bridge_token::config::test_init_module;
    #[test_only]
    use endless_std::ed25519::{generate_keys, public_key_into_unvalidated};
    #[test_only]
    use std::bcs::to_bytes;
    #[test_only]
    use std::string;

    #[test(account = @bridge_token, coin = @0x1001)]
    public fun test_basic_flow(account: &signer, coin: &auth) acquires ManagingRefs {
        test_init_module(account);

        create(
            account,
            coin,
            string::utf8(b"Tether USD"), /* name */
            string::utf8(b"USDT"), /* symbol */
            6, /* decimals */
            string::utf8(
                b"https://etherscan.io/token/images/tethernew_32.png"
            ), /* icon */
            string::utf8(b"") /* project */
        );

        // create(
        //     account,
        //     coin,
        //     string::utf8(b"Tether USD"), /* name */
        //     string::utf8(b"USDT"), /* symbol */
        //     6, /* decimals */
        //     string::utf8(b"https://etherscan.io/token/images/tethernew_32.png"), /* icon */
        //     string::utf8(b"")/* project */
        // ); // should fail

        let aaron_address = @0xface;
        let coin_address = endless_std::from_bcs::to_address(to_bytes(coin));
        mint(coin_address, aaron_address, 100);
        let asset_obj = get_metadata(coin_address);
        assert!(primary_fungible_store::balance(aaron_address, asset_obj) == 100, 4);

        let creator_address = @bridge_token;
        mint(coin_address, creator_address, 100);
        let bal = balance(creator_address, coin_address);
        print(&bal);

        burn(coin_address, 50);
        let bal = balance(creator_address, coin_address);
        print(&bal);
    }
}
