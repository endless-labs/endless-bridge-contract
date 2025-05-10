// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import "@openzeppelin/contracts@5.0.0/utils/structs/EnumerableSet.sol";
import "@openzeppelin/contracts@5.0.0/utils/math/Math.sol";
import {ComFunUtil} from "../comn/ComFunUtil.sol";
import {IValidator} from "../comn/IValidator.sol";
import {Comn} from "./Comn.sol";

/**
 * @title Executor
 * @dev This contract serves as an executor for cross - chain token operations. It manages the relationships between tokens on different chains, 
 * creates new tokens, and handles the bridging and message processing of cross - chain tokens. 
 * It has functions for administrators to set chain - related information and token relationships, as well as functions for users to bridge tokens 
 * and for the system to process received cross - chain messages.
 */
contract Validator is Comn, IValidator {
    using EnumerableSet for EnumerableSet.Bytes32Set;

    EnumerableSet.Bytes32Set private validators;
    // Defines a private set of type Bytes32Set to store the public keys of validators
    uint private min_verify_threshold;
    // Defines a private unsigned integer variable to store the minimum verification threshold

    /**
     * @dev Adds validators to the validator set in batches and sets the minimum verification threshold.
     * This function can only be called by the administrator.
     * @param signer_pk An array of bytes32 type, containing the public keys of the validators to be added.
     * @param threshold The minimum verification threshold, which must be less than or equal to 255.
     */
    function batch_add_validators(
        bytes32[] memory signer_pk,
        uint threshold
    ) public onlyAdmin {
        // Iterates through the signer_pk array and adds each public key to the validators set
        for (uint i = 0; i < signer_pk.length; i++) {
            validators.add(signer_pk[i]);
        }

        // Checks if the threshold is greater than 255. If so, it reverts with an error message.
        if (threshold > 255) {
            revert(
                "The minimum verification threshold cannot be greater than 255"
            );
        }

        // Sets the minimum verification threshold
        min_verify_threshold = threshold;
    }

    /**
     * @dev Deletes validators from the validator set in batches and updates the minimum verification threshold.
     * This function can only be called by the administrator.
     * @param signer_pk An array of bytes32 type, containing the public keys of the validators to be deleted.
     * @return The updated minimum verification threshold.
     */
    function batch_delete_validators(
        bytes32[] memory signer_pk
    ) public onlyAdmin returns (uint) {
        // Iterates through the signer_pk array and removes each public key from the validators set
        for (uint i = 0; i < signer_pk.length; i++) {
            validators.remove(signer_pk[i]);
        }

        // Gets the current length of the validator set
        uint threshold = validators.length();
        // Sets the new minimum verification threshold to the smaller value between the current minimum verification threshold and the length of the validator set
        min_verify_threshold = Math.min(min_verify_threshold, threshold);
        return min_verify_threshold;
    }

    /**
     * @dev Sets the minimum verification threshold.
     * This function can only be called by the administrator.
     * @param threshold The minimum verification threshold to be set, which must be less than or equal to 255.
     */
    function set_min_verify_threshold(uint threshold) public onlyAdmin {
        // Checks if the threshold is greater than 255. If so, it reverts with an error message.
        if (threshold > 255) {
            revert(
                "The minimum verification threshold cannot be greater than 255"
            );
        }
        // Sets the minimum verification threshold
        min_verify_threshold = threshold;
    }

    /**
     * @dev Gets the current minimum verification threshold.
     * @return The current minimum verification threshold.
     */
    function get_min_verify_threshold() public view returns (uint) {
        return min_verify_threshold;
    }

    /**
     * @dev Fetches the addresses of all validators and the current minimum verification threshold.
     * @return An array of address type, containing the addresses of all validators; and the current minimum verification threshold.
     */
    function fetch_all_validators()
        public
        view
        returns (address[] memory, uint)
    {
        // Creates an array of address type with a length equal to the length of the validator set
        address[] memory all_validators = new address[](validators.length());
        // Iterates through the validator set, converts each public key to an address, and stores it in the all_validators array
        for (uint i = 0; i < validators.length(); i++) {
            all_validators[i] = ComFunUtil.bytes32ToAddress(validators.at(i));
        }

        return (all_validators, min_verify_threshold);
    }
}
