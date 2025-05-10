// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

interface IValidator {
    function batch_add_validators(
        bytes32[] memory signer_pk,
        uint threshold
    ) external;

    function batch_delete_validators(bytes32[] memory signer_pk) external returns (uint);

    function set_min_verify_threshold(uint v) external;

    function get_min_verify_threshold() external view returns (uint);

    function fetch_all_validators()
        external
        view
        returns (address[] memory, uint);

}
