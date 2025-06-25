// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import "./Types.sol";

interface IExecutor {
    function setChainContract(
        uint source_chain_id,
        bytes32 contract_addr
    ) external;

    function setChainFeeToken(
        uint source_chain_id,
        bytes32 fee_token_addr
    ) external;

    function setTokenRelationship(
        uint source_chain_id, // combain chain_type&chain_id
        bytes32 source_token,
        uint8 source_token_decimals,
        bytes32 dest_token,
        uint8 dest_token_type // 0 pool. 1 means mint
    ) external;

    function removeTokenRelationship(
        uint source_chain_id,
        bytes32 source_token
    ) external;

    function setCrossTokenLimits(
        address token,
        uint256 minAmount,
        uint256 maxAmount
    ) external;

    function setSigner(address newSigner) external;

    function signer() external view returns (address);

    function setCollectFee(uint256 _collectFee) external;

    function collectFee() external view returns (uint256);

    function createNewToken(
        string memory name,
        string memory symbol,
        uint8 decimals
    ) external returns (address newToken);

    function bridgeToken(
        bytes32 source_token,
        Types.Chain memory to_chain,
        bytes32 to_who,
        bytes32 receiver,
        uint128 all_amount,
        uint128 upload_gas_fee
    ) external payable;

    function bridgeToken(
        bytes32 source_token,
        Types.Chain memory to_chain,
        bytes32 to_who,
        bytes32 receiver,
        uint128 all_amount,
        uint128 upload_gas_fee,
        bytes memory extra_data
    ) external payable;

    function decode_bridge_msg_body(
        bytes memory msg_body
    ) external pure returns (Types.BridgeMessageBodyV2 memory);

    function decode_bridge_msg(
        Types.Message memory decMsg
    )
        external
        pure
        returns (Types.MessageHeader memory, Types.BridgeMessageBodyV2 memory);

    function processMsg(
        Types.Message memory message,
        // uint16[] memory signer_index,
        bytes[] memory signature
    ) external returns (bool);

    function getLpFeeAndFinalAmount(
        uint source_chain_id,
        bytes32 source_token,
        uint all_amount
    ) external view returns (uint lp_fee, uint final_amount);

    function getTokenRelationship(
        uint source_chain_id,
        bytes32 source_token
    ) external view returns (bool, Types.RelationShipInfo memory);

    function getStrictTokenRelationship(
        uint source_chain_id,
        bytes32 source_token
    ) external view returns (bool, Types.RelationShipInfo memory);

    function getSourceTokenInfo(
        uint source_chain_id,
        bytes32 source_token
    ) external view returns (Types.SourceTokenInfo memory);

    function getAllCrossRelation()
        external
        view
        returns (Types.CrossRelation[] memory);
}
