// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {ECDSA} from "@openzeppelin/contracts@5.0.0/utils/cryptography/ECDSA.sol";
import {Address} from "@openzeppelin/contracts@5.0.0/utils/Address.sol";
import {Types} from "../comn/Types.sol";
import {IMessager} from "../comn/IMessager.sol";
import {IValidator} from "../comn/IValidator.sol";
import {ComFunUtil} from "../comn/ComFunUtil.sol";
import {Comn} from "./Comn.sol";

/**
 * @title Messager
 * @dev This contract inherits from both Comn and IMessager. It is designed to handle messaging - related operations in the context of a cross - chain or decentralized system.
 * It may be responsible for emitting, consuming, and decoding messages, which are crucial for coordinating actions between different components, chains, or contracts.
 * The contract serves as a communication hub to ensure the proper flow of information and execution of associated tasks within the overall system.
 */
contract Messager is Comn, IMessager {
    // deprecated, no longer used
    uint public bridge_fee;

    // Mapping from target chain ID to a nonce value. Nonce starts from 1 for each chain ID.
    // to chain_id => id start from 1
    mapping(uint => uint) public nonceMap;
    // Mapping from source chain ID to another mapping of nonce to a boolean indicating if the nonce has been used.
    // from chain_id => (nonce => bool)
    mapping(uint => mapping(uint => bool)) public nonceStateMap;
    // emit msg when consume_bridge_msg is called.
    event ConfirmMsg(
        address executor,
        Types.Chain from_chain,
        uint64 nonce,
        bytes mbody
    );

    /**
     * @dev Sets the bridge fee. Only the administrator can call this function.
     * @param _bridge_fee The new bridge fee to be set.
     */
    function set_bridge_fee(uint _bridge_fee) public onlyAdmin {
        bridge_fee = _bridge_fee;
    }

    /**
     * @dev Decodes a bytes - encoded message into a Types.Message struct.
     * @param message The bytes array representing the encoded message.
     * @return A Types.Message struct decoded from the input bytes.
     */
    function decode_msg(
        bytes memory message
    ) public pure returns (Types.Message memory) {
        return abi.decode(message, (Types.Message));
    }

    /**
     * @dev Converts a Types.MessageHeader struct to a bytes array.
     * @param header The Types.MessageHeader struct to be converted.
     * @return A bytes array representing the encoded message header.
     */
    function _convert_header_to_bytes(
        Types.MessageHeader memory header
    ) private pure returns (bytes memory) {
        return
            abi.encodePacked(
                header.msg_type,
                header.nonce,
                ComFunUtil.combainChain(header.from_chain),
                header.sender,
                ComFunUtil.combainChain(header.to_chain),
                header.receiver,
                header.upload_gas_fee
            );
    }

    /**
     * @dev Verifies the signature of a message and checks if it meets the minimum validator requirements.
     * @param messageDec The decoded Types.Message struct.
     * @param signature An array of bytes representing the signatures of the message.
     * @return A boolean indicating if the message is valid and the original decoded message.
     */
    function _verify_msg(
        Types.Message memory messageDec,
        bytes[] memory signature
    ) private returns (bool, Types.Message memory) {
        bytes32 msgHash = keccak256(
            bytes.concat(
                _convert_header_to_bytes(messageDec.msg_header),
                messageDec.msg_body
            )
        );

        emit Types.Log("msgHash in verify_msg: ", msgHash);
        Types.Message memory msgDec = messageDec;

        (address[] memory validators, uint min_verify_threshold) = IValidator(
            ValidatorAddr
        ).fetch_all_validators();
        if (signature.length < min_verify_threshold) {
            emit Types.Log("require min verify node", min_verify_threshold);
            return (false, msgDec);
        }

        uint256 validSignerCount = 0;
        bool[] memory uniqueSigners = new bool[](validators.length);
        for (uint i = 0; i < signature.length; i++) {
            address msg_signer = ECDSA.recover(msgHash, signature[i]);

            if (!isValidator(msg_signer, validators)) {
                revert("Not a valid signer node");
            }

            uint256 signerIndex = getValidatorIndex(msg_signer, validators);
            if (!uniqueSigners[signerIndex]) {
                uniqueSigners[signerIndex] = true;
                validSignerCount++;
            }
        }

        require(
            validSignerCount >= min_verify_threshold,
            "not meet minimum signer requirement"
        );
        return (true, msgDec);
    }

    /**
     * @dev Checks if an address is a validator.
     * @param signer The address to be checked.
     * @param validators An array of validator addresses.
     * @return A boolean indicating if the address is a validator.
     */
    function isValidator(
        address signer,
        address[] memory validators
    ) private pure returns (bool) {
        for (uint256 i = 0; i < validators.length; i++) {
            if (validators[i] == signer) {
                return true;
            }
        }
        return false;
    }

    /**
     * @dev Gets the index of a validator address in the validators array.
     * @param signer The address of the validator.
     * @param validators An array of validator addresses.
     * @return The index of the validator address in the array.
     */
    function getValidatorIndex(
        address signer,
        address[] memory validators
    ) private pure returns (uint256) {
        for (uint256 i = 0; i < validators.length; i++) {
            if (validators[i] == signer) {
                return i;
            }
        }
        revert("Signer not found in validators");
    }

    /**
     * @dev Verifies the signature of a message and returns a boolean indicating its validity.
     * @param messageDec The decoded Types.Message struct.
     * @param signature An array of bytes representing the signatures of the message.
     * @return A boolean indicating if the message is valid.
     */
    function verify_msg(
        Types.Message memory messageDec,
        bytes[] memory signature
    ) public returns (bool) {
        (bool rs, ) = _verify_msg(messageDec, signature);
        return rs;
    }

    /**
     * @dev Verifies the signature of a bridge message and consumes it by marking the nonce as used.
     * @param messageDec The decoded Types.Message struct.
     * @param signature An array of bytes representing the signatures of the message.
     * @return A boolean indicating if the message is valid and can be consumed.
     */
    function consume_bridge_msg(
        Types.Message memory messageDec,
        bytes[] memory signature
    ) public returns (bool) {
        address receiver = ComFunUtil.bytes32ToAddress(
            messageDec.msg_header.receiver
        );
        require(msg.sender == receiver, "not match receiver");

        (bool rs, ) = _verify_msg(messageDec, signature);

        uint from_chain_id = ComFunUtil.combainChain(
            messageDec.msg_header.from_chain
        );
        uint nonce = messageDec.msg_header.nonce;

        // not empty key
        if (nonceStateMap[from_chain_id][nonce]) {
            emit Types.Log("nonce has been used");
            return false;
        } else {
            nonceStateMap[from_chain_id][nonce] = true;
        }

        emit ConfirmMsg(
            msg.sender,
            messageDec.msg_header.from_chain,
            messageDec.msg_header.nonce,
            messageDec.msg_body
        );

        return rs;
    }

    /**
     * @dev Emits a message for cross - chain communication.
     * @param msg_type The type of the message.
     * @param to_chain The target chain information.
     * @param receiver The receiver's identifier in bytes32 format.
     * @param body_message The body of the message in bytes.
     * @param upload_gas_fee The gas fee for uploading the message.
     */
    function emit_msg(
        uint8 msg_type,
        Types.Chain memory to_chain,
        bytes32 receiver,
        bytes memory body_message,
        uint128 upload_gas_fee
    ) public payable {
        require(upload_gas_fee > 0, "upload_gas_fee must greater than 0");

        uint to_chain_uint = ComFunUtil.combainChain(to_chain);
        nonceMap[to_chain_uint] += 1;
        uint nonce = nonceMap[to_chain_uint];
        require(
            block.chainid <= type(uint64).max,
            "chainid exceed the maximum"
        );
        require(nonce <= type(uint64).max, "nonce exceed the maximum");

        Types.Message memory rs = Types.Message(
            Types.MessageHeader({
                msg_type: msg_type,
                nonce: uint64(nonce),
                from_chain: Types.Chain(
                    uint8(ChainType),
                    uint64(block.chainid)
                ),
                sender: ComFunUtil.addressToBytes32(address(msg.sender)),
                to_chain: to_chain,
                receiver: receiver,
                upload_gas_fee: upload_gas_fee
            }),
            body_message
        );
        emit Msg(rs);
        emit UploadFee(upload_gas_fee);
    }

    /**
     * @dev Allows a admin to withdraw the bridge fee.
     * @param amount The amount to be withdrawn.
     */
    function withdrawFee(uint amount) public onlyFinancer {
        require(amount <= address(this).balance, "not enough balance");

        Address.sendValue(payable(msg.sender), amount);
    }

    function get_bridge_fee() external view returns (uint) {
        return bridge_fee;
    }
}
