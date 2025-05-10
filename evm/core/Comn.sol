// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import "../BaseComn.sol";
import {Types} from "../comn/Types.sol";

/**
 * @title all sol extends from this
 * @dev Extends BaseComn with additional address constants
 */
abstract contract Comn is BaseComn {
    // local
    // address constant ValidatorAddr = 0xd2bA7eBd42a39315Dac3f8bba68d30f622fe467f;

    // tbsc
    address constant ValidatorAddr = address(0xA83389748caDA06DE25C95e80e4bee44613834E1);

    // sepolia
    // address constant ValidatorAddr = address(0xA83389748caDA06DE25C95e80e4bee44613834E1);

    // nile
    // address constant ValidatorAddr = address(0x242E81D3b1cb407b23C160d15AA37EF4D83a76f6); //TDGX3LXDWe9vyRJ16oonz2KFxmGatCCrNQ

    // ETH chain
    Types.ChainType constant ChainType = Types.ChainType.ETH;
    // TRX chain
    // Types.ChainType constant ChainType = Types.ChainType.TRX;
}
