// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {Types} from "./Types.sol";

library ComFunUtil {
    function isNotEmpty(address ad, string memory msgs) private pure {
        require(ad != address(0), msgs);
    }

    function isNotEmpty(uint ad, string memory msgs) private pure {
        require(ad != 0, msgs);
    }

    function combainChain(
        Types.Chain memory chain_
    ) internal pure returns (uint72) {
        uint72 c = chain_.chain_id;
        // must use uint72 to avoid u8 overflow
        uint72 chain_type = chain_.chain_type;
        c += chain_type << 64;
        return c;
    }

    function splitChain(uint a1) internal pure returns (Types.Chain memory c) {
        c.chain_id = uint64(a1);
        c.chain_type = uint8(a1 >> 64);
    }

    function addressToBytes32(address a) internal pure returns (bytes32 b) {
        return bytes32(uint(uint160(a)));
    }

    function bytes32ToAddress(bytes32 a) internal pure returns (address b) {
        return address(uint160(uint(a)));
    }

    function hexStr2bytes32(string memory data) internal pure returns (bytes32) {
        return bytes2bytes32(hexStr2bytes(data));
    }

    function bytes2bytes32(bytes memory data) internal pure returns (bytes32) {
        uint len = data.length;
        if (len > 32) {
            revert("data len is overflow 32");
        }

        uint rs = 0;
        for (uint i = 0; i < len; i++) {
            rs = rs << 8;
            rs += uint8(data[i]);
        }

        return bytes32(rs);
    }

    // convert hex string to bytes
    function hexStr2bytes(
        string memory data
    ) internal pure returns (bytes memory) {
        bytes memory a = bytes(data);
        if (a.length % 2 != 0) {
            revert("hex string len is invalid");
        }
        uint8[] memory b = new uint8[](a.length);

        for (uint i = 0; i < a.length; i++) {
            uint8 _a = uint8(a[i]);

            if (_a > 96) {
                b[i] = _a - 97 + 10;
            } else if (_a > 66) {
                b[i] = _a - 65 + 10;
            } else {
                b[i] = _a - 48;
            }
        }

        bytes memory c = new bytes(b.length / 2);
        for (uint _i = 0; _i < b.length; _i += 2) {
            c[_i / 2] = bytes1(b[_i] * 16 + b[_i + 1]);
        }

        return c;
    }

    function stringConcat(
        string memory a,
        string memory b,
        bytes memory d
    ) internal pure returns (string memory) {
        bytes memory a1 = bytes(a);
        bytes memory a2 = bytes(b);
        bytes memory a3;
        a3 = new bytes(a1.length + a2.length + d.length);
        uint k = 0;
        for (uint i = 0; i < a1.length; i++) {
            a3[k++] = a1[i];
        }

        for (uint i = 0; i < d.length; i++) {
            a3[k++] = d[i];
        }

        for (uint i = 0; i < a2.length; i++) {
            a3[k++] = a2[i];
        }

        return string(a3);
    }

    function currentTimestamp() internal view returns (uint256) {
        return block.timestamp;
    }
}
