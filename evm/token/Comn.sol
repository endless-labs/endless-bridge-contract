// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import "../BaseComn.sol";

/**
 * @title all sol extends from this
 * @dev Extends BaseComn with additional address constants
 */
abstract contract Comn is BaseComn {
    // local
    // address constant ExecutorAddr = 0x0165878A594ca255338adfa4d48449f69242Eb8F;
    // address constant PoolAddr = 0xbbc9C2C381588Caba7D9799201e1D93e87b72A01;
    // address constant MessagerAddr = 0x2279B7A0a67DB372996a5FaB50D91eAA73d2eBe6;

    // tbsc
    address constant WTOKEN_ADDRESS = 0xae13d989daC2f0dEbFf460aC112a837C89BAa7cd;
    address constant PoolAddr = address(0x3f75a7e2DE087C0aDebE29dC4D5bad2c041246dB);
    address constant ExecutorAddr = address(0x3398364Ea6B845A3E212b7284b8f70B20F49F67E);
    address constant MessagerAddr = address(0xCcde64ef52edCFA9c1578Fed7682E61dC0c783FE);
    address constant ManagerAddr = address(0x304De8ea1e18de1Cd2C75B7E5AfA8E696A705d4c);

    // sepolia
    // address constant WTOKEN_ADDRESS = 0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14;
    // address constant PoolAddr = address(0x3f75a7e2DE087C0aDebE29dC4D5bad2c041246dB);
    // address constant ExecutorAddr = address(0x3398364Ea6B845A3E212b7284b8f70B20F49F67E);
    // address constant MessagerAddr = address(0xCcde64ef52edCFA9c1578Fed7682E61dC0c783FE);
    // address constant ManagerAddr = address(0x792C04261E6DB94dcD7a41D668577c1E73f92C4b);

    // nile
    // address constant WTOKEN_ADDRESS = 0xfb3b3134F13CcD2C81F4012E53024e8135d58FeE; //TYsbWxNnyTgsZaTFaue9hqpxkU3Fkco94a
    // address constant PoolAddr = address(0x672Ae498DA018cF8A6eBB5cded2d96534A751CE4); //TKNhz59zZLDfwvc8cT3xZksQLT61VKwbBs
    // address constant ExecutorAddr = address(0xca273F5804B8975CaFA7bF3b0A9919AECe59310A); //TUQ6WmXMTphLehhfp9jARdy7Rtjv6SyJ5n
    // address constant MessagerAddr = address(0x976ec2e0ADCdAB308a3Ade2baaA93F11531b7108); //TPmuirL6spG12Do3Kj2pgD8NNqQMD9nqwR
    // address constant ManagerAddr = address(0xAFc1717c2Fef79c05745D6c809c98D9bADABE038); //TRzWzJg2T9fG9iTxKiaoDq3LcRJ3UNkrx6

    /**
     * @dev Checks if a given token is the wrapped token.
     * @param token The address of the token to check.
     * @return A boolean indicating whether the token is the wrapped token.
     */
    function isWToken(address token) public pure returns (bool) {
        return token == WTOKEN_ADDRESS;
    }
}
