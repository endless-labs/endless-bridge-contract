// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {ERC20} from "@openzeppelin/contracts@5.0.0/token/ERC20/ERC20.sol";

contract BridgeToken is ERC20 {
    // the minter address
    address private _minter;

    // decimals
    uint8 private _decimals;

    /**
     * @dev Throws if called by any account other than the master.
     */
    modifier onlyMinter() {
        require(msg.sender == _minter, "Must minter");
        _;
    }

    /**
     * @dev construct
     */
    constructor(
        string memory name_,
        string memory symbol_,
        uint8 decimals_,
        address minter_
    ) ERC20(name_, symbol_) {
        _decimals = decimals_;
        _minter = minter_;
    }

    /**
     * @dev set decimals 6, same as usdt
     */
    function decimals() public view virtual override returns (uint8) {
        return _decimals;
    }

    /**
     * @dev Get the address is the minter
     */
    function isMinter(address addr) public view returns (bool) {
        return _minter == addr;
    }

    /**
     * @dev bridge mint token
     */
    function mintFor(address account, uint256 amount) public onlyMinter {
        _mint(account, amount);
    }

    /**
     * @dev bridge burn token
     */
    function burnFor(address account, uint256 amount) public onlyMinter {
        _burn(account, amount);
    }
}
