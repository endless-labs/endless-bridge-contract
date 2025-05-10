// SPDX-License-Identifier: GPL-3.0

pragma solidity ^0.8.0;

/**
 * @dev administrator.
 * master & admin.
 */
contract Admin {
    address public master; // master, role as 0, develop & upgrade the contract
    address public admin; // admin, role as 1, set the contract options
    address public financer; // financer, role as 2, can withdraw token

    event AuthorityChanged(address oldAddr, address newAddr, uint8 role);

    /**
     * @dev Throws if called by any account other than the master.
     */
    modifier onlyMaster() {
        require(isMaster(msg.sender), "Must master");
        _;
    }

    /**
     * @dev constructor
     */
    constructor() {
        init(msg.sender);
    }

    /**
     * @dev init the master & admin address.
     * the proxy call
     */
    function init(address addr) public {
        if (master == address(0)) {
            master = addr;
            admin = addr;
            financer = addr;
        }
    }

    /**
     * @dev change the master address.
     */
    function setMaster(address addr) public onlyMaster {
        require(addr != master, "Same as old");
        emit AuthorityChanged(master, addr, 1);
        master = addr;
    }

    /**
     * @dev change the admin address.
     */
    function setAdmin(address addr) public onlyMaster {
        require(addr != admin, "Same as old");
        emit AuthorityChanged(admin, addr, 2);
        admin = addr;
    }

    /**
     * @dev change the financer address.
     */
    function setFinancer(address addr) public onlyMaster {
        require(addr != financer, "Same as old");
        emit AuthorityChanged(financer, addr, 3);
        financer = addr;
    }

    /**
     * @dev Throws if called by any account other than the master.
     */
    function mustMaster(address addr) public view {
        require(isMaster(addr), "Must master");
    }

    /**
     * @dev Throws if called by any account other than the admin.
     */
    function mustAdmin(address addr) public view {
        require(isAdmin(addr), "Must admin");
    }

    /**
     * @dev Throws if called by any account other than the financer.
     */
    function mustFinancer(address addr) public view {
        require(isFinancer(addr), "Must financer");
    }

    /**
     * @dev Whether address is master.
     */
    function isMaster(address addr) public view returns (bool) {
        return master == addr;
    }

    /**
     * @dev Whether address is admin.
     */
    function isAdmin(address addr) public view returns (bool) {
        return admin == addr;
    }

    /**
     * @dev Whether address is financer.
     */
    function isFinancer(address addr) public view returns (bool) {
        return financer == addr;
    }
}
