// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Deliberately vulnerable: missing access control and tx.origin auth.
/// Test fixture -- never deploy.
contract AccessControlFail {
    address public owner;
    uint256 public fee;

    // BUG: anyone can initialise, so anyone can become owner (SWC-118).
    function initialize() external {
        owner = msg.sender;
    }

    // BUG: unprotected selfdestruct (SWC-106).
    function kill() external {
        selfdestruct(payable(msg.sender));
    }

    // BUG: anyone can sweep the balance to any address (SWC-105).
    function sweep(address payable to) external {
        to.transfer(address(this).balance);
    }

    // BUG: tx.origin authorization is phishable (SWC-115).
    function setFee(uint256 newFee) external {
        require(tx.origin == owner, "not owner");
        fee = newFee;
    }

    receive() external payable {}
}
