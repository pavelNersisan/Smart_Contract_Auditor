// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Deliberately vulnerable: zero-address and approve-race issues.
/// Test fixture -- never deploy.
contract BadToken {
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => uint256) public balanceOf;
    address public backingToken;

    // BUG: no zero-address validation (CWE-20).
    constructor(address token_) {
        backingToken = token_;
    }

    // BUG: allowance overwritten directly (SWC-114).
    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        return true;
    }

    function transfer(address to, uint256 value) external returns (bool) {
        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;
        return true;
    }
}
