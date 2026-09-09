// SPDX-License-Identifier: MIT
// Pragma deliberately spans pre-0.8 versions so the compiler may silently wrap.
pragma solidity >=0.6.0 <0.9.0;

/// Deliberately vulnerable: arithmetic on a compiler range allowing < 0.8.0.
/// Test fixture -- never deploy.
contract OldArithmetic {
    mapping(address => uint256) public balances;
    uint256 public total;

    // BUG: silent overflow/underflow on pre-0.8 compilers (SWC-101).
    function add(uint256 amount) external {
        balances[msg.sender] = balances[msg.sender] + amount;
        total = total + amount;
    }

    // BUG: division before multiplication truncates.
    function share(uint256 a, uint256 b, uint256 c) external pure returns (uint256) {
        require(b != 0, "zero");
        return (a / b) * c;
    }

    // BUG: caller-supplied divisor with no non-zero check.
    function split(uint256 pot, uint256 parts) external pure returns (uint256) {
        return pot / parts;
    }
}
