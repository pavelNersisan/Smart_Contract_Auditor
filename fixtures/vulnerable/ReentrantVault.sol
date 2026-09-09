// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Deliberately vulnerable: classic reentrancy (SWC-107).
/// Used as a test fixture -- never deploy.
contract ReentrantVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // BUG: ether is sent before the balance is zeroed.
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "no balance");

        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");

        balances[msg.sender] = 0;
    }

    // BUG: non-eth reentrancy via an external call before the state write.
    function sync(address oracle) external {
        oracle.call(abi.encodeWithSignature("ping()"));
        balances[msg.sender] = 1;
    }

    receive() external payable {}
}
