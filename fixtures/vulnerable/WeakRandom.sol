// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Deliberately vulnerable: predictable randomness and timestamp logic.
/// Test fixture -- never deploy.
contract WeakRandom {
    uint256 public winner;
    uint256 public deadline;

    // BUG: blockhash + timestamp entropy (SWC-120), and a timestamp
    // comparison (SWC-116).
    function draw() external {
        require(block.timestamp > deadline, "too early");
        uint256 random = uint256(
            keccak256(abi.encodePacked(blockhash(block.number - 1), block.timestamp))
        ) % 100;
        winner = random;
    }

    function extend(uint256 secs) external {
        deadline = block.timestamp + secs;
    }
}
