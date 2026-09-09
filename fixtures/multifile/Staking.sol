// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "./token/Token.sol";
import "./vault/Vault.sol";

/// Staking on top of the token and vault, exercising deeper import chains.
contract Staking {
    Token public immutable rewardToken;
    Vault public immutable vault;

    uint256 public constant REWARD_PER_BLOCK = 1e18;
    uint256 public lastUpdateBlock;

    mapping(address => uint256) public staked;
    mapping(address => uint256) public pendingRewards;
    uint256 public totalStaked;

    event Staked(address indexed user, uint256 amount);
    event Unstaked(address indexed user, uint256 amount);
    event RewardClaimed(address indexed user, uint256 amount);

    constructor(Token rewardToken_, Vault vault_) {
        require(address(rewardToken_) != address(0), "Staking: zero token");
        require(address(vault_) != address(0), "Staking: zero vault");
        rewardToken = rewardToken_;
        vault = vault_;
        lastUpdateBlock = block.number;
    }

    modifier updateRewards(address user) {
        _accrue(user);
        _;
    }

    function stake(uint256 amount) external updateRewards(msg.sender) {
        require(amount > 0, "Staking: zero amount");

        staked[msg.sender] += amount;
        totalStaked += amount;

        require(
            rewardToken.transferFrom(msg.sender, address(this), amount),
            "Staking: transfer failed"
        );
        emit Staked(msg.sender, amount);
    }

    function unstake(uint256 amount) external updateRewards(msg.sender) {
        require(amount > 0, "Staking: zero amount");
        require(staked[msg.sender] >= amount, "Staking: insufficient stake");

        staked[msg.sender] -= amount;
        totalStaked -= amount;

        require(rewardToken.transfer(msg.sender, amount), "Staking: transfer failed");
        emit Unstaked(msg.sender, amount);
    }

    function claim() external updateRewards(msg.sender) {
        uint256 reward = pendingRewards[msg.sender];
        require(reward > 0, "Staking: nothing to claim");

        pendingRewards[msg.sender] = 0;

        require(rewardToken.transfer(msg.sender, reward), "Staking: reward failed");
        emit RewardClaimed(msg.sender, reward);
    }

    function earned(address user) external view returns (uint256) {
        return pendingRewards[user];
    }

    function _accrue(address user) private {
        uint256 elapsed = block.number - lastUpdateBlock;
        lastUpdateBlock = block.number;

        if (elapsed == 0 || totalStaked == 0) {
            return;
        }
        uint256 share = (staked[user] * elapsed * REWARD_PER_BLOCK) / totalStaked;
        pendingRewards[user] += share;
    }
}
