// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "../interfaces/IERC20.sol";

/// Token vault with a reentrancy mutex and access control.
/// Exercises nested-directory imports plus inherited-modifier handling.
contract Vault {
    IERC20 public immutable token;
    address public owner;

    mapping(address => uint256) private _shares;
    uint256 public totalShares;
    bool private _locked;

    event Deposited(address indexed user, uint256 assets, uint256 shares);
    event Withdrawn(address indexed user, uint256 assets, uint256 shares);

    modifier onlyOwner() {
        require(msg.sender == owner, "Vault: not owner");
        _;
    }

    modifier nonReentrant() {
        require(!_locked, "Vault: reentrant call");
        _locked = true;
        _;
        _locked = false;
    }

    constructor(IERC20 token_, address owner_) {
        require(address(token_) != address(0), "Vault: zero token");
        require(owner_ != address(0), "Vault: zero owner");
        token = token_;
        owner = owner_;
    }

    function sharesOf(address user) external view returns (uint256) {
        return _shares[user];
    }

    function deposit(uint256 assets) external nonReentrant returns (uint256 shares) {
        require(assets > 0, "Vault: zero assets");

        shares = totalShares == 0 ? assets : (assets * totalShares) / _totalAssets();
        require(shares > 0, "Vault: zero shares");

        _shares[msg.sender] += shares;
        totalShares += shares;

        require(token.transferFrom(msg.sender, address(this), assets), "Vault: transfer failed");
        emit Deposited(msg.sender, assets, shares);
    }

    /// Checks-effects-interactions: shares burned before the token moves, with a
    /// mutex as defence in depth.
    function withdraw(uint256 shares) external nonReentrant returns (uint256 assets) {
        require(shares > 0, "Vault: zero shares");
        require(_shares[msg.sender] >= shares, "Vault: insufficient shares");

        assets = (shares * _totalAssets()) / totalShares;

        _shares[msg.sender] -= shares;
        totalShares -= shares;

        require(token.transfer(msg.sender, assets), "Vault: transfer failed");
        emit Withdrawn(msg.sender, assets, shares);
    }

    function setOwner(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Vault: zero owner");
        owner = newOwner;
    }

    function _totalAssets() private view returns (uint256) {
        return token.balanceOf(address(this));
    }
}
