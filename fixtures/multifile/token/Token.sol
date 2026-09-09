// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "../interfaces/IERC20.sol";

/// Deliberately clean ERC-20 used to test cross-file compilation.
contract Token is IERC20 {
    string public name;
    string public symbol;
    uint8 public constant decimals = 18;
    uint256 public override totalSupply;

    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;

    constructor(string memory name_, string memory symbol_, uint256 initialSupply) {
        name = name_;
        symbol = symbol_;
        totalSupply = initialSupply;
        _balances[msg.sender] = initialSupply;
        emit Transfer(address(0), msg.sender, initialSupply);
    }

    function balanceOf(address account) external view override returns (uint256) {
        return _balances[account];
    }

    function allowance(address holder, address spender) external view override returns (uint256) {
        return _allowances[holder][spender];
    }

    function transfer(address to, uint256 value) external override returns (bool) {
        require(to != address(0), "Token: zero address");
        _balances[msg.sender] -= value;
        _balances[to] += value;
        emit Transfer(msg.sender, to, value);
        return true;
    }

    function approve(address spender, uint256 value) external override returns (bool) {
        _allowances[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    /// Mitigates the approve race (SWC-114).
    function increaseAllowance(address spender, uint256 added) external returns (bool) {
        uint256 next = _allowances[msg.sender][spender] + added;
        _allowances[msg.sender][spender] = next;
        emit Approval(msg.sender, spender, next);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) external override returns (bool) {
        require(to != address(0), "Token: zero address");
        uint256 allowed = _allowances[from][msg.sender];
        require(allowed >= value, "Token: insufficient allowance");

        _allowances[from][msg.sender] = allowed - value;
        _balances[from] -= value;
        _balances[to] += value;
        emit Transfer(from, to, value);
        return true;
    }
}
