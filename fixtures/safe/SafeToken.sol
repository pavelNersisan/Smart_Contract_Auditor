// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// Clean ERC-20: exact pragma, zero-address checks, safe allowance helpers.
/// Used to measure false positives.
contract SafeToken {
    string public name = "Safe";
    string public symbol = "SAFE";
    uint8 public constant decimals = 18;
    uint256 public totalSupply;

    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(uint256 initialSupply) {
        require(initialSupply > 0, "zero supply");
        totalSupply = initialSupply;
        _balances[msg.sender] = initialSupply;
        emit Transfer(address(0), msg.sender, initialSupply);
    }

    function balanceOf(address account) external view returns (uint256) {
        return _balances[account];
    }

    function allowance(address holder, address spender) external view returns (uint256) {
        return _allowances[holder][spender];
    }

    function transfer(address to, uint256 value) external returns (bool) {
        require(to != address(0), "zero address");
        _balances[msg.sender] -= value;
        _balances[to] += value;
        emit Transfer(msg.sender, to, value);
        return true;
    }

    function approve(address spender, uint256 value) external returns (bool) {
        _allowances[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    /// Mitigates the approve race condition (SWC-114).
    function increaseAllowance(address spender, uint256 added) external returns (bool) {
        uint256 next = _allowances[msg.sender][spender] + added;
        _allowances[msg.sender][spender] = next;
        emit Approval(msg.sender, spender, next);
        return true;
    }

    function decreaseAllowance(address spender, uint256 removed) external returns (bool) {
        uint256 current = _allowances[msg.sender][spender];
        require(current >= removed, "allowance underflow");
        uint256 next = current - removed;
        _allowances[msg.sender][spender] = next;
        emit Approval(msg.sender, spender, next);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        require(to != address(0), "zero address");
        uint256 allowed = _allowances[from][msg.sender];
        require(allowed >= value, "insufficient allowance");

        _allowances[from][msg.sender] = allowed - value;
        _balances[from] -= value;
        _balances[to] += value;
        emit Transfer(from, to, value);
        return true;
    }
}
