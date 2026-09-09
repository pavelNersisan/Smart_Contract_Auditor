// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// Written to be clean: pinned pragma, CEI ordering, reentrancy mutex,
/// access control and zero-address validation. Used to measure false positives.
contract SafeVault {
    mapping(address => uint256) private _balances;
    address public owner;
    bool private _locked;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    modifier nonReentrant() {
        require(!_locked, "reentrant call");
        _locked = true;
        _;
        _locked = false;
    }

    constructor(address initialOwner) {
        require(initialOwner != address(0), "zero owner");
        owner = initialOwner;
    }

    function deposit() external payable {
        _balances[msg.sender] += msg.value;
    }

    function balanceOf(address account) external view returns (uint256) {
        return _balances[account];
    }

    /// Checks-effects-interactions: balance zeroed before the transfer, plus a
    /// mutex as defence in depth.
    function withdraw() external nonReentrant {
        uint256 amount = _balances[msg.sender];
        require(amount > 0, "no balance");

        _balances[msg.sender] = 0;

        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }

    function setOwner(address newOwner) external onlyOwner {
        require(newOwner != address(0), "zero owner");
        owner = newOwner;
    }

    receive() external payable {}
}
