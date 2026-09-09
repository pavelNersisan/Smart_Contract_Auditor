// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Deliberately vulnerable: unchecked returns, loops and delegatecall.
/// Test fixture -- never deploy.
contract ExternalCallIssues {
    address public implementation;
    address[] public payees;
    mapping(address => uint256) public paid;

    // BUG: send()'s false return is ignored (SWC-104).
    function tip(address payable to) external payable {
        to.send(msg.value);
    }

    // BUG: low-level call result discarded (SWC-104).
    function poke(address target) external {
        target.call(abi.encodeWithSignature("ping()"));
    }

    // BUG: external call inside an unbounded loop (SWC-113).
    function flush() external {
        for (uint256 i = 0; i < payees.length; i++) {
            (bool ok, ) = payees[i].call{value: 1}("");
            require(ok);
        }
    }

    // BUG: msg.value counted once per iteration.
    function spread(uint256 n) external payable {
        for (uint256 i = 0; i < n; i++) {
            paid[payees[i]] += msg.value;
        }
    }

    // BUG: delegatecall to a caller-supplied target (SWC-112).
    function upgradeAndRun(address impl, bytes calldata data) external returns (bytes memory) {
        (bool ok, bytes memory ret) = impl.delegatecall(data);
        require(ok);
        return ret;
    }

    receive() external payable {}
}
