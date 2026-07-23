// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/// @notice Spike fixture exercising the three CPG enrichment facts.
contract Sample {
    address public owner;
    uint256 public config;
    uint256 public counter;
    mapping(address => uint256) public balances;

    event Configured(uint256 value);

    constructor() {
        owner = msg.sender;
    }

    // (a) state write GUARDED by require(msg.sender==owner)
    //     -> validationDominates should be TRUE
    function setConfigGuarded(uint256 value) external {
        require(msg.sender == owner, "not owner");
        config = value;
        emit Configured(value);
    }

    // (b) state write with NO guard
    //     -> validationDominates should be FALSE
    function bumpCounter(uint256 delta) external {
        counter += delta;
    }

    // (c) user-supplied address/param forwarded into a low-level .call
    //     -> taint source (parameter) -> EXTERNAL_CALL sink
    function forward(address target, bytes calldata payload) external {
        (bool ok, ) = target.call(payload);
        require(ok, "call failed");
    }

    // (d) a normal transfer
    function withdraw(uint256 amount) external {
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
}
