// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

interface ICallback {
    function ping() external;
}

contract CallControl {
    mapping(address => uint256) public balances;
    uint256 private guardState = 1;

    modifier nonReentrant() {
        require(guardState == 1, "guarded");
        guardState = 2;
        _;
        guardState = 1;
    }

    function _book(uint256 amount) internal {
        balances[msg.sender] += amount;
    }

    function callInternal(uint256 amount) external {
        _book(amount);
    }

    function callExternal(ICallback target) external {
        target.ping();
    }

    function callLowLevel(address target) external returns (bool ok) {
        (ok,) = target.call("");
    }

    function callDelegate(address target, bytes calldata data)
        external
        returns (bytes memory result)
    {
        (bool ok, bytes memory returned) = target.delegatecall(data);
        require(ok, "delegate failed");
        return returned;
    }

    function unsafeWithdraw(address payable receiver, uint256 amount) external {
        receiver.call("");
        balances[msg.sender] -= amount;
    }

    function guardedWithdraw(address payable receiver, uint256 amount)
        external
        nonReentrant
    {
        receiver.call("");
        balances[msg.sender] -= amount;
    }

    function effectsFirst(address payable receiver, uint256 amount) external {
        balances[msg.sender] -= amount;
        receiver.call("");
    }
}
