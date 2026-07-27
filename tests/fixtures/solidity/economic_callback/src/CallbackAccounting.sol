// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

interface ICreditCallbackReceiver {
    function onCreditReceived() external;
}

interface ICallbackAccountingTarget {
    function withdrawCallbackPreset() external;
}

contract SyntheticCallbackReceiver is ICreditCallbackReceiver {
    ICallbackAccountingTarget public target;
    uint256 public callbackCount;
    bool private entered;

    function configureTarget(address configuredTarget) external {
        require(address(target) == address(0), "target already configured");
        target = ICallbackAccountingTarget(configuredTarget);
    }

    function onCreditReceived() external {
        require(msg.sender == address(target), "configured target required");
        callbackCount += 1;
        if (!entered) {
            entered = true;
            try target.withdrawCallbackPreset() {} catch {}
            entered = false;
        }
    }
}

contract UnsafeCallbackAccounting {
    ICreditCallbackReceiver public immutable receiver;
    uint256 public availableCredit = 1;
    uint256 public settledCredit;
    uint256 public invalidCallbackTransitions;

    constructor(address configuredReceiver) {
        receiver = ICreditCallbackReceiver(configuredReceiver);
    }

    function withdrawCallbackPreset() external {
        uint256 amount = availableCredit;
        require(amount != 0, "no available credit");

        receiver.onCreditReceived();
        availableCredit = 0;
        settledCredit += amount;
        if (settledCredit > 1) {
            invalidCallbackTransitions += 1;
        }
    }
}

contract SafeCallbackAccounting {
    ICreditCallbackReceiver public immutable receiver;
    uint256 public availableCredit = 1;
    uint256 public settledCredit;
    uint256 public invalidCallbackTransitions;

    constructor(address configuredReceiver) {
        receiver = ICreditCallbackReceiver(configuredReceiver);
    }

    function withdrawCallbackPreset() external {
        uint256 amount = availableCredit;
        require(amount != 0, "no available credit");

        availableCredit = 0;
        settledCredit += amount;
        receiver.onCreditReceived();
    }
}
