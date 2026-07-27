// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

interface IPriceSource {
    function latestPrice() external view returns (uint256 price, uint256 updatedAt);
}

contract UnsafeRoleDrain {
    function drain(address payable recipient) external {
        recipient.transfer(address(this).balance);
    }

    receive() external payable {}
}

contract SafeRoleDrain {
    address public immutable owner = msg.sender;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function rescue(address payable recipient) external onlyOwner {
        recipient.transfer(address(this).balance);
    }

    receive() external payable {}
}

contract TimelockedGovernor {
    uint256 public constant MIN_DELAY = 2 days;
    address public immutable governor = msg.sender;
    mapping(bytes32 => uint256) public readyAt;

    modifier onlyGovernor() {
        require(msg.sender == governor, "not governor");
        _;
    }

    function queue(bytes32 action) external onlyGovernor {
        readyAt[action] = block.timestamp + MIN_DELAY;
    }

    function execute(bytes32 action) external onlyGovernor {
        require(block.timestamp >= readyAt[action], "not ready");
        readyAt[action] = 0;
    }
}

contract ImmediateGovernor {
    address public immutable governor = msg.sender;

    modifier onlyGovernor() {
        require(msg.sender == governor, "not governor");
        _;
    }

    function execute(bytes32 action) external onlyGovernor {
        require(action != bytes32(0), "empty");
    }
}

contract UnsafeOracleConsumer {
    IPriceSource public immutable oracle;

    constructor(IPriceSource configuredOracle) {
        oracle = configuredOracle;
    }

    function quote(uint256 amount) external view returns (uint256) {
        (uint256 price,) = oracle.latestPrice();
        return amount * price;
    }
}

contract SafeOracleConsumer {
    uint256 public constant MAX_AGE = 30 minutes;
    IPriceSource public immutable oracle;

    constructor(IPriceSource configuredOracle) {
        oracle = configuredOracle;
    }

    function quote(uint256 amount) external view returns (uint256) {
        (uint256 price, uint256 updatedAt) = oracle.latestPrice();
        require(updatedAt <= block.timestamp, "future");
        require(block.timestamp - updatedAt <= MAX_AGE, "stale");
        return amount * price;
    }
}
