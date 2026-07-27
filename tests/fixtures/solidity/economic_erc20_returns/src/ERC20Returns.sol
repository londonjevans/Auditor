// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

interface IERC20TransferSelector {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract SyntheticReturnToken {
    enum ReturnMode {
        TrueReturn,
        MissingReturn,
        FalseReturn,
        ShortReturn
    }

    ReturnMode public mode;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function setMode(ReturnMode nextMode) external {
        mode = nextMode;
    }

    function mint(address account, uint256 amount) external {
        balanceOf[account] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external {
        ReturnMode selected = mode;
        if (selected == ReturnMode.TrueReturn || selected == ReturnMode.MissingReturn) {
            uint256 approved = allowance[from][msg.sender];
            require(approved >= amount, "allowance");
            require(balanceOf[from] >= amount, "balance");
            allowance[from][msg.sender] = approved - amount;
            balanceOf[from] -= amount;
            balanceOf[to] += amount;
        }
        if (selected == ReturnMode.MissingReturn) {
            assembly {
                return(0, 0)
            }
        }
        if (selected == ReturnMode.ShortReturn) {
            assembly {
                mstore(0, 1)
                return(31, 1)
            }
        }
        bool result = selected == ReturnMode.TrueReturn;
        assembly {
            mstore(0, result)
            return(0, 32)
        }
    }
}

contract UnsafeUncheckedReturnVault {
    SyntheticReturnToken public immutable asset;
    mapping(address => uint256) public credit;

    constructor(SyntheticReturnToken configuredAsset) {
        asset = configuredAsset;
    }

    function deposit(uint256 amount) external {
        (bool ok,) = address(asset).call(
            abi.encodeWithSelector(IERC20TransferSelector.transferFrom.selector, msg.sender, address(this), amount)
        );
        require(ok, "token call");
        credit[msg.sender] += amount;
    }

    function claimable(address account) external view returns (uint256) {
        return credit[account];
    }
}

contract SafeReturnCheckedVault {
    SyntheticReturnToken public immutable asset;
    mapping(address => uint256) public credit;

    constructor(SyntheticReturnToken configuredAsset) {
        asset = configuredAsset;
    }

    function deposit(uint256 amount) external {
        uint256 beforeBalance = asset.balanceOf(address(this));
        _safeTransferFrom(msg.sender, address(this), amount);
        uint256 received = asset.balanceOf(address(this)) - beforeBalance;
        require(received > 0, "no assets received");
        credit[msg.sender] += received;
    }

    function _safeTransferFrom(address from, address to, uint256 amount) private {
        (bool ok, bytes memory returned) =
            address(asset).call(abi.encodeWithSelector(IERC20TransferSelector.transferFrom.selector, from, to, amount));
        require(ok, "token call");
        require(returned.length == 0 || (returned.length == 32 && abi.decode(returned, (bool))), "token return");
    }

    function claimable(address account) external view returns (uint256) {
        return credit[account];
    }
}
