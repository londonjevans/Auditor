// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

// Synthetic fixture only. Every inheriting contract is intentionally non-deployable.
abstract contract SyntheticFixtureOnly {
    error SyntheticFixtureCannotDeploy();

    constructor() {
        revert SyntheticFixtureCannotDeploy();
    }
}

abstract contract SyntheticAccess is SyntheticFixtureOnly {
    error AlreadyInitialized();
    error InvalidSyntheticAddress();
    error PausedSyntheticMarket();
    error UnauthorizedSyntheticActor();

    address internal _governor;
    mapping(address guardian => bool approved) internal _guardians;
    bool internal _paused;

    event GovernorChanged(address indexed previousGovernor, address indexed newGovernor);
    event GuardianSet(address indexed guardian, bool approved);
    event PauseStateChanged(bool paused);

    modifier onlyGovernor() {
        if (msg.sender != _governor) revert UnauthorizedSyntheticActor();
        _;
    }

    modifier onlyGuardian() {
        if (!_guardians[msg.sender]) revert UnauthorizedSyntheticActor();
        _;
    }

    modifier whenActive() {
        if (_paused) revert PausedSyntheticMarket();
        _;
    }

    function _initializeSyntheticAccess(address governor_) internal {
        if (_governor != address(0)) revert AlreadyInitialized();
        if (governor_ == address(0)) revert InvalidSyntheticAddress();
        _governor = governor_;
        emit GovernorChanged(address(0), governor_);
    }

    function governor() external view returns (address) {
        return _governor;
    }

    function isGuardian(address account) external view returns (bool) {
        return _guardians[account];
    }

    function setGuardian(address guardian, bool approved) external onlyGovernor {
        if (guardian == address(0)) revert InvalidSyntheticAddress();
        _guardians[guardian] = approved;
        emit GuardianSet(guardian, approved);
    }

    function transferGovernor(address nextGovernor) external onlyGovernor {
        if (nextGovernor == address(0)) revert InvalidSyntheticAddress();
        address previous = _governor;
        _governor = nextGovernor;
        emit GovernorChanged(previous, nextGovernor);
    }

    function pause() external onlyGuardian {
        _paused = true;
        emit PauseStateChanged(true);
    }

    function unpause() external onlyGovernor {
        _paused = false;
        emit PauseStateChanged(false);
    }
}

abstract contract SyntheticAccounting is SyntheticAccess {
    error InsufficientSyntheticBalance();
    error InvalidSyntheticAmount();

    mapping(address account => uint256 shares) internal _shareBalance;
    uint256 internal _totalShares;
    uint256 internal _totalManagedAssets;

    event SyntheticSharesMinted(address indexed receiver, uint256 assets, uint256 shares);
    event SyntheticSharesBurned(address indexed owner, uint256 assets, uint256 shares);

    function _convertToShares(uint256 assets) internal view returns (uint256) {
        if (assets == 0) revert InvalidSyntheticAmount();
        if (_totalShares == 0 || _totalManagedAssets == 0) return assets;
        return assets * _totalShares / _totalManagedAssets;
    }

    function _convertToAssets(uint256 shares) internal view returns (uint256) {
        if (shares == 0) revert InvalidSyntheticAmount();
        if (_totalShares == 0 || _totalManagedAssets == 0) return shares;
        return shares * _totalManagedAssets / _totalShares;
    }

    function _mintSyntheticShares(
        address receiver,
        uint256 assets
    ) internal returns (uint256 shares) {
        shares = _convertToShares(assets);
        _shareBalance[receiver] += shares;
        _totalShares += shares;
        _totalManagedAssets += assets;
        emit SyntheticSharesMinted(receiver, assets, shares);
    }

    function _burnSyntheticShares(
        address owner,
        uint256 shares
    ) internal returns (uint256 assets) {
        if (_shareBalance[owner] < shares) revert InsufficientSyntheticBalance();
        assets = _convertToAssets(shares);
        _shareBalance[owner] -= shares;
        _totalShares -= shares;
        _totalManagedAssets -= assets;
        emit SyntheticSharesBurned(owner, assets, shares);
    }

    function shareBalance(address account) external view returns (uint256) {
        return _shareBalance[account];
    }

    function totalShares() external view returns (uint256) {
        return _totalShares;
    }
}
