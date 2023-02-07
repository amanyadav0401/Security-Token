// SPDX-License-Identifier: GPL-3.0

pragma solidity ^0.8.0;

import 'contracts/interface/ICompliance.sol';
import 'contracts/interface/IIdentityRegistry.sol';

contract TokenStorage {
    /// @dev ERC20 basic variables
    mapping(address => uint256) internal _balances;
    mapping(address => mapping(address => uint256)) internal _allowances;
    uint256 internal _totalSupply;

    /// @dev Token information
    string internal tokenName;
    string internal tokenSymbol;
    uint8 internal tokenDecimals;
    address internal tokenIdentity;
    uint256 public maxSupply;
    uint256 public frozenTokensCount;
    string internal constant TOKEN_VERSION = '0.1';

    /// @dev Variables of freeze and pause functions
    mapping(address => bool) internal frozen;
    mapping(address => uint256) internal frozenTokens;

    bool internal tokenPaused = false;

    /// @dev Identity Registry contract used by the onchain validator system
    IIdentityRegistry internal tokenIdentityRegistry;

    /// @dev Compliance contract linked to the onchain validator system
    ICompliance internal tokenCompliance;
}
