// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {UnshieldingCommitment} from "../Warptoad.sol";

interface IWrapperFactory {
    // takes `_amount` of `_underlying` from `msg.sender` and mints the same amount of wrapper tokens to `_to`
    // returns the wrapper address
    function wrap(
        address _underlying,
        uint256 _amount,
        address _to
    ) external returns (address);

    // burns `_amount` of `_wrapper` from `msg.sender` and sends the same amount of underlying tokens to `_to`
    // returns the underlying address
    function unWrap(
        address _wrapper,
        uint256 _amount,
        address _to
    ) external returns (address);

    function shield(
        address _from,
        uint256 _amount,
        bytes memory _wrapperArgs
    ) external returns (uint256 _wrapperAssetHash);

    function unShield(
        address _recipient,
        uint256 _amount,
        bytes memory _wrapperArgs
    ) external returns (uint256 _wrapperAssetHash);
}
