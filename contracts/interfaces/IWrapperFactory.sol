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
        uint256 _amount,
        // in this function we check that _wrapperArgs causes a correct hash that matches _expectedArgHash
        // then we burn `_amount` wrapper tokens from `msg.sender`
        uint256 _expectedArgHash,
        // `_commitmentHash` extra, not needed our use warptoads usecase, but allows to additional logic to gate unshielding
        // based on the commitHash like revealing part of it's pre image
        uint256 _commitmentHash,
        // to reproduce _expectedArgHash
        bytes memory _wrapperArgs
    ) external;

    function unShield(
        address _recipient,
        uint256 _amount,
        // in this function we check that _wrapperArgs causes a correct hash that matches _expectedArgHash
        // then we mint `_amount` wrapper tokens and send it to  `_recipient`
        uint256 _expectedArgHash,
        // `_commitmentHash` extra, not needed our use warptoads usecase, but allows to additional logic to gate unshielding
        // based on the commitHash like revealing part of it's pre image
        uint256 _commitmentHash,
        // to reproduce _expectedArgHash
        bytes memory _wrapperArgs
    ) external;
}
