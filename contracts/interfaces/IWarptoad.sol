// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IWarptoad {
    // takes `_amount` of `_underlying` from `msg.sender` and mints the same amount of wrapper tokens to `_to`
    // returns the wrapper address
    function gigaIndex() external returns(uint64);
}
