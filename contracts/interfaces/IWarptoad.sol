// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IWarptoad {
    // takes `_amount` of `_underlying` from `msg.sender` and mints the same amount of wrapper tokens to `_to`
    // returns the wrapper address
    function gigaIndex() external view returns (uint64);

    // stores (msg.sender, wrapperAssetHash) under the assetId they produce, so wallets can find the preimage.
    // called by a wrapper factory when it deploys a wrapper
    function registerAsset(
        uint256 _firstGigaIndex,
        uint256 _lastGigaIndex,
        uint256 _wrapperAssetHash
    ) external returns (uint256 _assetId);
}
