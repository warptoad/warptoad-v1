// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

contract Warptoad {
    using Strings for uint256;

    string symbolPreFix;
    string namePreFix;
    string chainSymbol;
    string chainName;

    constructor(
        string memory _symbolPreFix,
        string memory _namePreFix,
        string memory _chainSymbol,
        string memory _chainName
    ) {
        symbolPreFix = _symbolPreFix;
        namePreFix = _namePreFix;
        chainSymbol = _chainSymbol;
        chainName = _chainName;
    }

    function _getTokenSymbol(string memory _baseTokenSymbol) private returns (string memory) {
        return string.concat(symbolPreFix, "-", _baseTokenSymbol, "-", chainSymbol);
    }

    function _getTokenName(string memory _baseTokenName) private returns (string memory) {
        return string.concat("Wrapped", " ", namePreFix, " ", _baseTokenName, " ", chainName);
    }

    function wrapERC20() public {}

    function unwrapERC20() public {}

    function wrapER1155() public {}

    function unwrapER1155() public {}
}
