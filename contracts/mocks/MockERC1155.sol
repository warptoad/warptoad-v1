// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ERC1155} from "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";

/// @dev Test-only ERC-1155 exposing the conventional (non-standard) name/symbol.
contract MockERC1155 is ERC1155 {
    string public name;
    string public symbol;

    constructor(string memory name_, string memory symbol_, string memory uri_) ERC1155(uri_) {
        name = name_;
        symbol = symbol_;
    }

    function mint(address to, uint256 id, uint256 value) external {
        _mint(to, id, value, "");
    }
}
