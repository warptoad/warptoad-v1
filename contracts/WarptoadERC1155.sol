// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ERC1155} from "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import {IERC1155MetadataURI} from "@openzeppelin/contracts/token/ERC1155/extensions/IERC1155MetadataURI.sol";

/**
 * @title WarptoadERC1155
 * @notice The wrapped representation of a single ERC-1155 collection, minted 1:1
 * per token id against collateral held by the {Warptoad} vault that deployed it.
 *
 * Token ids mirror the underlying collection's, so a wrapped balance of id `x`
 * is always redeemable for the same amount of the underlying's id `x`.
 */
contract WarptoadERC1155 is ERC1155 {
    /// @notice The vault that deployed this collection and is allowed to mint and burn it.
    address public immutable warptoad;

    /// @notice The collection this one is a wrapped representation of.
    address public immutable underlying;

    /// @dev Not part of ERC-1155, but conventional enough that wallets and indexers read it.
    string public name;
    string public symbol;

    error OnlyWarptoad(address caller);

    modifier onlyWarptoad() {
        if (msg.sender != warptoad) {
            revert OnlyWarptoad(msg.sender);
        }
        _;
    }

    constructor(address _underlying, string memory _name, string memory _symbol) ERC1155("") {
        warptoad = msg.sender;
        underlying = _underlying;
        name = _name;
        symbol = _symbol;
    }

    /**
     * @dev Forwards to the underlying collection so wrapped ids keep their artwork
     * and traits. Returns an empty string when the underlying exposes no metadata.
     */
    function uri(uint256 id) public view override returns (string memory) {
        try IERC1155MetadataURI(underlying).uri(id) returns (string memory underlyingUri) {
            return underlyingUri;
        } catch {
            return "";
        }
    }

    function mint(address to, uint256 id, uint256 value) external onlyWarptoad {
        _mint(to, id, value, "");
    }

    /**
     * @dev Burns without an approval check. The vault is immutable code that only
     * ever burns from the account unwrapping its own balance.
     */
    function burn(address from, uint256 id, uint256 value) external onlyWarptoad {
        _burn(from, id, value);
    }
}
